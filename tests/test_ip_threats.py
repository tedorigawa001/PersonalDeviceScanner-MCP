"""Synthetic destinations and explicit temporary caches only; never collect owner connections."""
import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from pc_scanner import connections as c, dashboard, history, ip_threats as t
from pc_scanner.core import Scanner, ScannerError
from tests.test_connections import Clock

NOW = datetime(2026, 10, 31, 3, 0, tzinfo=timezone.utc)


def feed(version, published=NOW, cidrs=None):
    cidrs = cidrs if cidrs is not None else (["8.8.8.0/24"] if version == 4 else ["2606:4700::/32"])
    body = b"".join((json.dumps({"cidr": cidr, "rir": "arin", "sblid": "SBL" + str(i + 1)}) + "\n").encode()
                    for i, cidr in enumerate(cidrs))
    meta = {"type": "metadata", "timestamp": int(published.timestamp()), "records": len(cidrs), "size": len(body),
            "copyright": "(c) 2026 The Spamhaus Project SLU", "terms": t.TERMS}
    return body + (json.dumps(meta) + "\n").encode()


def cache_bytes(published=NOW, retrieved=NOW, bodies=None):
    bodies = bodies or {v: feed(v, published) for v in (4, 6)}
    return json.dumps({"schema": 1, "retrieved_at": t.stamp(retrieved), "feeds": {
        str(v): {"body": base64.b64encode(b).decode(), "sha256": hashlib.sha256(b).hexdigest()}
        for v, b in bodies.items()}}).encode()


class ParserTests(unittest.TestCase):
    def test_cidr_boundaries_overlap_duplicates_and_ipv6(self):
        parsed = t.parse_feed(feed(4, cidrs=["8.8.8.0/24", "8.8.8.0/24", "8.8.8.0/25"]), 4)
        self.assertEqual(len(t.lookup(parsed, ipaddress.ip_address("8.8.8.0"), time.monotonic()+1, None)[0]), 3)
        for addr in ["8.8.8.0", "8.8.8.255"]:
            self.assertTrue(t.lookup(parsed, ipaddress.ip_address(addr), time.monotonic()+1, None)[0])
        self.assertFalse(t.lookup(parsed, ipaddress.ip_address("8.8.9.0"), time.monotonic()+1, None)[0])
        parsed = t.parse_feed(feed(6), 6)
        self.assertTrue(t.lookup(parsed, ipaddress.ip_address("2606:4700::1"), time.monotonic()+1, None)[0])
        self.assertFalse(t.lookup(parsed, ipaddress.ip_address("2606:4701::1"), time.monotonic()+1, None)[0])
        self.assertTrue(t.lookup(parsed, ipaddress.ip_address("2606:4700:ffff:ffff:ffff:ffff:ffff:ffff"), time.monotonic()+1, None)[0])

    def test_invalid_families_ranges_metadata_and_duplicate_json_keys(self):
        for cidr in ["10.0.0.0/8", "127.0.0.0/8", "192.0.2.0/24", "0.0.0.0/0", "8.8.8.1/24", "224.0.0.0/4", "::ffff:808:800/120"]:
            with self.subTest(cidr=cidr), self.assertRaises(ValueError):t.parse_feed(feed(4,cidrs=[cidr]),4)
        raw = feed(4)
        for value in [raw.replace(b'"records": 1', b'"records": true'), raw.replace(b'"type": "metadata"',b'"type":"metadata","type":"metadata"'),
                      raw.replace(b'SBL1', b'<script>'), raw[:-1].splitlines()[0], b'[]', feed(4,cidrs=[])]:
            with self.subTest(raw=value[:20]), self.assertRaises((ValueError,TypeError)):t.parse_feed(value,4)

    def test_bounded_parser_and_cancellation(self):
        with self.assertRaises(ValueError):t.parse_feed(b'x'*(t.FEED_LIMIT+1),4)
        with patch.object(t,'MAX_NETWORKS',1), self.assertRaises(ValueError):t.parse_feed(feed(4,cidrs=['8.8.8.0/24']*2),4)
        with self.assertRaises(c.Stopped):t.parse_feed(feed(4),4,lambda:c.check(0,None))

    def test_bundle_integrity_dates_and_freshness_boundary(self):
        feeds,retrieved=t.bundle(cache_bytes())
        expiry=NOW+timedelta(hours=48)
        for delta,state in [(-1,'fresh'),(0,'stale'),(1,'stale')]:
            self.assertEqual(t.describe(feeds,retrieved,expiry+timedelta(microseconds=delta),48)['4']['freshness'],state)
        self.assertEqual(t.describe(feeds,retrieved,NOW-timedelta(microseconds=1),48)['4']['freshness'],'unverified')
        for bad in [cache_bytes(retrieved=NOW-timedelta(seconds=1)), cache_bytes().replace(b'"sha256": "',b'"sha256": "bad')]:
            with self.assertRaises(ValueError):t.bundle(bad)

    def test_many_references_are_bounded_with_explicit_omission(self):
        parsed=t.parse_feed(feed(4,cidrs=['8.8.8.0/24']*20),4)
        retained,omitted=t.lookup(parsed,ipaddress.ip_address('8.8.8.8'),time.monotonic()+1,None)
        self.assertEqual(len(retained),4);self.assertEqual(omitted,16)

    def test_settings_and_unknown_key_warning(self):
        for raw in [[],{'enabled':1},{'allow_updates':'true'},{'max_age_hours':True},{'max_age_hours':169},{'cache_directory':'relative'},{'save_details':1}]:
            with self.assertRaises(ScannerError):Scanner({'ip_threats':raw})
        self.assertIn('ip_threats.enabld',str(Scanner({'ip_threats':{'enabld':True}}).config_warnings))


@unittest.skipUnless(os.name=='posix','Private cache backend is POSIX only')
class CacheTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.folder=self.root/'cache'
        self.cfg={'history':{'enabled':False,'file':str(self.root/'history.jsonl')},'ip_threats':{
            'enabled':True,'allow_updates':True,'cache_directory':str(self.folder)},'outbound_connections':{
            'enabled':True,'duration_seconds':1,'interval_seconds':1}}
        guard=patch.object(history,'default_file',side_effect=AssertionError('personal default resolved'));guard.start();self.addCleanup(guard.stop)
        network=patch.object(t,'download',side_effect=AssertionError('unexpected public download'));network.start();self.addCleanup(network.stop)

    def scanner(self):
        scanner=Scanner(copy.deepcopy(self.cfg));scanner.via='cli';return scanner

    def write(self, raw=None):
        with t.Cache(t.cache_settings(self.scanner())).open(create=True) as cache:
            cache.atomic('current.json',raw if raw is not None else cache_bytes(),t.BUNDLE_LIMIT)

    def row(self,**changes):
        return {'pid':'42','start_time':'1000','process':'synthetic-private-app','family':'2','protocol':'6',
            'local_address':'192.168.1.2','local_port':'50001','remote_address':'8.8.8.8','remote_port':'443','state':'ESTABLISHED',**changes}

    def observe(self,rows=None,scanner=None,cancel=None):
        clock=Clock();snapshot=({'192.168.1.2'},{'192.168.1.255'},{('synthetic','192.168.1.2')})
        with patch.object(c.Backend,'__init__',lambda self,*a:setattr(self,'limits',set())), \
             patch.object(c.Backend,'addresses',return_value=snapshot),patch.object(c.Backend,'sockets',return_value=rows or [self.row()]), \
             patch.object(c.time,'monotonic',clock.monotonic),patch.object(c.time,'sleep',clock.sleep):
            return (scanner or self.scanner()).invoke('check_connection_destinations',cancel=cancel)

    def test_matching_deduplication_counts_and_no_vulnerability_findings(self):
        self.write()
        rows=[self.row(),self.row(),self.row(remote_port='80'),self.row(pid='43'),self.row(remote_address='1.1.1.1'),self.row(remote_address='192.168.1.3')]
        scanner=self.scanner();scanner.connection_settings['duration_seconds']=2
        with patch.object(t,'clock',return_value=NOW):r=self.observe(rows,scanner=scanner)
        self.assertEqual(r['status'],'completed',r);self.assertEqual(r['findings'],[])
        v=r['data']['destination_threats'];self.assertEqual(v['unique_destinations'],3)
        self.assertEqual(v['destination_counts'],{'matched':1,'not_listed':1,'not_applicable':1})
        self.assertEqual(v['matched_connection_records'],3);self.assertEqual(v['matched_processes'],2)
        self.assertTrue(all(row['sample_count']==2 for row in r['data']['connections']))

    def test_mapped_ipv6_udp_missing_and_unknown_attribution(self):
        self.write()
        rows=[self.row(family='10',local_address='::ffff:192.168.1.2',remote_address='::ffff:8.8.8.8'),
              self.row(start_time=None),self.row(protocol='17',remote_address='0.0.0.0',remote_port='0')]
        with patch.object(t,'clock',return_value=NOW):r=self.observe(rows)
        self.assertEqual(r['data']['destination_threats']['unique_destinations'],1)
        self.assertEqual(r['data']['destination_threats']['matched_unattributed_records'],1)
        self.assertEqual(r['data']['unavailable_counts']['destination_unavailable'],1)
        scoped=[self.row(family='10',local_address='fe80::2%'+scope,remote_address='fe80::1%'+scope)
                for scope in ('test0','test1')]
        with patch.object(t,'clock',return_value=NOW):r=self.observe(scoped)
        self.assertEqual(r['data']['destination_threats']['destination_counts'],{'not_applicable':2})

    def test_missing_and_corrupt_cache_never_create_or_fallback(self):
        with patch.object(t,'clock',return_value=NOW):r=self.observe()
        self.assertEqual(r['status'],'partial');self.assertFalse(self.folder.exists())
        self.assertEqual(r['data']['connections'][0]['threat']['state'],'unverified')
        self.write(b'{broken')
        (self.folder/'previous.json').write_bytes(cache_bytes());(self.folder/'previous.json').chmod(0o600)
        with patch.object(t,'clock',return_value=NOW):r=self.observe()
        self.assertEqual(r['data']['connections'][0]['threat']['state'],'unverified')

    def test_stale_match_not_listed_and_completion_crossing_expiry(self):
        self.write()
        with patch.object(t,'clock',return_value=NOW+timedelta(hours=48)):
            r=self.observe([self.row(),self.row(remote_address='1.1.1.1')])
        self.assertEqual(r['data']['destination_threats']['destination_counts'],{'unverified':2})
        self.assertTrue(next(row for row in r['data']['connections'] if row['remote_ip']=='8.8.8.8')['threat']['historical_match'])
        with patch.object(t,'clock',side_effect=[NOW,NOW+timedelta(hours=48)]):r=self.observe()
        self.assertEqual(r['data']['connections'][0]['threat']['state'],'unverified')

    def test_unsafe_modes_symlinks_and_missing_lock_read_only(self):
        self.write();(self.folder/'.lock').unlink();before=sorted(p.name for p in self.folder.iterdir())
        with patch.object(t,'clock',return_value=NOW):r=self.observe()
        self.assertEqual(r['status'],'completed');self.assertEqual(sorted(p.name for p in self.folder.iterdir()),before)
        file=self.folder/'current.json';file.chmod(0o644)
        with patch.object(t,'clock',return_value=NOW):self.assertEqual(self.observe()['status'],'partial')
        file.chmod(0o600);file.unlink();file.symlink_to(self.root/'history.jsonl')
        with patch.object(t,'clock',return_value=NOW):self.assertEqual(self.observe()['status'],'partial')
        self.assertFalse((self.root/'history.jsonl').exists())

    def test_disabled_never_collects_and_cancel_releases_locks(self):
        scanner=self.scanner();scanner.ip_threat_settings['enabled']=False
        with patch.object(c,'Backend',side_effect=AssertionError('must not collect')):self.assertEqual(scanner.invoke('check_connection_destinations')['status'],'error')
        scanner=self.scanner();stop=threading.Event();stop.set()
        r=scanner.invoke('check_connection_destinations',cancel=stop);self.assertEqual(r['status'],'partial')
        self.assertTrue(scanner._connection_lock.acquire(False));scanner._connection_lock.release()

    def test_update_success_rate_limit_atomic_failure_and_permissions(self):
        from pc_scanner.progress import ScanProgress
        scanner=self.scanner()
        progress=ScanProgress()
        with patch.object(t,'clock',return_value=NOW),patch.object(t,'download',side_effect=lambda v,*a:feed(v)) as download:
            r=scanner.invoke('update_ip_threat_lists',progress=progress);self.assertEqual(r['status'],'completed',r);self.assertEqual(download.call_count,2)
            self.assertEqual(progress.snapshot()['persistence'],'cache_saved')
            limited=scanner.invoke('update_ip_threat_lists');self.assertEqual(limited['status'],'partial');self.assertEqual(download.call_count,2)
            self.assertEqual(limited['data']['stop_reason'],'rate_limited_no_request_sent')
        old=(self.folder/'current.json').read_bytes()
        with patch.object(t,'clock',return_value=NOW+timedelta(hours=1)),patch.object(t,'download',side_effect=[feed(4),b'bad']):
            self.assertEqual(scanner.invoke('update_ip_threat_lists')['status'],'partial')
        self.assertEqual((self.folder/'current.json').read_bytes(),old)
        self.assertEqual(self.folder.stat().st_mode&0o777,0o700)
        self.assertTrue(all(p.stat().st_mode&0o777==0o600 for p in self.folder.iterdir()))

    def test_update_cancel_between_families_retains_generation(self):
        self.write();old=(self.folder/'current.json').read_bytes();stop=threading.Event()
        def download(v,*a):stop.set();return feed(v)
        with patch.object(t,'clock',return_value=NOW),patch.object(t,'download',side_effect=download):r=self.scanner().invoke('update_ip_threat_lists',cancel=stop)
        self.assertEqual(r['data']['stop_reason'],'cancelled');self.assertEqual((self.folder/'current.json').read_bytes(),old)
        self.assertFalse(list(self.folder.glob('.*.tmp')))

    def test_publication_rollback_and_future_attempt_never_replace_current(self):
        self.write();old=(self.folder/'current.json').read_bytes()
        with patch.object(t,'clock',return_value=NOW),patch.object(t,'download',side_effect=lambda v,*a:feed(v,NOW-timedelta(hours=1))):
            self.assertEqual(self.scanner().invoke('update_ip_threat_lists')['status'],'partial')
        self.assertEqual((self.folder/'current.json').read_bytes(),old)
        with t.Cache(t.cache_settings(self.scanner())).open() as cache:cache.atomic('attempt.json',json.dumps({'attempted_at':t.stamp(NOW+timedelta(days=1))}).encode(),1024)
        with patch.object(t,'clock',return_value=NOW),patch.object(t,'download',side_effect=AssertionError('future attempt must not fetch')):
            self.assertEqual(self.scanner().invoke('update_ip_threat_lists')['status'],'partial')

    def test_cache_writer_contention_and_recovery(self):
        self.write()
        with t.Cache(t.cache_settings(self.scanner())).open():
            with patch.object(t,'clock',return_value=NOW):self.assertEqual(self.scanner().invoke('update_ip_threat_lists')['status'],'partial')
        with patch.object(t,'clock',return_value=NOW),patch.object(t,'download',side_effect=lambda v,*a:feed(v)):
            self.assertEqual(self.scanner().invoke('update_ip_threat_lists')['status'],'completed')

    def test_partial_feed_family_and_empty_observation_keep_unverified_coverage(self):
        self.write(cache_bytes(bodies={4:feed(4),6:feed(6,NOW-timedelta(hours=49))}))
        with patch.object(t,'clock',return_value=NOW):r=self.observe()
        self.assertEqual(r['status'],'partial');self.assertEqual(r['data']['connections'][0]['threat']['state'],'matched')
        report={'status':'completed','data':{'connections':[]},'warnings':[]}
        with patch.object(t,'clock',return_value=NOW):t.enrich(self.scanner(),report,time.monotonic()+1)
        self.assertEqual(report['status'],'partial');self.assertEqual(report['data']['destination_threats']['unique_destinations'],0)

    def test_update_mcp_and_permission_gates_before_network(self):
        scanner=self.scanner();scanner.via='mcp'
        self.assertEqual(scanner.invoke('update_ip_threat_lists')['status'],'error')
        scanner.via='cli';scanner.ip_threat_settings['allow_updates']=False
        self.assertEqual(scanner.invoke('update_ip_threat_lists')['status'],'error');self.assertFalse(self.folder.exists())

    def test_no_network_in_observation_and_strict_mcp_anonymity_with_saving_enabled(self):
        self.write();scanner=self.scanner();scanner.via='mcp';scanner.history_enabled=True;scanner.history_details=True
        scanner.connection_settings.update(save_details=True,expose_identifiers_to_mcp=True);scanner.ip_threat_settings['save_details']=True
        with patch.object(t,'clock',return_value=NOW),patch.object(history,'append') as append:r=self.observe(scanner=scanner)
        raw=json.dumps(r)
        for secret in ['8.8.8.8','synthetic-private-app','SBL1','8.8.8.0/24','remote_ip','pid','observation_id','current.json']:
            self.assertNotIn(secret,raw)
        self.assertEqual(append.call_args.args[2],None)
        summary_record=append.call_args.args[1];self.assertNotIn('synthetic-private-app',json.dumps(summary_record))
        self.assertEqual(r['data']['destination_threats']['destination_counts'],{'matched':1})

    def test_history_validation_and_dashboard_summary_without_detail_permission(self):
        self.write()
        with patch.object(t,'clock',return_value=NOW):r=self.observe()
        item=history.entry('check_connection_destinations',{},r,NOW,1,'cli');parsed=history.parse(json.dumps(item))
        self.assertIsNotNone(parsed);self.assertEqual(parsed['findings'],{})
        rendered=dashboard.render([parsed],[(None,'off')],{'file':'synthetic-history','recording':True,'details':False,'details_mb':1,'skipped':0,'generated':'synthetic'})
        self.assertIn('No match does not prove safety',rendered);self.assertNotIn('8.8.8.8',rendered)
        self.assertNotIn('Findings in the latest results',rendered)
        dirty=copy.deepcopy(item);dirty['destination_threats']['destination_counts']['matched']='private-app'
        self.assertNotIn('destination_threats',history.parse(json.dumps(dirty)))
        detailed=dashboard.connection_details(r['data']);self.assertIn('8.8.8.8',detailed);self.assertIn('SBL1',detailed)

    def test_local_cli_roundtrip_uses_fixed_collector_and_real_store(self):
        self.write();engine=self.root/'fake-osquery';engine.write_text('#!'+sys.executable+'\nimport json,sys\nprint(json.dumps('+repr([{'interface':'test','address':'192.168.1.2','broadcast':'192.168.1.255'}])+ ' if "interface_addresses" in sys.argv[-1] else '+repr([self.row()])+'))\n');engine.chmod(0o700)
        cfg=self.root/'scanner.toml';cfg.write_text('[history]\nenabled=false\nfile='+json.dumps(str(self.root/'history.jsonl'))+'\n[local]\nosquery_binary='+json.dumps(str(engine))+'\n[outbound_connections]\nenabled=true\nduration_seconds=1\ninterval_seconds=1\n[ip_threats]\nenabled=true\ncache_directory='+json.dumps(str(self.folder))+'\nmax_age_hours=168\n')
        # The CLI uses the real current clock, so publish this synthetic fixture now.
        with t.Cache(t.cache_settings(self.scanner())).open() as cache:cache.atomic('current.json',cache_bytes(published=datetime.now(timezone.utc).replace(microsecond=0),retrieved=datetime.now(timezone.utc)),t.BUNDLE_LIMIT)
        z=subprocess.run([sys.executable,'-m','pc_scanner.cli','--config',str(cfg),'outbound-connections','--check-ip-threats','--json'],capture_output=True,text=True,timeout=10)
        self.assertEqual(z.returncode,0,z.stderr);self.assertEqual(json.loads(z.stdout)['data']['destination_threats']['destination_counts'],{'matched':1})

    @unittest.skipUnless(importlib.util.find_spec('mcp'),'agent extra not installed')
    def test_real_mcp_transport_tool_is_anonymous_and_has_no_update_entry(self):
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server
        self.write();scanner=self.scanner();scanner.via='cli'
        async def run():
            async with create_connected_server_and_client_session(create_server(scanner)) as session:
                tools=(await session.list_tools()).tools;tool=next(v for v in tools if v.name=='check_connection_destinations')
                self.assertTrue(tool.annotations.readOnlyHint);self.assertFalse(tool.annotations.openWorldHint)
                self.assertFalse(any('update_ip_threat' in v.name for v in tools))
                with patch.object(t,'clock',return_value=NOW):
                    # Mock only the collector, leaving the actual MCP transport and local matcher intact.
                    original=c.observe
                    def observed(s,cancel=None,progress=None,check_ip_threats=False):
                        snapshot=({'192.168.1.2'},set(),{('test','192.168.1.2')})
                        with patch.object(c.Backend,'__init__',lambda self,*a:setattr(self,'limits',set())),patch.object(c.Backend,'addresses',return_value=snapshot),patch.object(c.Backend,'sockets',return_value=[self.row()]):
                            return original(s,cancel,progress,check_ip_threats)
                    with patch.object(c,'observe',side_effect=observed):reply=await session.call_tool('check_connection_destinations',{})
                raw=reply.content[0].text;self.assertNotIn('8.8.8.8',raw);self.assertNotIn('synthetic-private-app',raw)
                self.assertEqual(json.loads(raw)['data']['destination_threats']['destination_counts'],{'matched':1})
        asyncio.run(run())

    @unittest.skipUnless(importlib.util.find_spec('mcp'),'agent extra not installed')
    def test_actual_stdio_anonymous_reply_even_with_all_detail_settings(self):
        from mcp import ClientSession,StdioServerParameters
        from mcp.client.stdio import stdio_client
        self.write();engine=self.root/'fixture-osquery'
        engine.write_text('#!'+sys.executable+'\nimport json,sys\nprint(json.dumps('+repr([{'interface':'test','address':'192.168.1.2','broadcast':'192.168.1.255'}])+' if "interface_addresses" in sys.argv[-1] else '+repr([self.row()])+'))\n');engine.chmod(0o700)
        with t.Cache(t.cache_settings(self.scanner())).open() as cache:cache.atomic('current.json',cache_bytes(published=datetime.now(timezone.utc).replace(microsecond=0),retrieved=datetime.now(timezone.utc)),t.BUNDLE_LIMIT)
        cfg=self.root/'stdio.toml';cfg.write_text('[history]\nenabled=true\ndetails=true\nfile='+json.dumps(str(self.root/'history.jsonl'))+'\n[local]\nosquery_binary='+json.dumps(str(engine))+'\n[outbound_connections]\nenabled=true\nexpose_identifiers_to_mcp=true\nsave_details=true\nduration_seconds=1\ninterval_seconds=1\n[ip_threats]\nenabled=true\nsave_details=true\ncache_directory='+json.dumps(str(self.folder))+'\n')
        async def run():
            params=StdioServerParameters(command=sys.executable,args=['-m','pc_scanner.cli','--config',str(cfg),'serve'])
            with (self.root/'stderr.txt').open('w') as log:
                async with stdio_client(params,errlog=log) as (rd,wr):
                    async with ClientSession(rd,wr) as session:
                        await session.initialize();reply=await session.call_tool('check_connection_destinations',{})
                        raw=reply.content[0].text;r=json.loads(raw)
                        self.assertEqual(r['status'],'completed',r)
                        for secret in ['8.8.8.8','synthetic-private-app','SBL1','8.8.8.0/24',str(self.root)]:self.assertNotIn(secret,raw)
                        self.assertEqual(r['data']['destination_threats']['destination_counts'],{'matched':1})
        asyncio.run(run())
        records,_=history.read(self.root/'history.jsonl',10)
        self.assertIsNone(records[0]['details']);self.assertNotIn('8.8.8.8',(self.root/'history.jsonl').read_text())

    def test_local_detail_permission_is_separate_and_dashboard_is_escaped(self):
        self.write();scanner=self.scanner();scanner.history_enabled=True;scanner.history_details=True;scanner.connection_settings['save_details']=True
        with patch.object(t,'clock',return_value=NOW),patch.object(history,'append') as append:self.observe(scanner=scanner)
        self.assertIsNone(append.call_args.args[2])
        scanner.ip_threat_settings['save_details']=True
        with patch.object(t,'clock',return_value=NOW),patch.object(history,'append') as append:r=self.observe(scanner=scanner)
        self.assertIsNotNone(append.call_args.args[2])
        r['data']['connections'][0]['process']='</summary><script>attack</script>'
        html=dashboard.connection_details(r['data']);self.assertNotIn('<script>',html);self.assertIn('&lt;script&gt;',html)

    def test_cache_mid_read_deadline_is_timeout_not_missing_feed(self):
        self.write()
        def timeout(cache,*a,**kw):cache.deadline=0;cache.check()
        with patch.object(t.Cache,'read',timeout),patch.object(t,'clock',return_value=NOW):r=self.observe()
        # A store read has its own fixed error, but only an actually expired observation deadline is timeout.
        self.assertEqual(r['status'],'partial');self.assertEqual(r['data']['connections'][0]['threat']['state'],'unverified')

    def test_deadline_during_matching_marks_unfinished_destinations_unverified(self):
        self.write()
        with patch.object(t,'lookup',side_effect=c.Stopped('timeout')),patch.object(t,'clock',return_value=NOW):r=self.observe()
        self.assertEqual(r['status'],'partial');self.assertEqual(r['data']['stop_reason'],'timeout')
        self.assertEqual(r['data']['connections'][0]['threat']['state'],'unverified')

    def test_anonymous_errors_never_echo_internal_messages(self):
        scanner=self.scanner();scanner.via='mcp';scanner.history_enabled=True
        with patch.object(c,'Backend',side_effect=ScannerError('synthetic-private-app 8.8.8.8 /synthetic/private')),patch.object(history,'append') as append:
            r=scanner.invoke('check_connection_destinations')
        self.assertEqual(r['status'],'error')
        for secret in ['8.8.8.8','synthetic-private-app','/synthetic/private']:
            self.assertNotIn(secret,json.dumps(r));self.assertNotIn(secret,json.dumps(append.call_args.args[1]))


class NetworkTests(unittest.TestCase):
    def test_updater_has_fixed_urls_headers_tls_and_no_proxy(self):
        for v in (4,6):
            with patch.object(t,'fetch_bounded',return_value=b'data') as fetch:
                self.assertEqual(t.download(v,time.monotonic()+1,None),b'data')
            args=fetch.call_args.args;request=args[2]
            self.assertEqual(request.full_url,t.URLS[v]);self.assertEqual(request.get_method(),'GET')
            self.assertEqual(set(k.lower() for k in request.headers),{'user-agent','accept-encoding'})
            self.assertEqual(args[1]._context.verify_mode,ssl.CERT_REQUIRED)
            self.assertTrue(args[1]._context.check_hostname)

    @unittest.skipUnless(importlib.util.find_spec('cryptography'),'cryptography not installed')
    def test_real_tls_header_and_body_stalls_cancel_deadline_and_end_worker(self):
        from tests.test_scanner import SlowWazuhServer
        from urllib.request import Request
        for headers in (False,True):
            for mode in ('cancel','deadline'):
                with self.subTest(headers=headers,mode=mode), tempfile.TemporaryDirectory() as folder:
                    with SlowWazuhServer(Path(folder),headers_only=headers) as server:
                        context=ssl.create_default_context(cafile=str(server.ca_file));cancel=threading.Event()
                        timer=threading.Timer(.1,cancel.set) if mode=='cancel' else None
                        before={v.ident for v in threading.enumerate() if v.name=='public threat list-request'}
                        if timer:timer.start()
                        # This test fixture expects Content-Length even for GET; production GETs do not add it.
                        def request(url,headers):return Request(url,headers={**headers,'Content-Length':'0'})
                        with patch.object(t,'URLS',{4:server.url}),patch.object(t.ssl,'create_default_context',return_value=context),patch.object(t,'Request',side_effect=request):
                            with self.assertRaises(ScannerError):t.download(4,time.monotonic()+.25,cancel)
                        if timer:timer.join()
                        until=time.monotonic()+1
                        while time.monotonic()<until and any(v.name=='public threat list-request' and v.ident not in before for v in threading.enumerate()):time.sleep(.01)
                        self.assertFalse(any(v.name=='public threat list-request' and v.ident not in before for v in threading.enumerate()))

