"""Synthetic records in explicit temporary stores only; never inspect personal process data."""
import asyncio
import copy
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
import hashlib
import importlib.util
import json
import os
import secrets
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from pc_scanner import core, process_review as review, process_store as store


class ConfigTests(unittest.TestCase):
    def test_storage_settings(self):
        for raw in [[], {"enabled": 1}, {"max_records": True}, {"max_total_mb": 129},
                    {"retention_days": 0}, {"directory": "relative"}, {"directory": "/a/../b"}, {"mystery": True}]:
            with self.subTest(raw=raw), self.assertRaises(core.ScannerError):
                store.load(raw)
        self.assertFalse(core.Scanner({}).process_review_settings["storage"]["enabled"])


    @unittest.skipUnless(importlib.util.find_spec('mcp'),'agent extra not installed')
    def test_real_mcp_with_storage_enabled_never_saves_or_discloses(self):
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        folder=Path(tmp.name).resolve()/'records'
        scanner=core.Scanner({'history':{'enabled':False},'process_review':{'enabled':True,
            'targets':{'demo':{'pid':42,'start_time':1000}},'storage':{'enabled':True,'directory':str(folder)}}});scanner.via='mcp'
        row={'pid':'42','start_time':'1000','path':'/private/example/node','name':'private-name','parent':'1','parent_path':None,'parent_start_time':'1'}
        async def run():
            async with create_connected_server_and_client_session(create_server(scanner)) as session:
                tools=(await session.list_tools()).tools
                self.assertFalse(any('record' in t.name or 'dashboard' in t.name for t in tools))
                response=await session.call_tool('review_processes',{});raw=response.content[0].text
                report=json.loads(raw)
                self.assertEqual(report['status'],'completed')
                self.assertEqual(report['data']['reviewed_count'],1)
                self.assertNotIn('private-name',raw);self.assertNotIn('run_id',raw);self.assertNotIn('record_id',raw)
                self.assertEqual(json.loads(raw)['data']['persistence'],'not_saved')
        with patch.object(review.Backend,'__init__',lambda self,*a:setattr(self,'limits',set())), \
             patch.object(review.Backend,'query',return_value=[row]), \
             patch.object(store.history,'default_file',side_effect=AssertionError('personal default store resolved')):
            asyncio.run(run())
        self.assertFalse(folder.exists())

@unittest.skipUnless(os.name == "posix", "Private store backend is POSIX only")
class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.folder = self.base / "records"
        self.now = datetime.now(timezone.utc)
        self.default = patch.object(store.history, "default_file", side_effect=AssertionError("default personal store resolved"))
        self.default.start()
        self.addCleanup(self.default.stop)

    def scanner(self, **settings):
        scanner = core.Scanner({"history": {"enabled": False, "file": str(self.base / "history.jsonl")},
            "process_review": {"enabled": True, "targets": {"private-alias": {"pid": 42, "start_time": 1000}},
                "storage": {"enabled": True, "directory": str(self.folder), **settings}}})
        scanner.via = "cli"
        return scanner

    def report(self):
        return core.result("process_review", "partial", data={"run_id": "b" * 32,
            "started_at": store.stamp(self.now - timedelta(seconds=2)),
            "finished_at": store.stamp(self.now - timedelta(seconds=1)),
            "target_count": 1, "reviewed_count": 1, "stop_reason": None, "processes": [{
                "label": "P01", "identity": "start_time_matches", "runtime": "node", "launch": "not_requested",
                "script": "not_requested", "package": "not_requested", "attention": [],
                "details": {"process": {"pid": "42", "start_time": "1000", "parent": "1", "parent_start_time": "1",
                    "path": "/private/example/node", "name": "private<app>", "parent_path": None},
                    "source": "NEVER_SAVE_SOURCE", "environment": "NEVER_SAVE_SECRET"}}]})

    def save(self, scanner=None, report=None):
        scanner, report = scanner or self.scanner(), report or self.report()
        with patch.object(store, "clock", return_value=self.now):
            store.save(scanner, report)
        self.assertEqual(report["data"]["persistence"], "details_saved", report)
        self.assertEqual(report["warnings"], [])
        return report["data"]["record_id"]

    def manage(self, action="list", scanner=None, **kw):
        return store.manage(scanner or self.scanner(), action, **kw)

    def test_no_missing_store_created_by_management(self):
        for action in ["list", "prune", "dashboard"]:
            self.assertFalse(self.manage(action)["data"]["store_exists"])
            self.assertFalse(self.folder.exists())

    def test_unavailable_parent_start_time_can_be_saved_without_claiming_a_time(self):
        for value in (-1, "-1"):
            with self.subTest(value=value):
                report = self.report()
                report["data"]["run_id"] = secrets.token_hex(16)
                report["data"]["processes"][0]["details"]["process"]["parent_start_time"] = value
                rid = self.save(report=report)
                saved = json.loads((self.folder / (rid + ".json")).read_text())
                self.assertIsNone(saved["snapshot"]["processes"][0]["details"]["process"]["parent_start_time"])

    def test_other_negative_process_fields_still_refused(self):
        for field, value in (("pid", -1), ("start_time", -1), ("parent", -1), ("parent_start_time", -2)):
            with self.subTest(field=field):
                report = self.report()
                report["data"]["processes"][0]["details"]["process"][field] = value
                store.save(self.scanner(), report)
                self.assertEqual(report["data"]["persistence"], "save_failed")
                self.assertFalse(self.folder.exists())

    def test_save_whitelist_permissions_and_no_general_history(self):
        rid = self.save()
        raw = (self.folder / (rid + ".json")).read_text()
        self.assertNotIn("NEVER_SAVE", raw)
        self.assertNotIn('"source"', raw)
        self.assertEqual(self.folder.stat().st_mode & 0o777, 0o700)
        for p in self.folder.iterdir(): self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        rows = self.manage()["data"]["records"]
        self.assertEqual(rows[0]["record_id"], rid)
        self.assertNotIn("private<app>", json.dumps(rows))
        self.assertIn("private<app>", json.dumps(self.manage(show_details=True)))
        self.assertFalse((self.base / "history.jsonl").exists())

    def test_double_consent_and_no_mcp_save(self):
        scanner = self.scanner(enabled=False)
        with patch.object(review, "Backend", side_effect=AssertionError("unauthorized collection")):
            report = scanner.invoke("review_processes", save_details=True)
        self.assertEqual(report["error"], "Process review detail saving is not authorized")
        self.assertFalse(self.folder.exists())
        scanner = self.scanner()
        scanner.via = "mcp"
        with self.assertRaises(core.ScannerError): store.save(scanner, self.report())
        with self.assertRaises(core.ScannerError): self.manage(scanner=scanner)
        self.assertFalse(self.folder.exists())

    def test_collection_only_does_not_save_and_cli_projection_is_private(self):
        scanner = self.scanner()
        row = {"pid": "42", "start_time": "1000", "path": "/private/example/node", "name": "private<app>",
               "parent": "1", "parent_path": None, "parent_start_time": "1"}
        with patch.object(review.Backend, "__init__", lambda self, *a: setattr(self, "limits", set())), \
             patch.object(review.Backend, "query", return_value=[row]):
            report = scanner.invoke("review_processes")
            self.assertFalse(self.folder.exists())
            saved = scanner.invoke("review_processes", save_details=True)
        self.assertEqual(saved["data"]["persistence"], "details_saved", saved)
        public = review.for_cli(saved)
        self.assertIn("record_id", public["data"])
        self.assertNotIn("run_id", public["data"])
        self.assertNotIn("private<app>", json.dumps(public))
        mcp = review.for_mcp(saved)
        self.assertNotIn("record_id", mcp["data"])
        self.assertEqual(mcp["data"]["persistence"], "not_saved")

    def test_interrupted_and_error_results_are_not_saved(self):
        # Only a cancel or timeout is an interruption; a read limit or engine warning leaves an incomplete result.
        for reason, state in [("cancelled", "not_saved_interrupted"), ("timeout", "not_saved_interrupted"),
                              ("read_limit", "not_saved_incomplete"), ("read_limit_or_warning", "not_saved_incomplete")]:
            r = self.report(); r["data"]["stop_reason"] = reason
            store.save(self.scanner(), r)
            self.assertEqual(r["data"]["persistence"], state)
            self.assertEqual(review.for_cli(r)["data"]["persistence"], state)
        cancel = threading.Event(); cancel.set(); r = self.report()
        store.save(self.scanner(), r, cancel)
        self.assertEqual(r["data"]["persistence"], "not_saved_interrupted")
        r = self.report();r["status"] = "error"
        store.save(self.scanner(), r)
        self.assertEqual(r["data"]["persistence"], "save_failed")
        self.assertFalse(self.folder.exists())

    def test_expiry_microsecond_boundaries(self):
        self.save()
        until = self.now + timedelta(days=7)
        for delta, expected in [(-1, "active"), (0, "expired"), (1, "expired")]:
            with self.subTest(delta=delta), patch.object(store, "clock", return_value=until+timedelta(microseconds=delta)):
                row = self.manage(show_details=True)["data"]["records"][0]
                self.assertEqual(row["state"], expected)
                self.assertEqual("details" in row, expected == "active")

    def test_retention_shortening_invalidates_html_from_list(self):
        self.save()
        self.manage("dashboard")
        self.assertTrue((self.folder / "dashboard.html").exists())
        with patch.object(store, "clock", return_value=self.now + timedelta(days=2)):
            rows = self.manage(scanner=self.scanner(retention_days=1))["data"]["records"]
        self.assertEqual(rows[0]["state"], "expired")
        self.assertFalse((self.folder / "dashboard.html").exists())

    def test_extension_never_extends_original_expiry(self):
        self.save()
        with patch.object(store, "clock", return_value=self.now + timedelta(days=7)):
            self.assertEqual(self.manage(scanner=self.scanner(retention_days=30))["data"]["records"][0]["state"], "expired")

    def test_delete_revision_and_invalidate_page(self):
        rid = self.save();self.manage("dashboard")
        with self.assertRaises(core.ScannerError): self.manage("delete", record_id=rid, revision="0"*64)
        self.assertTrue((self.folder/(rid+'.json')).exists())
        row = self.manage()["data"]["records"][0]
        self.manage("delete", record_id=rid, revision=row["revision"])
        self.assertFalse((self.folder/(rid+'.json')).exists())
        self.assertFalse((self.folder/'dashboard.html').exists())
        self.assertTrue((self.folder/'.lock').exists())
        for value in ['../x','a'*31,'/absolute','A'*32]:
            with self.assertRaises(core.ScannerError):self.manage('delete',record_id=value,revision='a'*64)

    def test_invalidating_html_failure_blocks_json_deletion(self):
        rid=self.save();self.manage('dashboard');row=self.manage()['data']['records'][0]
        original=store.Store.unlink
        def deny(s,name,*a):
            if name=='dashboard.html':raise PermissionError('denied')
            return original(s,name,*a)
        with patch.object(store.Store,'unlink',deny),self.assertRaises(core.ScannerError):
            self.manage('delete',record_id=rid,revision=row['revision'])
        self.assertTrue((self.folder/(rid+'.json')).exists())

    def test_prune_dry_run_and_selected_expiry(self):
        rid=self.save()
        with patch.object(store,'clock',return_value=self.now+timedelta(days=7)):
            self.assertEqual(self.manage('prune',dry_run=True)['data']['deleted_count'],0)
            self.assertTrue((self.folder/(rid+'.json')).exists())
            self.assertEqual(self.manage('prune')['data']['deleted_count'],1)
        self.assertFalse((self.folder/(rid+'.json')).exists())

    def test_duplicate_run_ids_not_counted_or_shown_as_latest(self):
        rid=self.save();obj=json.loads((self.folder/(rid+'.json')).read_text());other='c'*32;obj['record_id']=other
        p=self.folder/(other+'.json');p.write_bytes(store.encode(obj));p.chmod(0o600)
        rows=self.manage()['data']['records'];self.assertEqual([r['state'] for r in rows],['duplicate','duplicate'])
        r=self.manage('dashboard');self.assertEqual(r['data']['record_count'],0)
        page=(self.folder/'dashboard.html').read_text();self.assertIn('Latest result cannot be established',page)
        self.assertNotIn('private&lt;app&gt;',page)

    def test_no_automatic_save_retry_or_capacity_eviction(self):
        scanner=self.scanner(max_records=1);rid=self.save(scanner)
        r=self.report();r['data']['run_id']='c'*32;store.save(scanner,r)
        self.assertEqual(r['data']['persistence'],'save_failed')
        self.assertTrue((self.folder/(rid+'.json')).exists())
        r=self.report();store.save(scanner,r);self.assertEqual(r['data']['persistence'],'save_failed')
        original=(self.folder/(rid+'.json')).read_bytes()
        r=self.report();r['data']['run_id']='d'*32
        with patch.object(store.secrets,'token_hex',return_value=rid):store.save(self.scanner(),r)
        self.assertEqual(r['data']['persistence'],'save_failed')
        self.assertEqual((self.folder/(rid+'.json')).read_bytes(),original)

    def test_corrupt_future_and_unknown_schema_do_not_substitute_old_latest(self):
        rid=self.save();p=self.folder/(rid+'.json');obj=json.loads(p.read_text())
        for changes in [{'schema':2},{'schema':True},{'saved_at':store.stamp(self.now+timedelta(seconds=10))},{'new_key':'bad'}]:
            altered={**obj,**changes};p.write_bytes(store.encode(altered))
            self.assertEqual(self.manage()['data']['records'][0]['state'],'invalid')
        p.write_text('{broken')
        self.assertTrue(self.manage()['data']['latest_uncertain'])

    def test_html_escape_and_static_local_links(self):
        self.save();self.manage('dashboard');page=(self.folder/'dashboard.html').read_text()
        self.assertIn('private&lt;app&gt;',page)
        self.assertNotIn('<script',page.lower());self.assertNotIn('href="http',page)
        self.assertIn('default-src',page);self.assertIn('not prove runtime loading',page)
        self.assertIn('href="#record-',page)
        self.assertEqual((self.folder/'dashboard.html').stat().st_mode&0o777,0o600)
        again=self.manage('dashboard');self.assertEqual(again['data']['record_count'],1)
        first=self.manage()['data']['records'][0]['record_id']
        older=self.report();older['data']['run_id']='c'*32
        older['data']['started_at']=store.stamp(self.now-timedelta(seconds=21))
        older['data']['finished_at']=store.stamp(self.now-timedelta(seconds=20))
        with patch.object(store,'clock',return_value=self.now+timedelta(seconds=1)):store.save(self.scanner(),older)
        second=older['data']['record_id']
        with patch.object(store,'clock',return_value=self.now+timedelta(seconds=2)):self.manage('dashboard')
        page=(self.folder/'dashboard.html').read_text()
        self.assertLess(page.index('id="record-'+first+'"'),page.index('id="record-'+second+'"'))

    def test_detail_json_preserves_formatting_without_restoring_untrusted_controls(self):
        report = self.report()
        report["data"]["processes"][0]["details"]["process"]["name"] = (
            'demo\n\r\t\x1b\u202e</pre><script>alert("demo")</script> literal \\u000a')
        rid = self.save(report=report)
        saved = json.loads((self.folder / (rid + ".json")).read_text())
        self.manage("dashboard")
        page = (self.folder / "dashboard.html").read_text()

        class PreText(HTMLParser):
            def __init__(self):
                super().__init__()
                self.in_pre = False
                self.text = ""

            def handle_starttag(self, tag, attrs):
                if tag == "pre":
                    self.in_pre = True

            def handle_endtag(self, tag):
                if tag == "pre":
                    self.in_pre = False

            def handle_data(self, data):
                if self.in_pre:
                    self.text += data

        parsed = PreText()
        parsed.feed(page)
        self.assertIn('\n  "process": {\n', parsed.text)
        expected = saved["snapshot"]["processes"][0]["details"]
        self.assertEqual(json.loads(parsed.text), expected)
        self.assertIn('\\\\u000a', parsed.text)
        self.assertNotIn("\x1b", page)
        self.assertNotIn("\u202e", page)
        self.assertNotIn("<script", page.lower())
        self.assertIn("&lt;/pre&gt;&lt;script&gt;", page)

    def test_permissions_links_fifo_and_cloud_are_refused(self):
        self.save();p=self.folder/(self.manage()['data']['records'][0]['record_id']+'.json')
        p.chmod(0o644);self.assertEqual(self.manage()['status'],'partial');p.chmod(0o600)
        self.folder.chmod(0o755)
        with self.assertRaises(core.ScannerError):self.manage()
        self.folder.chmod(0o700)
        for kind in ['symlink','hardlink','fifo']:
            q=self.folder/('d'*32+'.json')
            if kind=='symlink':q.symlink_to(p)
            elif kind=='hardlink':os.link(p,q)
            else:os.mkfifo(q,0o600)
            self.assertEqual(self.manage()['status'],'partial');q.unlink()
        with patch.object(store.core,'cloud_placeholder',return_value=True),self.assertRaises(core.ScannerError):self.manage()

    def test_parent_symlink_and_network_filesystem_refused(self):
        alias=self.base/'alias';alias.symlink_to(self.folder,target_is_directory=True)
        with self.assertRaises(core.ScannerError):self.manage(scanner=self.scanner(directory=str(alias)))
        self.save()
        with patch.object(store,'local_filesystem',return_value=False),self.assertRaises(core.ScannerError):self.manage()

    def test_cancellation_and_deadline_around_atomic_publication(self):
        for point in ['before','after']:
            folder=self.base/point;scanner=self.scanner(directory=str(folder));cancel=threading.Event();original=store.os.replace
            def replace(*args,**kw):
                if point=='before':raise OSError('interrupted before publication')
                result=original(*args,**kw);cancel.set();return result
            r=self.report()
            with patch.object(store.os,'replace',replace):store.save(scanner,r,cancel)
            self.assertEqual(r['data']['persistence'],'save_failed' if point=='before' else 'details_saved')
            self.assertFalse(list(folder.glob('*.tmp')));self.assertEqual(len(list(folder.glob('*.json'))),int(point=='after'))

    def test_actual_cross_process_store_lock(self):
        self.save();cfg=store.settings(self.scanner())
        code='import sys,json; from pc_scanner.process_store import Store; s=Store(json.loads(sys.argv[1]));\nwith s.open(): print("locked",flush=True); sys.stdin.readline()'
        child=subprocess.Popen([sys.executable,'-c',code,json.dumps(cfg)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(),'locked')
            with self.assertRaises(core.ScannerError):self.manage()
        finally:child.communicate('\n',timeout=5)
        self.assertEqual(child.returncode,0);self.assertEqual(self.manage()['status'],'completed')

    def test_json_and_total_capacity_fail_without_eviction(self):
        rid=self.save();report=self.report();report['data']['run_id']='c'*32
        with patch.object(store.Store,'used',return_value=128*1024*1024):store.save(self.scanner(),report)
        self.assertEqual(report['data']['persistence'],'save_failed')
        self.assertTrue((self.folder/(rid+'.json')).exists())
        with store.Store(store.settings(self.scanner())).open() as s:
            with self.assertRaises(OSError):s.atomic('e'*32+'.json',b'x'*(store.JSON_LIMIT+1),store.JSON_LIMIT)

    def test_orphan_temp_cleanup_and_unrelated_file_preserved(self):
        self.save();orphan=self.folder/('.'+'e'*32+'.tmp');orphan.write_text('orphan');orphan.chmod(0o600)
        unrelated=self.folder/'unrelated.txt';unrelated.write_text('leave');unrelated.chmod(0o600)
        preview=self.manage('prune',dry_run=True);self.assertEqual(preview['data']['temporary_files_removed'],0)
        self.assertTrue(orphan.exists())
        self.assertEqual(self.manage('prune')['data']['temporary_files_removed'],1)
        self.assertTrue(unrelated.exists());self.assertFalse(orphan.exists())

    def test_unrelated_files_never_block_saving_or_the_page(self):
        # Finder writes .DS_Store with ordinary permissions if the folder is ever opened.
        self.save()
        finder = self.folder / ".DS_Store"; finder.write_bytes(b"x"); finder.chmod(0o644)
        (self.folder / "notes").mkdir()
        report = self.report(); report["data"]["run_id"] = "c" * 32
        self.save(report=report)
        self.assertEqual(self.manage("dashboard")["status"], "completed")
        self.assertEqual(self.manage()["data"]["unmanaged_count"], 2)
        self.assertEqual(finder.read_bytes(), b"x"); self.assertTrue((self.folder / "notes").is_dir())

    def test_missing_parent_is_no_store_and_saving_names_the_cause(self):
        scanner = self.scanner(directory=str(self.base / "absent" / "records"))
        self.assertFalse(self.manage(scanner=scanner)["data"]["store_exists"])
        report = self.report()
        store.save(scanner, report)
        self.assertEqual((report["data"]["persistence"], report["data"]["persistence_reason"]),
                         ("save_failed", "store_parent_missing"))
        self.assertEqual(review.for_cli(report)["data"]["persistence_reason"], "store_parent_missing")
        self.assertNotIn(str(self.base), json.dumps(report))
        self.assertFalse((self.base / "absent").exists())

    def test_publication_and_deletion_sync_the_store_folder(self):
        real, synced = store.os.fsync, []
        def folder(fd): return stat.S_ISDIR(os.fstat(fd).st_mode)
        def fsync(fd):
            synced.append(folder(fd))
            return real(fd)
        with patch.object(store.os, "fsync", fsync):
            rid = self.save()
            self.assertTrue(synced[-1], "the folder is synced after the rename")
            synced.clear()
            self.manage("delete", record_id=rid, revision=self.manage()["data"]["records"][0]["revision"])
            self.assertEqual(synced, [True])
        # A failing folder sync after publication must not turn a saved record into "not saved".
        def failing(fd):
            if folder(fd):
                raise OSError("folder sync unsupported")
            return real(fd)
        report = self.report(); report["data"]["run_id"] = "d" * 32
        with patch.object(store.os, "fsync", failing):
            self.save(report=report)

    def test_duplicate_json_keys_are_invalid(self):
        rid=self.save();p=self.folder/(rid+'.json');raw=p.read_text();p.write_text(raw.replace('"schema":1','"schema":2,"schema":1'))
        self.assertEqual(self.manage()['data']['records'][0]['state'],'invalid')

    def test_each_management_operation_invalidates_stale_html(self):
        self.save()
        for action in ['list','prune','dashboard']:
            self.manage('dashboard');self.assertTrue((self.folder/'dashboard.html').exists())
            with patch.object(store,'clock',return_value=self.now+timedelta(days=7)):
                report=self.manage(action,dry_run=True)
            if action=='dashboard':
                self.assertEqual(report['data']['record_count'],0)
                self.assertNotIn('private&lt;app&gt;',(self.folder/'dashboard.html').read_text())
            else:self.assertFalse((self.folder/'dashboard.html').exists())
            # Re-seed for the next subcase; expired dashboard generation prunes the record.
            if not list(self.folder.glob('[0-9a-f]*.json')):self.save()

    def test_expired_prune_partial_failure_is_reported(self):
        self.save();original=store.Store.unlink
        def deny(s,name,*args):
            if store.ID.fullmatch(name[:-5]):raise PermissionError('denied')
            return original(s,name,*args)
        with patch.object(store,'clock',return_value=self.now+timedelta(days=7)),patch.object(store.Store,'unlink',deny):
            r=self.manage('prune')
        self.assertEqual(r['status'],'partial');self.assertEqual(r['data']['failed_count'],1)

    def test_store_save_deadline_before_publication_and_no_retry(self):
        original=store.Store.atomic;calls=[]
        def expire(s,name,data,limit):
            calls.append(name);s.deadline=time.monotonic()-1;return original(s,name,data,limit)
        report=self.report()
        with patch.object(store.Store,'atomic',expire):store.save(self.scanner(),report)
        self.assertEqual(len(calls),1);self.assertEqual(report['data']['persistence'],'save_failed')
        self.assertFalse(list(self.folder.glob('*.tmp')));self.assertFalse(list(self.folder.glob('[0-9a-f]*.json')))

    def test_cli_records_roundtrip_and_no_store_creation(self):
        cfg=self.base/'scanner.toml';cfg.write_text('[history]\nenabled = false\n[process_review.storage]\ndirectory = '+json.dumps(str(self.folder))+'\n')
        cmd=[sys.executable,'-m','pc_scanner.cli','--config',str(cfg),'process-review-records']
        z=subprocess.run([*cmd,'list','--json'],capture_output=True,text=True,timeout=10)
        self.assertEqual(z.returncode,0,z.stderr);self.assertFalse(self.folder.exists())
        rid=self.save()
        z=subprocess.run([*cmd,'dashboard','--no-open'],capture_output=True,text=True,timeout=10)
        self.assertEqual(z.returncode,0,z.stderr);self.assertTrue((self.folder/'dashboard.html').exists())
        z=subprocess.run([*cmd,'list','--json'],capture_output=True,text=True,timeout=10);r=json.loads(z.stdout)
        z=subprocess.run([*cmd,'delete',rid,'--revision',r['data']['records'][0]['revision'],'--json'],capture_output=True,text=True,timeout=10)
        self.assertEqual(z.returncode,0,z.stderr);self.assertFalse((self.folder/(rid+'.json')).exists())

    def test_cli_save_details_requires_both_permissions_and_hides_names(self):
        engine=self.base/'fake-osquery'
        row={'pid':'42','start_time':'1000','path':'/synthetic/node','name':'sensitive-app','parent':'1','parent_path':None,'parent_start_time':'1'}
        engine.write_text('#!'+sys.executable+'\nimport json\nprint('+repr(json.dumps([row]))+')\n');engine.chmod(0o700)
        cfg=self.base/'save.toml';cfg.write_text('[local]\nosquery_binary = '+json.dumps(str(engine))+'\n[history]\nenabled = false\n[process_review]\nenabled = true\n[process_review.targets.demo]\npid = 42\nstart_time = 1000\n[process_review.storage]\nenabled = true\ndirectory = '+json.dumps(str(self.folder))+'\n')
        cmd=[sys.executable,'-m','pc_scanner.cli','--config',str(cfg),'review-processes','--json']
        z=subprocess.run(cmd,capture_output=True,text=True,timeout=10)
        self.assertEqual(z.returncode,0,z.stderr);self.assertFalse(self.folder.exists())
        z=subprocess.run([*cmd,'--save-details'],capture_output=True,text=True,timeout=10)
        self.assertEqual(z.returncode,0,z.stderr);r=json.loads(z.stdout)
        self.assertEqual(r['data']['persistence'],'details_saved');self.assertNotIn('sensitive-app',z.stdout)
        self.assertIn('persistence=details_saved',z.stderr)
        self.assertNotIn('run_id',z.stdout);self.assertEqual(len(self.manage()['data']['records']),1)

    def test_cancel_after_fsync_before_rename_cleans_temporary_file(self):
        cancel=threading.Event();original=store.os.fsync
        def syncing(fd):
            original(fd);cancel.set()
        r=self.report()
        with patch.object(store.os,'fsync',syncing):store.save(self.scanner(),r,cancel)
        self.assertEqual(r['data']['persistence'],'save_failed')
        self.assertFalse(list(self.folder.glob('*.tmp')));self.assertFalse(list(self.folder.glob('[0-9a-f]*.json')))




if __name__ == '__main__': unittest.main()
