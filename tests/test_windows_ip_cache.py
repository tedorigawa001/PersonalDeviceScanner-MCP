"""Windows destination-cache contracts; native tests never touch owner defaults."""
import unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import contextmanager
from pc_scanner import ip_threats as t

class DispatchTests(unittest.TestCase):
    def test_windows_uses_safe_backend_with_read_only_options_and_deadline(self):
        from pc_scanner import windows_ip_cache as w
        seen=[]
        class Backend:
            def __init__(self,settings,cancel,deadline):seen.append((settings,cancel,deadline))
            @contextmanager
            def open(self,create=False,file_lock=True):
                seen.append((create,file_lock));yield 'safe-cache'
        settings={'directory':str(Path('/explicit-cache')),'max_total_mb':32}
        with patch.object(t.os,'name','nt'),patch.object(w,'Store',Backend):
            with t.Cache(settings,deadline=123).open(file_lock=False) as cache:self.assertEqual(cache,'safe-cache')
        self.assertEqual(seen,[(settings,None,123),(False,False)])


class ModelTests(unittest.TestCase):
    """Run the store state machine against a handle model, not Windows API claims."""
    def setUp(self):
        import tempfile
        from pc_scanner import windows_ip_cache as w
        self.w=w;self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        class WindowsPath:
            def __init__(self,value):
                self.value=str(value)
            def __str__(self):return self.value
            def __truediv__(self,part):return WindowsPath(self.value.rstrip('\\')+'\\'+part)
            def iterdir(self):
                path=root.joinpath(*self.value.replace('C:\\','').split('\\'))
                for child in path.iterdir():yield type('Entry',(),{'name':child.name})()
        class API:
            def __init__(api):api.handles={};api.n=0;api.denied=set();api.fail_publish=False;api.events=[];api.locked=True
            def path(api,path):return root.joinpath(*str(path).replace('C:\\','').split('\\'))
            def new(api,path,stream=None):api.n+=1;api.handles[api.n]=(api.path(path),stream);return api.n
            def open_directory(api,path,**kwargs):
                if not api.path(path).is_dir():raise FileNotFoundError
                return api.new(path)
            def create_directory(api,path):api.path(path).mkdir(mode=0o700)
            def info(api,handle,directory=False,private=True):
                from types import SimpleNamespace
                path,stream=api.handles[handle]
                if private and path.name in api.denied:raise OSError('Unsafe owner/ACL/type')
                info=path.stat();return SimpleNamespace(size=info.st_size,revision=(info.st_ino,info.st_size,info.st_mtime_ns))
            def local_volume(api,*args):pass
            def open(api,path,access=None,share=None,disposition=3,private=False):
                p=api.path(path)
                mode='x+b' if disposition==1 else ('r+b' if p.exists() else 'w+b') if disposition==4 else 'rb'
                stream=p.open(mode);api.events.append(('open',p.name));return api.new(path,stream)
            def close(api,handle):
                path,stream=api.handles.pop(handle)
                if stream:stream.close()
            def lock(api,handle):return api.locked
            def read(api,h,n):return api.handles[h][1].read(n)
            def write(api,h,data):api.handles[h][1].write(data)
            def flush(api,h):api.handles[h][1].flush()
            def remove(api,h):api.handles[h][0].unlink()
            def rename(api,h,parent,name):
                if api.fail_publish:raise OSError('Publication failed')
                p,s=api.handles[h];target=api.handles[parent][0]/name;p.replace(target);api.handles[h]=(target,s)
        self.api=API();self.root=root;self.path=WindowsPath
        self.patchers=[patch.object(w,'Native',return_value=self.api),patch.object(w,'Path',WindowsPath)]
        for p in self.patchers:p.start();self.addCleanup(p.stop)
        self.settings={'directory':'C:\\cache','max_total_mb':32}

    def store(self,**kw):return self.w.Store(self.settings,**kw)

    def test_absent_reader_has_no_side_effects_and_pins_are_closed(self):
        with self.store().open(file_lock=False) as cache:self.assertIsNone(cache)
        self.assertEqual(list(self.root.iterdir()),[]);self.assertEqual(self.api.handles,{})

    def test_atomic_failure_preserves_old_bytes_and_releases_lock(self):
        with self.store().open(create=True) as cache:
            cache.atomic('current.json',b'old',100)
            self.api.fail_publish=True
            with self.assertRaises(OSError):cache.atomic('current.json',b'new',100)
            self.assertEqual(cache.read('current.json',100)[0],b'old')
            self.assertFalse(any(n.endswith('.tmp') for n in cache.names()))
        self.assertEqual(self.api.handles,{})
        self.api.fail_publish=False
        with self.store().open() as cache:cache.atomic('current.json',b'recovered',100)

    def test_unsafe_entry_is_rejected_before_read_or_overwrite(self):
        with self.store().open(create=True) as cache:
            cache.atomic('current.json',b'old',100);self.api.denied.add('current.json')
            with self.assertRaises(OSError):cache.read('current.json',100)
            with self.assertRaises(OSError):cache.atomic('current.json',b'new',100)
        self.assertEqual((self.root/'cache/current.json').read_bytes(),b'old')

    def test_cancelled_write_cleans_temp_and_keeps_generation(self):
        import threading
        stop=threading.Event()
        with self.store(cancel=stop).open(create=True) as cache:
            cache.atomic('current.json',b'old',100)
            original=self.api.flush
            def cancel(h):original(h);stop.set()
            self.api.flush=cancel
            with self.assertRaises(OSError):cache.atomic('current.json',b'new',100)
        self.assertEqual((self.root/'cache/current.json').read_bytes(),b'old')
        self.assertFalse(list((self.root/'cache').glob('*.tmp')))
        self.assertEqual(self.api.handles,{})

    def test_lockfile_cannot_be_replaced_by_publication(self):
        with self.store().open(create=True) as cache:
            with self.assertRaises(OSError):cache.atomic('.lock',b'not a lock',100)
            self.assertEqual((self.root/'cache/.lock').read_bytes(),b'')

    def test_missing_parent_bad_path_and_cancel_release_process_lock(self):
        import threading
        for path in ['C:\\missing\\cache','\\\\server\\share\\cache','C:\\cache:stream','C:\\a\\..\\cache','C:\\OneDrive\\cache']:
            with self.subTest(path=path),self.assertRaises(OSError):
                with self.w.Store({**self.settings,'directory':path}).open(create=True):pass
            self.assertEqual(self.api.handles,{})
        stop=threading.Event();stop.set()
        with self.assertRaises(OSError):
            with self.store(cancel=stop).open():pass
        with self.store().open(create=True):pass


class NativeValidationModelTests(unittest.TestCase):
    def test_reparse_offline_recall_hardlink_and_non_disk_rejected_before_acl(self):
        from pc_scanner import windows_ip_cache as w
        from types import SimpleNamespace
        for attrs,links,kind in [(0x400,1,1),(0x1000,1,1),(0x40000,1,1),(0x400000,1,1),(0,2,1),(0,1,2),(0x10,1,1)]:
            api=w.Native.__new__(w.Native)
            def information(handle,out):out._obj.attributes=attrs;out._obj.links=links;return True
            api.k=SimpleNamespace(GetFileInformationByHandle=information,GetFileType=lambda h:kind)
            with self.subTest(attrs=attrs,links=links,kind=kind),patch.object(api,'private_acl',side_effect=AssertionError('Must reject before ACL')):
                with self.assertRaises(OSError):api.info(1)

    def test_private_acl_rejects_broad_null_unprotected_unknown_aces_and_owner_failure(self):
        import ctypes as ct
        from types import SimpleNamespace
        from pc_scanner import windows_ip_cache as w
        for protected,present,kind,flags,sid,owner in [(True,True,0,0,'self',True),(True,True,0,0,'S-1-5-18',True),
                (False,True,0,0,'self',True),(True,False,0,0,'self',True),(True,True,0,0,'Everyone',True),
                (True,True,5,0,'self',True),(True,True,0,8,'self',True),(True,True,0,0,'self',False)]:
            api=w.Native.__new__(w.Native);api.user='self';acl=ct.create_string_buffer(16);ace=ct.create_string_buffer(32)
            ct.c_ushort.from_buffer(acl,4).value=1;ct.c_ubyte.from_buffer(ace).value=kind;ct.c_ubyte.from_buffer(ace,1).value=flags
            def security(*args):args[-1]._obj.value=1;return 0
            def control(d,c,r):c._obj.value=0x1000 if protected else 0;return True
            def dacl(d,p,a,default):p._obj.value=present;a._obj.value=ct.addressof(acl) if present else None;return True
            def getace(a,i,p):p._obj.value=ct.addressof(ace);return True
            api.a=SimpleNamespace(GetSecurityInfo=security,GetSecurityDescriptorControl=control,GetSecurityDescriptorDacl=dacl,GetAce=getace)
            api.k=SimpleNamespace(LocalFree=lambda x:None);api.sid=lambda p:sid
            with self.subTest(protected=protected,present=present,kind=kind,flags=flags,sid=sid,owner=owner),patch('pc_scanner.windows_owner.owns_handle',return_value=owner):
                if protected and present and kind==0 and flags==0 and sid in {'self','S-1-5-18'} and owner:api.private_acl(1)
                else:
                    with self.assertRaises(OSError):api.private_acl(1)


@unittest.skipUnless(__import__('os').name=='nt','Native Windows filesystem/APIs required')
class NativeWindowsTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from tests.test_ip_threats import NOW
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.cache=self.root/'cache';self.now=NOW
        from pc_scanner.core import Scanner
        self.scanner=Scanner({'history':{'enabled':False,'file':str(self.root/'history.jsonl')},'updates':{'lookup':False},
            'ip_threats':{'enabled':True,'allow_updates':True,'cache_directory':str(self.cache)}})
        self.scanner.via='cli'

    def update(self,**kwargs):
        from tests.test_ip_threats import feed
        with patch.object(t,'clock',return_value=self.now),patch.object(t,'download',side_effect=lambda v,*a:feed(v)):
            return self.scanner.invoke('update_ip_threat_lists',**kwargs)

    def test_native_update_read_private_acl_and_failed_generation_preservation(self):
        from datetime import timedelta
        from tests.test_ip_threats import feed
        from pc_scanner.windows_ip_cache import Native
        self.assertEqual(self.update()['status'],'completed')
        before=(self.cache/'current.json').read_bytes()
        with t.Cache(t.cache_settings(self.scanner)).open(file_lock=False) as cache:
            self.assertEqual(cache.read('current.json',t.BUNDLE_LIMIT)[0],before)
        # Native info validates owner + protected DACL and single-link type, not POSIX mode bits.
        api=Native()
        for path in [self.cache,self.cache/'current.json',self.cache/'.lock']:
            h=api.open_directory(path,final=True) if path.is_dir() else api.open(path)
            try:api.info(h,directory=path.is_dir())
            finally:api.close(h)
        with patch.object(t,'clock',return_value=self.now+timedelta(hours=1)),patch.object(t,'download',side_effect=[feed(4),b'broken']):
            self.assertEqual(self.scanner.invoke('update_ip_threat_lists')['status'],'partial')
        self.assertEqual((self.cache/'current.json').read_bytes(),before)
        with patch.object(t,'download',side_effect=AssertionError('Hourly limit bypassed')),patch.object(t,'clock',return_value=self.now+timedelta(hours=1)):
            self.assertEqual(self.scanner.invoke('update_ip_threat_lists')['data']['stop_reason'],'rate_limited_no_request_sent')

    def test_native_missing_reader_creates_no_artifacts_and_pinned_parent_cannot_move(self):
        with t.Cache(t.cache_settings(self.scanner)).open(file_lock=False) as cache:self.assertIsNone(cache)
        self.assertFalse(self.cache.exists())
        self.assertEqual(self.update()['status'],'completed')
        with t.Cache(t.cache_settings(self.scanner)).open(file_lock=False):
            with self.assertRaises(OSError):self.cache.rename(self.root/'moved')
        self.cache.rename(self.root/'moved')

    def test_native_existing_inherited_dacl_and_hardlinks_fail_closed(self):
        import os
        self.cache.mkdir()  # Inherited ACL is never silently repaired or accepted.
        with self.assertRaises(OSError):
            with t.Cache(t.cache_settings(self.scanner)).open():pass
        self.cache.rmdir();self.assertEqual(self.update()['status'],'completed')
        os.link(self.cache/'current.json',self.root/'extra-link')
        with t.Cache(t.cache_settings(self.scanner)).open(file_lock=False) as cache:
            with self.assertRaises(OSError):cache.read('current.json',t.BUNDLE_LIMIT)

    def test_native_cross_process_writer_lock_and_recovery(self):
        import subprocess,sys
        self.assertEqual(self.update()['status'],'completed')
        child=subprocess.Popen([sys.executable,'-u','-c',
            'import sys;from pc_scanner.ip_threats import Cache;'+
            'c=Cache({"directory":sys.argv[1],"max_total_mb":32});'+
            'ctx=c.open();ctx.__enter__();print("READY",flush=True);sys.stdin.readline();ctx.__exit__(None,None,None)',str(self.cache)],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(),'READY')
            with self.assertRaises(OSError):
                with t.Cache(t.cache_settings(self.scanner)).open():pass
        finally:
            child.communicate('release\n',timeout=10)
        self.assertEqual(child.returncode,0)
        with t.Cache(t.cache_settings(self.scanner)).open() as cache:cache.read('current.json',t.BUNDLE_LIMIT)

    def test_native_failed_publish_cleans_temp_and_keeps_current(self):
        from pc_scanner import windows_ip_cache as w
        self.assertEqual(self.update()['status'],'completed');before=(self.cache/'current.json').read_bytes()
        with t.Cache(t.cache_settings(self.scanner)).open() as cache:
            with patch.object(w.Native,'rename',side_effect=OSError('Injected publish failure')):
                with self.assertRaises(OSError):cache.atomic('current.json',b'new',1000000)
        self.assertEqual((self.cache/'current.json').read_bytes(),before)
        self.assertFalse(list(self.cache.glob('.*.tmp')))

    def test_native_protected_but_everyone_accessible_cache_is_refused(self):
        from pc_scanner.windows_ip_cache import Native
        api=Native();api.user='WD'  # SDDL Everyone alias, only a fresh empty test directory.
        api.create_directory(self.cache)
        with self.assertRaises(OSError):
            with t.Cache(t.cache_settings(self.scanner)).open():pass

    def test_native_cache_matching_projects_anonymous_result_without_lock_creation(self):
        from pc_scanner import connections as c
        from tests.test_connections import Clock
        self.assertEqual(self.update()['status'],'completed');(self.cache/'.lock').unlink()
        self.scanner.via='mcp';self.scanner.connection_settings.update(enabled=True,duration_seconds=1,interval_seconds=1)
        clock=Clock();row={'pid':'42','start_time':'1000','process':'private-test-process','family':'2','protocol':'6',
            'local_address':'192.168.1.2','local_port':'50001','remote_address':'8.8.8.8','remote_port':'443','state':'ESTABLISHED'}
        with patch.object(c.Backend,'__init__',lambda obj,*a:setattr(obj,'limits',set())), \
             patch.object(c.Backend,'addresses',return_value=({'192.168.1.2'},set(),set())), \
             patch.object(c.Backend,'sockets',return_value=[row]),patch.object(c.time,'monotonic',clock.monotonic), \
             patch.object(c.time,'sleep',clock.sleep),patch.object(t,'clock',return_value=self.now):
            report=self.scanner.invoke('check_connection_destinations')
        self.assertEqual(report['status'],'completed',report)
        self.assertEqual(report['data']['destination_threats']['destination_counts'],{'matched':1})
        import json
        for secret in ['private-test-process','8.8.8.8','8.8.8.0/24','remote_ip','current.json']:
            self.assertNotIn(secret,json.dumps(report))
        self.assertFalse((self.cache/'.lock').exists());self.assertFalse((self.root/'history.jsonl').exists())
