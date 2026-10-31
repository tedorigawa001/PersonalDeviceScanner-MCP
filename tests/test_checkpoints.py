"""Checkpoint management uses only synthetic private state, never the owner's real checkpoints."""
import asyncio
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from pc_scanner import checkpoints, history, malware_batch as batch
from pc_scanner.core import Scanner, ScannerError


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.root = self.base / "input"; self.root.mkdir()
        (self.root / "one.txt").write_text("test data")
        self.config = {"local": {"clamav_binary": sys.executable}, "scan_roots": {"sample": str(self.root)},
                       "history": {"enabled": False, "file": str(self.base / "state" / "history.jsonl")}}
        self.scanner = Scanner(self.config)
        self.folder = self.base / "state" / "malware-checkpoints"
        self.enterContext(patch("pc_scanner.core.clamav_signatures", return_value={
            "engine": "test", "version": 1, "built_at": datetime.now(timezone.utc)}))
        self.enterContext(patch("pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 1\nInfected files: 0\n", "")))
        self.enterContext(patch("pc_scanner.history.append", side_effect=AssertionError("Management/tests must not write real scan history")))

    def seed(self, index=1, raw=None):
        self.folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        p = self.folder / (f"{index:064x}" + ".json")
        history.replace_private(p, raw if raw is not None else json.dumps({"schema": 1, "parts": {}, "context": "legacy"}).encode())
        return p

    def listing(self, **kwargs): return checkpoints.list_checkpoints(self.scanner, **kwargs)

    def row(self, checkpoint_id=None):
        rows = self.listing()["data"]["checkpoints"]
        return next(r for r in rows if r["checkpoint_id"] == checkpoint_id) if checkpoint_id else rows[0]

    def delete(self, row): return checkpoints.delete_checkpoint(self.scanner, row["checkpoint_id"], row["revision"])

    def test_empty_inventory_creates_no_directory_or_engine(self):
        with patch.object(self.scanner, "binary", side_effect=AssertionError("no engine required")):
            r = self.listing()
        self.assertEqual(r["data"]["checkpoints"], [])
        self.assertEqual(r["status"], "completed")
        self.assertFalse(self.folder.parent.exists())

    def test_batch_metadata_is_listed_and_only_selected_state_is_deleted(self):
        first = self.scanner.invoke("malware", root_alias="sample", batch=True)
        self.assertEqual(first["status"], "completed", first)
        other = self.seed(1)
        rows = self.listing()["data"]["checkpoints"]
        selected = next(r for r in rows if r.get("root_alias") == "sample")
        self.assertNotIn("relative_path", selected)
        self.assertEqual(self.listing(show_paths=True)["data"]["checkpoints"][1].get("relative_path"), ".")
        self.assertEqual(selected["saved_parts"], 1)
        report = self.delete(selected)
        self.assertTrue(report["data"]["deleted"])
        self.assertFalse((self.folder / (selected["checkpoint_id"] + ".json")).exists())
        self.assertTrue(other.exists())
        self.assertEqual((self.root / "one.txt").read_text(), "test data")
        self.assertTrue((self.folder / ".active.lock").exists(), "never unlink the shared lock")

    def test_legacy_corrupt_and_removed_root_are_manageable(self):
        legacy = self.seed(1); corrupt = self.seed(2, b"{broken")
        rows = self.listing()["data"]["checkpoints"]
        self.assertEqual([r["state"] for r in rows], ["valid", "invalid"])
        self.assertTrue(all(r["deletable"] for r in rows))
        self.assertNotIn("root_alias", rows[0])
        orphan_scanner = Scanner({"history": self.config["history"]})
        for row in rows: checkpoints.delete_checkpoint(orphan_scanner, row["checkpoint_id"], row["revision"])
        self.assertFalse(legacy.exists()); self.assertFalse(corrupt.exists())

    def test_stale_content_or_replaced_identical_content_requires_relisting(self):
        path = self.seed(); row = self.row()
        raw = path.read_bytes(); history.replace_private(path, raw)
        with self.assertRaisesRegex(ScannerError, "changed since listing"): self.delete(row)
        row = self.row(); history.replace_private(path, b"changed")
        with self.assertRaisesRegex(ScannerError, "changed since listing"): self.delete(row)
        self.assertEqual(path.read_bytes(), b"changed")

    def test_selection_accepts_only_exact_id_and_revision(self):
        path = self.seed(); row = self.row()
        for value in ("../outside", "a.json", "A" * 64, "a" * 63, "a" * 65, "a" * 64 + "\n", "", None):
            for key in ("checkpoint_id", "revision"):
                changed = {**row, key: value}
                with self.subTest(value=value, key=key), self.assertRaises(ScannerError): self.delete(changed)
        self.assertTrue(path.exists())

    def test_in_process_scan_protects_all_checkpoints_and_does_not_wait(self):
        path = self.seed(); row = self.row(); start = time.monotonic()
        with batch._lock:
            report = self.listing()
            self.assertEqual(report["status"], "partial")
            self.assertTrue(report["data"]["scan_running"])
            self.assertFalse(report["data"]["checkpoints"][0]["deletable"])
            with self.assertRaisesRegex(ScannerError, "running"): self.delete(row)
        self.assertLess(time.monotonic() - start, 1)
        self.assertTrue(path.exists())
        self.assertTrue(self.row()["deletable"])

    def test_listing_only_probes_the_scan_lock_and_reads_without_holding_it(self):
        self.seed(); seen = []
        describe = checkpoints.describe
        def reading(raw, show_paths):
            # A batch scan starting now waits only about 2 seconds, so it must get both locks at once.
            self.assertTrue(batch._lock.acquire(False)); batch._lock.release()
            until = time.monotonic() + .05
            def waiting():
                if time.monotonic() >= until: raise AssertionError("the list still holds the scan lock")
            with history.locked(self.folder / ".active", check_wait=waiting): seen.append(True)
            return describe(raw, show_paths)
        with patch.object(checkpoints, "describe", reading):
            report = self.listing()
        self.assertEqual(seen, [True])
        self.assertFalse(report["data"]["scan_running"])
        self.assertTrue(report["data"]["checkpoints"][0]["deletable"])

    def test_gap_listing_without_a_checkpoint_folder_explains_instead_of_crashing(self):
        with self.assertRaisesRegex(ScannerError, "No coverage selection state"):
            batch.read_coverage(self.scanner, "sample", ".")
        config = self.base / "gaps.toml"
        config.write_text("[scan_roots]\nsample = " + json.dumps(str(self.root)) + "\n[history]\nenabled = false\nfile = "
                          + json.dumps(self.config["history"]["file"]) + "\n")
        gaps = subprocess.run([sys.executable, "-m", "pc_scanner.cli", "--config", str(config), "malware-gaps", "sample",
                               "--scan", "0" * 32, "--json"], capture_output=True, text=True, timeout=15)
        self.assertEqual(gaps.returncode, 2, gaps.stderr)
        self.assertIn("No coverage selection state", json.loads(gaps.stdout)["error"])
        self.assertFalse(self.folder.parent.exists())

    def test_windows_stat_and_fstat_may_report_different_st_ctime(self):
        # Windows Python 3.12+: os.stat gives the creation time as st_ctime, os.fstat the change time.
        # Simulated by shifting st_ctime_ns on the path side only.
        self.seed()
        entry_stat = checkpoints.entry_stat
        class Shifted:
            def __init__(self, info): self.info = info
            def __getattr__(self, name):
                return self.info.st_ctime_ns + 1 if name == "st_ctime_ns" else getattr(self.info, name)
        with patch.object(checkpoints, "entry_stat", lambda *args: Shifted(entry_stat(*args))):
            # Elsewhere both calls mean the same time, so a difference still marks the entry unavailable.
            for windows, state in ((False, "unavailable"), (True, "valid")):
                with self.subTest(windows=windows), patch.object(checkpoints.identity, "__defaults__", (windows,)):
                    self.assertEqual(self.row()["state"], state)
            with patch.object(checkpoints.identity, "__defaults__", (True,)):
                self.assertTrue(self.delete(self.row())["data"]["deleted"])
        self.assertEqual(list(self.folder.glob("*.json")), [])

    def test_other_process_scan_lock_protects_state_and_is_released_after_exit(self):
        path = self.seed(); row = self.row(); ready = self.base / "ready"
        code = ("import sys; from pathlib import Path; from pc_scanner import history; "
                "lock=history.locked(Path(" + repr(str(self.folder / ".active")) + ")); lock.__enter__(); "
                "Path(" + repr(str(ready)) + ").write_text('ready'); sys.stdin.buffer.read(1); lock.__exit__(None,None,None)")
        child = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            until = time.monotonic() + 10
            while not ready.exists() and child.poll() is None and time.monotonic() < until: time.sleep(.01)
            self.assertTrue(ready.exists())
            start = time.monotonic(); report = self.listing()
            self.assertTrue(report["data"]["scan_running"])
            with self.assertRaisesRegex(ScannerError, "running"): self.delete(row)
            self.assertLess(time.monotonic() - start, 1)
            self.assertTrue(path.exists())
        finally:
            if child.poll() is None:
                child.stdin.write(b"x");child.stdin.flush()
            child.communicate(timeout=10)
        self.assertTrue(self.row()["deletable"])

    def test_running_batch_with_saved_state_is_protected_until_engine_finishes(self):
        started, release = threading.Event(), threading.Event()
        result = {}
        def engine(*args, **kwargs):
            started.set()
            if not release.wait(5): raise RuntimeError("test did not release synthetic engine")
            return 0, "Scanned files: 1\nInfected files: 0\n", ""
        with patch("pc_scanner.core.run_bounded", side_effect=engine):
            worker = threading.Thread(target=lambda: result.update(self.scanner.invoke("malware", root_alias="sample", batch=True)))
            worker.start()
            try:
                self.assertTrue(started.wait(3))
                row = self.row()
                self.assertFalse(row["deletable"])
                path = self.folder / (row["checkpoint_id"] + ".json")
                before = path.read_bytes()
                with self.assertRaisesRegex(ScannerError, "running"): self.delete(row)
                self.assertEqual(path.read_bytes(), before)
            finally:
                release.set(); worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result["status"], "completed", result)
        self.assertTrue(self.row()["deletable"])

    def test_limit_is_recoverable_by_deleting_one_selected_checkpoint(self):
        for i in range(batch.MAX_CHECKPOINTS): self.seed(i)
        r = self.scanner.invoke("malware", root_alias="sample", batch=True)
        self.assertEqual(r["status"], "error")
        self.assertIn("count limit", r["error"])
        self.delete(self.row())
        r = self.scanner.invoke("malware", root_alias="sample", batch=True)
        self.assertEqual(r["status"], "completed", r)
        self.assertEqual(len(list(self.folder.glob("*.json"))), batch.MAX_CHECKPOINTS)

    def test_symlink_hardlink_directory_and_fifo_are_never_read_or_deleted(self):
        path = self.seed(); row = self.row(); raw = path.read_bytes()
        outside = self.base / "outside.json"; outside.write_bytes(raw)
        path.unlink()
        try: path.symlink_to(outside)
        except OSError: self.skipTest("symlinks unavailable")
        self.assertFalse(self.row()["deletable"])
        with self.assertRaises(ScannerError): self.delete(row)
        self.assertTrue(path.is_symlink());self.assertEqual(outside.read_bytes(), raw)
        path.unlink();os.link(outside, path)
        self.assertFalse(self.row()["deletable"])
        with self.assertRaises(ScannerError): self.delete(row)
        self.assertTrue(outside.exists());path.unlink()
        path.mkdir()
        with self.assertRaises(ScannerError): self.delete(row)
        path.rmdir()
        if hasattr(os, "mkfifo"):
            os.mkfifo(path)
            self.assertFalse(self.row()["deletable"])
            with self.assertRaises(ScannerError): self.delete(row)
            path.unlink()

    def test_foreign_files_and_api_failures_fail_closed(self):
        path = self.seed(); row = self.row()
        selected_inode = path.stat().st_ino
        def owned(fd, info=None): return (info or os.fstat(fd)).st_ino != selected_inode
        with patch.object(history, "owned", side_effect=owned):
            self.assertFalse(self.row()["deletable"])
            with self.assertRaises(ScannerError): self.delete(row)
        self.assertTrue(path.exists())
        # A foreign lock file fails the whole operation, before reading any selected file.
        lock_inode = (self.folder / ".active.lock").stat().st_ino
        with patch.object(history, "owned", side_effect=lambda fd, info=None: (info or os.fstat(fd)).st_ino != lock_inode):
            with self.assertRaises(ScannerError): self.listing()
            with self.assertRaises(ScannerError): self.delete(row)
        self.assertTrue(path.exists())

    def test_folder_link_is_refused_without_touching_target(self):
        self.folder.parent.mkdir(parents=True)
        outside = self.base / "outside"; outside.mkdir()
        try: self.folder.symlink_to(outside, target_is_directory=True)
        except OSError: self.skipTest("directory symlinks unavailable")
        with self.assertRaises(ScannerError): self.listing()
        self.assertEqual(list(outside.iterdir()), [])

    def test_metadata_names_are_optional_escaped_and_not_authorization(self):
        state = {"schema": 1, "parts": {}, "target": {"root_alias": "sample", "relative_path": "x\u202e<test>"}}
        self.seed(raw=json.dumps(state).encode())
        self.assertNotIn("relative_path", self.row())
        row = self.listing(show_paths=True)["data"]["checkpoints"][0]
        self.assertNotIn("\u202e", row["relative_path"])
        self.assertIn("\\u202e", row["relative_path"])
        for bad in ("../outside", "/outside"):
            state["target"]["relative_path"] = bad
            self.seed(raw=json.dumps(state).encode())
            self.assertNotIn("relative_path", self.listing(show_paths=True)["data"]["checkpoints"][0])

    def test_oversized_cloud_and_unmanaged_entries_fail_closed(self):
        path = self.seed(); row = self.row()
        with patch.object(batch, "MAX_STATE_BYTES", 1):
            self.assertFalse(self.row()["deletable"])
            with self.assertRaises(ScannerError): self.delete(row)
        with patch.object(checkpoints.core, "cloud_placeholder", return_value=True):
            with self.assertRaises(ScannerError): self.listing()
        (self.folder / "notes.json").write_text("must keep")
        r = self.listing();self.assertEqual(r["data"]["unmanaged_json_count"], 1)
        self.delete(row)
        self.assertEqual((self.folder / "notes.json").read_text(), "must keep")

    def test_read_budget_and_enumeration_limit_are_explicit(self):
        self.seed(1);self.seed(2)
        with patch.object(checkpoints, "MAX_READ_BYTES", 1):
            r=self.listing();self.assertEqual(r["status"], "partial")
            self.assertFalse(r["data"]["enumeration_complete"])
            self.assertTrue(all(not row["deletable"] for row in r["data"]["checkpoints"]))
        with patch.object(checkpoints, "MAX_ENTRIES", 1):
            self.assertFalse(self.listing()["data"]["enumeration_complete"])

    def test_posix_permissions_are_not_silently_fixed_by_management(self):
        if os.name == "nt": return  # Native ACL ownership is exercised separately in Windows CI.
        path=self.seed();row=self.row();path.chmod(0o644)
        self.assertFalse(self.row()["deletable"])
        with self.assertRaises(ScannerError):self.delete(row)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o644)
        path.chmod(0o600);self.folder.chmod(0o755)
        try:
            with self.assertRaises(ScannerError):self.listing()
        finally:self.folder.chmod(0o700)

    def config_file(self):
        path=self.base/'scanner.toml'
        path.write_text('[history]\nenabled=false\nfile='+json.dumps(self.config['history']['file'])+'\n')
        return path

    def cli(self, *args):
        return subprocess.run([sys.executable,'-m','pc_scanner.cli','--config',str(self.config_file()),'malware-checkpoints',*args],capture_output=True,text=True,timeout=15)

    def test_real_cli_list_select_delete_and_text_have_no_engine_dependency(self):
        path=self.seed()
        config=self.config_file();config.write_text(config.read_text()+'unknown_checkpoint_setting=true\n')
        with patch.object(self, 'config_file', return_value=config):
            listed=self.cli('list','--json')
        self.assertEqual(listed.returncode,0,listed.stderr)
        self.assertIn('history.unknown_checkpoint_setting',str(json.loads(listed.stdout)['warnings']))
        row=json.loads(listed.stdout)['data']['checkpoints'][0]
        text=self.cli('list');self.assertIn(row['checkpoint_id'],text.stdout)
        self.assertIn('revision=',text.stdout)
        deleted=self.cli('delete',row['checkpoint_id'],'--revision',row['revision'],'--json')
        self.assertEqual(deleted.returncode,0,deleted.stderr)
        self.assertTrue(json.loads(deleted.stdout)['data']['deleted']);self.assertFalse(path.exists())
        missing=self.cli('delete',row['checkpoint_id'],'--revision',row['revision'],'--json')
        self.assertEqual(missing.returncode,2)
        self.assertEqual(json.loads(missing.stdout)['status'],'error')

    def test_two_processes_cannot_delete_the_same_selection_twice(self):
        path=self.seed();row=self.row();config=self.config_file()
        argv=[sys.executable,'-m','pc_scanner.cli','--config',str(config),'malware-checkpoints','delete',row['checkpoint_id'],'--revision',row['revision'],'--json']
        children=[subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for _ in range(2)]
        outputs=[p.communicate(timeout=15) for p in children]
        self.assertEqual(sorted(p.returncode for p in children),[0,2],outputs)
        self.assertFalse(path.exists())

    def test_management_is_not_an_invoke_operation_and_refuses_mcp(self):
        path=self.seed();row=self.row();self.scanner.via='mcp'
        with self.assertRaises(ScannerError):self.listing()
        with self.assertRaises(ScannerError):self.delete(row)
        self.assertEqual(self.scanner.invoke('delete_checkpoint')['status'],'error')
        self.assertTrue(path.exists())

    @unittest.skipUnless(importlib.util.find_spec('mcp'),'agent extra not installed')
    def test_actual_mcp_schema_has_no_checkpoint_management_tools(self):
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server
        async def run():
            self.scanner.via='mcp'
            async with create_connected_server_and_client_session(create_server(self.scanner)) as session:
                tools=(await session.list_tools()).tools
                self.assertFalse(any('checkpoint' in t.name for t in tools))
                reply=await session.call_tool('delete_checkpoint',{})
                self.assertTrue(reply.isError)
        asyncio.run(run())
