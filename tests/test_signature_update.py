"""Private updater transactions with synthetic CVDs; no downloads or personal files."""
import copy
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from datetime import datetime, timezone

from pc_scanner import core, history, signature_update as update


@unittest.skipUnless(os.name == "posix" and os.geteuid() != 0, "non-root POSIX private updater")
class UpdateTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.root = self.base / "signatures"
        self.inputs = self.base / "inputs"
        self.inputs.mkdir()
        (self.inputs / "a.txt").write_text("harmless synthetic file")
        self.config = {"local": {"clamav_binary": sys.executable},
                       "scan_roots": {"test": str(self.inputs)},
                       "history": {"file": str(self.base / "history" / "history.jsonl")},
                       "clamav_updates": {"enabled": True, "directory": str(self.root),
                                          "freshclam_binary": sys.executable, "sigtool_binary": sys.executable}}
        self.calls = []
        self.version = 1
        self.cancel = threading.Event()
        self.signatures = {"engine": "1.5.4", "version": 1, "built_at": datetime.now(timezone.utc)}
        self.enterContext(patch("pc_scanner.signature_update.executable", side_effect=lambda x: x))
        # Capacity tests are separate; synthetic fixtures never need several GB free.
        self.enterContext(patch("pc_scanner.signature_update.shutil.disk_usage", return_value=type("Disk", (), {"free": 10 * update.MAX_BYTES})()))

    def scanner(self):
        scanner = core.Scanner(copy.deepcopy(self.config))
        scanner.via = "cli"
        return scanner

    def engine(self, argv, *args, **kwargs):
        self.calls.append(argv)
        if "--version" in argv:
            return 0, "ClamAV 1.5.4/1/" + datetime.now().strftime("%a %b %d %H:%M:%S %Y"), ""
        db = next((Path(a.split("=", 1)[1]) for a in argv if a.startswith("--datadir=")), None)
        if db is not None:
            for name in update.DATABASES:
                header = f"ClamAV-VDB:01 Nov 2026 00-00 +0000:{self.version}:100:90:hash:signature:builder:1".encode()
                (db / name).write_bytes(header.ljust(512, b" ") + b"synthetic")
            return 0, "", ""
        if any(a.startswith("--info=") for a in argv):
            return 0, "Digital signature: synthetic\nVerification OK.\n", ""
        return 0, "Scanned files: 1\nInfected files: 0\n", ""

    def do_update(self, engine=None):
        with patch("pc_scanner.core.run_bounded", side_effect=engine or self.engine):
            return update.update(self.scanner(), self.cancel)

    def allow_next(self):
        update.write_json(self.root / "attempt.json", {"next_attempt": time.time() - 1, "pending": False})

    def test_publish_signed_complete_private_generation_and_unchanged(self):
        first = self.do_update()
        self.assertEqual(first["data"]["update_status"], "updated", first)
        old = update.read_json(self.root / "current.json")
        generation = self.root / old["generation"]
        self.assertEqual(sorted(p.name for p in generation.iterdir()), sorted(update.DATABASES))
        self.assertEqual(generation.stat().st_mode & 0o777, 0o700)
        for file in generation.iterdir():
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        self.assertFalse(list(self.root.glob("stage-*")))
        self.assertEqual(self.do_update()["data"]["update_status"], "rate_limited")
        self.allow_next()
        self.assertEqual(self.do_update()["data"]["update_status"], "unchanged")
        self.assertEqual(old, update.read_json(self.root / "current.json"))
        configs = [a for call in self.calls for a in call if a.startswith("--config-file=")]
        self.assertTrue(configs)
        self.assertNotIn("sudo", repr(self.calls))

    def test_failures_preserve_current_and_block_automatic_retries(self):
        self.do_update()
        old = (self.root / "current.json").read_bytes()
        for failure in ("network", "unsigned", "missing", "rollback", "load", "cancel"):
            with self.subTest(failure=failure):
                self.allow_next()
                self.cancel.clear()
                def bad(argv, *args, **kwargs):
                    answer = self.engine(argv, *args, **kwargs)
                    db = next((Path(a.split("=", 1)[1]) for a in argv if a.startswith("--datadir=")), None)
                    if db is not None:
                        if failure == "network":
                            return 1, "", "secret proxy credentials must never escape"
                        if failure == "missing":
                            (db / "daily.cvd").unlink()
                        if failure == "cancel":
                            self.cancel.set()
                    if failure == "unsigned" and any(a.startswith("--info=") for a in argv):
                        return 0, "Verification OK.", ""
                    if failure == "rollback" and db is not None:
                        for name in update.DATABASES:
                            (db / name).write_bytes(b"ClamAV-VDB:date:0:100:".ljust(512, b" ") + b"old")
                    if failure == "load" and any(a.startswith("--database=") for a in argv):
                        return 2, "", "load failed"
                    return answer
                # Failed staging is intentionally retained. Use a generous fixture-only count limit.
                with patch.object(update, "MAX_GENERATIONS", 32):
                    report = self.do_update(bad)
                self.assertNotEqual(report["status"], "completed", report)
                self.assertEqual(old, (self.root / "current.json").read_bytes())
                self.assertNotIn("secret proxy", json.dumps(report))
                self.assertTrue(update.read_json(self.root / "attempt.json")["pending"])
                count = len(self.calls)
                self.cancel.clear()
                self.do_update()
                self.assertEqual(count, len(self.calls))

    def test_generation_pin_survives_publication_and_supports_parallel_readers(self):
        self.do_update()
        scanner = self.scanner()
        with update.pin(scanner) as old, update.pin(scanner) as second:
            old_path = old.local["clamav_database_directory"]
            self.assertEqual(old_path, second.local["clamav_database_directory"])
            self.allow_next()
            self.version = 2
            report = self.do_update()
            self.assertEqual(report["data"]["update_status"], "updated", report)
            self.assertEqual(old_path, old.local["clamav_database_directory"])
            self.assertTrue(Path(old_path).exists())
            with update.pin(scanner) as new:
                self.assertNotEqual(old_path, new.local["clamav_database_directory"])
        self.assertNotIn("clamav_database_directory", scanner.local)

    def test_update_lock_is_cross_process_and_released(self):
        self.do_update()
        script = "from pathlib import Path; from pc_scanner import history; import sys;\nwith history.locked(Path(sys.argv[1]), attempts=1):\n print('ready', flush=True); sys.stdin.read(1)"
        child = subprocess.Popen([sys.executable, "-c", script, str(self.root / "update")],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), "ready")
            self.assertEqual(self.do_update()["data"]["update_status"], "busy")
        finally:
            child.communicate("x", timeout=10)
        self.allow_next()
        self.assertEqual(self.do_update()["data"]["update_status"], "unchanged")

    def test_resume_uses_content_not_generation_metadata_and_invalidates_new_content(self):
        self.do_update()
        with patch("pc_scanner.core.clamav_signatures", return_value=self.signatures), patch("pc_scanner.core.run_bounded", side_effect=self.engine):
            scanner = self.scanner()
            first = scanner.invoke("malware", root_alias="test", batch=True)
            self.assertEqual(first["status"], "completed", first)
            self.assertIsNotNone(scanner._coverage_snapshot)
            second = self.scanner().invoke("malware", root_alias="test", resume=True)
            self.assertEqual(second["data"]["batch"]["reused"], 1, second)
            obj = update.read_json(self.root / "current.json")
            for file in (self.root / obj["generation"]).iterdir():
                os.utime(file, None)
            unchanged = self.scanner().invoke("malware", root_alias="test", resume=True)
            self.assertEqual(unchanged["data"]["batch"]["reused"], 1, unchanged)
        self.version = 2
        self.allow_next()
        self.do_update()
        with patch("pc_scanner.core.clamav_signatures", return_value=self.signatures), patch("pc_scanner.core.run_bounded", side_effect=self.engine):
            new = self.scanner().invoke("malware", root_alias="test", resume=True)
        self.assertEqual(new["data"]["batch"]["reused"], 0, new)
        self.assertEqual(new["data"]["engine_counts"]["scanned"], 1)

    def test_untrusted_paths_permissions_and_contents_are_refused(self):
        self.do_update()
        obj = update.read_json(self.root / "current.json")
        file = self.root / obj["generation"] / "daily.cvd"
        file.chmod(0o644)
        with self.assertRaises(OSError):
            with update.pin(self.scanner()):
                self.fail("readable generation accepted")
        file.chmod(0o600)
        file.write_bytes(b"modified")
        with self.assertRaises(OSError):
            with update.pin(self.scanner()):
                self.fail("modified generation accepted")

    def test_failed_update_preserves_reusable_checkpoint(self):
        self.do_update()
        with patch("pc_scanner.core.clamav_signatures", return_value=self.signatures), patch("pc_scanner.core.run_bounded", side_effect=self.engine):
            first = self.scanner().invoke("malware", root_alias="test", batch=True)
        self.assertEqual(first["status"], "completed", first)
        self.allow_next()
        self.assertEqual(self.do_update(lambda *a, **kw: (1, "", "synthetic error"))["status"], "error")
        with patch("pc_scanner.core.clamav_signatures", return_value=self.signatures), patch("pc_scanner.core.run_bounded", side_effect=self.engine):
            resumed = self.scanner().invoke("malware", root_alias="test", resume=True)
        self.assertEqual(resumed["data"]["batch"]["reused"], 1, resumed)

    def test_cloud_store_and_link_store_are_rejected_before_any_runner(self):
        self.root.mkdir(mode=0o700)
        elsewhere = self.base / "elsewhere"
        elsewhere.mkdir(mode=0o700)
        self.root.rmdir()
        self.root.symlink_to(elsewhere, target_is_directory=True)
        self.assertEqual(self.do_update()["status"], "error")
        self.assertFalse(self.calls)
        self.root.unlink()
        with patch("pc_scanner.core.cloud_placeholder", return_value=True):
            self.assertEqual(self.do_update()["status"], "error")
        self.assertFalse(self.calls)

    def test_unknown_freshness_is_never_reported_as_fresh_after_update(self):
        with patch("pc_scanner.core.clamav_signatures", return_value={"engine": "1.5.4", "version": 1, "built_at": None}):
            report = self.do_update()
        self.assertTrue(report["data"]["published"])
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["data"]["signature_check"]["freshness"], "unknown")

    def test_no_mcp_or_implicit_update_and_conflicting_configuration(self):
        scanner = self.scanner()
        scanner.via = "mcp"
        with self.assertRaises(core.ScannerError):
            update.update(scanner)
        self.assertEqual(scanner.invoke("update_clamav_signatures")["status"], "error")
        self.assertFalse(self.root.exists())
        self.config["local"]["clamav_database_directory"] = str(self.base)
        with self.assertRaises(core.ScannerError):
            self.scanner()

    def test_capacity_or_publication_failure_never_replaces_current(self):
        self.do_update()
        old = (self.root / "current.json").read_bytes()
        self.allow_next()
        with patch.object(update, "MAX_GENERATIONS", 1):
            self.assertEqual(self.do_update()["status"], "error")
        self.version = 2
        original = update.write_json
        def fail(path, obj):
            if path.name == "current.json":
                raise OSError("synthetic publication failure")
            original(path, obj)
        with patch.object(update, "write_json", side_effect=fail):
            report = self.do_update()
        self.assertEqual(report["data"]["update_status"], "unknown")
        self.assertEqual(old, (self.root / "current.json").read_bytes())

    def test_cancellation_after_publication_does_not_roll_back(self):
        self.do_update()
        self.allow_next()
        old = update.read_json(self.root / "current.json")
        self.version = 2
        original = update.write_json
        def publish(path, obj):
            original(path, obj)
            if path.name == "current.json":
                self.cancel.set()
        with patch.object(update, "write_json", side_effect=publish):
            report = self.do_update()
        self.assertTrue(report["data"]["published"])
        self.assertTrue(report["data"]["cancellation_requested_after_publication"])
        self.assertNotEqual(old, update.read_json(self.root / "current.json"))

    def test_failure_after_pointer_replace_reports_unknown_publication(self):
        self.do_update()
        self.allow_next()
        self.version = 2
        original = update.write_json
        def uncertain(path, obj):
            original(path, obj)
            if path.name == "current.json":
                raise OSError("synthetic durability failure after replace")
        with patch.object(update, "write_json", side_effect=uncertain):
            report = self.do_update()
        self.assertEqual(report["data"]["update_status"], "unknown")
        self.assertIsNone(report["data"]["published"])
        self.assertEqual(update.read_json(self.root / "current.json")["versions"]["daily.cvd"], 2)

    def test_real_updater_child_is_reaped_on_timeout_and_cancel(self):
        self.do_update()
        original = core.run_bounded
        marker = self.base / "synthetic-child.pid"
        code = "import os,time; from pathlib import Path; Path(%r).write_text(str(os.getpid())); time.sleep(30)" % str(marker)
        for cancelled in (False, True):
            with self.subTest(cancelled=cancelled):
                self.allow_next()
                self.cancel.clear()
                self.config["clamav_updates"]["timeout_seconds"] = 1 if not cancelled else 10
                timer = threading.Timer(.5, self.cancel.set) if cancelled else None
                if timer:
                    timer.start()
                try:
                    with patch("pc_scanner.core.run_bounded", side_effect=lambda argv, timeout, limit, cancel=None: original(
                            [sys.executable, "-c", code], timeout, limit, cancel)):
                        report = update.update(self.scanner(), self.cancel)
                finally:
                    if timer:
                        timer.cancel()
                        timer.join()
                self.assertEqual(report["data"]["update_status"], "cancelled" if cancelled else "timeout", report)
                pid = int(marker.read_text())
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)
                with history.locked(self.root / "update", attempts=1):
                    pass

    def test_external_change_preserves_findings_and_never_finishes_batch_evidence(self):
        db = self.base / "external"
        db.mkdir()
        (db / "daily.cvd").write_text("synthetic metadata")
        config = {"local": {"clamav_binary": sys.executable, "clamav_database_directory": str(db)},
                  "scan_roots": {"test": str(self.inputs)},
                  "history": self.config["history"]}
        def engine(argv, *a, **kw):
            (db / "daily.cvd").write_text("changed definitions")
            return 1, str(self.inputs / "a.txt") + ": Synthetic.Marker FOUND\nScanned files: 1\nInfected files: 1\n", ""
        with patch("pc_scanner.core.clamav_signatures", return_value=self.signatures), patch("pc_scanner.core.run_bounded", side_effect=engine):
            report = core.Scanner(config).invoke("malware", root_alias="test", batch=True)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(len(report["findings"]), 1)
        checkpoint = next((self.base / "history").rglob("*.json"))
        state = json.loads(checkpoint.read_text())
        self.assertTrue(all(not r["finished"] for r in state["parts"].values()))
        with patch("pc_scanner.core.clamav_signatures", return_value=self.signatures), patch("pc_scanner.core.run_bounded", side_effect=engine):
            direct = core.Scanner(config).invoke("malware", root_alias="test")
        self.assertGreater(direct["data"]["coverage"]["unresolved"]["count"], 0)

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "agent extra not installed")
    def test_sdk_mcp_can_check_private_definitions_but_cannot_update(self):
        self.do_update()
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server
        async def exercise():
            async with create_connected_server_and_client_session(create_server(self.scanner())) as session:
                names = {t.name for t in (await session.list_tools()).tools}
                self.assertNotIn("update_clamav_signatures", names)
                response = await session.call_tool("check_clamav_signatures", {})
                report = json.loads(response.content[0].text)
                self.assertEqual(report["status"], "completed", report)
                self.assertEqual(report["data"]["signature_check"]["update_mode"], "private_owner_cli")
                self.assertNotIn(str(self.root), json.dumps(report))
        with patch("pc_scanner.core.clamav_signatures", return_value=self.signatures):
            asyncio.run(exercise())

    def test_timeout_releases_lock_and_leaves_old_generation(self):
        self.do_update()
        old = (self.root / "current.json").read_bytes()
        self.allow_next()
        self.config["clamav_updates"]["timeout_seconds"] = 1
        with patch("pc_scanner.core.run_bounded", side_effect=lambda *a, **k: (time.sleep(1.01), (_ for _ in ()).throw(core.ScannerError("stopped")))[-1]):
            report = update.update(self.scanner())
        self.assertEqual(report["data"]["update_status"], "timeout")
        self.assertEqual(old, (self.root / "current.json").read_bytes())
        with history.locked(self.root / "update", attempts=1):
            pass


class ConfigTests(unittest.TestCase):
    def test_invalid_settings_fail_at_load(self):
        for raw in ({"enabled": "yes"}, {"enabled": True}, {"directory": "/tmp/a\nb"}, {"unknown": 1}, {"timeout_seconds": True}):
            with self.subTest(raw=raw), self.assertRaises(core.ScannerError):
                core.Scanner({"clamav_updates": raw})

    def test_owner_cli_command_is_recognized_and_disabled_by_default(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "scanner.toml"
            config.write_text("")
            proc = subprocess.run([sys.executable, "-m", "pc_scanner.cli", "--config", str(config), "update-clamav-signatures"],
                                  capture_output=True, text=True, timeout=15)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            report = json.loads(proc.stdout)
            self.assertEqual(report["data"]["update_status"], "failed")
