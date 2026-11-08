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

from pc_scanner import core, history, process_store, signature_update as update


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

    @unittest.skipUnless(sys.platform == "darwin", "macOS ACL entries apply regardless of the file mode")
    def test_ancestor_acl_letting_others_move_the_store_refuses_update_before_download(self):
        # Otherwise another account could move the store away, and the next update would start without its waits.
        subprocess.run(["/bin/chmod", "+a", "everyone allow list,search,add_subdirectory,delete_child", str(self.base)], check=True)
        report = self.do_update()
        self.assertEqual(report["data"]["update_status"], "failed", report)
        self.assertEqual(self.calls, [])
        self.assertFalse(self.root.exists())

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

    def test_zero_exit_provider_wait_preserves_stage_and_requires_recovery(self):
        self.do_update()
        pointer = (self.root / "current.json").read_bytes()
        generation = self.root / json.loads(pointer)["generation"]
        original = {p.name: p.read_bytes() for p in generation.iterdir()}
        messages = [
            ("", "WARNING: FreshClam received error code 429 from the ClamAV Content Delivery Network (CDN).\n"),
            ("WARNING: FreshClam previously received error code 429 or 403 from the CDN.\n", ""),
            ("", "WARNING: You are still on cool-down until after: 2026-11-10 00:00:00\n"),
            ("WARNING: You are on cool-down until after: 2026-11-10 00:00:00\n", ""),
        ]
        for index, (out, err) in enumerate(messages):
            with self.subTest(index=index):
                self.allow_next()  # This test owns only its synthetic temporary store.
                previous_provider = b"previous opaque provider state"
                history.replace_private(self.root / "provider.dat", previous_provider)
                saved_provider = b"new opaque 48-hour provider state " + str(index).encode()
                stages_before = set(self.root.glob("stage-*"))

                def waiting(argv, *args, **kwargs):
                    if not any(a.startswith("--datadir=") for a in argv):
                        return self.engine(argv, *args, **kwargs)
                    self.calls.append(argv)
                    db = Path(next(a.split("=", 1)[1] for a in argv if a.startswith("--datadir=")))
                    self.assertEqual((db / "freshclam.dat").read_bytes(), previous_provider)
                    (db / "freshclam.dat").write_bytes(saved_provider)
                    # A later database may be throttled after an earlier one was downloaded.
                    (db / "daily.cvd").write_bytes(b"ClamAV-VDB:date:2:100:".ljust(512, b" ") + b"newer")
                    return 0, out + "private proxy credentials", err + str(self.root)

                with patch.object(update, "MAX_GENERATIONS", 32):
                    report = self.do_update(waiting)
                self.assertEqual((report["status"], report["data"]["update_status"]), ("partial", "rate_limited"), report)
                self.assertTrue(report["data"]["recovery_required"])
                self.assertFalse(report["data"]["published"])
                self.assertNotIn("private proxy", json.dumps(report))
                self.assertNotIn(str(self.root), json.dumps(report))
                self.assertTrue(any("provider" in w.lower() for w in report["warnings"]))
                self.assertEqual((self.root / "current.json").read_bytes(), pointer)
                self.assertEqual({p.name: p.read_bytes() for p in generation.iterdir()}, original)
                new_stages = set(self.root.glob("stage-*")) - stages_before
                self.assertEqual(len(new_stages), 1)
                stage = new_stages.pop()
                self.assertEqual((stage / "db/freshclam.dat").read_bytes(), saved_provider)
                self.assertEqual((self.root / "provider.dat").read_bytes(), saved_provider)
                sync = update.read_json(self.root / "provider-sync.json")
                self.assertEqual((sync["status"], sync["stage"]), ("synced", stage.name))
                pending = (self.root / "attempt.json").read_bytes()
                self.assertTrue(json.loads(pending)["pending"])
                calls_before = len(self.calls)
                self.do_update()
                self.assertEqual(len(self.calls), calls_before)
                self.assertEqual((self.root / "attempt.json").read_bytes(), pending)

    def test_zero_exit_wait_allows_longer_owner_guard_but_not_early_recovery(self):
        from pc_scanner import signature_maintenance as maintenance
        self.do_update()
        self.allow_next()
        provider = b"opaque provider cooldown lasting 48 hours"

        def waiting(argv, *args, **kwargs):
            if not any(a.startswith("--datadir=") for a in argv):
                return self.engine(argv, *args, **kwargs)
            self.calls.append(argv)
            db = Path(next(a.split("=", 1)[1] for a in argv if a.startswith("--datadir=")))
            (db / "freshclam.dat").write_bytes(provider)
            return 0, "", "WARNING: FreshClam received error code 429 from the CDN.\n"

        report = self.do_update(waiting)
        self.assertEqual(report["data"]["update_status"], "rate_limited", report)
        listing = maintenance.manage(self.scanner(), "list")["data"]
        stage = next(r for r in listing["entries"] if r["kind"] == "stage")
        self.assertEqual(stage["reason"], "pending_recovery")
        with self.assertRaises(core.ScannerError):
            maintenance.manage(self.scanner(), "delete", stage["id"], stage["revision"])
        until = int(time.time()) + 172800
        ack = datetime.fromtimestamp(until, timezone.utc).isoformat()
        result = maintenance.manage(self.scanner(), "recover", revision=listing["recovery_revision"], not_before=ack)
        self.assertFalse(result["data"]["recovered"])
        self.assertEqual(update.read_json(self.root / "attempt.json"), {"pending": True, "next_attempt": until})
        listing = maintenance.manage(self.scanner(), "list")["data"]
        result = maintenance.manage(self.scanner(), "recover", revision=listing["recovery_revision"],
                                    not_before=datetime.now(timezone.utc).isoformat())
        self.assertFalse(result["data"]["recovered"])
        self.assertEqual(update.read_json(self.root / "attempt.json")["next_attempt"], until)
        count = len(self.calls)
        self.do_update()  # A new Scanner instance must retain the durable pending guard.
        self.assertEqual(len(self.calls), count)
        self.assertEqual((self.root / "provider.dat").read_bytes(), provider)
        self.assertEqual((self.root / stage["id"] / "db/freshclam.dat").read_bytes(), provider)
        with history.locked(self.root / "update", attempts=1), history.locked(self.root / "publish", attempts=1):
            pass

    def test_provider_save_failure_during_zero_exit_wait_stays_failed_and_pending(self):
        self.do_update()
        self.allow_next()
        pointer = (self.root / "current.json").read_bytes()
        old_provider = b"old provider state"
        history.replace_private(self.root / "provider.dat", old_provider)
        new_provider = b"new provider cooldown state"

        def waiting(argv, *args, **kwargs):
            self.calls.append(argv)
            db = Path(next(a.split("=", 1)[1] for a in argv if a.startswith("--datadir=")))
            (db / "freshclam.dat").write_bytes(new_provider)
            return 0, "", "WARNING: You are on cool-down until after: 2026-11-10 00:00:00\n"

        with patch("pc_scanner.signature_maintenance.preserve_provider", side_effect=OSError("synthetic save failure")):
            report = self.do_update(waiting)
        self.assertEqual((report["status"], report["data"]["update_status"]), ("error", "failed"), report)
        self.assertEqual((self.root / "provider.dat").read_bytes(), old_provider)
        self.assertEqual((self.root / "current.json").read_bytes(), pointer)
        self.assertTrue(update.read_json(self.root / "attempt.json")["pending"])
        sync = update.read_json(self.root / "provider-sync.json")
        self.assertEqual(sync["status"], "pending")
        self.assertEqual((self.root / sync["stage"] / "db/freshclam.dat").read_bytes(), new_provider)

    def test_ordinary_zero_exit_messages_still_allow_successful_unchanged(self):
        self.do_update()
        self.allow_next()

        def ordinary(argv, *args, **kwargs):
            answer = self.engine(argv, *args, **kwargs)
            if any(a.startswith("--datadir=") for a in argv):
                return 0, "daily.cvd is up-to-date (version: 429, sigs: 100)\n", (
                    "WARNING: DNS Update Info disabled. Falling back to HTTP mode.\n"
                    "WARNING: remote_cvdhead: file not found: https://localhost/daily.cld\n")
            return answer

        report = self.do_update(ordinary)
        self.assertEqual((report["status"], report["data"]["update_status"]), ("completed", "unchanged"), report)
        self.assertFalse(update.read_json(self.root / "attempt.json")["pending"])
        self.assertFalse(list(self.root.glob("stage-*")))

    def test_actual_zero_exit_child_cooldown_is_captured_and_preserved(self):
        self.do_update()
        self.allow_next()
        pointer = (self.root / "current.json").read_bytes()
        child = self.base / "synthetic-cooldown.py"
        marker = self.base / "child.pid"
        child.write_text(
            "import os,sys\nfrom pathlib import Path\n"
            f"Path({str(marker)!r}).write_text(str(os.getpid()))\n"
            "db=Path(next(a.split('=',1)[1] for a in sys.argv if a.startswith('--datadir=')))\n"
            "(db/'freshclam.dat').write_bytes(b'opaque synthetic 48-hour wait')\n"
            "print('WARNING: You are still on cool-down until after: 2026-11-10 00:00:00', file=sys.stderr)\n")
        real = core.run_bounded

        def engine(argv, timeout, limit, cancel=None):
            if any(a.startswith("--datadir=") for a in argv):
                self.calls.append(argv)
                return real([sys.executable, str(child), *argv[1:]], timeout, limit, cancel)
            return self.engine(argv, timeout, limit, cancel)

        report = self.do_update(engine)
        self.assertEqual((report["status"], report["data"]["update_status"]), ("partial", "rate_limited"), report)
        self.assertEqual((self.root / "current.json").read_bytes(), pointer)
        self.assertTrue(update.read_json(self.root / "attempt.json")["pending"])
        stage = next(self.root.glob("stage-*"))
        self.assertEqual((self.root / "provider.dat").read_bytes(), b"opaque synthetic 48-hour wait")
        self.assertEqual((stage / "db/freshclam.dat").read_bytes(), b"opaque synthetic 48-hour wait")
        with self.assertRaises(ProcessLookupError):
            os.kill(int(marker.read_text()), 0)

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

    def test_simultaneous_starts_wait_briefly_and_hash_outside_the_publication_lock(self):
        self.do_update()
        real, results = update.digest_directory, []
        def slow(*args, **kwargs):
            # Fails when the hash runs inside the publication lock; waits out the other start's short section.
            with history.locked(self.root / "publish"):
                pass
            time.sleep(0.2)
            return real(*args, **kwargs)
        def check():
            results.append(self.scanner().invoke("check_clamav_signatures"))
        with patch("pc_scanner.core.clamav_signatures", return_value=self.signatures), \
                patch("pc_scanner.signature_update.digest_directory", side_effect=slow):
            first = threading.Thread(target=check)
            with history.locked(self.root / "publish"):  # a publication is switching the reference
                first.start()
                time.sleep(0.1)
            # A threat-list download can keep the shared private-store lock for its whole update; never wait on it.
            with process_store._lock:
                check()
            first.join()
        self.assertEqual([r["status"] for r in results], ["completed"] * 2, results)

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

    def test_unreadable_reference_after_scan_is_unknown_not_newer(self):
        self.do_update()
        def corrupting(argv, *args, **kwargs):
            (self.root / "current.json").write_text("{")
            return self.engine(argv, *args, **kwargs)
        with patch("pc_scanner.core.clamav_signatures", return_value=self.signatures), patch("pc_scanner.core.run_bounded", side_effect=corrupting):
            report = self.scanner().invoke("malware", root_alias="test")
        self.assertIsNone(report["data"]["definition_generation"]["newer_generation_available"], report)
        self.assertFalse(any("New definitions were published" in w for w in report["warnings"]))
        self.assertTrue(any("could not be confirmed" in w for w in report["warnings"]))

    def test_engine_text_naming_the_private_store_is_masked(self):
        self.do_update()
        generation = self.root / update.read_json(self.root / "current.json")["generation"]
        def noisy(argv, *args, **kwargs):
            code, output, error = self.engine(argv, *args, **kwargs)
            return code, output, error + f"LibClamAV Warning: synthetic note for {generation}/daily.cvd and {self.root}/x\n"
        with patch("pc_scanner.core.clamav_signatures", return_value=self.signatures), patch("pc_scanner.core.run_bounded", side_effect=noisy):
            report = self.scanner().invoke("malware", root_alias="test")
        self.assertNotIn(str(self.root), json.dumps(report))
        self.assertIn("<definitions>/daily.cvd and <definitions>/x", report["data"]["diagnostic"], report)

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
        # A folder without definitions still takes a slot: the owner investigates it, nothing is removed automatically.
        empty = self.root / ("0" * 32)
        empty.mkdir(mode=0o700)
        calls = len(self.calls)
        with patch.object(update, "MAX_GENERATIONS", 2):
            self.assertEqual(self.do_update()["status"], "error")
        self.assertEqual(len(self.calls), calls)
        empty.rmdir()
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
        self.allow_next()
        self.version = 3
        def interrupted(path, obj):
            original(path, obj)
            if path.name == "current.json":
                self.cancel.set()  # Ctrl-C while the new reference is being made durable
                raise OSError("synthetic durability failure after replace")
        with patch.object(update, "write_json", side_effect=interrupted):
            report = self.do_update()
        self.assertEqual((report["data"]["update_status"], report["data"]["published"]), ("unknown", None), report)
        self.assertEqual(update.read_json(self.root / "current.json")["versions"]["daily.cvd"], 3)

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
            # Docker filesystems can retain the same timestamps for rapid same-size rewrites.
            # Change the bytes and size on every invocation, including the second (ordinary) scan.
            with (db / "daily.cvd").open("a") as f:
                f.write("\nchanged definitions")
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


class ExplicitDatabaseChangeTests(unittest.TestCase):
    """Normal scans with an explicit database folder; runs on every OS."""
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        base = Path(temp.name).resolve()
        self.db, inputs = base / "db", base / "inputs"
        self.db.mkdir()
        inputs.mkdir()
        for name in ("main.cvd", "daily.cvd", "bytecode.cvd", "custom.ndb"):
            (self.db / name).write_text("synthetic " + name)
        (inputs / "a.txt").write_text("harmless synthetic file")
        self.config = {"local": {"clamav_binary": sys.executable, "clamav_database_directory": str(self.db)},
                       "scan_roots": {"test": str(inputs)},
                       "history": {"file": str(base / "history" / "history.jsonl")}}
        self.calls = []
        self.enterContext(patch("pc_scanner.core.clamav_signatures", return_value={
            "engine": "1.5.4", "version": 1, "built_at": datetime.now(timezone.utc)}))

    def engine(self, argv, *args, **kwargs):
        self.calls.append(argv)
        return 0, "Scanned files: 1\nInfected files: 0\n", ""

    def scan(self, engine=None, **kwargs):
        with patch("pc_scanner.core.run_bounded", side_effect=engine or self.engine):
            return core.Scanner(self.config).invoke("malware", root_alias="test", **kwargs)

    def test_unchanged_custom_database_is_not_a_definition_change(self):
        self.assertEqual(self.scan()["status"], "completed")
        self.assertEqual(self.scan(batch=True)["status"], "completed")
        calls = len(self.calls)
        resumed = self.scan(batch=True, resume=True)
        self.assertEqual((resumed["status"], resumed["data"]["batch"]["reused"], len(self.calls)), ("completed", 1, calls), resumed)
        def changing(argv, *args, **kwargs):
            (self.db / "custom.ndb").write_text("changed custom signatures")
            return self.engine(argv, *args, **kwargs)
        changed = self.scan(engine=changing)
        self.assertEqual(changed["status"], "partial")
        self.assertTrue(changed["data"]["definitions_changed"])

    def test_engine_text_naming_the_definitions_folder_is_masked(self):
        def noisy(argv, *args, **kwargs):
            self.calls.append(argv)
            return 0, "Scanned files: 1\nInfected files: 0\n", f"LibClamAV Warning: synthetic note for {self.db}/daily.cvd\n"
        report = self.scan(engine=noisy)
        self.assertNotIn(str(self.db), json.dumps(report))
        self.assertIn("<definitions>/daily.cvd", report["data"]["diagnostic"], report)

    def test_custom_database_change_between_sessions_invalidates_resume(self):
        self.assertEqual(self.scan(batch=True)["status"], "completed")
        (self.db / "custom.ndb").write_text("custom signatures changed between sessions")
        calls = len(self.calls)
        resumed = self.scan(batch=True, resume=True)
        self.assertEqual(resumed["data"]["batch"]["reused"], 0, resumed)
        self.assertGreater(len(self.calls), calls)
