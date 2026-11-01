"""Owner maintenance contracts using synthetic stores only; never contact providers."""
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pc_scanner import core, history, signature_update as update, signature_maintenance as maintenance


@unittest.skipUnless(os.name == "posix" and os.geteuid() != 0, "non-root POSIX backend")
class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.root = self.base / "store"
        self.config = {"local": {"clamav_binary": sys.executable}, "clamav_updates": {
            "enabled": True, "directory": str(self.root), "freshclam_binary": sys.executable,
            "sigtool_binary": sys.executable}}
        self.scanner = core.Scanner(copy.deepcopy(self.config))
        self.scanner.via = "cli"
        with update.root(self.scanner, create=True):
            pass
        self.active = self.generation()
        self.previous = self.generation()
        self.removable = self.generation()
        manifest = update.digest_directory(self.root / self.active, time.monotonic() + 30)
        update.write_json(self.root / "current.json", dict(generation=self.active, **manifest))
        update.write_json(self.root / "attempt.json", {"pending": False, "next_attempt": time.time() + 86400})

    def generation(self):
        name = secrets.token_hex(16)
        folder = self.root / name
        folder.mkdir(mode=0o700)
        for db in update.DATABASES:
            history.replace_private(folder / db, b"ClamAV-VDB:date:1:10:90:hash:sig".ljust(512, b" ") + b"synthetic")
        return name

    def stage(self):
        name = "stage-" + secrets.token_hex(16)
        folder = self.root / name
        folder.mkdir(mode=0o700)
        (folder / "db").mkdir(mode=0o700)
        history.replace_private(folder / "db/freshclam.dat", b"synthetic provider cooldown state")
        return name

    def listing(self):
        return maintenance.manage(self.scanner, "list")["data"]

    def entry(self, name):
        return next(r for r in self.listing()["entries"] if r["id"] == name)

    def test_inventory_current_and_selected_delete_preserve_wait_and_pointer(self):
        info = self.listing()
        self.assertTrue(next(r for r in info["entries"] if r["id"] == self.active)["current"])
        before = {n: (self.root / n).read_bytes() for n in ("current.json", "attempt.json")}
        entry = self.entry(self.removable)
        result = maintenance.manage(self.scanner, "delete", self.removable, entry["revision"])
        self.assertEqual(result["status"], "completed")
        self.assertFalse((self.root / self.removable).exists())
        for name, data in before.items():
            self.assertEqual((self.root / name).read_bytes(), data)
        self.assertEqual(self.entry(self.previous)["reason"], "last_previous")
        row = self.entry(self.previous)
        with self.assertRaises(core.ScannerError):
            maintenance.manage(self.scanner, "delete", self.previous, row["revision"])

    def test_current_last_previous_forged_id_and_stale_revision_are_refused(self):
        for name, rev in ((self.active, self.entry(self.active)["revision"]), ("../outside", "0" * 64),
                          (self.removable, "0" * 64)):
            with self.subTest(name=name), self.assertRaises(core.ScannerError):
                maintenance.manage(self.scanner, "delete", name, rev)
        entry = self.entry(self.removable)
        history.replace_private(self.root / self.removable / "daily.cvd", b"changed")
        with self.assertRaises(core.ScannerError):
            maintenance.manage(self.scanner, "delete", self.removable, entry["revision"])
        self.assertTrue((self.root / self.removable / "main.cvd").exists())

    def test_cross_process_lease_blocks_delete_then_allows_it_after_exit(self):
        revision = self.entry(self.removable)["revision"]
        script = "from pathlib import Path; from pc_scanner.signature_update import generation_lease; import sys;\nwith generation_lease(Path(sys.argv[1])):\n print('ready',flush=True); sys.stdin.read(1)"
        child = subprocess.Popen([sys.executable, "-c", script, str(self.root / (self.removable + ".lease"))],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), "ready")
            row = self.entry(self.removable)
            self.assertEqual(row["reason"], "in_use")
            with self.assertRaises(core.ScannerError):
                maintenance.manage(self.scanner, "delete", self.removable, revision)
        finally:
            child.communicate("x", timeout=10)
        self.assertEqual(maintenance.manage(self.scanner, "delete", self.removable, revision)["status"], "completed")

    def test_updater_lock_blocks_all_maintenance(self):
        with history.locked(self.root / "update", attempts=1):
            self.assertEqual(maintenance.manage(self.scanner, "list")["status"], "partial")

    def test_pending_stage_cannot_be_deleted_recovery_wait_and_revision(self):
        stage = self.stage()
        until = time.time() + 100
        update.write_json(self.root / "attempt.json", {"pending": True, "next_attempt": until})
        info = self.listing()
        row = self.entry(stage)
        with self.assertRaises(core.ScannerError):
            maintenance.manage(self.scanner, "delete", stage, row["revision"])
        stamp = datetime.fromtimestamp(until, timezone.utc).isoformat()
        before = (self.root / "attempt.json").read_bytes()
        result = maintenance.manage(self.scanner, "recover", revision=info["recovery_revision"], not_before=stamp)
        self.assertEqual(result["status"], "partial")
        self.assertTrue(update.read_json(self.root / "attempt.json")["pending"])
        with self.assertRaises(core.ScannerError):
            maintenance.manage(self.scanner, "recover", revision="0" * 64, not_before=stamp)

    def test_extension_persists_and_cannot_be_shortened(self):
        original = time.time() + 100
        later = original + 1000
        update.write_json(self.root / "attempt.json", {"pending": True, "next_attempt": original})
        result = maintenance.manage(self.scanner, "recover", revision=self.listing()["recovery_revision"],
            not_before=datetime.fromtimestamp(later, timezone.utc).isoformat())
        self.assertEqual(result["status"], "partial")
        self.assertAlmostEqual(update.read_json(self.root / "attempt.json")["next_attempt"], later, places=5)
        with patch("pc_scanner.signature_maintenance.time.time", return_value=later + 1):
            result = maintenance.manage(self.scanner, "recover", revision=self.listing()["recovery_revision"],
                not_before=datetime.fromtimestamp(original, timezone.utc).isoformat())
        self.assertEqual(result["status"], "partial")
        self.assertTrue(update.read_json(self.root / "attempt.json")["pending"])

    def test_recovery_boundary_preserves_provider_before_stage_delete(self):
        stage = self.stage()
        until = 1800000000.0
        update.write_json(self.root / "attempt.json", {"pending": True, "next_attempt": until})
        stamp = datetime.fromtimestamp(until, timezone.utc).isoformat()
        with patch("pc_scanner.signature_maintenance.time.time", return_value=until - .000001):
            early = maintenance.manage(self.scanner, "recover", revision=self.listing()["recovery_revision"], not_before=stamp)
            self.assertEqual(early["status"], "partial")
            self.assertTrue(update.read_json(self.root / "attempt.json")["pending"])
        with patch("pc_scanner.signature_maintenance.time.time", return_value=until):
            info = self.listing()
            result = maintenance.manage(self.scanner, "recover", revision=info["recovery_revision"], not_before=stamp)
        self.assertEqual(result["status"], "completed", result)
        state = update.read_json(self.root / "attempt.json")
        self.assertFalse(state["pending"])
        self.assertEqual(state["next_attempt"], until)
        expected = (self.root / stage / "db/freshclam.dat").read_bytes()
        self.assertEqual((self.root / "provider.dat").read_bytes(), expected)
        row = self.entry(stage)
        self.assertEqual(maintenance.manage(self.scanner, "delete", stage, row["revision"])["status"], "completed")
        self.assertEqual((self.root / "provider.dat").read_bytes(), expected)

    def test_symlink_hardlink_cloud_and_permissive_files_block_whole_deletion(self):
        for kind in ("symlink", "hardlink", "mode", "cloud"):
            with self.subTest(kind=kind):
                name = self.generation()
                target = self.root / name / "daily.cvd"
                outside = self.base / "outside"
                outside.write_bytes(b"must remain")
                if kind in {"symlink", "hardlink"}:
                    target.unlink()
                    target.symlink_to(outside) if kind == "symlink" else os.link(outside, target)
                elif kind == "mode":
                    target.chmod(0o644)
                if kind == "cloud":
                    original_stat = os.stat
                    def metadata(name, *args, **kwargs):
                        info = original_stat(name, *args, **kwargs)
                        return SimpleNamespace(st_flags=core.SF_DATALESS) if name == "daily.cvd" else info
                    with patch("pc_scanner.signature_maintenance.os.stat", side_effect=metadata):
                        row = self.entry(name)
                else:
                    row = self.entry(name)
                self.assertFalse(row["deletable"])
                with self.assertRaises(core.ScannerError):
                    maintenance.manage(self.scanner, "delete", name, row["revision"] or "0" * 64)
                self.assertEqual(outside.read_bytes(), b"must remain")
                self.assertTrue((self.root / name / "main.cvd").exists())

    def test_mcp_and_unknown_actions_have_no_dispatch(self):
        self.scanner.via = "mcp"
        with self.assertRaises(core.ScannerError):
            maintenance.manage(self.scanner, "list")
        self.assertEqual(self.scanner.invoke("clamav_signature_store")["status"], "error")

    def test_invalid_wait_and_corrupt_current_do_not_clear_pending(self):
        update.write_json(self.root / "attempt.json", {"pending": True, "next_attempt": time.time() - 1})
        for stamp in (None, "tomorrow", "2026-11-01T00:00:00"):
            with self.subTest(stamp=stamp), self.assertRaises(core.ScannerError):
                maintenance.manage(self.scanner, "recover", revision=self.listing()["recovery_revision"], not_before=stamp)
        (self.root / self.active / "daily.cvd").write_bytes(b"corrupt")
        with self.assertRaises(core.ScannerError):
            maintenance.manage(self.scanner, "recover", revision=self.listing()["recovery_revision"],
                not_before=datetime.now(timezone.utc).isoformat())
        self.assertTrue(update.read_json(self.root / "attempt.json")["pending"])

    def test_real_cli_inventory_and_no_arbitrary_path_delete(self):
        config = self.base / "scanner.toml"
        config.write_text("[local]\nclamav_binary=" + json.dumps(sys.executable) + "\n[clamav_updates]\nenabled=true\ndirectory=" + json.dumps(str(self.root)) +
                          "\nfreshclam_binary=" + json.dumps(sys.executable) + "\nsigtool_binary=" + json.dumps(sys.executable))
        proc = subprocess.run([sys.executable, "-m", "pc_scanner.cli", "--config", str(config), "clamav-signature-store", "list"],
                              capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(len(report["data"]["entries"]), 3)
        self.assertNotIn(str(self.root), proc.stdout)

    def test_real_cli_recovery_and_selected_stage_deletion(self):
        stage = self.stage()
        until = int(time.time()) - 10
        update.write_json(self.root / "attempt.json", {"pending": True, "next_attempt": until})
        config = self.base / "scanner.toml"
        config.write_text("[local]\nclamav_binary=" + json.dumps(sys.executable) + "\n[clamav_updates]\nenabled=true\ndirectory=" + json.dumps(str(self.root)) +
                          "\nfreshclam_binary=" + json.dumps(sys.executable) + "\nsigtool_binary=" + json.dumps(sys.executable))
        def cli(*args):
            proc = subprocess.run([sys.executable, "-m", "pc_scanner.cli", "--config", str(config), "clamav-signature-store", *args],
                                  capture_output=True, text=True, timeout=15)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            return json.loads(proc.stdout)["data"]
        info = cli("list")
        recovered = cli("recover", "--revision", info["recovery_revision"], "--not-before", info["minimum_not_before"])
        self.assertTrue(recovered["recovered"])
        row = next(r for r in cli("list")["entries"] if r["id"] == stage)
        self.assertEqual(cli("delete", stage, "--revision", row["revision"])["deleted"], stage)
        self.assertTrue((self.root / "provider.dat").exists())

    def test_provider_wait_survives_failure_recovery_stage_delete_and_next_update(self):
        saved = {}
        def engine(argv, *args, **kwargs):
            dbarg = next((a for a in argv if a.startswith("--datadir=")), None)
            if dbarg:
                db = Path(dbarg.split("=", 1)[1])
                if saved:
                    self.assertEqual((db / "freshclam.dat").read_bytes(), b"provider wait must survive")
                    return 1, "", "synthetic provider still waiting"
                history.replace_private(db / "freshclam.dat", b"provider wait must survive")
                (db / "main.cvd").chmod(0o644)
                saved["failed"] = True
                return 1, "", "synthetic network failure"
            self.fail("validation must not run after an updater failure")
        update.write_json(self.root / "attempt.json", {"pending": False, "next_attempt": time.time() - 1})
        with patch("pc_scanner.signature_update.executable", side_effect=lambda x: x), patch("pc_scanner.core.run_bounded", side_effect=engine), patch("pc_scanner.signature_update.shutil.disk_usage", return_value=SimpleNamespace(free=10*update.MAX_BYTES)):
            self.assertEqual(update.update(self.scanner)["status"], "error")
            state = update.read_json(self.root / "attempt.json")
            self.assertEqual((self.root / "provider.dat").read_bytes(), b"provider wait must survive")
            stage = next(self.root.glob("stage-*"))
            self.assertEqual((stage / "db/main.cvd").stat().st_mode & 0o777, 0o600)
            with patch("pc_scanner.signature_maintenance.time.time", return_value=state["next_attempt"] + 1):
                result = maintenance.manage(self.scanner, "recover", revision=self.listing()["recovery_revision"],
                    not_before=datetime.fromtimestamp(state["next_attempt"], timezone.utc).isoformat())
                self.assertEqual(result["status"], "completed")
                row = next(r for r in self.listing()["entries"] if r["kind"] == "stage")
                maintenance.manage(self.scanner, "delete", row["id"], row["revision"])
                self.assertEqual(update.update(self.scanner)["status"], "error")
                self.assertTrue(update.read_json(self.root / "attempt.json")["pending"])

    def test_ambiguous_provider_stages_and_changed_recovery_revision_fail_closed(self):
        self.stage()
        self.stage()
        until = time.time() - 10
        update.write_json(self.root / "attempt.json", {"pending": True, "next_attempt": until})
        revision = self.listing()["recovery_revision"]
        history.replace_private(self.root / self.removable / "daily.cvd", b"changed")
        with self.assertRaises(core.ScannerError):
            maintenance.manage(self.scanner, "recover", revision=revision, not_before=datetime.now(timezone.utc).isoformat())
        with self.assertRaises(core.ScannerError):
            maintenance.manage(self.scanner, "recover", revision=self.listing()["recovery_revision"], not_before=datetime.now(timezone.utc).isoformat())
        self.assertTrue(update.read_json(self.root / "attempt.json")["pending"])
