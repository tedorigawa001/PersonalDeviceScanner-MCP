"""Owner maintenance contracts using synthetic stores only; never contact providers."""
import copy
import hashlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import shutil
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
            # Each published generation differs from the others; an unchanged update never publishes a copy.
            history.replace_private(folder / db, b"ClamAV-VDB:date:1:10:90:hash:sig".ljust(512, b" ") + name.encode())
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
        self.assertFalse((self.root / (self.removable + ".lease")).exists())  # never accumulates toward the limit
        for name, data in before.items():
            self.assertEqual((self.root / name).read_bytes(), data)
        self.assertEqual(self.entry(self.previous)["reason"], "last_previous")
        row = self.entry(self.previous)
        with self.assertRaises(core.ScannerError):
            maintenance.manage(self.scanner, "delete", self.previous, row["revision"])

    def test_an_incomplete_folder_never_stands_in_for_the_last_previous_generation(self):
        # Empty folders once counted as generations: the real previous one could go, leaving only an empty "previous".
        maintenance.manage(self.scanner, "delete", self.removable, self.entry(self.removable)["revision"])
        empty = secrets.token_hex(16)
        (self.root / empty).mkdir(mode=0o700)
        partial = secrets.token_hex(16)
        (self.root / partial).mkdir(mode=0o700)
        history.replace_private(self.root / partial / update.DATABASES[0], b"synthetic")
        real = self.entry(self.previous)
        self.assertEqual((real["deletable"], real["reason"], real["incomplete"]), (False, "last_previous", False))
        with self.assertRaises(core.ScannerError):
            maintenance.manage(self.scanner, "delete", self.previous, real["revision"])
        self.assertEqual(self.entry(self.active)["incomplete"], False)
        for name in (empty, partial):
            row = self.entry(name)
            self.assertEqual((row["deletable"], row["reason"], row["incomplete"]), (True, None, True))
            self.assertEqual(maintenance.manage(self.scanner, "delete", name, row["revision"])["status"], "completed")
            self.assertFalse((self.root / name).exists())
        self.assertEqual(self.entry(self.previous)["reason"], "last_previous")

    def test_only_a_verified_folder_stands_beside_the_last_previous_generation(self):
        # These hold three regular files by name, yet none could replace the current generation.
        maintenance.manage(self.scanner, "delete", self.removable, self.entry(self.removable)["revision"])
        outside = self.base / "outside"
        outside.mkdir(mode=0o700)
        for db in update.DATABASES:
            history.replace_private(outside / db, b"ClamAV-VDB:date:1:10:90:hash:sig".ljust(512, b" ") + b"synthetic")
        def linked(folder):
            folder.symlink_to(outside, target_is_directory=True)
        def finder_file(folder):
            shutil.copytree(outside, folder)
            history.replace_private(folder / ".DS_Store", b"\0\0\0\1Bud1")
        def malformed(folder):
            folder.mkdir(mode=0o700)
            for db in update.DATABASES:
                history.replace_private(folder / db, b"x")
        def non_ascii_header(folder):
            folder.mkdir(mode=0o700)
            for db in update.DATABASES:
                history.replace_private(folder / db, b"ClamAV-VDB:\xff\xfe:1:10:90".ljust(512, b" ") + b"synthetic")
        def duplicate_of_current(folder):
            shutil.copytree(self.root / self.active, folder)
        for label, make, listed in (("linked", linked, "unavailable"), ("finder_file", finder_file, "unavailable"),
                                    ("malformed", malformed, None), ("non_ascii_header", non_ascii_header, None),
                                    ("duplicate_of_current", duplicate_of_current, None)):
            with self.subTest(label):
                folder = self.root / secrets.token_hex(16)
                make(folder)
                self.assertTrue(maintenance.complete(folder))
                real = self.entry(self.previous)
                self.assertEqual((real["deletable"], real["reason"]), (False, "last_previous"))
                with self.assertRaises(core.ScannerError):
                    maintenance.manage(self.scanner, "delete", self.previous, real["revision"])
                self.assertEqual(self.entry(folder.name)["reason"], listed)
                folder.unlink() if folder.is_symlink() else shutil.rmtree(folder)
        self.assertTrue((self.root / self.previous / "main.cvd").exists())

    def test_damaged_headers_fail_closed_instead_of_crashing_maintenance(self):
        broken = self.root / secrets.token_hex(16)
        broken.mkdir(mode=0o700)
        for db in update.DATABASES:
            history.replace_private(broken / db, b"ClamAV-VDB:\xff\xfe:1:10:90".ljust(512, b" ") + b"synthetic")
        with self.assertRaises(OSError):
            update.digest_directory(broken, time.monotonic() + 30)
        # A damaged previous generation is listed and can be removed like any other unusable folder.
        row = self.entry(broken.name)
        self.assertEqual(maintenance.manage(self.scanner, "delete", broken.name, row["revision"])["status"], "completed")
        # A current generation damaged after publication stops maintenance with the ordinary error, not a crash.
        main = self.root / self.active / "main.cvd"
        history.replace_private(main, b"ClamAV-VDB:\xff:1:10:90".ljust(512, b" ") + b"synthetic")
        row = self.entry(self.removable)
        with self.assertRaisesRegex(core.ScannerError, "Signature maintenance could not complete"):
            maintenance.manage(self.scanner, "delete", self.removable, row["revision"])
        self.assertTrue((self.root / self.removable).exists())

    def test_unmanaged_stage_names_are_counted_and_reported(self):
        listing = maintenance.manage(self.scanner, "list")
        self.assertEqual((listing["data"]["unrecognized_entries"], listing["warnings"]), (0, []))
        for name in ("stage-junk", "stage-" + "A" * 32, "0" * 31):
            (self.root / name).mkdir(mode=0o700)
        listing = maintenance.manage(self.scanner, "list")
        # Only the two stage-* names take an updater slot; a short hex name is neither counted nor listed.
        self.assertEqual(listing["data"]["unrecognized_entries"], 2)
        self.assertIn("count toward the generation limit", listing["warnings"][0])
        self.assertNotIn("stage-junk", [r["id"] for r in listing["data"]["entries"]])
        counted = sorted(p.name for p in self.root.iterdir() if update.counts_toward_capacity(p.name))
        self.assertEqual(counted, sorted([self.active, self.previous, self.removable, "stage-junk", "stage-" + "A" * 32]))

    def test_listing_never_exclusively_locks_the_current_generation(self):
        real, locked = maintenance.exclusive_lease, []
        def recording(path):
            locked.append(path.name)
            return real(path)
        with patch.object(maintenance, "exclusive_lease", side_effect=recording):
            row = self.entry(self.active)
        # A scan starting now takes a shared lease on the current generation; an exclusive probe would fail it.
        self.assertNotIn(self.active + ".lease", locked)
        self.assertIn(self.previous + ".lease", locked)
        self.assertEqual(row["reason"], "current")

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
            # minimum_not_before is rounded up to whole seconds; a microsecond ISO round trip of the float
            # deadline can land just below it and is then rightly refused as shortening the wait.
            with patch("pc_scanner.signature_maintenance.time.time", return_value=state["next_attempt"] + 2):
                info = self.listing()
                result = maintenance.manage(self.scanner, "recover", revision=info["recovery_revision"],
                    not_before=info["minimum_not_before"])
                self.assertEqual(result["status"], "completed")
                row = next(r for r in self.listing()["entries"] if r["kind"] == "stage")
                maintenance.manage(self.scanner, "delete", row["id"], row["revision"])
                self.assertEqual(update.update(self.scanner)["status"], "error")
                self.assertTrue(update.read_json(self.root / "attempt.json")["pending"])

    def test_second_failure_recovers_from_preserved_provider_state(self):
        row = self.entry(self.removable)
        maintenance.manage(self.scanner, "delete", self.removable, row["revision"])
        runs = []
        def engine(argv, *args, **kwargs):
            db = Path(next(a for a in argv if a.startswith("--datadir=")).split("=", 1)[1])
            runs.append(db)
            history.replace_private(db / "freshclam.dat", b"provider wait %d" % len(runs))
            return 1, "", "synthetic network failure"
        def fail():
            # Stands in for the retry interval having passed.
            update.write_json(self.root / "attempt.json", {"pending": False, "next_attempt": time.time() - 1})
            with patch("pc_scanner.signature_update.executable", side_effect=lambda x: x), patch("pc_scanner.core.run_bounded", side_effect=engine), patch("pc_scanner.signature_update.shutil.disk_usage", return_value=SimpleNamespace(free=10*update.MAX_BYTES)):
                self.assertEqual(update.update(self.scanner)["status"], "error")
        def recover():
            state = update.read_json(self.root / "attempt.json")
            with patch("pc_scanner.signature_maintenance.time.time", return_value=state["next_attempt"] + 2):
                info = self.listing()
                return maintenance.manage(self.scanner, "recover", revision=info["recovery_revision"],
                    not_before=info["minimum_not_before"])
        fail()
        self.assertEqual(recover()["status"], "completed")
        fail()  # the first failed stage was kept
        self.assertEqual(recover()["status"], "completed")
        self.assertEqual((self.root / "provider.dat").read_bytes(), b"provider wait 2")
        stages = [r for r in self.listing()["entries"] if r["kind"] == "stage"]
        self.assertEqual([r["deletable"] for r in stages], [True, True])

    def test_provider_persistence_failure_never_recovers_with_stale_canonical_state(self):
        history.replace_private(self.root / "provider.dat", b"older provider wait")
        # A previous successful sync must never serve as evidence for the next failed attempt.
        update.write_json(self.root / "provider-sync.json", {"stage": "stage-" + secrets.token_hex(16),
            "status": "synced", "provider_hash": hashlib.sha256(b"older provider wait").hexdigest()})
        update.write_json(self.root / "attempt.json", {"pending": False, "next_attempt": time.time() - 1})
        def engine(argv, *args, **kwargs):
            db = Path(next(a for a in argv if a.startswith("--datadir=")).split("=", 1)[1])
            history.replace_private(db / "freshclam.dat", b"newer provider wait")
            return 1, "", "synthetic provider failure"
        with patch("pc_scanner.signature_update.executable", side_effect=lambda x: x), patch("pc_scanner.core.run_bounded", side_effect=engine), patch("pc_scanner.signature_update.shutil.disk_usage", return_value=SimpleNamespace(free=10*update.MAX_BYTES)), patch.object(maintenance, "preserve_provider", side_effect=OSError("synthetic disk failure")):
            self.assertEqual(update.update(self.scanner)["status"], "error")
        state = update.read_json(self.root / "attempt.json")
        with patch("pc_scanner.signature_maintenance.time.time", return_value=state["next_attempt"] + 2):
            info = self.listing()
            with patch.object(maintenance, "preserve_provider", side_effect=OSError("disk still unavailable")):
                with self.assertRaises(core.ScannerError):
                    maintenance.manage(self.scanner, "recover", revision=info["recovery_revision"], not_before=info["minimum_not_before"])
            self.assertTrue(update.read_json(self.root / "attempt.json")["pending"])
            self.assertEqual((self.root / "provider.dat").read_bytes(), b"older provider wait")
            info = self.listing()
            recovered = maintenance.manage(self.scanner, "recover", revision=info["recovery_revision"], not_before=info["minimum_not_before"])
            self.assertEqual(recovered["status"], "completed")
        self.assertEqual((self.root / "provider.dat").read_bytes(), b"newer provider wait")
        self.assertFalse(update.read_json(self.root / "attempt.json")["pending"])

    def test_provider_replace_then_durability_failure_keeps_recovery_blocked_until_retry(self):
        history.replace_private(self.root / "provider.dat", b"old wait")
        update.write_json(self.root / "attempt.json", {"pending": False, "next_attempt": time.time()-1})
        def engine(argv, *args, **kwargs):
            db = Path(next(a for a in argv if a.startswith("--datadir=")).split("=",1)[1])
            history.replace_private(db / "freshclam.dat", b"new wait")
            return 1, "", "synthetic error"
        real = history.replace_private
        def broken(path, data):
            real(path, data)
            if path == self.root / "provider.dat":
                raise OSError("synthetic durability failure after replacement")
        with patch("pc_scanner.signature_update.executable", side_effect=lambda x:x), patch("pc_scanner.core.run_bounded", side_effect=engine), patch("pc_scanner.signature_update.shutil.disk_usage", return_value=SimpleNamespace(free=10*update.MAX_BYTES)), patch.object(history, "replace_private", side_effect=broken):
            self.assertEqual(update.update(self.scanner)["status"], "error")
        self.assertEqual((self.root / "provider.dat").read_bytes(), b"new wait")
        self.assertEqual(maintenance.provider_sync(self.root)["status"], "pending")
        state = update.read_json(self.root / "attempt.json")
        with patch("pc_scanner.signature_maintenance.time.time", return_value=state["next_attempt"]+2):
            info = self.listing()
            with patch.object(history, "replace_private", side_effect=broken), self.assertRaises(core.ScannerError):
                maintenance.manage(self.scanner,"recover",revision=info["recovery_revision"],not_before=info["minimum_not_before"])
            self.assertTrue(update.read_json(self.root / "attempt.json")["pending"])
            info = self.listing()
            self.assertEqual(maintenance.manage(self.scanner,"recover",revision=info["recovery_revision"],not_before=info["minimum_not_before"])["status"],"completed")

    def test_pending_sync_missing_source_and_synced_hash_mismatch_refuse_recovery(self):
        stage = self.stage()
        history.replace_private(self.root / "provider.dat", b"old canonical")
        update.write_json(self.root / "attempt.json", {"pending":True,"next_attempt":time.time()-5})
        maintenance.begin_provider_sync(self.root,stage)
        (self.root / stage / "db/freshclam.dat").unlink()
        info = self.listing()
        with self.assertRaises(core.ScannerError):
            maintenance.manage(self.scanner,"recover",revision=info["recovery_revision"],not_before=info["minimum_not_before"])
        self.assertTrue(update.read_json(self.root / "attempt.json")["pending"])
        history.replace_private(self.root / stage / "db/freshclam.dat",b"new canonical")
        maintenance.finish_provider_sync(self.root,stage)
        history.replace_private(self.root / "provider.dat",b"corrupt or stale canonical")
        info = self.listing()
        with self.assertRaises(core.ScannerError):
            maintenance.manage(self.scanner,"recover",revision=info["recovery_revision"],not_before=info["minimum_not_before"])
        self.assertTrue(update.read_json(self.root / "attempt.json")["pending"])

    def test_legacy_canonical_alone_is_not_proof_but_single_stage_can_be_resaved(self):
        history.replace_private(self.root / "provider.dat", b"legacy old wait")
        update.write_json(self.root / "attempt.json", {"pending":True,"next_attempt":time.time()-5})
        info = self.listing()
        with self.assertRaises(core.ScannerError):
            maintenance.manage(self.scanner,"recover",revision=info["recovery_revision"],not_before=info["minimum_not_before"])
        stage=self.stage()
        expected=(self.root/stage/"db/freshclam.dat").read_bytes()
        info=self.listing()
        self.assertEqual(maintenance.manage(self.scanner,"recover",revision=info["recovery_revision"],not_before=info["minimum_not_before"])["status"],"completed")
        self.assertEqual((self.root/"provider.dat").read_bytes(),expected)

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
