"""Owner maintenance contracts using synthetic stores only; never contact providers."""
import copy
import errno
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
from contextlib import contextmanager
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
        update.write_json(self.root / "current.json", dict(self.record(self.active), schema=2,
                          previous=[self.record(self.previous), self.record(self.removable)], legacy_untracked=[]))
        update.write_json(self.root / "attempt.json", {"pending": False, "next_attempt": time.time() + 86400})

    def record(self, name):
        return dict(generation=name, **update.digest_directory(self.root / name, time.monotonic() + 30))

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

    def cleanup(self, name):
        row = next(r for r in self.listing()["cleanup"] if r["id"] == name)
        return maintenance.manage(self.scanner, "cleanup", name, row["revision"])

    def test_inventory_current_and_selected_delete_preserve_wait_and_pointer(self):
        info = self.listing()
        self.assertTrue(next(r for r in info["entries"] if r["id"] == self.active)["current"])
        reference = update.pointer(self.root)
        wait = (self.root / "attempt.json").read_bytes()
        entry = self.entry(self.removable)
        result = maintenance.manage(self.scanner, "delete", self.removable, entry["revision"])
        self.assertEqual(result["status"], "completed")
        self.assertFalse((self.root / self.removable).exists())
        self.assertFalse((self.root / (self.removable + ".lease")).exists())  # never accumulates toward the limit
        self.assertEqual((self.root / "attempt.json").read_bytes(), wait)
        self.assertEqual(update.pointer(self.root), dict(reference, previous=reference["previous"][:1]))
        self.assertEqual(self.entry(self.previous)["reason"], "last_previous")
        row = self.entry(self.previous)
        with self.assertRaises(core.ScannerError):
            maintenance.manage(self.scanner, "delete", self.previous, row["revision"])

    def test_parent_sync_failure_reports_deleted_generation_and_unconfirmed_sync(self):
        target = self.root / self.removable
        lease = self.root / (self.removable + ".lease")
        with update.generation_lease(lease):
            pass
        entry = self.entry(self.removable)
        reference = (self.root / "current.json").read_bytes()
        wait = (self.root / "attempt.json").read_bytes()
        sync = update.sync_dir

        def fail_after_rmdir(folder):
            if folder == self.root and not target.exists():
                raise OSError(errno.EIO, "synthetic parent sync failure")
            sync(folder)

        with patch.object(update, "sync_dir", side_effect=fail_after_rmdir):
            result = maintenance.manage(self.scanner, "delete", self.removable, entry["revision"])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["data"], {"deleted": self.removable, "update_performed": False,
                                          "directory_synced": False, "lease_removed": True,
                                          "history_updated": False})
        self.assertFalse(target.exists())
        self.assertFalse(lease.exists())
        self.assertEqual((self.root / "current.json").read_bytes(), reference)
        self.assertEqual((self.root / "attempt.json").read_bytes(), wait)
        self.assertEqual(self.entry(self.previous)["reason"], "last_previous")
        self.assertEqual(self.listing()["cleanup"][0]["pending"], ["directory_sync", "history_update"])
        report = self.cleanup(self.removable)
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["data"], {"deleted": self.removable, "update_performed": False,
                                         "directory_synced": True, "lease_removed": True, "history_updated": True})
        self.assertEqual(self.listing()["cleanup"], [])
        self.assertEqual((self.root / "attempt.json").read_bytes(), wait)

    def test_lease_unlink_failure_reports_deleted_generation_and_preserves_history(self):
        target = self.root / self.removable
        lease = self.root / (self.removable + ".lease")
        with update.generation_lease(lease):
            pass
        entry = self.entry(self.removable)
        reference = (self.root / "current.json").read_bytes()
        wait = (self.root / "attempt.json").read_bytes()
        unlink = Path.unlink

        def fail_lease_only(path, *args, **kwargs):
            if path == lease:
                raise OSError(errno.EIO, "synthetic lease unlink failure")
            return unlink(path, *args, **kwargs)

        with patch.object(Path, "unlink", fail_lease_only):
            result = maintenance.manage(self.scanner, "delete", self.removable, entry["revision"])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["data"], {"deleted": self.removable, "update_performed": False,
                                          "directory_synced": True, "lease_removed": False,
                                          "history_updated": False})
        self.assertTrue(any("lease file removal" in warning for warning in result["warnings"]))
        self.assertFalse(target.exists())
        with maintenance.exclusive_lease(lease) as leased:
            self.assertTrue(leased)
        self.assertEqual((self.root / "current.json").read_bytes(), reference)
        self.assertEqual((self.root / "attempt.json").read_bytes(), wait)
        self.assertEqual(self.entry(self.previous)["reason"], "last_previous")
        self.assertEqual(self.listing()["cleanup"][0]["pending"], ["lease_removal", "directory_sync", "history_update"])
        with patch.object(Path, "unlink", fail_lease_only):
            self.assertEqual(self.cleanup(self.removable)["status"], "partial")
        self.assertEqual(self.cleanup(self.removable)["status"], "completed")
        self.assertFalse(lease.exists())
        self.assertEqual(self.listing()["cleanup"], [])

    def test_cleanup_removes_only_the_selected_legacy_leftover_and_preserves_wait_and_scans(self):
        # Simulate the older CLI, which left no deletion record.
        second = self.generation()
        reference = update.pointer(self.root)
        reference["previous"].append(self.record(second))
        update.write_json(self.root / "current.json", reference)
        for name in (self.removable, second):
            shutil.rmtree(self.root / name)
            with update.generation_lease(self.root / (name + ".lease")):
                pass
        stage = self.stage()
        maintenance.begin_provider_sync(self.root, stage)
        maintenance.finish_provider_sync(self.root, stage)
        update.write_json(self.root / "attempt.json", {"pending": True, "next_attempt": time.time() + 172800})
        protected = ("attempt.json", "provider.dat", "provider-sync.json", stage + "/db/freshclam.dat")
        before = {name: (self.root / name).read_bytes() for name in protected}
        candidates = {row["id"]: row["revision"] for row in self.listing()["cleanup"]}
        self.assertEqual(set(candidates), {self.removable, second})
        verify = update.verify

        def start_scan_then_verify(*args):
            # pin also verifies the active definitions.
            with patch.object(update, "verify", verify):
                with update.pin(self.scanner) as pinned:
                    self.assertEqual(pinned.local["clamav_database_directory"], str(self.root / self.active))
            return verify(*args)

        with patch.object(update, "verify", side_effect=start_scan_then_verify):
            self.assertEqual(self.cleanup(self.removable)["status"], "completed")
        self.assertTrue((self.root / (second + ".lease")).exists())
        self.assertEqual(self.entry(self.previous)["reason"], "last_previous")
        with self.assertRaisesRegex(core.ScannerError, "unavailable or changed"):
            maintenance.manage(self.scanner, "cleanup", second, candidates[second])
        self.assertEqual(self.cleanup(second)["status"], "completed")
        self.assertEqual(self.listing()["cleanup"], [])
        self.assertEqual(update.pointer(self.root)["previous"], reference["previous"][:1])
        self.assertEqual({name: (self.root / name).read_bytes() for name in protected}, before)

    def test_cleanup_recovers_an_unrecorded_generation_after_directory_sync_failure(self):
        name = self.generation()
        original = update.sync_dir

        def fail_after_delete(path):
            if path == self.root and not (self.root / name).exists():
                raise OSError("synthetic sync failure")
            original(path)

        reference = update.pointer(self.root)
        with patch.object(update, "sync_dir", side_effect=fail_after_delete):
            report = maintenance.manage(self.scanner, "delete", name, self.entry(name)["revision"])
        self.assertIsNone(report["data"]["history_updated"])
        self.assertEqual(self.listing()["cleanup"][0]["pending"], ["directory_sync"])
        self.assertEqual(self.cleanup(name)["data"]["history_updated"], None)
        self.assertEqual(update.pointer(self.root), reference)
        self.assertEqual(self.listing()["cleanup"], [])

    def test_cleanup_retries_history_write_and_readback_after_a_corrupt_newer_generation(self):
        # This damaged generation appeared before the protected predecessor and its absence holds deletion
        # until we can match the durable deletion record to this reference.
        reference = update.pointer(self.root)
        reference["previous"].reverse()
        update.write_json(self.root / "current.json", reference)
        (self.root / self.removable / "main.cvd").write_bytes(b"corrupt synthetic data")
        original_write, original_read = update.write_json, update.pointer

        def fail_history_write(path, obj):
            if path == self.root / "current.json":
                raise OSError("synthetic history write failure")
            original_write(path, obj)

        with patch.object(update, "write_json", side_effect=fail_history_write):
            report = maintenance.manage(self.scanner, "delete", self.removable, self.entry(self.removable)["revision"])
            self.assertFalse(report["data"]["history_updated"])
            self.assertFalse(self.cleanup(self.removable)["data"]["history_updated"])
        self.assertEqual(self.listing()["previous_protection"]["status"], "previous_unavailable")
        self.assertEqual(original_read(self.root), reference)
        with patch.object(update, "pointer", side_effect=OSError("synthetic readback failure")):
            self.assertFalse(self.cleanup(self.removable)["data"]["history_updated"])
        self.assertEqual(original_read(self.root)["previous"], reference["previous"][1:])
        self.assertTrue(self.cleanup(self.removable)["data"]["history_updated"])
        self.assertEqual(self.entry(self.previous)["reason"], "last_previous")
        self.assertEqual(self.listing()["cleanup"], [])

    def test_older_leftover_ahead_of_the_protected_predecessor_waits_for_the_next_publication(self):
        # 0.11.4 and earlier left no deletion record. Without one, a missing entry ahead of the protected
        # predecessor stays unproven until a publication records an intact predecessor before it.
        reference = update.pointer(self.root)
        reference["previous"].reverse()
        update.write_json(self.root / "current.json", reference)
        (self.root / self.removable / "main.cvd").write_bytes(b"corrupt synthetic data")
        self.assertIsNone(self.entry(self.removable)["reason"])
        shutil.rmtree(self.root / self.removable)
        lease = self.root / (self.removable + ".lease")
        with update.generation_lease(lease):
            pass
        info = self.listing()
        self.assertEqual(info["previous_protection"]["status"], "previous_unavailable")
        self.assertEqual(info["cleanup"], [])
        self.assertEqual(self.entry(self.previous)["reason"], "previous_unavailable")
        with self.assertRaisesRegex(core.ScannerError, "unavailable or changed"):
            maintenance.manage(self.scanner, "cleanup", self.removable, "0" * 64)
        self.assertTrue(lease.is_file())
        self.assertEqual(update.pointer(self.root), reference)

        newer = self.generation()
        update.write_json(self.root / "current.json", dict(self.record(newer), schema=2, legacy_untracked=[],
                          previous=[{k: reference[k] for k in update.RECORD_KEYS}, *reference["previous"]]))
        row, = self.listing()["cleanup"]
        self.assertEqual(row["id"], self.removable)
        self.assertEqual(row["pending"], ["lease_removal", "directory_sync", "history_update"])
        self.assertEqual(self.cleanup(self.removable)["status"], "completed")
        self.assertFalse(lease.exists())
        self.assertEqual([r["generation"] for r in update.pointer(self.root)["previous"]], [self.active, self.previous])
        self.assertEqual(self.listing()["cleanup"], [])

    def test_cleanup_keeps_protected_and_unproven_generations_and_rejects_non_owner_entrypoint(self):
        unknown = "f" * 32
        for name in (self.active, self.previous, unknown):
            with update.generation_lease(self.root / (name + ".lease")):
                pass
            with self.assertRaisesRegex(core.ScannerError, "unavailable or changed"):
                maintenance.manage(self.scanner, "cleanup", name, "0" * 64)
        shutil.rmtree(self.root / self.previous)
        self.assertEqual(self.listing()["cleanup"], [])
        for name in (self.active, self.previous, unknown):
            self.assertTrue((self.root / (name + ".lease")).is_file())
        self.scanner.via = "mcp"
        with self.assertRaisesRegex(core.ScannerError, "owner CLI"):
            maintenance.manage(self.scanner, "cleanup", self.removable, "0" * 64)

    def test_cleanup_rejects_busy_unsafe_or_reappeared_target(self):
        target = self.root / self.removable
        shutil.rmtree(target)
        lease = self.root / (self.removable + ".lease")
        with update.generation_lease(lease):
            result = self.cleanup(self.removable)
            self.assertEqual(result["status"], "partial")
            self.assertTrue(lease.is_file())

        row = self.listing()["cleanup"][0]
        original = update.pointer(self.root)
        target.mkdir(mode=0o700)
        with self.assertRaisesRegex(core.ScannerError, "unavailable or changed"):
            maintenance.manage(self.scanner, "cleanup", self.removable, row["revision"])
        target.rmdir()
        sidecar = update.verification_file(target)
        history.replace_private(sidecar, b"synthetic evidence")
        self.assertEqual(self.listing()["cleanup"], [])
        sidecar.unlink()
        hardlink = self.root / "other"
        os.link(lease, hardlink)
        self.assertEqual(self.listing()["cleanup"], [])
        hardlink.unlink()
        lease.chmod(0o644)
        self.assertEqual(self.listing()["cleanup"], [])
        lease.unlink()
        lease.symlink_to(self.root / "current.json")
        self.assertEqual(self.listing()["cleanup"], [])
        self.assertTrue(lease.is_symlink())
        self.assertEqual(update.pointer(self.root), original)

    def test_cleanup_rejects_other_owner_and_acl_on_the_lease(self):
        from pc_scanner import process_store

        shutil.rmtree(self.root / self.removable)
        lease = self.root / (self.removable + ".lease")
        with update.generation_lease(lease):
            pass
        inode = lease.stat().st_ino
        fstat = os.fstat

        def foreign_owner(fd):
            info = fstat(fd)
            if info.st_ino == inode:
                values = list(info)
                values[4] = os.geteuid() + 1
                return os.stat_result(values)
            return info

        self.assertEqual(self.listing()["cleanup"][0]["id"], self.removable)
        with patch.object(os, "fstat", side_effect=foreign_owner):
            self.assertEqual(self.listing()["cleanup"], [])
        acl_allows = process_store.acl_allows
        with patch.object(process_store, "acl_allows", side_effect=lambda fd: fstat(fd).st_ino == inode or acl_allows(fd)):
            self.assertEqual(self.listing()["cleanup"], [])
        self.assertTrue(lease.is_file())

    def test_delete_keeps_the_generation_when_the_cleanup_record_cannot_be_synced(self):
        entry = self.entry(self.removable)
        with patch.object(update, "sync_dir", side_effect=OSError("synthetic journal sync failure")):
            with self.assertRaisesRegex(core.ScannerError, "maintenance could not complete"):
                maintenance.manage(self.scanner, "delete", self.removable, entry["revision"])
        self.assertTrue((self.root / self.removable).is_dir())
        self.assertEqual(self.listing()["cleanup"], [])
        self.assertEqual(maintenance.manage(self.scanner, "delete", self.removable, entry["revision"])["status"], "completed")

    def test_real_cli_lists_and_retries_a_selected_cleanup(self):
        shutil.rmtree(self.root / self.removable)
        config = self.base / "scanner.toml"
        config.write_text("[clamav_updates]\nenabled=true\ndirectory=" + json.dumps(str(self.root)) +
                          "\nfreshclam_binary=" + json.dumps(sys.executable) + "\nsigtool_binary=" + json.dumps(sys.executable))

        def cli(*args):
            return subprocess.run([sys.executable, "-m", "pc_scanner.cli", "--config", str(config),
                                   "clamav-signature-store", *args], capture_output=True, text=True, timeout=15)

        listing = cli("list")
        self.assertEqual(listing.returncode, 0, listing.stderr)
        row, = json.loads(listing.stdout)["data"]["cleanup"]
        self.assertEqual(row["id"], self.removable)
        invalid = cli("cleanup", str(self.root / self.removable), "--revision", row["revision"])
        self.assertEqual(invalid.returncode, 2)
        retried = cli("cleanup", row["id"], "--revision", row["revision"])
        self.assertEqual(retried.returncode, 0, retried.stdout + retried.stderr)
        self.assertTrue(json.loads(retried.stdout)["data"]["history_updated"])
        self.assertEqual(json.loads(cli("list").stdout)["data"]["cleanup"], [])

    def test_generation_rmdir_failure_does_not_report_it_as_deleted(self):
        target = self.root / self.removable
        lease = self.root / (self.removable + ".lease")
        with update.generation_lease(lease):
            pass
        entry = self.entry(self.removable)
        reference = update.pointer(self.root)
        rmdir = Path.rmdir

        def fail_rmdir(path):
            if path == target:
                raise OSError(errno.EIO, "synthetic generation rmdir failure")
            return rmdir(path)

        with patch.object(Path, "rmdir", fail_rmdir):
            with self.assertRaisesRegex(core.ScannerError, "maintenance could not complete"):
                maintenance.manage(self.scanner, "delete", self.removable, entry["revision"])
        self.assertTrue(target.is_dir())
        self.assertTrue(lease.is_file())
        self.assertEqual(update.pointer(self.root), reference)

    def test_history_sync_failure_reports_unconfirmed_even_if_reference_has_changed(self):
        entry = self.entry(self.removable)
        reference = update.pointer(self.root)
        revised = dict(reference, previous=reference["previous"][:1])
        sync = update.sync_dir

        def fail_history_sync(folder):
            if folder == self.root and update.pointer(self.root) == revised:
                raise OSError(errno.EIO, "synthetic publication sync failure after replacing the pointer")
            sync(folder)

        with patch.object(update, "sync_dir", side_effect=fail_history_sync):
            result = maintenance.manage(self.scanner, "delete", self.removable, entry["revision"])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["data"], {"deleted": self.removable, "update_performed": False,
                                          "directory_synced": True, "lease_removed": True,
                                          "history_updated": False})
        self.assertFalse((self.root / self.removable).exists())
        self.assertEqual(update.pointer(self.root), revised)
        self.assertIn("could not be confirmed", result["warnings"][0])
        report = self.cleanup(self.removable)
        self.assertTrue(report["data"]["history_updated"])
        self.assertEqual(self.listing()["cleanup"], [])

    def test_stage_parent_sync_failure_reports_the_deleted_stage(self):
        stage = self.stage()
        row = self.entry(stage)
        reference = (self.root / "current.json").read_bytes()
        wait = (self.root / "attempt.json").read_bytes()
        sync = update.sync_dir

        def fail_after_rmdir(folder):
            if folder == self.root and not (self.root / stage).exists():
                raise OSError(errno.EIO, "synthetic parent sync failure")
            sync(folder)

        with patch.object(update, "sync_dir", side_effect=fail_after_rmdir):
            result = maintenance.manage(self.scanner, "delete", stage, row["revision"])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["data"], {"deleted": stage, "update_performed": False, "directory_synced": False})
        self.assertIn("parent directory sync", result["warnings"][0])
        self.assertFalse((self.root / stage).exists())
        self.assertEqual((self.root / "current.json").read_bytes(), reference)
        self.assertEqual((self.root / "attempt.json").read_bytes(), wait)

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
        def newer_than_current(folder):
            # Left by a crash after the rename but before current.json: never published, so it cannot be a rollback.
            folder.mkdir(mode=0o700)
            for db in update.DATABASES:
                history.replace_private(folder / db, b"ClamAV-VDB:date:2:10:90:hash:sig".ljust(512, b" ") + b"synthetic")
        for label, make, listed in (("linked", linked, "unavailable"), ("finder_file", finder_file, "unavailable"),
                                    ("malformed", malformed, None), ("non_ascii_header", non_ascii_header, None),
                                    ("duplicate_of_current", duplicate_of_current, None),
                                    ("newer_than_current", newer_than_current, None)):
            with self.subTest(label):
                folder = self.root / secrets.token_hex(16)
                make(folder)
                self.assertTrue(all((folder / database).is_file() for database in update.DATABASES))
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

    def test_published_order_and_full_hash_choose_verified_predecessor(self):
        orphan = self.generation()
        record = self.record(orphan)
        update.write_json(update.verification_file(self.root / orphan),
                          dict(schema=1, content=record["content"], versions=record["versions"],
                               detached_signatures=dict.fromkeys(update.DATABASES, "verified")))
        self.assertEqual(self.entry(self.previous)["reason"], "last_previous")
        self.assertTrue(self.entry(orphan)["deletable"])
        self.assertTrue(self.entry(self.removable)["deletable"])
        main = self.root / self.previous / "main.cvd"
        history.replace_private(main, main.read_bytes()[:512] + b"body damage")
        listing = self.listing()["previous_protection"]
        self.assertEqual(listing["generation"], self.removable)
        self.assertEqual([r["status"] for r in listing["checks"]], ["invalid", "last_previous"])
        row = self.entry(self.previous)
        self.assertTrue(row["deletable"])
        self.assertEqual(maintenance.manage(self.scanner, "delete", self.previous, row["revision"])["status"], "completed")
        self.assertFalse(main.exists())
        self.assertTrue((self.root / orphan).is_dir())
        self.assertEqual(self.entry(self.removable)["reason"], "last_previous")

    def test_no_valid_published_predecessor_holds_orphan_deletion(self):
        orphan = self.generation()
        for generation in (self.previous, self.removable):
            history.replace_private(self.root / generation / "main.cvd", b"invalid database")
        row = self.entry(orphan)
        self.assertEqual((row["deletable"], row["reason"]), (False, "no_valid_previous"))
        with self.assertRaisesRegex(core.ScannerError, "no_valid_previous"):
            maintenance.manage(self.scanner, "delete", orphan, row["revision"])
        self.assertTrue((self.root / orphan).is_dir())

    def test_duplicate_current_content_and_mismatched_recorded_version_do_not_count(self):
        duplicate = secrets.token_hex(16)
        shutil.copytree(self.root / self.active, self.root / duplicate)
        wrong_version = self.record(self.previous)
        wrong_version["versions"]["daily.cvd"] += 1
        reference = update.pointer(self.root)
        update.write_json(self.root / "current.json", dict(reference, previous=[
            self.record(duplicate), wrong_version, self.record(self.removable)]))
        result = self.listing()["previous_protection"]
        self.assertEqual(result["generation"], self.removable)
        self.assertEqual([check["status"] for check in result["checks"]], ["duplicate", "invalid", "last_previous"])

    def test_earlier_reference_format_keeps_one_rollback_and_lets_a_full_store_free_a_slot(self):
        # Before the first publication with history, the earlier release's rule applies, so a store that was
        # already full when upgraded can still free a slot and migrate. The reference keeps its earlier format.
        reference = self.root / "current.json"
        active = self.record(self.active)
        update.write_json(reference, active)
        self.assertEqual(update.current(self.root, time.monotonic() + 30), active)
        raw = reference.read_bytes()
        result = self.listing()["previous_protection"]
        self.assertEqual((result["status"], result["generation"]), ("legacy_history", None))
        for name in (self.previous, self.removable):
            self.assertEqual((self.entry(name)["reason"], self.entry(name)["deletable"]), (None, True))
        row = self.entry(self.removable)
        self.assertEqual(maintenance.manage(self.scanner, "delete", self.removable, row["revision"])["status"], "completed")
        self.assertFalse((self.root / self.removable).exists())
        self.assertEqual(reference.read_bytes(), raw)
        # The only remaining rollback is kept. Folders that cannot be one stay deletable beside it.
        broken, newer, duplicate = self.generation(), self.generation(), secrets.token_hex(16)
        history.replace_private(self.root / broken / "main.cvd", b"invalid database")
        for db in update.DATABASES:
            history.replace_private(self.root / newer / db, b"ClamAV-VDB:date:2:10:90:hash:sig".ljust(512, b" ") + newer.encode())
        shutil.copytree(self.root / self.active, self.root / duplicate)
        result = self.listing()["previous_protection"]
        self.assertEqual(result["generation"], self.previous)
        self.assertEqual(sorted(c["status"] for c in result["checks"]), ["invalid", "invalid", "invalid", "last_previous"])
        for name in (broken, newer, duplicate):
            self.assertTrue(self.entry(name)["deletable"], name)
        with self.assertRaisesRegex(core.ScannerError, "last_previous"):
            maintenance.manage(self.scanner, "delete", self.previous, self.entry(self.previous)["revision"])
        # A folder that cannot be read completely holds every generation deletion.
        os.chmod(self.root / broken, 0o755)
        try:
            self.assertEqual(self.listing()["previous_protection"]["status"], "previous_unavailable")
            row = self.entry(newer)
            self.assertEqual((row["reason"], row["deletable"]), ("previous_unavailable", False))
        finally:
            os.chmod(self.root / broken, 0o700)
        self.assertEqual(reference.read_bytes(), raw)

    def test_unrecorded_earlier_generations_are_released_once_a_recorded_predecessor_is_protected(self):
        # Migration marks pre-history generations legacy_untracked. They predate the recorded predecessor or were never
        # published, so once that predecessor is verified they guard nothing and can be deleted, leaving the history.
        older, orphan = self.generation(), self.generation()
        reference = update.pointer(self.root)
        update.write_json(self.root / "current.json", dict(reference, legacy_untracked=sorted([older, orphan])))
        self.assertEqual(self.entry(self.previous)["reason"], "last_previous")
        row = self.entry(older)
        self.assertEqual((row["reason"], row["deletable"]), (None, True))
        self.assertEqual(maintenance.manage(self.scanner, "delete", older, row["revision"])["status"], "completed")
        after = update.pointer(self.root)
        self.assertEqual((after["legacy_untracked"], after["previous"]), ([orphan], reference["previous"]))
        # Without an intact recorded predecessor they stay held.
        for generation in (self.previous, self.removable):
            history.replace_private(self.root / generation / "main.cvd", b"invalid database")
        row = self.entry(orphan)
        self.assertEqual((row["reason"], row["deletable"]), ("legacy_untracked", False))
        with self.assertRaisesRegex(core.ScannerError, "legacy_untracked"):
            maintenance.manage(self.scanner, "delete", orphan, row["revision"])
        self.assertTrue((self.root / orphan).is_dir())

    def test_corrupt_publication_history_holds_deletion(self):
        reference = self.root / "current.json"
        active = self.record(self.active)
        for raw in (b"{", json.dumps(active).replace('"generation":', '"generation": null, "generation":').encode(),
                    json.dumps(dict(active, schema=2, previous=[active], legacy_untracked=[])).encode(),
                    json.dumps(dict(active, schema=2, previous=[], legacy_untracked=[self.active])).encode(),
                    json.dumps(dict(active, schema=2, previous=[], legacy_untracked=[None])).encode(),
                    json.dumps(dict(active, schema=True, previous=[], legacy_untracked=[])).encode(),
                    json.dumps(dict(active, schema=2, previous=[dict(self.record(self.previous), content="x")],
                                    legacy_untracked=[])).encode()):
            with self.subTest(raw=raw):
                history.replace_private(reference, raw)
                row = self.entry(self.removable)
                self.assertEqual(row["reason"], "history_unavailable")
                with self.assertRaisesRegex(core.ScannerError, "publication history unavailable"):
                    maintenance.manage(self.scanner, "delete", self.removable, row["revision"])
                self.assertEqual(reference.read_bytes(), raw)
        reference.unlink()
        self.assertEqual(self.entry(self.removable)["reason"], "missing_history")
        self.assertTrue((self.root / self.removable).is_dir())

    def test_newer_published_read_failure_does_not_fall_back(self):
        reference = (self.root / "current.json").read_bytes()
        attempt = (self.root / "attempt.json").read_bytes()
        orphan = self.generation()
        revision = self.entry(orphan)["revision"]
        digest = update.digest_directory
        for problem in (OSError(errno.EIO, "synthetic read failure"),
                        core.ScannerError("Signature operation timed out")):
            def interrupted(folder, *args):
                if folder.name == self.previous:
                    raise problem
                return digest(folder, *args)
            with self.subTest(problem=problem), patch.object(update, "digest_directory", side_effect=interrupted):
                listing = self.listing()
                self.assertEqual(listing["previous_protection"], {"status": "previous_unavailable", "generation": None,
                                 "checks": [{"id": self.previous, "status": "unavailable"}]})
                row = self.entry(orphan)
                self.assertNotEqual(row["revision"], revision)
                self.assertEqual((row["deletable"], row["reason"]), (False, "previous_unavailable"))
                with self.assertRaises(core.ScannerError):
                    maintenance.manage(self.scanner, "delete", orphan, row["revision"])
                self.assertTrue((self.root / orphan).is_dir())
                self.assertEqual((self.root / "current.json").read_bytes(), reference)
                self.assertEqual((self.root / "attempt.json").read_bytes(), attempt)
                self.assertFalse((self.root / (orphan + ".lease")).exists())

    def test_replaced_predecessor_after_selected_lease_leaves_target_and_sidecar(self):
        target = self.root / self.removable
        sidecar = update.verification_file(target)
        update.write_json(sidecar, {"schema": 1})
        revision = self.entry(self.removable)["revision"]
        lease = self.root / (self.removable + ".lease")
        with update.generation_lease(lease):
            pass
        exclusive = maintenance.exclusive_lease
        calls = 0

        @contextmanager
        def replace_predecessor(path):
            nonlocal calls
            with exclusive(path) as leased:
                if path == lease:
                    calls += 1
                    if calls == 2:  # after inventory, before the selected entry can be removed
                        file = self.root / self.previous / "main.cvd"
                        history.replace_private(file, file.read_bytes())
                yield leased

        with patch.object(maintenance, "exclusive_lease", side_effect=replace_predecessor):
            with self.assertRaisesRegex(core.ScannerError, "maintenance could not complete"):
                maintenance.manage(self.scanner, "delete", self.removable, revision)
        self.assertTrue(sidecar.is_file())
        self.assertTrue(lease.is_file())
        self.assertTrue(target.is_dir())

    def test_transient_short_read_of_published_header_holds_deletion(self):
        orphan = self.generation()
        identity = (self.root / self.previous / "main.cvd").stat()
        read = os.read

        def short_read(fd, size):
            info = os.fstat(fd)
            if size == 512 and (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
                return read(fd, 511)
            return read(fd, size)

        with patch.object(os, "read", side_effect=short_read):
            row = self.entry(orphan)
            self.assertEqual(row["reason"], "previous_unavailable")
            with self.assertRaises(core.ScannerError):
                maintenance.manage(self.scanner, "delete", orphan, row["revision"])
        self.assertTrue((self.root / orphan).is_dir())

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

    def test_generation_evidence_is_in_revision_bytes_and_selected_deletion(self):
        entry = self.entry(self.removable)
        folder = self.root / self.removable
        manifest = update.digest_directory(folder, time.monotonic() + 30)
        sidecar = self.root / (self.removable + ".verification.json")
        record = dict(schema=1, **manifest, detached_signatures=dict.fromkeys(update.DATABASES, "verified"))
        update.write_json(sidecar, record)
        newer = self.entry(self.removable)
        self.assertNotEqual(entry["revision"], newer["revision"])
        self.assertEqual(newer["bytes"], entry["bytes"] + sidecar.stat().st_size)
        with self.assertRaises(core.ScannerError):
            maintenance.manage(self.scanner, "delete", self.removable, entry["revision"])
        self.assertTrue(sidecar.exists())
        self.assertEqual(maintenance.manage(self.scanner, "delete", self.removable, newer["revision"])["status"], "completed")
        self.assertFalse(sidecar.exists())
        self.assertFalse(folder.exists())

    def test_failed_stage_evidence_can_be_selected_after_recovery(self):
        stage = self.stage()
        update.write_json(self.root / stage / "verification.json", {"schema": 1})
        row = self.entry(stage)
        self.assertTrue(row["deletable"], row)
        self.assertEqual(maintenance.manage(self.scanner, "delete", stage, row["revision"])["status"], "completed")

    def test_a_temporary_file_left_by_a_killed_write_keeps_its_stage_recoverable_and_deletable(self):
        # history.replace_private writes .<name>.<8 hex>.tmp and renames it; a kill or power loss in between leaves it.
        # Otherwise the stage would be unavailable, recovery refused and every update blocked until manual removal.
        for name in ("verification.json", "validation.txt", "freshclam.conf", "db/freshclam.dat"):
            with self.subTest(name=name):
                stage = self.stage()
                file = self.root / stage / name
                leftover = file.with_name(f".{file.name}.{secrets.token_hex(4)}.tmp")
                fd = os.open(leftover, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.write(fd, b"partial")
                os.close(fd)
                past = time.time() - 60
                update.write_json(self.root / "attempt.json", {"pending": True, "next_attempt": past})
                info = self.listing()
                self.assertEqual(self.entry(stage)["reason"], "pending_recovery")
                stamp = datetime.fromtimestamp(past + 1, timezone.utc).isoformat()
                result = maintenance.manage(self.scanner, "recover", revision=info["recovery_revision"], not_before=stamp)
                self.assertEqual(result["status"], "completed", result)
                row = self.entry(stage)
                self.assertEqual(maintenance.manage(self.scanner, "delete", stage, row["revision"])["status"], "completed")
                self.assertFalse((self.root / stage).exists())
        # Only those names: anything else, or a link under such a name, still stops maintenance for owner review.
        for name in (".verification.json.zz.tmp", ".verification.json.0123abcd.tmp.extra", ".other.json.0123abcd.tmp", "link"):
            with self.subTest(other=name):
                stage = self.stage()
                if name == "link":
                    (self.root / stage / ".validation.txt.0123abcd.tmp").symlink_to(self.root / stage / "db")
                else:
                    history.replace_private(self.root / stage / name, b"unknown")
                self.assertEqual(self.entry(stage)["reason"], "unavailable")

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
        def broken(path, data, **kwargs):
            real(path, data, **kwargs)
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
