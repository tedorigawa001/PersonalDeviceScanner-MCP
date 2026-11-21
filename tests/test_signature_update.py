"""Private updater transactions with synthetic CVDs; no downloads or personal files."""
import copy
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from datetime import datetime, timezone

from pc_scanner import core, history, process_store, signature_maintenance as maintenance, signature_update as update
from pc_scanner import signature_first_publication as first


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
                # The official distribution serves a detached signature named for each database version.
                (db / f"{name.removesuffix('.cvd')}-{self.version}.cvd.sign").write_bytes(b"synthetic detached signature")
            return 0, "", ""
        if any(a.startswith("--info=") for a in argv):
            return 0, "Digital signature: synthetic\nVerification OK.\n", ""
        if "--verify" in argv:
            return 0, "verify: Successfully verified file with signature, signed by 'synthetic'\n", ""
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
        self.assertEqual((old["schema"], old["previous"], old["legacy_untracked"]), (2, [], []))
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

    def test_later_publication_excludes_generation_left_before_switch(self):
        self.assertEqual(self.do_update()["data"]["update_status"], "updated")
        first = update.pointer(self.root)
        original = update.write_json

        def fail_switch(path, obj):
            if path.name == "current.json":
                raise OSError("synthetic publication failure")
            original(path, obj)

        self.allow_next()
        self.version = 2
        with patch.object(update, "write_json", side_effect=fail_switch):
            self.assertEqual(self.do_update()["data"]["update_status"], "unknown")
        self.assertEqual(update.pointer(self.root), first)
        orphan, = [p for p in self.root.iterdir() if update.GEN.fullmatch(p.name) and p.name != first["generation"]]
        self.assertTrue(update.verification_file(orphan).is_file())
        self.allow_next()
        self.version = 3
        self.assertEqual(self.do_update()["data"]["update_status"], "updated")
        new = update.pointer(self.root)
        self.assertEqual(new["previous"], [{k: first[k] for k in update.RECORD_KEYS}])
        self.assertEqual(new["legacy_untracked"], [])
        rows = {r["id"]: r for r in maintenance.manage(self.scanner(), "list")["data"]["entries"]}
        self.assertEqual(rows[first["generation"]]["reason"], "last_previous")
        self.assertTrue(rows[orphan.name]["deletable"])

    def test_legacy_first_switch_leftovers_are_held_even_with_space_and_no_wait(self):
        original = update.write_json

        def fail_first_switch(path, obj):
            if path.name == "current.json":
                raise OSError("synthetic failure while writing the first reference")
            original(path, obj)

        with patch.object(update, "write_json", side_effect=fail_first_switch):
            self.assertEqual(self.do_update()["data"]["update_status"], "unknown")
        self.allow_next()
        snapshot = set(self.root.iterdir())
        wait = (self.root / "attempt.json").read_bytes()
        self.calls.clear()
        report = self.do_update()
        self.assertEqual(report["status"], "error")
        self.assertIn("First publication cannot be confirmed", report["warnings"][0])
        self.assertEqual(self.calls, [])
        self.assertEqual(snapshot, set(self.root.iterdir()))
        self.assertEqual(wait, (self.root / "attempt.json").read_bytes())
        info = self.first_list()
        row, = [row for row in info["entries"] if row["kind"] == "generation"]
        self.assertEqual(row["reason"], "missing_history")
        self.assertFalse(row["deletable"])
        with self.assertRaisesRegex(core.ScannerError, "missing_history"):
            self.first_delete(row)
        self.assertIsNone(update.pointer(self.root))
        self.assertFalse((self.root / first.JOURNAL).exists())

    def first_list(self):
        return maintenance.manage(self.scanner(), "list")["data"]

    def first_delete(self, row):
        return maintenance.manage(self.scanner(), "delete", row["id"], row["revision"])

    def first_row(self, name=None):
        rows = self.first_list()["entries"]
        return next(row for row in rows if row["id"] == name or (name is None and row["kind"] == "generation"))

    def stop_before_first_switch(self, engine=None):
        self.config["clamav_updates"]["store_format"] = update.TRACKED_FIRST
        with patch.object(first, "start_switch", side_effect=OSError("synthetic stop before switch")):
            self.assertEqual(self.do_update(engine)["status"], "error")

    def engine_with_provider(self, argv, *args, **kwargs):
        db = next((Path(arg.split("=", 1)[1]) for arg in argv if arg.startswith("--datadir=")), None)
        if db:
            history.replace_private(db / "freshclam.dat", b"test provider state")
        return self.engine(argv, *args, **kwargs)

    def test_first_tracked_store_does_not_adopt_an_existing_directory(self):
        self.root.mkdir(mode=0o700)
        self.config["clamav_updates"]["store_format"] = update.TRACKED_FIRST
        self.assertEqual(self.do_update()["status"], "error")
        self.assertFalse((self.root / first.JOURNAL).exists())
        self.assertFalse((self.root / "attempt.json").exists())
        self.assertEqual(self.calls, [])
        self.assertEqual(self.first_list()["first_publication"], "unavailable")

    def test_first_tracked_store_requires_two_slots_and_frees_only_selected_generations(self):
        self.stop_before_first_switch()
        self.allow_next()
        self.stop_before_first_switch()
        self.allow_next()
        status = self.first_list()
        eligible = [row for row in status["entries"] if row["reason"] == first.UNPUBLISHED]
        self.assertEqual(status["capacity"], {"used_slots": 4, "max_slots": 4, "required_slots": 2})
        self.assertEqual(len(eligible), 2)
        stages = set(self.root.glob("stage-*"))
        wait = (self.root / "attempt.json").read_bytes()
        self.calls.clear()
        for used in (4, 3):
            snapshot = set(self.root.iterdir())
            self.assertIn("capacity exhausted", self.do_update()["warnings"][0])
            self.assertEqual(self.calls, [])
            self.assertEqual(snapshot, set(self.root.iterdir()))
            self.assertEqual(wait, (self.root / "attempt.json").read_bytes())
            if used == 4:
                self.assertEqual(self.first_delete(eligible[0])["status"], "completed")
        self.assertEqual(self.first_list()["capacity"]["used_slots"], 3)
        self.assertFalse((self.root / eligible[0]["id"]).exists())
        self.assertTrue((self.root / eligible[1]["id"]).is_dir())
        with self.assertRaisesRegex(core.ScannerError, "changed"):
            self.first_delete(eligible[1])
        self.assertEqual(self.first_delete(self.first_row(eligible[1]["id"]))["status"], "completed")
        self.assertEqual(self.first_list()["capacity"]["used_slots"], 2)
        self.assertEqual(stages, set(self.root.glob("stage-*")))
        self.assertEqual(wait, (self.root / "attempt.json").read_bytes())
        start = first.start_switch

        def confirm_reservation(path, journal, generation):
            self.assertEqual(first.used_slots(update.store_names(path, time.monotonic() + 30), journal), 4)
            self.assertIsNone(update.pointer(path))
            return start(path, journal, generation)

        with patch.object(first, "start_switch", side_effect=confirm_reservation):
            self.assertTrue(self.do_update()["data"]["published"])
        current = update.pointer(self.root)["generation"]
        self.assertEqual(self.first_row(current)["reason"], "current")
        self.assertEqual(self.first_list()["first_publication"], "published")

    def test_first_tracked_selection_preserves_stage_wait_provider_and_unknown_generation(self):
        self.stop_before_first_switch(self.engine_with_provider)
        known = self.first_row()
        unknown = self.root / ("f" * 32)
        unknown.mkdir(mode=0o700)
        sync = maintenance.provider_sync(self.root)
        unchanged = [self.root / name for name in ("attempt.json", "provider.dat", "provider-sync.json",
                                                   sync["stage"] + "/db/freshclam.dat")]
        snapshot = {path: path.read_bytes() for path in unchanged}
        with self.assertRaisesRegex(core.ScannerError, "provider_sync_stage"):
            self.first_delete(next(row for row in self.first_list()["entries"] if row["id"] == sync["stage"]))
        with self.assertRaisesRegex(core.ScannerError, "unknown_publication"):
            self.first_delete(self.first_row(unknown.name))
        self.assertEqual(self.first_delete(known)["status"], "completed")
        self.assertEqual({path: path.read_bytes() for path in unchanged}, snapshot)
        self.assertTrue(unknown.exists())
        self.allow_next()
        self.calls.clear()
        self.assertIn("First publication cannot be confirmed", self.do_update()["warnings"][0])
        self.assertEqual(self.calls, [])

    def test_first_tracked_selection_holds_mismatched_provider_state(self):
        self.stop_before_first_switch(self.engine_with_provider)
        candidate = self.first_row()
        canonical = self.root / "provider.dat"
        sync_file = self.root / "provider-sync.json"
        sync = maintenance.provider_sync(self.root)
        self.assertEqual(sync["status"], "synced")
        self.assertIsNotNone(sync["provider_hash"])
        canonical_bytes, sync_bytes = canonical.read_bytes(), sync_file.read_bytes()
        generation = self.root / candidate["id"]
        protected = [self.root / "attempt.json", self.root / first.JOURNAL,
                     self.root / sync["stage"] / "db/freshclam.dat", update.verification_file(generation)]
        protected.extend(generation.iterdir())
        snapshots = {path: path.read_bytes() for path in protected}
        self.calls.clear()

        for fault in ("missing_canonical", "different_canonical", "canonical_expected_absent", "missing_sync"):
            with self.subTest(fault=fault):
                history.replace_private(canonical, canonical_bytes)
                history.replace_private(sync_file, sync_bytes)
                if fault == "missing_canonical":
                    canonical.unlink()
                elif fault == "different_canonical":
                    history.replace_private(canonical, b"different provider state")
                elif fault == "canonical_expected_absent":
                    update.write_json(sync_file, dict(sync, provider_hash=None))
                else:
                    sync_file.unlink()
                provider_state = {path: path.read_bytes() if path.exists() else None for path in (canonical, sync_file)}

                with self.assertRaisesRegex(core.ScannerError, "changed"):
                    self.first_delete(candidate)
                held = self.first_row(candidate["id"])
                self.assertEqual((held["deletable"], held["reason"]), (False, "provider_state_mismatch"))
                with self.assertRaisesRegex(core.ScannerError, "provider_state_mismatch"):
                    self.first_delete(held)
                self.assertEqual({path: path.read_bytes() for path in protected}, snapshots)
                self.assertEqual({path: path.read_bytes() if path.exists() else None for path in provider_state}, provider_state)
                self.assertEqual(self.first_list()["capacity"]["used_slots"], 2)
                self.assertEqual(self.calls, [])

        history.replace_private(canonical, canonical_bytes)
        history.replace_private(sync_file, sync_bytes)
        self.assertEqual(self.first_delete(self.first_row(candidate["id"]))["status"], "completed")

    def test_first_tracked_candidates_are_held_after_switch_intent_is_visible(self):
        for fault in ("intent_sync", "reference_write", "reference_readback"):
            with self.subTest(fault=fault):
                self.root = self.base / fault
                self.config["clamav_updates"].update(directory=str(self.root), store_format=update.TRACKED_FIRST)
                real_write, real_pointer = update.write_json, update.pointer

                def write(path, obj):
                    if path.name == "current.json" and fault == "reference_write":
                        raise OSError("synthetic reference write failure")
                    real_write(path, obj)
                    if path.name == first.JOURNAL and obj["phase"] == "switch_started" and fault == "intent_sync":
                        raise OSError("synthetic intent sync failure")

                def pointer(path):
                    obj = real_pointer(path)
                    if obj is not None and fault == "reference_readback":
                        raise OSError("synthetic reference read-back failure")
                    return obj

                with patch.object(update, "write_json", side_effect=write), patch.object(update, "pointer", side_effect=pointer):
                    self.assertEqual(self.do_update()["status"], "error")
                journal, _ = first.load(self.root, update.TRACKED_FIRST)
                self.assertEqual(journal["phase"], "switch_started")
                if fault == "reference_readback":
                    self.assertEqual(self.first_list()["first_publication"], "confirm_published")
                    (self.root / "current.json").unlink()
                else:
                    self.assertIsNone(update.pointer(self.root))
                self.assertEqual(self.first_row()["reason"], "first_publication_unavailable")
                self.allow_next()
                self.calls.clear()
                self.assertEqual(self.do_update()["status"], "error")
                self.assertFalse(self.calls)
                self.assertEqual(first.load(self.root, update.TRACKED_FIRST)[0], journal)

    def test_first_tracked_restart_can_advance_a_verified_published_reference(self):
        self.config["clamav_updates"]["store_format"] = update.TRACKED_FIRST
        with patch.object(first, "published", side_effect=OSError("synthetic journal completion failure")):
            report = self.do_update()
        self.assertTrue(report["data"]["published"])
        current = update.pointer(self.root)
        self.assertEqual(self.first_list()["first_publication"], "confirm_published")
        self.allow_next()
        self.version += 1
        self.assertEqual(self.do_update()["data"]["update_status"], "updated")
        self.assertEqual(first.load(self.root, update.TRACKED_FIRST)[0]["target"], current["generation"])
        (self.root / "current.json").unlink()
        self.assertEqual(self.first_list()["first_publication"], "unavailable")
        self.allow_next()
        self.calls.clear()
        self.assertEqual(self.do_update()["status"], "error")
        self.assertEqual(self.calls, [])

    def test_first_tracked_stop_between_candidate_and_sidecar_moves(self):
        self.config["clamav_updates"]["store_format"] = update.TRACKED_FIRST
        rename = os.rename

        def fail_sidecar(source, dest, *args, **kwargs):
            if Path(dest).name.endswith(".verification.json"):
                raise OSError("synthetic sidecar move failure")
            return rename(source, dest, *args, **kwargs)

        with patch.object(os, "rename", side_effect=fail_sidecar):
            self.assertEqual(self.do_update()["status"], "error")
        row = self.first_row()
        self.assertTrue(row["deletable"])
        self.assertFalse(update.verification_file(self.root / row["id"]).exists())
        self.assertEqual(self.first_delete(row)["status"], "completed")

    def test_first_tracked_candidate_is_unselectable_until_its_directory_moves(self):
        self.config["clamav_updates"]["store_format"] = update.TRACKED_FIRST
        rename = os.rename

        def stop_before_move(source, dest, *args, **kwargs):
            if Path(source).name == "candidate":
                raise OSError("synthetic candidate move failure")
            return rename(source, dest, *args, **kwargs)

        with patch.object(os, "rename", side_effect=stop_before_move):
            self.assertEqual(self.do_update()["status"], "error")
        journal, _ = first.load(self.root, update.TRACKED_FIRST)
        self.assertEqual(len(journal["entries"]), 1)
        self.assertEqual(self.first_list()["capacity"]["used_slots"], 1)
        self.assertTrue(all(row["kind"] == "stage" for row in self.first_list()["entries"]))
        self.allow_next()
        self.assertTrue(self.do_update()["data"]["published"])

    def test_first_tracked_owner_cli_selects_by_id_and_revision(self):
        self.stop_before_first_switch()
        conf = self.base / "scanner.toml"
        settings = self.config["clamav_updates"]
        conf.write_text("[clamav_updates]\n" + "\n".join(f"{key}={json.dumps(value)}" for key, value in settings.items()))

        def invoke(*args):
            return subprocess.run([sys.executable, "-m", "pc_scanner.cli", "--config", str(conf),
                                   "clamav-signature-store", *args], capture_output=True, text=True, timeout=15)

        listed = invoke("list")
        self.assertEqual(listed.returncode, 0, listed.stdout + listed.stderr)
        row, = [row for row in json.loads(listed.stdout)["data"]["entries"] if row["reason"] == first.UNPUBLISHED]
        deleted = invoke("delete", row["id"], "--revision", row["revision"])
        self.assertEqual(deleted.returncode, 0, deleted.stdout + deleted.stderr)
        self.assertEqual(json.loads(deleted.stdout)["data"]["deleted"], row["id"])
        self.assertEqual(self.first_list()["capacity"]["used_slots"], 1)

    def test_first_tracked_candidates_reject_lease_link_corruption_and_stale_wait(self):
        self.stop_before_first_switch()
        row = self.first_row()
        generation = self.root / row["id"]
        lease_path = generation.with_name(generation.name + ".lease")
        with update.generation_lease(lease_path):
            self.assertEqual(self.first_row()["reason"], "lease_present")
            with self.assertRaises(core.ScannerError):
                self.first_delete(row)
        lease_path.unlink()
        self.allow_next()
        with self.assertRaisesRegex(core.ScannerError, "changed"):
            self.first_delete(row)
        cvd = generation / "main.cvd"
        data = cvd.read_bytes()
        cvd.unlink()
        cvd.symlink_to(generation / "daily.cvd")
        self.assertFalse(self.first_row()["deletable"])
        cvd.unlink()
        history.replace_private(cvd, data + b"corrupted")
        self.assertFalse(self.first_row()["deletable"])
        journal = self.root / first.JOURNAL
        history.replace_private(journal, b'{"schema":1,"schema":1}')
        self.assertEqual(self.first_list()["first_publication"], "unavailable")
        self.assertEqual(self.do_update()["status"], "error")
        self.assertTrue(generation.is_dir())

    def test_first_tracked_deletion_can_resume_and_holds_the_slot_until_sync(self):
        self.stop_before_first_switch()
        row = self.first_row()
        generation = self.root / row["id"]
        unlink = os.unlink
        calls = []

        def stop_on_second_cvd(path, *args, **kwargs):
            if path in update.DATABASES and kwargs.get("dir_fd") is not None:
                calls.append(path)
                if len(calls) == 2:
                    raise OSError("synthetic interrupted deletion")
            return unlink(path, *args, **kwargs)

        with patch.object(os, "unlink", side_effect=stop_on_second_cvd):
            partial = self.first_delete(row)
        self.assertEqual(partial["status"], "partial")
        self.assertNotIn("deleted", partial["data"])
        self.assertEqual(len(list(generation.iterdir())), 2)
        self.assertEqual(self.first_list()["capacity"]["used_slots"], 2)
        self.assertTrue(self.first_row()["deletable"])
        sync = update.sync_dir

        def stop_at_directory_sync(path):
            if path == self.root and not generation.exists():
                raise OSError("synthetic parent sync failure")
            return sync(path)

        with patch.object(update, "sync_dir", side_effect=stop_at_directory_sync):
            partial = self.first_delete(self.first_row())
        self.assertEqual(partial["status"], "partial")
        self.assertEqual(partial["data"], {"deleted": row["id"], "directory_synced": False, "update_performed": False})
        self.assertFalse(generation.exists())
        self.assertEqual(self.first_list()["capacity"]["used_slots"], 2)
        self.assertEqual(self.first_delete(self.first_row())["status"], "completed")
        self.assertEqual(self.first_list()["capacity"]["used_slots"], 1)
        self.assertFalse(any(row["kind"] == "generation" for row in self.first_list()["entries"]))

    def test_first_tracked_deletion_retry_requires_durable_intent_before_removal(self):
        self.stop_before_first_switch()
        row = self.first_row()
        name = row["id"]
        generation = self.root / name
        wait = (self.root / "attempt.json").read_bytes()
        files = [*generation.iterdir(), update.verification_file(generation)]
        snapshot = {file: file.read_bytes() for file in files}
        sync = update.sync_dir

        def fail_intent_sync(path):
            if path == self.root and generation.is_dir():
                journal, _ = first.load(path, update.TRACKED_FIRST)
                self.assertIsNotNone(journal["entries"][name]["deleting"])
                raise OSError("synthetic deletion intent sync failure")
            return sync(path)

        with patch.object(update, "sync_dir", side_effect=fail_intent_sync), \
             patch.object(maintenance, "remove_tree", wraps=maintenance.remove_tree) as remove:
            with self.assertRaisesRegex(core.ScannerError, "preserve state"):
                self.first_delete(row)
            retry = self.first_row(name)
            with self.assertRaisesRegex(core.ScannerError, "preserve state"):
                self.first_delete(retry)
            remove.assert_not_called()
        self.assertEqual({file: file.read_bytes() for file in files}, snapshot)
        self.assertEqual((self.root / "attempt.json").read_bytes(), wait)
        self.assertEqual(self.first_list()["capacity"]["used_slots"], 2)

        synced = False
        remove_tree = maintenance.remove_tree

        def sync_intent(path):
            nonlocal synced
            sync(path)
            if path == self.root and generation.is_dir():
                synced = True

        def require_synced_intent(*args, **kwargs):
            self.assertTrue(synced)
            return remove_tree(*args, **kwargs)

        with patch.object(update, "sync_dir", side_effect=sync_intent), \
             patch.object(maintenance, "remove_tree", side_effect=require_synced_intent):
            self.assertEqual(self.first_delete(self.first_row(name))["status"], "completed")
        self.assertFalse(generation.exists())
        self.assertEqual((self.root / "attempt.json").read_bytes(), wait)
        self.assertEqual(self.first_list()["capacity"]["used_slots"], 1)

    def test_first_tracked_update_points_to_an_unfinished_selected_deletion(self):
        # The store is not lost: the listing still offers the candidate, and finishing it allows the first publication.
        self.stop_before_first_switch()
        row = self.first_row()
        unlink = os.unlink

        def stop_on_first_cvd(path, *args, **kwargs):
            if path in update.DATABASES and kwargs.get("dir_fd") is not None:
                raise OSError("synthetic interrupted deletion")
            return unlink(path, *args, **kwargs)

        with patch.object(os, "unlink", side_effect=stop_on_first_cvd):
            self.assertEqual(self.first_delete(row)["status"], "partial")
        self.allow_next()
        snapshot = set(self.root.iterdir())
        wait = (self.root / "attempt.json").read_bytes()
        self.calls.clear()
        report = self.do_update()
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["warnings"], [
            "A selected first-publication cleanup is unfinished; list the store and retry that deletion"])
        self.assertEqual(self.calls, [])
        self.assertEqual(snapshot, set(self.root.iterdir()))
        self.assertEqual(wait, (self.root / "attempt.json").read_bytes())
        retry = self.first_row(row["id"])
        self.assertEqual((retry["reason"], retry["deletable"]), (first.UNPUBLISHED, True))
        self.assertEqual(self.first_delete(retry)["status"], "completed")
        self.assertTrue(self.do_update()["data"]["published"])

    def test_deletion_reports_the_removed_generation_when_the_history_rewrite_is_busy(self):
        refs = []
        for version in (1, 2, 3):
            self.version = version
            if refs:
                self.allow_next()
            self.assertEqual(self.do_update()["data"]["update_status"], "updated")
            refs.append(update.pointer(self.root)["generation"])
        damaged = self.root / refs[1] / "daily.cvd"
        damaged.write_bytes(damaged.read_bytes()[:-1] + b"X")
        rows = {r["id"]: r for r in maintenance.manage(self.scanner(), "list")["data"]["entries"]}
        self.assertEqual((rows[refs[0]]["reason"], rows[refs[1]]["deletable"]), ("last_previous", True))
        reference = update.pointer(self.root)
        # Scans starting one after another can hold the publication lock for the whole wait.
        import fcntl
        holder = os.open(history.lock_file(self.root / "publish"), os.O_RDWR)
        try:
            fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = maintenance.manage(self.scanner(), "delete", refs[1], rows[refs[1]]["revision"])
        finally:
            os.close(holder)
        self.assertEqual((result["status"], result["data"]["deleted"], result["data"]["history_updated"]),
                         ("partial", refs[1], False))
        self.assertTrue(result["data"]["directory_synced"])
        self.assertTrue(result["data"]["lease_removed"])
        self.assertNotIn("no maintenance completed", " ".join(result["warnings"]))
        self.assertFalse((self.root / refs[1]).exists())
        self.assertEqual(update.pointer(self.root), reference)
        row, = maintenance.manage(self.scanner(), "list")["data"]["cleanup"]
        self.assertEqual(row["id"], refs[1])
        finished = maintenance.manage(self.scanner(), "cleanup", refs[1], row["revision"])
        self.assertTrue(finished["data"]["history_updated"])
        self.assertEqual([r["generation"] for r in update.pointer(self.root)["previous"]], refs[:1])

    def test_legacy_migrates_only_on_changed_publication_at_the_same_versions(self):
        self.assertEqual(self.do_update()["data"]["update_status"], "updated")
        reference = self.root / "current.json"
        old = {k: update.pointer(self.root)[k] for k in update.RECORD_KEYS}
        update.write_json(reference, old)
        older = self.root / ("0" * 32)
        shutil.copytree(self.root / old["generation"], older)
        self.allow_next()
        self.assertEqual(self.do_update()["data"]["update_status"], "unchanged")
        self.assertEqual(update.pointer(self.root), old)
        with update.pin(self.scanner()) as pinned:
            self.assertEqual(pinned.local["clamav_database_directory"], str(self.root / old["generation"]))

        def changed_content(argv, *args, **kwargs):
            reply = self.engine(argv, *args, **kwargs)
            db = next((arg.partition("=")[2] for arg in argv if arg.startswith("--datadir=")), None)
            if db:
                with (Path(db) / "daily.cvd").open("ab") as file:
                    file.write(b"changed synthetic content at the same version")
            return reply

        self.allow_next()
        self.assertEqual(self.do_update(changed_content)["data"]["update_status"], "updated")
        new = update.pointer(self.root)
        self.assertEqual((new["previous"], new["legacy_untracked"], new["versions"]), ([old], [older.name], old["versions"]))
        self.assertNotEqual(new["content"], old["content"])
        rows = {r["id"]: r for r in maintenance.manage(self.scanner(), "list")["data"]["entries"]}
        self.assertEqual(rows[old["generation"]]["reason"], "last_previous")
        # The recorded predecessor is verified, so the unrecorded copy guards nothing and leaves the history.
        self.assertEqual((rows[older.name]["deletable"], rows[older.name]["reason"]), (True, None))
        self.assertEqual(maintenance.manage(self.scanner(), "delete", older.name, rows[older.name]["revision"])["status"],
                         "completed")
        after = update.pointer(self.root)
        self.assertEqual((after["previous"], after["legacy_untracked"]), ([old], []))

    def test_a_store_left_full_by_an_earlier_release_frees_a_slot_migrates_and_releases_old_generations(self):
        names = []
        for version in (1, 2, 3, 4):
            self.version = version
            if names:
                self.allow_next()
            self.assertEqual(self.do_update()["data"]["update_status"], "updated")
            names.append(update.pointer(self.root)["generation"])
        # The earlier release kept only the current reference, and four generations fill the store.
        old = {k: update.pointer(self.root)[k] for k in update.RECORD_KEYS}
        update.write_json(self.root / "current.json", old)
        self.allow_next()
        self.version = 5
        full = self.do_update()
        self.assertEqual((full["status"], full["data"]["update_status"]), ("error", "failed"))
        rows = {r["id"]: r for r in maintenance.manage(self.scanner(), "list")["data"]["entries"]}
        self.assertEqual([rows[n]["deletable"] for n in names], [True, True, True, False])
        self.assertEqual(maintenance.manage(self.scanner(), "delete", names[0], rows[names[0]]["revision"])["status"],
                         "completed")
        self.allow_next()
        self.assertEqual(self.do_update()["data"]["update_status"], "updated")
        new = update.pointer(self.root)
        self.assertEqual((new["previous"], new["legacy_untracked"]), ([old], sorted(names[1:3])))
        rows = {r["id"]: r for r in maintenance.manage(self.scanner(), "list")["data"]["entries"]}
        self.assertEqual(rows[names[3]]["reason"], "last_previous")
        self.assertEqual([rows[n]["deletable"] for n in names[1:3]], [True, True])
        # An unrecorded ID whose folder, record and lease are all gone leaves the history at the next publication.
        shutil.rmtree(self.root / names[1])
        update.verification_file(self.root / names[1]).unlink()
        self.allow_next()
        self.version = 6
        self.assertEqual(self.do_update()["data"]["update_status"], "updated")
        self.assertEqual(update.pointer(self.root)["legacy_untracked"], [names[2]])

    def test_publication_prunes_only_confirmed_absence_behind_verified_predecessor(self):
        refs = []
        for version in (1, 2, 3):
            self.version = version
            if refs:
                self.allow_next()
            self.assertEqual(self.do_update()["data"]["update_status"], "updated")
            refs.append(update.pointer(self.root)["generation"])
        old = update.pointer(self.root)
        revision = next(r["revision"] for r in maintenance.manage(self.scanner(), "list")["data"]["entries"]
                        if r["id"] == refs[0])
        original = update.write_json

        def fail_history_rewrite(path, obj):
            if path.name == "current.json":
                raise OSError("synthetic history rewrite failure")
            original(path, obj)

        with patch.object(update, "write_json", side_effect=fail_history_rewrite):
            # The folder is already gone, so the report says so instead of "no maintenance completed".
            result = maintenance.manage(self.scanner(), "delete", refs[0], revision)
        self.assertEqual((result["status"], result["data"]["deleted"], result["data"]["history_updated"]),
                         ("partial", refs[0], False))
        self.assertRegex(result["warnings"][0], "Generation deleted, but its publication history entry")
        self.assertEqual(update.pointer(self.root), old)
        self.assertFalse((self.root / refs[0]).exists())
        self.allow_next()
        self.version = 4
        self.assertEqual(self.do_update()["data"]["update_status"], "updated")
        self.assertEqual([r["generation"] for r in update.pointer(self.root)["previous"]], [refs[2], refs[1]])

        reference = update.pointer(self.root)
        shutil.rmtree(self.root / refs[2])
        update.verification_file(self.root / refs[2]).unlink()
        self.allow_next()
        self.version = 5
        self.assertEqual(self.do_update()["data"]["update_status"], "updated")
        self.assertEqual([r["generation"] for r in update.pointer(self.root)["previous"]],
                         [reference["generation"], refs[2], refs[1]])

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

    def test_only_a_verified_daily_detached_signature_makes_the_build_date_fresh(self):
        # The embedded signature does not cover the header's build time; clamscan reports daily's.
        def withheld(names):
            def engine(argv, *args, **kwargs):
                answer = self.engine(argv, *args, **kwargs)
                db = next((Path(a.split("=", 1)[1]) for a in argv if a.startswith("--datadir=")), None)
                if db is not None:
                    for name in names:
                        (db / f"{name.removesuffix('.cvd')}-{self.version}.cvd.sign").unlink()
                return answer
            return engine
        for label, missing, freshness in (("all_absent", update.DATABASES, "unverified"),
                                          ("daily_absent", ("daily.cvd",), "unverified"),
                                          ("only_daily_present", ("main.cvd", "bytecode.cvd"), "fresh"),
                                          ("all_present", (), "fresh")):
            with self.subTest(label):
                self.version += 1
                self.calls.clear()
                report = self.do_update(withheld(missing))
                self.allow_next()
                check = report["data"]["signature_check"]
                # Published either way: the embedded signature still refuses a version rollback.
                self.assertEqual(report["data"]["update_status"], "updated", report)
                self.assertEqual((report["status"], check["freshness"]), ("completed" if freshness == "fresh" else "partial", freshness))
                self.assertEqual(check["detached_signatures"], {n: "absent" if n in missing else "verified" for n in update.DATABASES})
                verified = sorted(Path(call[-1]).name for call in self.calls if "--verify" in call)
                self.assertEqual(verified, sorted(n for n in update.DATABASES if n not in missing))
                if freshness == "unverified":
                    self.assertIn(".cvd.sign", report["warnings"][0])

    def test_a_detached_signature_that_does_not_verify_stops_publication(self):
        self.do_update()
        old = (self.root / "current.json").read_bytes()
        for label in ("rejected", "no_success_line", "named_for_another_version"):
            with self.subTest(label):
                self.allow_next()
                self.version += 1
                def engine(argv, *args, **kwargs):
                    answer = self.engine(argv, *args, **kwargs)
                    db = next((Path(a.split("=", 1)[1]) for a in argv if a.startswith("--datadir=")), None)
                    if db is not None and label == "named_for_another_version":
                        # sigtool looks only for the name carrying the header's version, so it reports failure.
                        (db / f"daily-{self.version}.cvd.sign").rename(db / f"daily-{self.version - 1}.cvd.sign")
                    if "--verify" in argv and argv[-1].endswith("daily.cvd"):
                        return (0, "", "") if label == "no_success_line" else (1, "", "ERROR: verify: Failed to verify file")
                    return answer
                with patch.object(update, "MAX_GENERATIONS", 32):
                    report = self.do_update(engine)
                self.assertEqual((report["status"], report["data"]["update_status"]), ("error", "failed"), report)
                self.assertEqual(old, (self.root / "current.json").read_bytes())
                self.assertTrue(update.read_json(self.root / "attempt.json")["pending"])

    def without_daily_signature(self, argv, *args, **kwargs):
        answer = self.engine(argv, *args, **kwargs)
        for arg in argv:
            if arg.startswith("--datadir="):
                (Path(arg.split("=", 1)[1]) / f"daily-{self.version}.cvd.sign").unlink()
        return answer

    def test_unverified_publication_stays_unverified_in_checks_scans_and_resume(self):
        self.assertEqual(self.do_update(self.without_daily_signature)["status"], "partial")
        with patch("pc_scanner.core.run_bounded", side_effect=self.engine):
            for operation, arguments in (("check_clamav_signatures", {}), ("malware", {"root_alias": "test"}),
                                         ("malware", {"root_alias": "test", "batch": True}),
                                         ("malware", {"root_alias": "test", "resume": True})):
                with self.subTest(operation=operation, arguments=arguments):
                    report = self.scanner().invoke(operation, **arguments)
                    self.assertEqual((report["status"], report["data"]["signature_check"]["freshness"]),
                                     ("partial", "unverified"), report)
                    self.assertEqual(report["data"]["signature_check"]["detached_signatures"]["daily.cvd"], "absent")
                    if operation == "malware":
                        self.assertIn("unknown_definitions", report["data"]["coverage"]["assessment_limits"])
                    self.assertNotIn(str(self.root), json.dumps(report))

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "agent extra not installed")
    def test_sdk_mcp_checks_and_scans_keep_unverified_generation_evidence(self):
        self.do_update(self.without_daily_signature)
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server
        async def exercise():
            async with create_connected_server_and_client_session(create_server(self.scanner())) as session:
                for name, arguments in (("check_clamav_signatures", {}), ("scan_malware", {"root_alias": "test"})):
                    reply = await session.call_tool(name, arguments)
                    report = json.loads(reply.content[0].text)
                    self.assertEqual((report["status"], report["data"]["signature_check"]["freshness"]),
                                     ("partial", "unverified"), report)
                    self.assertNotIn(str(self.root), json.dumps(report))
        with patch("pc_scanner.core.run_bounded", side_effect=self.engine):
            asyncio.run(exercise())

    def test_actual_cli_check_and_scan_report_unverified_after_publication(self):
        self.do_update(self.without_daily_signature)
        engine = self.base / "synthetic-clamscan"
        engine.write_text(f"#!{sys.executable}\nimport sys\nfrom datetime import datetime\n"
                          "if '--version' in sys.argv:\n"
                          " print('ClamAV 1.5.4/1/' + datetime.now().strftime('%a %b %d %H:%M:%S %Y'))\n"
                          "else:\n print('Scanned files: 1\\nInfected files: 0')\n")
        engine.chmod(0o700)
        config = self.base / "cli.toml"
        config.write_text('[local]\nclamav_binary=' + json.dumps(str(engine)) + '\n[scan_roots]\ntest='
                          + json.dumps(str(self.inputs)) + '\n[history]\nenabled=false\n[clamav_updates]\nenabled=true\n'
                          + '\n'.join(k + '=' + json.dumps(self.config["clamav_updates"][k])
                                      for k in ("directory", "freshclam_binary", "sigtool_binary")) + '\n')
        for arguments in (("check-clamav-signatures",), ("malware", "test")):
            result = subprocess.run([sys.executable, "-m", "pc_scanner.cli", "--config", str(config), *arguments],
                                    capture_output=True, text=True, timeout=15)
            report = json.loads(result.stdout)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual((report["status"], report["data"]["signature_check"]["freshness"]), ("partial", "unverified"))
            self.assertIn("definitions=unverified", result.stderr)

    def test_legacy_invalid_or_mismatched_evidence_never_establishes_freshness(self):
        self.do_update()
        current = update.read_json(self.root / "current.json")
        sidecar = self.root / (current["generation"] + ".verification.json")
        original = sidecar.read_bytes()
        record = json.loads(original)
        bad_content = {**record, "content": "0" * 64}
        bad_versions = {**record, "versions": {**record["versions"], "daily.cvd": 999}}
        bad_status = {**record, "detached_signatures": {**record["detached_signatures"], "daily.cvd": True}}
        for label, contents in (("missing", None), ("json", b"{"), ("nested", b"[" * 2000 + b"]" * 2000),
                                ("schema", json.dumps({**record, "schema": 2}).encode()),
                                ("content", json.dumps(bad_content).encode()), ("versions", json.dumps(bad_versions).encode()),
                                ("status", json.dumps(bad_status).encode()), ("extra", json.dumps({**record, "extra": 1}).encode())):
            with self.subTest(label=label):
                sidecar.unlink(missing_ok=True)
                if contents is not None:
                    history.replace_private(sidecar, contents)
                with patch("pc_scanner.core.run_bounded", side_effect=self.engine):
                    report = self.scanner().invoke("check_clamav_signatures")
                self.assertEqual((report["status"], report["data"]["signature_check"]["freshness"]),
                                 ("partial", "unverified"), report)
        history.replace_private(sidecar, original)
        sidecar.chmod(0o644)
        with patch("pc_scanner.core.run_bounded", side_effect=self.engine):
            self.assertEqual(self.scanner().invoke("check_clamav_signatures")["data"]["signature_check"]["freshness"], "unverified")
        sidecar.chmod(0o600)
        outside = self.base / "outside-evidence.json"
        outside.write_bytes(original)
        sidecar.unlink()
        sidecar.symlink_to(outside)
        with patch("pc_scanner.core.run_bounded", side_effect=self.engine):
            self.assertEqual(self.scanner().invoke("check_clamav_signatures")["data"]["signature_check"]["freshness"], "unverified")

    def test_unchanged_updates_upgrade_and_preserve_matching_evidence(self):
        self.do_update(self.without_daily_signature)
        before = (self.root / "current.json").read_bytes()
        self.allow_next()
        upgraded = self.do_update()
        self.assertEqual((upgraded["status"], upgraded["data"]["update_status"]), ("completed", "unchanged"))
        self.assertEqual((self.root / "current.json").read_bytes(), before)
        sidecar = self.root / (json.loads(before)["generation"] + ".verification.json")
        self.assertEqual(sidecar.stat().st_mode & 0o777, 0o600)
        self.allow_next()
        retained = self.do_update(self.without_daily_signature)
        self.assertEqual((retained["status"], retained["data"]["signature_check"]["freshness"]), ("completed", "fresh"))
        with patch("pc_scanner.core.run_bounded", side_effect=self.engine):
            self.assertEqual(self.scanner().invoke("check_clamav_signatures")["status"], "completed")
        sidecar.unlink()  # A legacy generation can be repaired by the next verified unchanged update.
        self.allow_next()
        self.assertEqual(self.do_update()["data"]["update_status"], "unchanged")
        self.assertEqual((self.root / "current.json").read_bytes(), before)
        self.allow_next()
        def different_bytes_same_version(argv, *args, **kwargs):
            answer = self.without_daily_signature(argv, *args, **kwargs)
            for arg in argv:
                if arg.startswith("--datadir="):
                    daily = Path(arg.split("=", 1)[1]) / "daily.cvd"
                    daily.write_bytes(daily.read_bytes() + b"different synthetic content")
            return answer
        changed = self.do_update(different_bytes_same_version)
        self.assertEqual((changed["status"], changed["data"]["signature_check"]["freshness"]), ("partial", "unverified"))
        self.allow_next()
        self.version += 1
        changed = self.do_update(self.without_daily_signature)
        self.assertEqual((changed["status"], changed["data"]["signature_check"]["freshness"]), ("partial", "unverified"))

    def test_pinned_evidence_belongs_to_its_generation_across_publication(self):
        self.do_update()
        with update.pin(self.scanner()) as old:
            self.allow_next()
            self.version += 1
            self.do_update(self.without_daily_signature)
            with patch("pc_scanner.core.run_bounded", side_effect=self.engine):
                self.assertEqual(old.check_clamav_signatures()["status"], "completed")
                self.assertEqual(self.scanner().invoke("check_clamav_signatures")["status"], "partial")

    def test_private_evidence_keeps_exact_age_boundary_and_stale_unknown_states(self):
        from datetime import timedelta
        now = datetime(2026, 11, 17, 12, tzinfo=timezone.utc)
        for verified in (True, False):
            self.version += 1
            self.do_update(None if verified else self.without_daily_signature)
            self.allow_next()
            for delta, expected in ((timedelta(days=7), "fresh" if verified else "unverified"),
                                    (timedelta(days=7, microseconds=1), "stale"),
                                    (timedelta(days=-1), "unknown")):
                with self.subTest(verified=verified, delta=delta), patch("pc_scanner.core.datetime") as clock, patch(
                        "pc_scanner.core.clamav_signatures", return_value={**self.signatures, "built_at": now - delta}):
                    clock.now.return_value = now
                    report = self.scanner().invoke("check_clamav_signatures")
                    self.assertEqual(report["data"]["signature_check"]["freshness"], expected)

    def test_failed_evidence_publication_keeps_prior_pointer_and_retains_orphan(self):
        self.do_update()
        before = (self.root / "current.json").read_bytes()
        self.allow_next()
        self.version += 1
        real = update.os.rename
        def fail(source, destination):
            if source.name == "verification.json":
                raise OSError("synthetic evidence publication failure")
            return real(source, destination)
        with patch.object(update.os, "rename", side_effect=fail):
            report = self.do_update()
        self.assertEqual(report["status"], "error", report)
        self.assertEqual((self.root / "current.json").read_bytes(), before)
        self.assertTrue(update.read_json(self.root / "attempt.json")["pending"])
        self.assertTrue(any((stage / "verification.json").exists() for stage in self.root.glob("stage-*")))
        with patch("pc_scanner.core.run_bounded", side_effect=self.engine):
            self.assertEqual(self.scanner().invoke("check_clamav_signatures")["status"], "completed")

    def test_evidence_write_failure_preserves_current_and_pending_stage(self):
        self.do_update()
        before = (self.root / "current.json").read_bytes()
        self.allow_next()
        self.version += 1
        real = update.write_json
        def fail(path, value):
            if path.name == "verification.json":
                raise OSError("synthetic evidence save failure")
            real(path, value)
        with patch.object(update, "write_json", side_effect=fail):
            report = self.do_update()
        self.assertEqual(report["status"], "error", report)
        self.assertEqual((self.root / "current.json").read_bytes(), before)
        self.assertTrue(update.read_json(self.root / "attempt.json")["pending"])
        self.assertTrue(list(self.root.glob("stage-*")))

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

    def test_nonzero_exit_provider_wait_is_still_rate_limited_and_pending(self):
        # A provider wait notice decides the result whatever the exit code, e.g. a 403 cool-down or a failing 429.
        self.do_update()
        pointer = (self.root / "current.json").read_bytes()
        cases = [(1, "WARNING: FreshClam received error code 429 from the ClamAV Content Delivery Network (CDN).\n"),
                 (11, "WARNING: You are on cool-down until after: 2026-11-10 00:00:00\n")]
        for code, err in cases:
            with self.subTest(code=code):
                self.allow_next()
                provider = b"opaque provider wait after exit " + str(code).encode()
                stages_before = set(self.root.glob("stage-*"))

                def waiting(argv, *args, **kwargs):
                    if not any(a.startswith("--datadir=") for a in argv):
                        return self.engine(argv, *args, **kwargs)
                    self.calls.append(argv)
                    db = Path(next(a.split("=", 1)[1] for a in argv if a.startswith("--datadir=")))
                    (db / "freshclam.dat").write_bytes(provider)
                    return code, "", err

                with patch.object(update, "MAX_GENERATIONS", 32):
                    report = self.do_update(waiting)
                self.assertEqual((report["status"], report["data"]["update_status"]), ("partial", "rate_limited"), report)
                self.assertTrue(report["data"]["recovery_required"])
                self.assertFalse(report["data"]["published"])
                self.assertEqual((self.root / "current.json").read_bytes(), pointer)
                self.assertTrue(update.read_json(self.root / "attempt.json")["pending"])
                new_stages = set(self.root.glob("stage-*")) - stages_before
                self.assertEqual(len(new_stages), 1)
                stage = new_stages.pop()
                self.assertEqual((stage / "db/freshclam.dat").read_bytes(), provider)
                self.assertEqual((self.root / "provider.dat").read_bytes(), provider)
                sync = update.read_json(self.root / "provider-sync.json")
                self.assertEqual((sync["status"], sync["stage"]), ("synced", stage.name))

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
        # So does a work folder the owner CLI cannot manage; its listing reports these (maintenance tests).
        junk = self.root / "stage-junk"
        junk.mkdir(mode=0o700)
        with patch.object(update, "MAX_GENERATIONS", 2):
            self.assertEqual(self.do_update()["status"], "error")
        self.assertEqual(len(self.calls), calls)
        junk.rmdir()
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
        second = update.pointer(self.root)
        self.assertEqual(second["versions"]["daily.cvd"], 2)
        self.assertEqual([r["versions"]["daily.cvd"] for r in second["previous"]], [1])
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
        third = update.pointer(self.root)
        self.assertEqual(third["versions"]["daily.cvd"], 3)
        self.assertEqual([r["versions"]["daily.cvd"] for r in third["previous"]], [2, 1])

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


@unittest.skipUnless(os.name == "posix" and os.geteuid() != 0, "non-root POSIX updater executables")
class ExecutableTests(unittest.TestCase):
    """The real check, without the patch the update tests use."""
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.bin = self.base / "bin"
        self.bin.mkdir(mode=0o700)
        self.tool = self.bin / "freshclam"
        self.tool.write_text("#!/bin/sh\nexit 0\n")
        self.tool.chmod(0o700)

    def refused(self):
        with self.assertRaises(core.ScannerError):
            update.executable(str(self.tool))

    def test_links_are_followed_to_the_checked_real_file_which_is_what_runs(self):
        self.assertEqual(update.executable(str(self.tool)), str(self.tool))
        links = self.base / "links"
        links.mkdir(mode=0o700)
        (links / "absolute").symlink_to(self.tool)
        (links / "relative").symlink_to("../bin/freshclam")
        (links / "folder").symlink_to(self.bin, target_is_directory=True)
        (links / "chain").symlink_to("relative")
        for value in (links / "absolute", links / "relative", links / "folder" / "freshclam", links / "chain"):
            with self.subTest(value=value.relative_to(links)):
                self.assertEqual(update.executable(str(value)), str(self.tool))

    def test_a_link_in_a_folder_others_can_change_is_refused(self):
        # Another account could point it at any program that passes the rule, such as one that downloads nothing.
        shared = self.base / "shared"
        shared.mkdir()
        shared.chmod(0o777)
        (shared / "freshclam").symlink_to(self.tool)
        (shared / "bin").symlink_to(self.bin, target_is_directory=True)
        (self.bin / "through-shared").symlink_to("../shared/freshclam")
        for value in (shared / "freshclam", shared / "bin" / "freshclam", self.bin / "through-shared"):
            with self.subTest(value=value.name):
                with self.assertRaises(core.ScannerError):
                    update.executable(str(value))

    def test_a_link_owned_by_another_account_and_link_loops_are_refused(self):
        # In a root-owned sticky folder, which the rule accepts, a link's owner can still replace it.
        link = self.bin / "link"
        link.symlink_to(self.tool)
        original = os.lstat
        def lstat(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            if Path(path) == link:
                values = list(info[:10])
                values[4] = os.geteuid() + 1000
                return os.stat_result(values)
            return info
        with patch.object(update.os, "lstat", side_effect=lstat), self.assertRaises(core.ScannerError):
            update.executable(str(link))
        self.assertEqual(update.executable(str(link)), str(self.tool))
        (self.bin / "loop").symlink_to("loop")
        with self.assertRaises(core.ScannerError):
            update.executable(str(self.bin / "loop"))

    @unittest.skipUnless(sys.platform == "darwin", "macOS volumes that ignore ownership")
    def test_a_volume_that_ignores_ownership_is_refused(self):
        # External drives default to it: every file there looks owned by whoever asks, so others can change it.
        flags = process_store.MNT_LOCAL | process_store.MNT_IGNORE_OWNERSHIP
        with patch.object(process_store, "darwin_mount_flags", return_value=flags):
            self.refused()
        self.assertEqual(update.executable(str(self.tool)), str(self.tool))

    def test_files_and_folders_others_could_change_are_refused(self):
        for mode in (0o770, 0o600):  # group-writable, not executable
            with self.subTest(file=oct(mode)):
                self.tool.chmod(mode)
                self.refused()
        self.tool.chmod(0o700)
        for folder, mode in ((self.bin, 0o777), (self.bin, 0o1777), (self.base, 0o777)):
            # Sticky helps only when root owns the folder; a higher folder could let bin be renamed away and replaced.
            with self.subTest(folder=folder.name, mode=oct(mode)):
                folder.chmod(mode)
                try:
                    self.refused()
                finally:
                    folder.chmod(0o700)
        self.assertEqual(update.executable(str(self.tool)), str(self.tool))

    @unittest.skipUnless(sys.platform == "darwin", "macOS ACL entries apply regardless of the file mode")
    def test_ancestor_acl_letting_others_change_entries_is_refused(self):
        subprocess.run(["/bin/chmod", "+a", "everyone allow add_file,delete_child", str(self.bin)], check=True)
        self.refused()


@unittest.skipUnless(os.name == "posix", "POSIX durable state files")
class DurableStateTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()

    def test_new_state_reaches_the_disk_before_the_rename(self):
        file = self.base / "attempt.json"
        history.replace_private(file, b"old")
        seen = []
        def flush(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                seen.append(("folder", file.read_bytes()))
            else:
                # Not yet renamed, and the temporary file already holds the complete new data.
                temp, = self.base.glob(".attempt.json.*.tmp")
                self.assertEqual(os.fstat(fd).st_ino, temp.stat().st_ino)
                seen.append(("file", file.read_bytes(), temp.read_bytes()))
        with patch.object(history, "flush_to_disk", side_effect=flush):
            history.replace_private(file, b"new", durable=True)
            self.assertEqual(seen, [("file", b"old", b"new")])
            seen.clear()
            history.replace_private(file, b"plain")
            self.assertEqual(seen, [])  # other callers keep their plain replacement
            update.write_json(file, {"pending": True})
        state = b'{"pending": true}'
        self.assertEqual(seen, [("file", b"plain", state), ("folder", state)])

    def test_full_flush_where_available_and_fsync_where_it_is_refused(self):
        calls = []
        fd = os.open(self.base, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        with patch.object(history.os, "fsync", side_effect=lambda f: calls.append("fsync")):
            with patch.object(history.fcntl, "fcntl", side_effect=lambda f, op: calls.append(op)):
                history.flush_to_disk(fd)
            with patch.object(history.fcntl, "fcntl", side_effect=OSError("refused")):
                history.flush_to_disk(fd)
        full = getattr(history.fcntl, "F_FULLFSYNC", None)
        self.assertEqual(calls, [full if full is not None else "fsync", "fsync"])


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
