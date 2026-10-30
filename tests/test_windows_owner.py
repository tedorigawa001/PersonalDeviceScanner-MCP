"""Ownership boundaries, including real Windows security descriptors in CI."""
import contextlib
import ctypes
from types import SimpleNamespace
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from pc_scanner import history, updates


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "history.jsonl"
        self.path.write_text("foreign data")

    def test_foreign_file_is_not_appended_or_read_as_cache(self):
        with patch.object(history, "owned", return_value=False):
            with self.path.open("rb") as f:
                with self.assertRaises(OSError):
                    history.private(f.fileno())
            self.assertIsNone(history.read_private(self.path, 100))
        self.assertEqual(self.path.read_text(), "foreign data")

    def test_windows_reads_reject_foreign_history_and_details(self):
        from pc_scanner import windows_owner
        name = "20261019T000000.000000Z-12345678"
        history.details_folder(self.path).mkdir()
        (history.details_folder(self.path) / (name + ".json")).write_text('{"status":"completed"}')
        with patch.object(history.os, "name", "nt"), patch.object(windows_owner, "owns_fd", return_value=False), \
                patch.object(history, "locked", return_value=contextlib.nullcontext()):
            with self.assertRaises(OSError):
                history.read(self.path, 10)
            self.assertEqual(history.load_details(self.path, name), (None, "unreadable"))
            self.assertEqual(updates.load(self.path), {})

    def test_windows_rotation_checks_ownership_before_rename(self):
        from pc_scanner import windows_owner
        with patch.object(history.os, "name", "nt"), patch.object(windows_owner, "owns_fd", return_value=False), \
                patch.object(history, "locked", return_value=contextlib.nullcontext()), \
                patch.object(history, "FILE_BYTES", 1):
            with self.assertRaises(OSError):
                history.append(self.path, {})
        self.assertFalse(history.older(self.path).exists())
        self.assertEqual(self.path.read_text(), "foreign data")

    def test_windows_foreign_details_directory_is_not_used(self):
        from pc_scanner import windows_owner
        with patch.object(history.os, "name", "nt"), \
                patch.object(windows_owner, "owns_directory", return_value=False):
            with self.assertRaises(OSError):
                history.save_details(self.path, {}, 100)
        self.assertEqual(list(history.details_folder(self.path).iterdir()), [])

    def test_windows_owner_api_error_closes_file_and_ignores_cache(self):
        from pc_scanner import windows_owner
        with patch.object(history.os, "name", "nt"), \
                patch.object(windows_owner, "owns_fd", side_effect=OSError("owner unavailable")):
            self.assertIsNone(history.read_private(self.path, 100))
            with self.assertRaises(OSError):
                history.opener(self.path, os.O_RDONLY)
        self.path.unlink()  # Windows refuses this if a failed open leaked its handle.

    def test_cache_owner_api_failure_after_open_is_ignored(self):
        from pc_scanner import windows_owner
        with patch.object(history.os, "name", "nt"), \
                patch.object(windows_owner, "owns_fd", side_effect=[True, OSError("owner unavailable")]):
            self.assertIsNone(history.read_private(self.path, 100))


class CheckpointHandleTests(unittest.TestCase):
    def api(self):
        from unittest.mock import MagicMock
        kernel = MagicMock()
        kernel.CreateFileW.return_value = 123
        kernel.SetFileInformationByHandle.return_value = 1
        return kernel

    def test_delete_open_requests_exact_access_and_closes_on_fd_conversion_failure(self):
        from pc_scanner import windows_owner as w
        kernel = self.api()
        def fail(*args): raise OSError("conversion failed")
        crt = SimpleNamespace(open_osfhandle=fail)
        with patch.object(w.ctypes, "WinDLL", return_value=kernel, create=True), \
             patch.object(w.os, "O_BINARY", 0, create=True), patch.dict(sys.modules, {"msvcrt": crt}):
            with self.assertRaises(OSError): w.open_checkpoint("synthetic.json", delete=True)
        args = kernel.CreateFileW.call_args.args
        self.assertEqual(args[1:3], (0x80030000, 1))
        self.assertEqual(args[4:6], (3, 0x00300000))
        kernel.CloseHandle.assert_called_once_with(123)
        kernel.SetFileInformationByHandle.assert_not_called()

    def test_disposition_is_one_byte_and_api_failure_never_falls_back(self):
        from pc_scanner import windows_owner as w
        kernel = self.api()
        crt = SimpleNamespace(get_osfhandle=lambda fd: 123)
        with patch.object(w.ctypes, "WinDLL", return_value=kernel, create=True), \
             patch.object(w.ctypes, "get_last_error", return_value=5, create=True), \
             patch.object(w.ctypes, "WinError", side_effect=lambda code: OSError(code, "denied"), create=True), \
             patch.dict(sys.modules, {"msvcrt": crt}):
            w.delete_checkpoint_handle(7)
            args = kernel.SetFileInformationByHandle.call_args.args
            self.assertEqual((args[0], args[1], args[3]), (123, 4, 1))
            self.assertEqual(ctypes.cast(args[2], ctypes.POINTER(ctypes.c_ubyte))[0], 1)
            kernel.SetFileInformationByHandle.return_value = 0
            with self.assertRaises(OSError): w.delete_checkpoint_handle(7)


@unittest.skipUnless(os.name == "nt", "Windows security APIs")
class WindowsOwnershipTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "history.jsonl"
        self.path.write_text("owner data")

    def test_real_user_or_elevated_default_owner_is_accepted(self):
        from pc_scanner.windows_owner import owns_fd, owns_directory
        with self.path.open("rb") as f:
            self.assertTrue(owns_fd(f.fileno()))
            history.private(f.fileno())
        self.assertTrue(owns_directory(self.path.parent))
        self.assertEqual(history.read_private(self.path, 100), b"owner data")
        history.replace_private(self.path, b"updated")
        self.assertEqual(history.read_private(self.path, 100), b"updated")

    def test_real_hard_link_is_refused(self):
        link = self.path.with_name("hard-link")
        os.link(self.path, link)
        self.assertIsNone(history.read_private(link, 100))
        with self.assertRaises(OSError):
            history.make_private(link)

    def test_real_foreign_owner_is_refused(self):
        # The CI runner is elevated; icacls assigns the built-in Users group, not this token's user/default owner.
        result = subprocess.run(["icacls", str(self.path), "/setowner", "*S-1-5-32-545", "/Q"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIsNone(history.read_private(self.path, 100))
        with self.assertRaises(OSError):
            history.make_private(self.path)
        with self.assertRaises(OSError):
            history.read(self.path, 10)


if __name__ == "__main__":
    unittest.main()
