"""Native macOS ACL boundary regressions using disposable, synthetic stores only."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pc_scanner import history, malware_batch, checkpoints, coverage, dashboard
from pc_scanner.core import Scanner, ScannerError


@unittest.skipUnless(sys.platform == 'darwin', 'Native macOS extended ACLs')
class HistoryACLTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.folder = self.base / 'state'
        self.folder.mkdir(mode=0o700)
        self.path = self.folder / 'history.jsonl'

    def acl(self, path, text='everyone allow read'):
        subprocess.run(['/bin/chmod', '+a', text, str(path)], check=True, capture_output=True)

    def scanner(self):
        return Scanner({'history': {'file': str(self.path)}, 'scan_roots': {'fixture': str(self.base)}})

    def checkpoint(self):
        folder = malware_batch.checkpoint_directory(self.scanner(), create=True)
        path = folder / ('a'*64 + '.json')
        data = {'schema': 2, 'context': 'synthetic', 'parts': {}, 'coverage': coverage.new_ledger(),
                'target': {'root_alias': 'fixture', 'relative_path': '.'}}
        history.replace_private(path, json.dumps(data).encode())
        return folder, path

    def test_inherited_allow_refuses_history_and_detail_payload_without_acl_repair(self):
        self.acl(self.folder, 'everyone allow read,file_inherit,directory_inherit')
        with self.assertRaises(OSError):
            history.append(self.path, {'synthetic': 'summary'}, {'synthetic': 'detail'}, 4096)
        self.assertFalse(self.path.exists())
        self.assertFalse(history.details_folder(self.path).exists())
        fd = os.open(self.folder, os.O_RDONLY)
        try:
            from pc_scanner.process_store import acl_allows
            self.assertTrue(acl_allows(fd))
        finally:
            os.close(fd)

    def test_allow_on_0600_current_and_rotated_files_is_refused_before_rotation(self):
        for selected in ('current', 'older'):
            with self.subTest(selected=selected):
                self.setUp()
                for path in (self.path, history.older(self.path)):
                    path.write_text('synthetic preserved\n'); path.chmod(0o600)
                target = self.path if selected == 'current' else history.older(self.path)
                self.acl(target)
                with patch.object(history, 'FILE_BYTES', 1), self.assertRaises(OSError):
                    history.append(self.path, {'synthetic': 'new'})
                self.assertEqual(self.path.read_text(), 'synthetic preserved\n')
                self.assertEqual(history.older(self.path).read_text(), 'synthetic preserved\n')

    def test_allow_file_is_not_read_and_read_does_not_change_mode(self):
        self.path.write_text('synthetic private\n'); self.path.chmod(0o400); self.acl(self.path)
        self.assertIsNone(history.read_private(self.path, 4096))
        with self.assertRaises(OSError):
            history.read(self.path, 10)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o400)

    def test_lock_allow_is_refused_but_safe_read_fallback_still_works(self):
        history.append(self.path, {'synthetic': 'old'})
        lock = history.lock_file(self.path); self.acl(lock)
        with self.assertRaises(OSError):
            history.append(self.path, {'synthetic': 'new'})
        before = self.path.read_bytes()
        history.read(self.path, 10)  # lock acquisition failure may fall back to an independently safe read
        self.assertEqual(self.path.read_bytes(), before)
        self.acl(self.path)
        with self.assertRaises(OSError):
            history.read(self.path, 10)  # the read fallback must not bypass the actual file ACL

    def test_explicit_detail_file_and_folder_allow_are_unreadable(self):
        name = history.save_details(self.path, {'synthetic': 'detail'}, 4096)
        path = history.details_folder(self.path) / (name+'.json'); self.acl(path)
        self.assertEqual(history.load_details(self.path, name), (None, 'unreadable'))
        self.acl(history.details_folder(self.path))
        with self.assertRaises(OSError):
            history.save_details(self.path, {'synthetic': 'new'}, 4096)

    def test_atomic_dashboard_and_cache_writes_refuse_inheritable_allow(self):
        self.acl(self.folder, 'everyone allow read,file_inherit,directory_inherit')
        for path, write in ((self.folder/'page.html', lambda p: dashboard.write(p, 'synthetic HTML')),
                            (history.releases_file(self.path), lambda p: history.replace_private(p, b'synthetic cache'))):
            with self.subTest(name=path.name), self.assertRaises(OSError):
                write(path)
            self.assertFalse(path.exists())
        self.assertFalse(list(self.folder.glob('*.tmp')))

    def test_checkpoint_allow_file_is_unavailable_and_cannot_be_deleted(self):
        _, path = self.checkpoint()
        before = checkpoints.list_checkpoints(self.scanner())['data']['checkpoints'][0]
        self.assertTrue(before['deletable'])
        self.acl(path)
        row = checkpoints.list_checkpoints(self.scanner())['data']['checkpoints'][0]
        self.assertEqual(row['state'], 'unavailable')
        self.assertFalse(row['deletable'])
        with self.assertRaises(ScannerError):
            checkpoints.delete_checkpoint(self.scanner(), before['checkpoint_id'], before['revision'])
        self.assertTrue(path.exists())

    def test_checkpoint_folder_allow_prevents_creation_and_listing(self):
        folder, path = self.checkpoint(); self.acl(folder)
        with self.assertRaises((OSError, ScannerError)):
            malware_batch.checkpoint_directory(self.scanner(), create=True)
        with self.assertRaises(ScannerError):
            checkpoints.list_checkpoints(self.scanner())
        self.assertTrue(path.exists())

    def test_deny_only_inheritance_preserves_history_details_and_checkpoints(self):
        self.acl(self.folder, 'everyone deny chown,file_inherit,directory_inherit')
        history.append(self.path, {'synthetic': 'summary'}, {'synthetic': 'detail'}, 4096)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        name = next(history.details_folder(self.path).glob('*.json')).stem
        self.assertEqual(history.load_details(self.path, name), ({'synthetic': 'detail'}, ''))
        folder, path = self.checkpoint()
        self.assertTrue(checkpoints.list_checkpoints(self.scanner())['data']['checkpoints'][0]['deletable'])
        self.assertEqual(history.read_private(path, 4096), path.read_bytes())

    def test_existing_allow_atomic_target_is_preserved_instead_of_silently_repaired(self):
        self.path.write_text('synthetic original');self.path.chmod(0o600);self.acl(self.path)
        with self.assertRaises(OSError):
            history.replace_private(self.path, b'synthetic replacement')
        self.assertEqual(self.path.read_text(), 'synthetic original')

    def test_unsafe_old_detail_is_not_deleted_or_replaced_by_retention(self):
        name = history.save_details(self.path, {'synthetic': 'old'}, 4096)
        record = history.details_folder(self.path) / (name+'.json');self.acl(record)
        with self.assertRaises(OSError):
            history.save_details(self.path, {'synthetic': 'new'}, 1)
        self.assertTrue(record.exists())
        self.assertEqual(len(list(history.details_folder(self.path).glob('*.json'))), 1)

    def test_acl_query_failure_is_not_treated_as_private(self):
        from pc_scanner.posix_acl import acl_allows
        self.assertTrue(acl_allows(-1))
        with self.assertRaises(OSError):
            history.require_private_acl(-1)

    def test_owner_only_write_and_search_permissions_keep_working(self):
        self.folder.chmod(0o300)
        try:
            history.append(self.path, {'synthetic': 'created without directory listing'})
        finally:
            self.folder.chmod(0o700)
        self.path.chmod(0o200)
        try:
            history.append(self.path, {'synthetic': 'appended without file reading'})
            history.replace_private(self.path, b'synthetic replacement')
        finally:
            self.path.chmod(0o600)
        self.assertEqual(self.path.read_bytes(), b'synthetic replacement')
        self.folder.chmod(0o100)
        try:
            self.assertEqual(history.read_private(self.path, 4096), b'synthetic replacement')
        finally:
            self.folder.chmod(0o700)

    def test_history_failure_warns_without_changing_scan_result_or_acl(self):
        from pc_scanner.core import result
        scanner = self.scanner()
        scanner.via = "cli"
        self.acl(self.folder, 'everyone allow read,file_inherit,directory_inherit')
        with patch.object(scanner, 'inventory', return_value=result('osquery', 'completed')):
            response = scanner.invoke('inventory', query_id='applications')
        self.assertEqual(response['status'], 'completed')
        self.assertIn('Scan history could not be written; the scan itself is unaffected', response['warnings'])
        self.assertFalse(self.path.exists())

    def test_bytes_path_opener_preserves_safe_reads_and_rejects_allow_acl(self):
        self.path.write_bytes(b'synthetic bytes path');self.path.chmod(0o600)
        with open(os.fsencode(self.path), 'rb', opener=history.opener) as source:
            self.assertEqual(source.read(), b'synthetic bytes path')
        self.acl(self.path)
        with self.assertRaises(OSError):
            open(os.fsencode(self.path), 'rb', opener=history.opener)


if __name__ == '__main__':
    unittest.main()
