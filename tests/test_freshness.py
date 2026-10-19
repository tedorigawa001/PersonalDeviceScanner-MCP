"""Manager observations are bounded, supplementary and never a freshness verdict."""
import copy
import importlib.util
import json
import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from pc_scanner import freshness, history, dashboard
from pc_scanner.core import Scanner, ScannerError, result, encode_cursor

ENV = {'PC_SCANNER_WAZUH_MANAGER_USER': 'reader', 'PC_SCANNER_WAZUH_MANAGER_PASSWORD': 'secret-manager'}


def response(item):
    return json.dumps({'error': 0, 'data': {'affected_items': [item], 'total_affected_items': 1,
                                           'total_failed_items': 0, 'failed_items': []}}).encode()


class FreshnessTests(unittest.TestCase):
    def scanner(self, **settings):
        return Scanner({'history': {'enabled': False}, 'wazuh': {'url': 'https://indexer.example', 'agent_id': '001',
                        'agent_name': 'test-agent', 'freshness': {'enabled': True,
                        'manager_url': 'https://manager.example:55000', **settings}}})

    def report(self, status='completed'):
        return result('wazuh', status, findings=[{'kind': 'vulnerability', 'severity': 'high', 'id': 'CVE-TEST'}],
                      data={'freshness': 'unverified', 'live_scan_triggered': False,
                            'device': {'agent_names': ['test-agent']}})

    def bodies(self):
        when = datetime.now(timezone.utc).isoformat()
        return [b'header.payload.signature', response({'id': '001', 'name': 'test-agent', 'status': 'active',
                                                       'lastKeepAlive': when}),
                response({'agent_id': '001', 'scan': {'id': 0, 'time': when}})]

    def add(self, scanner=None, report=None, bodies=None, **kwargs):
        scanner = scanner or self.scanner()
        report = report or self.report()
        with patch.dict(os.environ, ENV), patch.object(freshness, 'fetch_bounded',
                side_effect=bodies or self.bodies()) as fetch:
            freshness.add(scanner, report, kwargs.pop('deadline', time.monotonic() + 30), **kwargs)
        return report, fetch

    def test_disabled_means_no_extra_network_or_credentials(self):
        report, fetch = self.add(self.scanner(enabled=False))
        fetch.assert_not_called()
        self.assertNotIn('freshness_evidence', report['data'])

    def test_success_is_supplementary_not_a_freshness_verdict(self):
        report, fetch = self.add()
        self.assertEqual(report['status'], 'completed')
        self.assertEqual(report['data']['freshness'], 'unverified')
        self.assertFalse(report['data']['live_scan_triggered'])
        self.assertEqual(report['data']['freshness_evidence']['agent_connection']['state'], 'recent')
        calls = fetch.call_args_list
        paths = [call.args[2].full_url for call in calls]
        self.assertEqual(paths, ['https://manager.example:55000/security/user/authenticate?raw=true',
                                'https://manager.example:55000/agents?agents_list=001&select=id,name,status,lastKeepAlive&limit=1',
                                'https://manager.example:55000/syscollector/001/os?select=scan.id,scan.time'])
        self.assertEqual([c.args[2].method for c in calls], ['POST', 'GET', 'GET'])
        self.assertTrue(all(0 < c.args[3] <= 5 for c in calls))
        self.assertEqual(calls[0].args[4], 16384)
        self.assertEqual(calls[1].args[4], 262144)
        shown = json.dumps(report)
        for private in ['secret-manager', 'header.payload.signature', 'manager.example', 'Bearer', 'Basic']:
            self.assertNotIn(private, shown)

    def test_boundary_exact_and_one_microsecond_over(self):
        now = datetime(2026, 10, 19, tzinfo=timezone.utc)
        for threshold in [300, 7200]:
            for extra, expected in [(0, 'recent'), (1, 'aged')]:
                value = (now - timedelta(seconds=threshold, microseconds=extra)).isoformat()
                self.assertEqual(freshness.observation(value, now, threshold)[0]['state'], expected)

    def test_invalid_missing_and_future_times(self):
        now = datetime.now(timezone.utc)
        for value in [None, 123, '2026-10-19', 'bad', '9' * 5000]:
            self.assertEqual(freshness.observation(value, now, 300)[0]['state'], 'unknown')
        for seconds, expected in [(60, 'recent'), (60.000001, 'unknown')]:
            observed, skew = freshness.observation((now + timedelta(seconds=seconds)).isoformat(), now, 300)
            self.assertEqual(observed['state'], expected)
            self.assertTrue(skew)

    def test_bad_fields_are_not_reported_as_recent(self):
        for label in ['missing', 'old', 'future', 'disconnected', 'unknown-status']:
            bodies = self.bodies()
            agent = json.loads(bodies[1])
            os_info = json.loads(bodies[2])
            if label == 'missing': os_info['data']['affected_items'][0].pop('scan')
            if label == 'old': os_info['data']['affected_items'][0]['scan']['time'] = '2000-01-01T00:00:00Z'
            if label == 'future': os_info['data']['affected_items'][0]['scan']['time'] = '2099-01-01T00:00:00Z'
            if label == 'disconnected': agent['data']['affected_items'][0]['status'] = 'disconnected'
            if label == 'unknown-status': agent['data']['affected_items'][0]['status'] = 'invented'
            bodies[1:3] = [json.dumps(agent).encode(), json.dumps(os_info).encode()]
            report, _ = self.add(bodies=bodies)
            self.assertEqual(report['status'], 'partial', label)
            self.assertEqual(len(report['findings']), 1)
            if label == 'old': self.assertIn('does not prove collection has stopped', ' '.join(report['warnings']))

    def test_foreign_agent_or_identity_is_not_adopted(self):
        for endpoint, field, value in [(1, 'id', '002'), (1, 'name', 'other-agent'), (2, 'agent_id', '002')]:
            bodies = self.bodies()
            data = json.loads(bodies[endpoint]); data['data']['affected_items'][0][field] = value
            bodies[endpoint] = json.dumps(data).encode()
            report, _ = self.add(bodies=bodies)
            self.assertEqual(report['status'], 'partial')
            self.assertIsNone(report['data']['freshness_evidence']['os_record']['recorded_at'])
            self.assertNotIn('other-agent', json.dumps(report))

    def test_partial_and_error_statuses_are_not_upgraded(self):
        for status in ['partial', 'error']:
            report, _ = self.add(report=self.report(status))
            self.assertEqual(report['status'], status)

    def test_failure_classes_preserve_findings_and_hide_exception_text(self):
        for failure in [HTTPError('https://secret-host', code, 'secret-manager', {}, None)
                        for code in [400, 401, 403, 404, 429, 500]] + [
                            OSError('header.payload.signature'), ScannerError('secret-manager'),
                            ValueError('secret-manager')]:
            report, _ = self.add(bodies=[failure])
            self.assertEqual(report['status'], 'partial')
            self.assertEqual(len(report['findings']), 1)
            self.assertNotIn('secret-manager', json.dumps(report))
            self.assertNotIn('secret-host', json.dumps(report))

    def test_application_failure_empty_and_invalid_response(self):
        for payload in [b'not-json', b'{}', response({}),
                        json.dumps({'error': 0, 'data': {'affected_items': [], 'total_affected_items': 0,
                                                        'total_failed_items': 0, 'failed_items': []}}).encode()]:
            report, _ = self.add(bodies=[b'a.b.c', payload])
            self.assertEqual(report['status'], 'partial')
        body = json.loads(self.bodies()[1]);body['data']['total_failed_items'] = 1
        report, _ = self.add(bodies=[b'a.b.c', json.dumps(body).encode()])
        self.assertEqual(report['status'], 'partial')

    def test_invalid_token_and_missing_credentials_do_not_fallback(self):
        report, fetch = self.add(bodies=[b'token\r\nprivate'])
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(report['status'], 'partial')
        scanner, report = self.scanner(), self.report()
        with patch.dict(os.environ, {'PC_SCANNER_WAZUH_MANAGER_USER': '', 'PC_SCANNER_WAZUH_MANAGER_PASSWORD': ''}), \
                patch.object(freshness, 'fetch_bounded') as fetch:
            freshness.add(scanner, report, time.monotonic() + 30)
        fetch.assert_not_called()
        self.assertEqual(report['status'], 'partial')

    def test_expired_budget_and_cancel_preserve_findings(self):
        report, fetch = self.add(deadline=time.monotonic() - 1)
        fetch.assert_not_called()
        self.assertEqual(report['status'], 'partial')
        cancel = threading.Event();cancel.set()
        report, fetch = self.add(cancel=cancel)
        fetch.assert_not_called()
        self.assertIn('cancelled', ' '.join(report['warnings']))
        self.assertEqual(len(report['findings']), 1)

    def test_common_budget_is_not_restarted_per_request(self):
        bodies = self.bodies()
        scanner, report = self.scanner(), self.report()
        budgets = []
        def fetch(*args, **kwargs):
            budgets.append(args[3]);time.sleep(.02);return bodies.pop(0)
        with patch.dict(os.environ, ENV), patch.object(freshness, 'fetch_bounded', side_effect=fetch):
            freshness.add(scanner, report, time.monotonic() + .3)
        self.assertEqual(len(budgets), 3)
        self.assertTrue(.0 < budgets[2] < budgets[1] < budgets[0] <= .3)

    def test_configuration_and_unknown_keys(self):
        for settings in [{'enabled': 1}, {'max_keepalive_age_seconds': True}, {'max_os_record_age_seconds': 604801},
                         {'manager_url': 'http://manager'}, {'manager_url': 'https://user:pass@manager'},
                         {'manager_url': 'https://@manager'}, {'manager_url': 'https://manager#'},
                         {'manager_url': 'https://manager/'}, {'manager_url': 'https://manager?secret'},
                         {'ca_file': 'relative.pem'}]:
            with self.assertRaises(ScannerError):self.scanner(**settings)
        scanner = self.scanner(password='secret-manager', invented=1)
        self.assertEqual(len(scanner.config_warnings), 2)
        self.assertNotIn('secret-manager', ' '.join(scanner.config_warnings))
        self.assertIn('remove credentials', ' '.join(scanner.config_warnings))

    def test_core_invokes_only_after_valid_index_results(self):
        payload = {'hits': {'total': {'value': 1, 'relation': 'eq'}, 'hits': [{'_source': {
            'agent': {'id': '001', 'name': 'test-agent'}, 'vulnerability': {'id': 'CVE-TEST', 'severity': 'high'}}}]}}
        env = {**ENV, 'PC_SCANNER_WAZUH_USER': 'index-reader', 'PC_SCANNER_WAZUH_PASSWORD': 'index-secret'}
        with patch.dict(os.environ, env), patch('pc_scanner.core.fetch_bounded', return_value=json.dumps(payload).encode()), \
                patch.object(freshness, 'fetch_bounded', side_effect=self.bodies()):
            report = self.scanner().invoke('vulnerabilities')
        self.assertEqual(report['status'], 'completed')
        self.assertIn('freshness_evidence', report['data'])
        with patch.dict(os.environ, env), patch('pc_scanner.core.fetch_bounded', side_effect=ScannerError('index failed')), \
                patch.object(freshness, 'fetch_bounded') as fetch:
            report = self.scanner().invoke('vulnerabilities')
        self.assertEqual(report['status'], 'error');fetch.assert_not_called()

    def test_indexer_time_is_deducted_from_manager_budget(self):
        payload = {'hits': {'total': 0, 'hits': []}}
        scanner = self.scanner()
        scanner.timeout = 1
        def indexed(*args, **kwargs):
            time.sleep(.08)
            return json.dumps(payload).encode()
        def supplementary(scanner, report, deadline, cancel):
            self.assertGreater(deadline - time.monotonic(), 0)
            self.assertLess(deadline - time.monotonic(), .95)
        with patch.dict(os.environ, {'PC_SCANNER_WAZUH_USER': 'reader', 'PC_SCANNER_WAZUH_PASSWORD': 'secret'}), \
                patch('pc_scanner.core.fetch_bounded', side_effect=indexed), \
                patch.object(freshness, 'add', side_effect=supplementary) as add:
            report = scanner.invoke('vulnerabilities')
        add.assert_called_once()
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(report['findings'], [])

    def test_summary_history_and_page_retry_use_fixed_metadata_without_details(self):
        first, _ = self.add()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'history.jsonl'
            started = datetime.now(timezone.utc)
            cursor = encode_cursor(2, [9.8, 'CVE-TEST', 'x', '1', 'a', 't', ''])
            for value in ['', cursor, cursor]:
                record = history.entry('vulnerabilities', {'cursor': value}, first, started, .1, 'cli')
                history.append(path, record)
            entries, skipped = history.read(path, 10)
            run = dashboard.latest_runs(entries)[0]
            self.assertEqual(len(run), 2)
            notes = dashboard.freshness_notes(run)
            self.assertIn('Vulnerability assessment completion: unverified', notes)
            self.assertIn('Index result retrieved (oldest page):', notes)
            self.assertNotIn('secret-manager', path.read_text())
            self.assertNotIn('manager.example', path.read_text())
            self.assertNotIn('Some pages', notes)
            run[0][1].pop('freshness_evidence')
            self.assertIn('Some pages', dashboard.freshness_notes(run))

    def test_history_metadata_is_normalized_and_extra_fields_removed(self):
        report, _ = self.add()
        data = report['data']['freshness_evidence']
        data['password'] = 'never keep'
        data['checked_at'] = '2026-10-19\u202e12:00:00+00:00'
        kept = freshness.project(data)
        self.assertNotIn('never keep', json.dumps(kept))
        self.assertNotIn('\u202e', json.dumps(kept, ensure_ascii=False))

    def test_dashboard_uses_oldest_observation_and_worst_state(self):
        report, _ = self.add()
        old = copy.deepcopy(report['data']['freshness_evidence'])
        old['checked_at'] = '2026-01-01T00:00:00+00:00'
        old['os_record']['state'] = 'aged'
        new = copy.deepcopy(report['data']['freshness_evidence'])
        run = [(0, {'freshness_evidence': old}), (1, {'freshness_evidence': new})]
        notes = dashboard.freshness_notes(run)
        self.assertIn('2026-01-01T00:00:00.000000+00:00', notes)
        self.assertIn('(aged)', notes)
        self.assertIn('Last communication', notes)

    @unittest.skipUnless(importlib.util.find_spec('cryptography'), 'cryptography not installed')
    def test_real_tls_stalls_obey_deadline_and_cancel_and_end_thread(self):
        from test_scanner import SlowWazuhServer, wait_for
        for mode in ['deadline', 'cancel']:
            for headers in [False, True]:
                with self.subTest(mode=mode, headers=headers), tempfile.TemporaryDirectory() as folder, \
                        SlowWazuhServer(Path(folder), headers_only=headers) as server:
                    scanner = self.scanner(manager_url=server.url, ca_file=str(server.ca_file))
                    report = self.report()
                    cancel = threading.Event()
                    timer = threading.Timer(.2, cancel.set) if mode == 'cancel' else None
                    if timer:timer.start()
                    started = time.monotonic()
                    try:
                        with patch.dict(os.environ, ENV):
                            freshness.add(scanner, report, started + (.4 if mode == 'deadline' else 2), cancel)
                    finally:
                        if timer:timer.cancel()
                    self.assertLess(time.monotonic() - started, 1)
                    self.assertEqual(report['status'], 'partial')
                    self.assertEqual(len(report['findings']), 1)
                    if mode == 'cancel':self.assertIn('cancelled', ' '.join(report['warnings']))
                    self.assertTrue(wait_for(lambda: not any(t.name == 'wazuh manager-request'
                                                           for t in threading.enumerate()), 4))


if __name__ == '__main__':
    unittest.main()
