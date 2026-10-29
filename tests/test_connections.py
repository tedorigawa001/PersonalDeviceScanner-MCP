"""Synthetic socket observations only: never inspect the owner's connections or history."""
import asyncio
import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from pc_scanner import connections as c, history, dashboard
from pc_scanner.core import Scanner, ScannerError
from pc_scanner.progress import ScanProgress, message


class Clock:
    def __init__(self): self.value = 100.0
    def monotonic(self): return self.value
    def sleep(self, value): self.value += value


class ConnectionTests(unittest.TestCase):
    def setUp(self):
        self.writes = []
        p = patch("pc_scanner.history.append", side_effect=lambda *a, **k: self.writes.append(a))
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(lambda: self.assertEqual(self.writes, [], "real history write attempted"))

    def scanner(self, **settings):
        return Scanner({"history": {"enabled": False}, "outbound_connections": {
            "enabled": True, "duration_seconds": 2, "interval_seconds": 1, **settings}})

    def row(self, **changes):
        return {"pid": "42", "start_time": "1000", "process": "/private/example/app<test>", "family": "2",
            "protocol": "6", "local_address": "192.168.1.2", "local_port": "50001", "remote_address": "8.8.8.8",
            "remote_port": "443", "state": "ESTABLISHED", **changes}

    def observe(self, rows=None, scanner=None, addresses=None, sockets=None, **kwargs):
        clock = Clock()
        snapshot = ({"192.168.1.2"}, {"192.168.1.255"}, {("en0", "192.168.1.2")})
        with patch.object(c.Backend, "__init__", lambda self, *a: setattr(self, "limits", set())), \
             patch.object(c.Backend, "addresses", side_effect=addresses, return_value=snapshot), \
             patch.object(c.Backend, "sockets", side_effect=sockets, return_value=rows if rows is not None else [self.row()]), \
             patch.object(c.time, "monotonic", clock.monotonic), patch.object(c.time, "sleep", clock.sleep):
            return (scanner or self.scanner()).invoke("observe_outbound_connections", **kwargs)

    def test_disabled_and_mcp_gate_never_collect(self):
        for scanner in [Scanner({"history": {"enabled": False}}), self.scanner()]:
            scanner.via = "mcp"
            with patch.object(c, "Backend", side_effect=AssertionError("unauthorized collection")):
                r = scanner.invoke("observe_outbound_connections")
            self.assertEqual(r["status"], "error")

    def test_settings_validation_and_unknown_key_warning(self):
        for key, val in [("enabled", 1), ("duration_seconds", 61), ("interval_seconds", 3),
                         ("max_connections", 0), ("max_connections", 2001), ("expose_identifiers_to_mcp", "true"),
                         ("save_details", "true")]:
            with self.subTest(key=key), self.assertRaises(ScannerError): self.scanner(**{key: val})
        self.assertIn("outbound_connections.enabld", str(self.scanner(enabld=True).config_warnings))
        self.assertEqual(self.scanner(save_details=False, max_connections=2000).config_warnings, [])
        with self.assertRaises(ScannerError): Scanner({"outbound_connections": []})

    def test_same_socket_same_sample_and_across_samples_not_double_counted(self):
        r = self.observe([self.row(), self.row()])
        self.assertEqual(r["status"], "completed", r)
        self.assertEqual(r["data"]["connection_count"], 1)
        self.assertEqual(r["data"]["connections"][0]["sample_count"], 2)
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["data"]["connections"][0]["direction"], "unknown")
        self.assertIn("process_join_not_atomic", r["data"]["coverage"])

    def test_pid_reuse_ports_and_unknown_start_not_merged(self):
        rows = [self.row(), self.row(start_time="1001"), self.row(local_port="50002"), self.row(start_time="-1")]
        r = self.observe(rows)
        self.assertEqual(r["data"]["connection_count"], 5)
        self.assertEqual(r["data"]["process_count"], 2)
        self.assertEqual(r["status"], "partial")
        self.assertIn("attribution_unavailable", r["data"]["limitations"])

    def test_payload_cmdline_environment_paths_never_enter_results_or_history(self):
        r = self.observe([self.row(payload="PAYLOAD_SECRET", cmdline="ARGV_SECRET", environment="ENV_SECRET", path="PATH_SECRET")])
        s = json.dumps(r)
        for secret in ["PAYLOAD_SECRET", "ARGV_SECRET", "ENV_SECRET", "PATH_SECRET", "/private/example"]:
            self.assertNotIn(secret, s)
        self.assertEqual(r["data"]["connections"][0]["process"], "app<test>")
        entry = history.entry("observe_outbound_connections", {}, r, datetime.now(timezone.utc), 1, "cli")
        s = json.dumps(history.parse(json.dumps({**entry, "connection_observation": {
            **entry["connection_observation"], "payload": "PAYLOAD_SECRET", "process": "PRIVATE_NAME"}})))
        for secret in ["PAYLOAD_SECRET", "PRIVATE_NAME", "8.8.8.8", "app<test>"]: self.assertNotIn(secret, s)

    def test_fixed_backend_queries_never_request_payload_or_command_line(self):
        scanner = self.scanner()
        calls = []
        def run(argv, timeout, limit, cancel=None):
            calls.append((argv, timeout, limit))
            return 0, json.dumps([{"interface": "en0", "address": "192.168.1.2", "broadcast": "192.168.1.255"}]
                                  if argv[-1] == c.ADDRESS_SQL else [self.row()]), ""
        with patch.object(scanner, "binary", return_value="/fixed/osqueryi"), patch.object(c, "run_bounded", side_effect=run):
            b = c.Backend(scanner, time.monotonic() + 10, None)
            b.addresses(); b.sockets()
        self.assertEqual({x[0][-1] for x in calls}, {c.SOCKET_SQL, c.ADDRESS_SQL})
        for argv, timeout, limit in calls:
            self.assertEqual(argv[:4], ["/fixed/osqueryi", "-S", "--json", "--disable_extensions=true"])
            self.assertIn("--disable_logging=true", argv)
            self.assertIn("--disable_events=true", argv)
            self.assertLessEqual(timeout, 2)
            self.assertEqual(limit, 2 * 1024 * 1024)
            for forbidden in ["cmdline", "payload", "path", "SELECT *"]: self.assertNotIn(forbidden, argv[-1])

    def test_stderr_and_failed_output_do_not_leak(self):
        scanner = self.scanner()
        with patch.object(scanner, "binary", return_value="/fixed/osqueryi"), patch.object(c, "run_bounded", return_value=(1, "PRIVATE", "PRIVATE")):
            r = scanner.invoke("observe_outbound_connections")
        self.assertNotIn("PRIVATE", json.dumps(r))
        self.assertEqual(r["status"], "error")

    def test_cancel_before_first_read_and_busy(self):
        scanner, cancel = self.scanner(), threading.Event()
        cancel.set()
        with patch.object(c, "Backend", side_effect=AssertionError("cancelled read")):
            r = scanner.invoke("observe_outbound_connections", cancel=cancel)
        self.assertEqual((r["status"], r["data"]["stop_reason"]), ("partial", "cancelled"))
        scanner._connection_lock.acquire()
        try:
            self.assertIn("busy", scanner.invoke("observe_outbound_connections")["error"])
        finally: scanner._connection_lock.release()
        self.assertFalse(scanner._connection_lock.locked())

    def test_cancel_during_backend_read_is_partial_not_error(self):
        cancel, scanner = threading.Event(), self.scanner()
        def run(*a, **k):
            cancel.set()
            raise ScannerError("SECRET raw error")
        with patch.object(scanner, "binary", return_value="/fixed/osqueryi"), patch.object(c, "run_bounded", side_effect=run):
            r = scanner.invoke("observe_outbound_connections", cancel=cancel)
        self.assertEqual((r["status"], r["data"]["stop_reason"]), ("partial", "cancelled"))
        self.assertNotIn("SECRET", json.dumps(r))

    def test_read_deadline_at_exact_boundary_and_one_microsecond_later(self):
        for elapsed in [2.0, 2.000001]:
            with self.subTest(elapsed=elapsed):
                clock, scanner = Clock(), self.scanner()
                def run(*a, **k): clock.value += elapsed; return 0, "[]", ""
                with patch.object(scanner, "binary", return_value="/fixed/osqueryi"), \
                     patch.object(c.time, "monotonic", clock.monotonic), patch.object(c, "run_bounded", side_effect=run):
                    b = c.Backend(scanner, 200, None)
                    with self.assertRaises(ScannerError): b.sockets()

    def test_process_and_total_deadline_and_empty_window(self):
        r = self.observe([])
        self.assertEqual(r["status"], "completed")
        self.assertEqual(r["data"]["connection_count"], 0)
        self.assertIn("short_lived_connections_may_be_missed", r["data"]["limitations"])
        with patch.object(c.time, "monotonic", return_value=5):
            with self.assertRaises(c.Stopped): c.check(5, None)
        with patch.object(c.time, "monotonic", return_value=5.000001):
            with self.assertRaises(c.Stopped): c.check(5, None)

    def test_network_change_preserves_previous_samples(self):
        old = ({"192.168.1.2"}, set(), {"old"})
        new = ({"192.168.1.3"}, set(), {"new"})
        r = self.observe(addresses=[old, old, new])
        self.assertEqual((r["status"], r["data"]["stop_reason"]), ("partial", "network_changed"))
        self.assertEqual(r["data"]["connection_count"], 1)

    def test_limits_and_malformed_rows(self):
        r = self.observe([self.row(), self.row(local_port="50002")], scanner=self.scanner(max_connections=1))
        self.assertEqual((r["status"], r["data"]["stop_reason"]), ("partial", "connection_limit"))
        self.assertEqual(r["data"]["connection_count"], 1)
        r = self.observe([self.row(remote_port="99999"), self.row()])
        self.assertEqual(r["data"]["unavailable_counts"]["invalid_rows"], 2)
        self.assertEqual(r["status"], "partial")

    def test_default_limit_fits_the_result_and_states_are_bounded(self):
        rows = [self.row(local_port=str(10000 + i)) for i in range(2000)]
        r = self.observe(rows)
        self.assertEqual((r["status"], r["data"]["connection_count"]), ("completed", 2000), r["data"]["limitations"])
        r = self.observe(rows + [self.row(local_port="9999")])
        self.assertEqual((r["status"], r["data"]["stop_reason"]), ("partial", "connection_limit"))
        # A record that went through every state still stays within what was reserved for it.
        first = self.observe(scanner=self.scanner(duration_seconds=1))["data"]["connections"][0]
        states = [f"STATE_{i:010d}" for i in range(20)]
        grown = self.observe(scanner=self.scanner(duration_seconds=20), sockets=[[self.row(state=v)] for v in states])
        grown = grown["data"]["connections"][0]
        self.assertEqual((len(grown["states"]), grown["sample_count"]), (16, 20))
        self.assertLessEqual(len(json.dumps(grown)), len(json.dumps(first)) - len("ESTABLISHED") + len(states[0]) + c.GROWTH)
        for state, expected in [("FIN_WAIT_1", "FIN_WAIT_1"), ("FIN_WAIT2", "FIN_WAIT2"), ("X" * 17, "unknown")]:
            with self.subTest(state=state):
                normalized, _ = c.normalize(self.row(state=state), set(), set(), 1, "t")
                self.assertEqual(normalized[1]["states"], [expected])

    def test_details_need_both_history_details_and_save_details(self):
        with tempfile.TemporaryDirectory() as temp:
            for details, save, expected in [(True, False, "summary_saved"), (False, True, "summary_saved"),
                                            (True, True, "details_saved")]:
                with self.subTest(details=details, save=save):
                    path = Path(temp) / f"{details}-{save}" / "history.jsonl"
                    scanner = Scanner({"history": {"file": str(path), "details": details}, "outbound_connections": {
                        "enabled": True, "duration_seconds": 1, "interval_seconds": 1, "save_details": save}})
                    scanner.via = "cli"
                    # The real writer, only into this temporary folder.
                    with patch.object(history, "append", history_append):
                        r = self.observe(scanner=scanner)
                    self.assertEqual(r["data"]["persistence"], expected)
                    self.assertNotIn("Unknown setting", json.dumps(r["warnings"]))
                    self.assertEqual("save_details has no effect" in json.dumps(r["warnings"]), save and not details)
                    entries, _ = history.read(path, 10)
                    self.assertEqual(len(entries), 1)
                    self.assertNotIn("8.8.8.8", path.read_text())
                    folder = history.details_folder(path)
                    saved = list(folder.glob("*.json")) if folder.exists() else []
                    self.assertEqual(len(saved), expected == "details_saved")
                    self.assertEqual(entries[0]["details"] is not None, expected == "details_saved")
                    if saved:
                        self.assertIn("8.8.8.8", saved[0].read_text())

    def test_mcp_gets_counts_first_then_a_bounded_excerpt(self):
        internet = [self.row(local_port=str(20000 + i)) for i in range(10)]
        with patch.object(c, "MCP_RECORDS", 10):
            r = self.observe([self.row(remote_address="192.168.1.9", local_port="1")] + internet)
            self.assertEqual(r["data"]["connections"][-1]["classification"], "private_or_local")
            out = c.for_mcp(r)
            view = out["data"]
            self.assertEqual((len(view["connections"]), view["omitted_count"]), (10, 1))
            self.assertTrue(all(x["classification"] == "internet_candidate" for x in view["connections"]))
            self.assertEqual(view["classification_counts"], {"internet_candidate": 10, "private_or_local": 1})
            self.assertEqual(view["process_counts"], [{"pid": 42, "process_started_at_epoch": 1000, "process": "app<test>",
                "records": 11, "by_classification": {"internet_candidate": 10, "private_or_local": 1}}])
            self.assertIn("omitted_count", " ".join(out["warnings"]))
            self.assertEqual(len(r["data"]["connections"]), 11)  # the full result is left as it was
            out = c.for_mcp(self.observe(internet + [self.row(start_time="-1", local_port="2")]))
            # Unattributed in both samples: two records, never merged into the known process.
            self.assertEqual((out["data"]["omitted_count"], out["data"]["unattributed_records"]), (2, 2))
            self.assertEqual([(x["pid"], x["records"]) for x in out["data"]["process_counts"]], [(42, 10)])
            exact = c.for_mcp(self.observe(internet))
            self.assertEqual((len(exact["data"]["connections"]), exact["data"]["omitted_count"]), (10, 0))
            self.assertNotIn("omitted_count", " ".join(exact["warnings"]))
        # With the real limits the 64 KiB reply fills before 100 records; long names fill it sooner.
        for rows in ([self.row(local_port=str(20000 + i)) for i in range(150)],
                     [self.row(pid=str(100 + i), process="\u540d" * 300, local_port=str(30000 + i)) for i in range(150)]):
            out = c.for_mcp(self.observe(rows))
            self.assertLessEqual(c.mcp_bytes(out), c.MCP_BYTES)
            self.assertGreater(c.mcp_bytes(out), c.MCP_BYTES - 2048)
            self.assertLess(len(out["data"]["connections"]), c.MCP_RECORDS)
            self.assertEqual(out["data"]["omitted_count"], 150 - len(out["data"]["connections"]))
            self.assertEqual(out["data"]["omitted_process_count"], len({r["pid"] for r in rows}) - len(out["data"]["process_counts"]))
        error = {"status": "error", "warnings": [], "data": {}}
        self.assertIs(c.for_mcp(error), error)

    def test_ipv4_ipv6_scope_classification_and_udp_unavailable(self):
        cases = {"8.8.8.8": "internet_candidate", "192.168.1.5": "private_or_local", "fc00::5": "private_or_local",
            "127.0.0.2": "self_or_loopback", "::1": "self_or_loopback", "192.0.2.4": "unknown",
            "100.64.0.1": "unknown", "2001:db8::1": "unknown", "ff02::fb": "multicast_or_broadcast",
            "192.168.1.2": "self_or_loopback", "192.168.1.255": "multicast_or_broadcast"}
        for addr, expected in cases.items():
            with self.subTest(addr=addr): self.assertEqual(c.classify(addr, {"192.168.1.2"}, {"192.168.1.255"}), expected)
        self.assertEqual(c.ip("::ffff:8.8.8.8"), ("8.8.8.8", None))
        r = self.observe([self.row(remote_address="fe80::1%en0", local_address="fe80::2%en0", family="30"), self.row(protocol="17", remote_address="0.0.0.0")])
        self.assertEqual(r["data"]["connections"][0]["remote_scope"], "en0")
        self.assertEqual(r["data"]["unavailable_counts"]["destination_unavailable"], 2)

    def test_unconnected_udp_unspecified_address_is_not_an_invalid_connection(self):
        for family in (2, 10, 23, 30):
            for remote in ("0.0.0.0", "::", "::ffff:0.0.0.0"):
                with self.subTest(family=family, remote=remote):
                    row = self.row(protocol="17", family=str(family), remote_address=remote, remote_port="0")
                    self.assertEqual(c.normalize(row, set(), set(), 1, "t"), (None, "destination_unavailable"))
        rows = [self.row(), self.row(protocol="17", family="30", local_address="::", remote_address="0.0.0.0", remote_port="0")]
        report = self.observe(rows)
        self.assertEqual(report["status"], "completed", report)
        self.assertEqual(report["data"]["connection_count"], 1)
        self.assertEqual(report["data"]["connections"][0]["sample_count"], 2)
        self.assertEqual(report["data"]["unavailable_counts"], {"destination_unavailable": 2})
        self.assertNotIn("invalid_rows", report["data"]["limitations"])

    def test_udp_normalization_does_not_hide_invalid_ports_or_real_family_mismatches(self):
        for changes in ({"remote_port": "-1"}, {"remote_port": "65536"}, {"remote_port": ""},
                        {"remote_port": True}, {"remote_address": "not-an-address"},
                        {"remote_address": "8.8.8.8"}, {"remote_port": "443"}, {"protocol": "6"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                c.normalize(self.row(protocol="17", family="30", local_address="::", remote_address="0.0.0.0",
                                     remote_port="0") | changes, set(), set(), 1, "t")

    def test_progress_contains_only_counters_and_persistence(self):
        p = ScanProgress()
        self.observe(progress=p)
        s = json.dumps(p.snapshot()) + message(p.snapshot())
        for v in ["8.8.8.8", "app<test>", "50001", "PAYLOAD"]: self.assertNotIn(v, s)
        self.assertEqual(p.snapshot()["samples_completed"], 2)
        self.assertEqual(p.snapshot()["persistence"], "not_saved")

    def test_history_off_summary_details_and_save_failure(self):
        r = self.observe()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "history.jsonl"
            entry = history.entry("observe_outbound_connections", {}, r, datetime.now(timezone.utc), 1, "cli")
            # Exercise the real writer only with a private temporary target.
            with patch.object(history, "append", history_append):
                history.append(path, entry)
                self.assertNotIn("8.8.8.8", path.read_text())
                self.assertFalse(history.details_folder(path).exists())
                history.append(path, entry, r, 1024 * 1024)
            entries, skipped = history.read(path, 10)
            self.assertEqual(skipped, 0)
            saved, _ = history.load_details(path, entries[-1]["details"])
            self.assertEqual(saved["data"]["connection_count"], 1)
            self.assertNotIn("payload", json.dumps(saved))
        scanner = self.scanner(); scanner.via = "cli"; scanner.history_enabled = True
        with patch.object(scanner, "history_path", return_value=Path("unused")), patch.object(history, "append", side_effect=OSError):
            r = self.observe(scanner=scanner)
        self.assertEqual(r["data"]["persistence"], "save_failed")

    def test_dashboard_latest_duplicate_and_partial_never_added_to_findings(self):
        r = self.observe([self.row(process="bad<script>\u202e")])
        e = history.parse(json.dumps(history.entry("observe_outbound_connections", {}, r, datetime.now(timezone.utc), 1, "cli")))
        partial = copy.deepcopy(e); partial["status"] = "partial"; partial["connection_observation"]["connection_count"] = 0
        e["started_at"] = "2026-10-29T00:00:00+00:00"
        partial["started_at"] = "2026-10-29T00:00:01+00:00"
        entries = [e, copy.deepcopy(e), partial, copy.deepcopy(e)]
        runs = dashboard.latest_runs(entries)
        self.assertEqual(len(runs), 1)
        section = dashboard.connection_section(runs)
        self.assertEqual(section.count("This PC connection history"), 1)
        self.assertIn("Observed records: 0", section)
        self.assertIn("partial", section)
        details = dashboard.connection_details(r["data"])
        self.assertIn("&lt;script&gt;", details)
        self.assertNotIn("<script>", details)
        self.assertNotIn("href=", details)
        self.assertNotIn("\u202e", details)
        self.assertIn("<details>", details)
        self.assertIn("unavailable_counts", details)
        self.assertIn("sampling", details)

    def test_cli_success_json_and_text_use_the_same_observation(self):
        import io
        from contextlib import redirect_stdout, redirect_stderr
        from pc_scanner import cli
        class Output(io.StringIO):
            def reconfigure(self, **kwargs): pass
        for json_flag in [[], ["--json"]]:
            scanner, out = self.scanner(duration_seconds=1), Output()
            snap = ({"192.168.1.2"}, set(), {"x"})
            with patch.object(cli.Scanner, "load", return_value=scanner), \
                 patch.object(sys, "argv", ["pc-scanner", "outbound-connections", *json_flag]), \
                 patch.object(c.Backend, "__init__", lambda self, *a: setattr(self, "limits", set())), \
                 patch.object(c.Backend, "addresses", return_value=snap), patch.object(c.Backend, "sockets", return_value=[self.row()]), \
                 redirect_stdout(out), redirect_stderr(io.StringIO()):
                cli.main()
            if json_flag:
                self.assertEqual(json.loads(out.getvalue())["data"]["connection_count"], 1)
            else:
                self.assertIn("8.8.8.8", out.getvalue())
                self.assertIn("Observed records: 1", out.getvalue())

    def test_cli_disabled_json_and_text_exit_two(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / "config.toml"; config.write_text('[history]\nenabled=false\n')
            for args in [[], ["--json"]]:
                p = subprocess.run([sys.executable, "-m", "pc_scanner.cli", "--config", str(config), "outbound-connections", *args],
                                   capture_output=True, text=True, timeout=10)
                self.assertEqual(p.returncode, 2, p.stderr)
                if args: self.assertIn("disabled", json.loads(p.stdout)["error"])
                else: self.assertIn("Status: error", p.stdout)

    def test_stalled_real_child_is_reaped_after_cancellation(self):
        scanner, cancel = self.scanner(), threading.Event()
        from pc_scanner.core import run_bounded
        children, original = [], subprocess.Popen
        def spawn(*a, **k):
            child = original(*a, **k); children.append(child); return child
        def run(argv, timeout, limit, cancel=None):
            return run_bounded([sys.executable, "-c", "import time; time.sleep(30)"], timeout, limit, cancel)
        timer = threading.Timer(.15, cancel.set)
        begin = time.monotonic()
        with patch.object(scanner, "binary", return_value="/fixed/osqueryi"), \
             patch.object(c, "run_bounded", side_effect=run), patch("pc_scanner.core.subprocess.Popen", side_effect=spawn):
            timer.start()
            try: r = scanner.invoke("observe_outbound_connections", cancel=cancel)
            finally: timer.cancel(); timer.join()
        self.assertLess(time.monotonic() - begin, 2)
        self.assertEqual(r["data"]["stop_reason"], "cancelled")
        self.assertTrue(children)
        self.assertTrue(all(p.poll() is not None for p in children))

    def test_read_output_and_total_limits_keep_fixed_reason(self):
        scanner = self.scanner()
        with patch.object(scanner, "binary", return_value="/fixed/osqueryi"), \
             patch.object(c, "run_bounded", side_effect=ScannerError("Engine output exceeded limits; scan was not completed")):
            r = scanner.invoke("observe_outbound_connections")
        self.assertEqual(r["data"]["stop_reason"], "read_limit")
        with patch.object(scanner, "binary", return_value="/fixed/osqueryi"), patch.object(c, "run_bounded", return_value=(0, "[]", "")):
            b = c.Backend(scanner, time.monotonic() + 10, None); b.total = 16 * 1024 * 1024 - 1
            with self.assertRaises(c.Stopped) as stopped: b.sockets()
            self.assertEqual(stopped.exception.reason, "total_byte_limit")

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "agent extra not installed")
    def test_mcp_cancel_busy_and_final_progress(self):
        import anyio
        import mcp.types as types
        from mcp.shared.exceptions import McpError
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server
        started, stopped = threading.Event(), threading.Event()
        snap = ({"192.168.1.2"}, set(), {"x"})
        def sockets(backend):
            started.set()
            try:
                while True:
                    c.check(backend.deadline, backend.cancel)
                    backend.cancel.wait(.01)
            finally: stopped.set()
        def init(backend, scanner, deadline, cancel):
            backend.deadline, backend.cancel, backend.limits = deadline, cancel, set()
        async def run():
            scanner = self.scanner(expose_identifiers_to_mcp=True); scanner.via = "mcp"
            async with create_connected_server_and_client_session(create_server(scanner)) as session:
                request_id = session._request_id
                async def call():
                    with self.assertRaises(McpError): await session.call_tool("observe_outbound_connections", {})
                async with anyio.create_task_group() as group:
                    group.start_soon(call)
                    self.assertTrue(await anyio.to_thread.run_sync(started.wait, 2))
                    busy = await session.call_tool("observe_outbound_connections", {})
                    self.assertIn("busy", busy.content[0].text)
                    await session.send_notification(types.ClientNotification(types.CancelledNotification(
                        params=types.CancelledNotificationParams(requestId=request_id))))
                self.assertTrue(await anyio.to_thread.run_sync(stopped.wait, 1))
                with anyio.fail_after(3):
                    while True:
                        reply = await session.call_tool("get_scan_progress", {})
                        data = json.loads(reply.content[0].text)["data"]
                        if data["stage"] == "cancelled": break
                        await anyio.sleep(.01)
                self.assertEqual(data["persistence"], "not_saved")
                self.assertNotIn("192.168.1.2", reply.content[0].text)
        with patch.object(c.Backend, "__init__", init), patch.object(c.Backend, "addresses", return_value=snap), \
             patch.object(c.Backend, "sockets", sockets):
            asyncio.run(run())

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "agent extra not installed")
    def test_mcp_schema_gate_annotations_and_observations(self):
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server
        async def run():
            scanner = self.scanner(duration_seconds=1); scanner.via = "mcp"
            async with create_connected_server_and_client_session(create_server(scanner)) as session:
                tools = {t.name: t for t in (await session.list_tools()).tools}
                tool = tools["observe_outbound_connections"]
                self.assertEqual(set(tool.inputSchema.get("properties", {})), set())
                self.assertTrue(tool.annotations.readOnlyHint)
                self.assertFalse(tool.annotations.openWorldHint)
                self.assertFalse(tool.annotations.idempotentHint)
                with patch.object(c, "Backend", side_effect=AssertionError("forbidden")):
                    reply = await session.call_tool(tool.name, {})
                self.assertIn("not authorized for MCP", reply.content[0].text)
                scanner.connection_settings["expose_identifiers_to_mcp"] = True
                snap = ({"192.168.1.2"}, set(), {"x"})
                with patch.object(c.Backend, "__init__", lambda self, *a: setattr(self, "limits", set())), \
                     patch.object(c.Backend, "addresses", return_value=snap), patch.object(c.Backend, "sockets", return_value=[self.row()]):
                    reply = await session.call_tool(tool.name, {})
                self.assertEqual(json.loads(reply.content[0].text)["data"]["connection_count"], 1)
                many = [self.row(local_port=str(20000 + i)) for i in range(150)]
                with patch.object(c.Backend, "__init__", lambda self, *a: setattr(self, "limits", set())), \
                     patch.object(c.Backend, "addresses", return_value=snap), patch.object(c.Backend, "sockets", return_value=many):
                    reply = await session.call_tool(tool.name, {})
                self.assertLessEqual(len(reply.content[0].text.encode()), 64 * 1024)
                data = json.loads(reply.content[0].text)["data"]
                self.assertEqual(data["connection_count"], 150)
                self.assertEqual(data["omitted_count"], 150 - len(data["connections"]))
                self.assertGreater(len(data["connections"]), 0)
        asyncio.run(run())


history_append = history.append
