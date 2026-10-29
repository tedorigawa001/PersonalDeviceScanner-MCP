import copy
import asyncio
import ctypes
import importlib.util
import ipaddress
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pc_scanner.core import Scanner, ScannerError
from pc_scanner import lan, lan_os, lan_mdns as mdns, history, dashboard


class LANTests(unittest.TestCase):
    def setUp(self):
        # A failed history write only becomes a warning, so record attempts and fail the test afterwards.
        writes = []
        patcher = patch("pc_scanner.history.append", side_effect=lambda path, *a, **k: writes.append(path))
        patcher.start()
        self.addCleanup(lambda: self.assertEqual(writes, [], "a LAN test tried to write scan history"))
        self.addCleanup(patcher.stop)

    def config(self, **settings):
        # History off: an MCP scanner records by default, and that file is the owner's real history.
        return {"history": {"enabled": False}, "lan": {"enabled": True, **settings}, "lan_networks": {"home": {
            "interface": "en0", "local_addresses": ["192.168.10.20"],
            "cidrs": ["192.168.10.0/24"], "neighbor_cache": True, "mdns": False}}}

    def test_disabled_and_unknown_alias_never_read_the_network(self):
        report = Scanner({}).invoke("discover_lan_devices", network_alias="home")
        self.assertEqual(report["status"], "error")
        self.assertIn("disabled", report["error"])
        report = Scanner(self.config()).invoke("discover_lan_devices", network_alias="other")
        self.assertEqual(report["status"], "error")
        self.assertIn("authorized", report["error"])

    def snapshot(self):
        return {"physical": True, "up": True, "index": 4, "addresses": ["192.168.10.20"],
                "onlink": ["192.168.10.0/24"], "mac": "02:00:00:00:00:01"}

    def test_cache_filters_scope_and_merges_evidence_without_claiming_online(self):
        rows = [{"ip": ip, "mac": "02:00:00:00:00:02", "method": "neighbor_cache",
                 "state": "stale", "observed_at": "2026-10-28T00:00:00+00:00"}
                for ip in ["192.168.10.2", "192.168.10.3", "192.168.11.2", "192.168.10.20"]]
        with patch("pc_scanner.lan_os.snapshot", return_value=self.snapshot(), create=True), patch(
                "pc_scanner.lan_os.neighbors", return_value=rows, create=True):
            report = Scanner(self.config()).invoke("discover_lan_devices", network_alias="home")
        self.assertEqual(report["status"], "completed", report)
        self.assertEqual(report["data"]["device_count"], 1)
        self.assertEqual(len(report["data"]["devices"][0]["addresses"]), 2)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["data"]["count_quality"], "observed_only")

    def run_cache(self, rows=(), **settings):
        with patch("pc_scanner.lan_os.snapshot", return_value=self.snapshot()), patch(
                "pc_scanner.lan_os.neighbors", return_value=list(rows)):
            return Scanner(self.config(**settings)).invoke("discover_lan_devices", network_alias="home")

    def test_invalid_or_expanded_authorization_is_rejected(self):
        for cidr in ("0.0.0.0/0", "8.8.8.0/24", "192.168.10.1/24", "127.0.0.0/8", "ff00::/8", "::/0", "fe80::%en0/64"):
            config = self.config(); config["lan_networks"]["home"]["cidrs"] = [cidr]
            with self.subTest(cidr=cidr), self.assertRaises(ScannerError):
                Scanner(config)
        for key, val in (("enabled", 1), ("timeout_seconds", 31), ("max_devices", 0), ("expose_identifiers_to_mcp", "true")):
            with self.subTest(key=key), self.assertRaises(ScannerError):
                Scanner(self.config(**{key: val}))

    def test_misspelled_network_permission_key_is_not_ignored(self):
        config = self.config(); config["lan_networks"]["home"]["mdsn"] = True
        with self.assertRaises(ScannerError):
            Scanner(config)

    def test_interface_or_address_mismatch_fails_before_reading_cache_or_mdns(self):
        for change in ({"physical": False}, {"up": False}, {"addresses": ["192.168.10.21"]}, {"onlink": ["10.0.0.0/24"]}):
            with self.subTest(change=change), patch("pc_scanner.lan_os.snapshot", return_value={**self.snapshot(), **change}), \
                    patch("pc_scanner.lan_os.neighbors", side_effect=AssertionError("unauthorized read")), \
                    patch("pc_scanner.lan_mdns.open_socket", side_effect=AssertionError("unauthorized send")):
                report = Scanner(self.config()).invoke("discover_lan_devices", network_alias="home")
            self.assertEqual(report["status"], "error")

    def test_network_change_keeps_observations_partial(self):
        snapshots = [self.snapshot(), self.snapshot(), {**self.snapshot(), "up": False}]
        row = {"ip": "192.168.10.2", "method": "neighbor_cache", "state": "stale"}
        with patch("pc_scanner.lan_os.snapshot", side_effect=snapshots), patch("pc_scanner.lan_os.neighbors", return_value=[row]):
            report = Scanner(self.config()).invoke("discover_lan_devices", network_alias="home")
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["data"]["stop_reason"], "network_changed")
        self.assertEqual(report["data"]["device_count"], 1)

    def run_os_reads(self, at, effect, **settings):
        """The real Darwin backend with fake command output; `effect` runs inside command call number `at`."""
        outputs = {"ifconfig": 'en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tether 02:00:00:00:00:01\n'
                               '\tinet 192.168.10.20 netmask 0xffffff00 broadcast 192.168.10.255\n\tmedia: autoselect\n\tstatus: active\n',
                   "arp": "? (192.168.10.2) at 2:0:0:0:0:2 on en0 ifscope [ethernet]\n",
                   "ndp": "Neighbor Linklayer Address Netif Expire S Flags\n"}
        calls, cancel = [], threading.Event()
        def run(argv, timeout, limit, cancel=None):
            calls.append(Path(argv[0]).name)
            if len(calls) == at:
                effect(cancel, timeout)
            return 0, outputs[calls[-1]], ""
        with patch("pc_scanner.lan_os.platform.system", return_value="Darwin"), patch(
                "pc_scanner.lan_os.socket.if_nametoindex", return_value=4), patch(
                "pc_scanner.lan_os.Path", **{"return_value.is_file.return_value": True}), patch(
                "pc_scanner.lan_os.run_bounded", side_effect=run):
            return Scanner(self.config(**settings)).invoke("discover_lan_devices", network_alias="home", cancel=cancel), calls

    def test_cancel_or_deadline_during_an_os_read_is_not_a_network_change_or_error(self):
        def stopped(cancel, timeout):
            cancel.set()
            raise ScannerError("Scan cancelled; engine stopped before completing")
        def expired(cancel, timeout):
            time.sleep(timeout)
            raise ScannerError("Engine timed out; scan was not completed")
        # Calls: ifconfig (authorization), ifconfig (check before the cache), arp, ndp, ifconfig (final check).
        for at, effect, reason, settings in [(5, stopped, "cancelled", {}), (5, lambda cancel, timeout: cancel.set(), "cancelled", {}),
                                              (5, expired, "timeout", {"timeout_seconds": 1}), (1, stopped, "cancelled", {}),
                                              (3, stopped, "cancelled", {})]:
            with self.subTest(at=at, reason=reason):
                report, calls = self.run_os_reads(at, effect, **settings)
                self.assertEqual(len(calls), at)
                self.assertEqual(report["status"], "partial", report)
                self.assertEqual(report["data"]["stop_reason"], reason)
                self.assertNotIn("network_changed", report["data"]["limitations"])
                self.assertNotIn("neighbor_cache_failed", report["data"]["limitations"])
                if at == 3:
                    self.assertEqual(report["data"]["methods"]["neighbor_cache"]["status"], "partial")

    def test_empty_cache_does_not_claim_no_devices_or_safety(self):
        report = self.run_cache()
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["data"]["device_count"], 0)
        self.assertIn("no_devices_observed", report["data"]["limitations"])
        self.assertEqual(report["findings"], [])

    def test_same_name_is_not_identity_and_conflicting_macs_are_visible(self):
        rows = [{"ip": ip, "name": "same-name", "method": "neighbor_cache", "mac": mac}
                for ip, mac in [("192.168.10.2", None), ("192.168.10.3", None),
                    ("192.168.10.4", "02:00:00:00:00:01"), ("192.168.10.4", "02:00:00:00:00:02")]]
        report = self.run_cache(rows)
        self.assertEqual(report["data"]["device_count"], 3)
        self.assertEqual(report["status"], "partial")
        self.assertTrue(any(r["identity_conflict"] for r in report["data"]["devices"]))

    def test_limit_exact_and_one_over_are_distinguished(self):
        rows = [{"ip": f"192.168.10.{i}", "method": "neighbor_cache"} for i in (2, 3)]
        self.assertEqual(self.run_cache(rows, max_devices=2)["status"], "completed")
        report = self.run_cache(rows, max_devices=1)
        self.assertEqual(report["status"], "partial")
        self.assertIn("device_limit", report["data"]["limitations"])

    def test_multicast_and_zero_mac_are_not_devices(self):
        rows = [{"ip": "192.168.10.2", "method": "neighbor_cache", "mac": m}
                for m in ("01:00:5e:00:00:01", "00:00:00:00:00:00")]
        self.assertEqual(self.run_cache(rows)["data"]["device_count"], 0)

    def test_cancellation_and_busy_do_not_start_readers(self):
        cancel = threading.Event(); cancel.set()
        with patch("pc_scanner.lan_os.snapshot", side_effect=AssertionError("cancelled")):
            report = Scanner(self.config()).invoke("discover_lan_devices", network_alias="home", cancel=cancel)
            self.assertEqual(report["status"], "partial")
            self.assertEqual(report["data"]["stop_reason"], "cancelled")
            with lan._lock:
                report = Scanner(self.config()).invoke("discover_lan_devices", network_alias="home")
            self.assertIn("busy", report["error"])

    def test_partial_mdns_evidence_survives_cancel(self):
        config = self.config(); config["lan_networks"]["home"]["mdns"] = True
        def stopped(spec, snapshot, deadline, cancel, guard, rows, progress):
            rows.append({"ip": "192.168.10.2", "method": "mdns", "name": "Test\u202e<script>\U000e0072\u2028\u061c.local"})
            raise lan.Stopped("cancelled")
        with patch("pc_scanner.lan_os.snapshot", return_value=self.snapshot()), patch(
                "pc_scanner.lan_os.neighbors", return_value=[]), patch("pc_scanner.lan_mdns.collect", side_effect=stopped):
            report = Scanner(config).invoke("discover_lan_devices", network_alias="home")
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["data"]["methods"]["mdns"]["observations"], 1)
        for hidden in ("\u202e", "\U000e0072", "\u2028", "\u061c"):
            self.assertNotIn(hidden, json.dumps(report, ensure_ascii=False))

    def test_unverified_reception_and_permission_denial_are_not_no_responses(self):
        config = self.config(); config["lan_networks"]["home"]["mdns"] = True
        for effect, expected in [(lambda *a: {"receive_path": "unverified", "validated_packets": 0}, "receive_unverified"),
                                 (PermissionError("denied"), "blocked")]:
            with self.subTest(expected=expected), patch("pc_scanner.lan_os.snapshot", return_value=self.snapshot()), patch(
                    "pc_scanner.lan_os.neighbors", return_value=[]), patch("pc_scanner.lan_mdns.collect", side_effect=effect):
                report = Scanner(config).invoke("discover_lan_devices", network_alias="home")
            self.assertEqual(report["status"], "partial")
            self.assertEqual(report["data"]["methods"]["mdns"]["status"], expected)
            self.assertNotIn("no_responses", json.dumps(report))

    def test_mcp_disclosure_is_separate_from_local_authorization(self):
        scanner = Scanner(self.config()); scanner.via = "mcp"
        with patch("pc_scanner.lan_os.snapshot", side_effect=AssertionError("must not start")):
            report = scanner.invoke("discover_lan_devices", network_alias="home")
        self.assertIn("not authorized for MCP", report["error"])

    def test_history_and_dashboard_keep_identifiers_only_in_opted_in_details(self):
        row = {"ip": "192.168.10.2", "mac": "02:11:22:33:44:55", "name": "Secret<script>", "method": "neighbor_cache"}
        report = self.run_cache([row])
        entry = history.entry("discover_lan_devices", {"network_alias": "home"}, report, datetime.now(timezone.utc), 1, "cli")
        public = json.dumps(history.parse(json.dumps(entry)))
        for private in (row["ip"], row["mac"], row["name"]):
            self.assertNotIn(private, public)
        entries = [history.parse(json.dumps(entry))] * 2
        meta = {"details_mb": 50, "details": True, "skipped": 0, "generated": "test", "file": "test", "recording": True}
        page = dashboard.render(entries, [(report, "")] * 2, meta)
        self.assertIn("Devices observed on LAN", page)
        self.assertIn("Secret&lt;script&gt;", page)
        self.assertNotIn("Secret<script>", page)
        self.assertNotIn('href="http', page)
        section = dashboard.lan_section(dashboard.latest_runs(entries))
        self.assertEqual(section.count('<tr><td><a href="#scan-'), 1)
        off = dashboard.render(entries, [(None, "off")] * 2, meta)
        self.assertNotIn(row["ip"], off)

    def test_history_disabled_does_not_write_and_updates_lookup_does_not_call_out(self):
        config = self.config(); config.update(history={"enabled": False}, updates={"lookup": True})
        scanner = Scanner(config); scanner.via = "cli"
        with patch("pc_scanner.lan_os.snapshot", return_value=self.snapshot()), patch(
                "pc_scanner.lan_os.neighbors", return_value=[]), patch("pc_scanner.history.append", side_effect=AssertionError("write")), patch(
                "pc_scanner.updates.check", side_effect=AssertionError("external lookup")):
            self.assertEqual(scanner.invoke("discover_lan_devices", network_alias="home")["status"], "completed")

    def test_darwin_numeric_formats_and_interface_filter(self):
        text = 'en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tether 02:00:00:00:00:01\n\tinet 192.168.10.20 netmask 0xffffff00 broadcast 192.168.10.255\n\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x4\n\tmedia: autoselect\n\tstatus: active\n'
        snap = lan_os.darwin_snapshot("en0", text, 4)
        self.assertTrue(snap["physical"])
        self.assertEqual(snap["onlink"], ["192.168.10.0/24", "fe80::/64"])
        rows = lan_os.darwin_neighbors("en0", '? (192.168.10.2) at 2:0:0:0:0:2 on en0 ifscope [ethernet]\n? (192.168.10.3) at (incomplete) on en0\n? (10.0.0.1) at 2:0:0:0:0:1 on en1\n',
            'Neighbor Linklayer Address Netif Expire S Flags\nfe80::2%en0 2:0:0:0:0:2 en0 23h S R\n')
        self.assertEqual([r["ip"] for r in rows], ["192.168.10.2", "fe80::2"])
        with self.assertRaises(ScannerError):
            lan_os.darwin_neighbors("en0", "Unexpected ARP format", "")
        with self.assertRaises(ScannerError):
            lan_os.darwin_neighbors("en0", "", "Changed header\n")

    def test_linux_and_windows_backends_filter_and_validate_os_facts(self):
        outputs = [json.dumps([{"ifindex": 4, "flags": ["UP", "LOWER_UP"], "link_type": "ether", "address": "02:00:00:00:00:01"}]),
                   json.dumps([{"addr_info": [{"family": "inet", "local": "192.168.10.20", "prefixlen": 24}]}]),
                   json.dumps([{"dst": "192.168.10.0/24"}, {"dst": "default", "gateway": "192.168.10.1"}]), "[]"]
        with patch("pc_scanner.lan_os.platform.system", return_value="Linux"), patch("pc_scanner.lan_os.command", side_effect=outputs), \
                patch("pc_scanner.lan_os.Path.exists", return_value=True):
            self.assertTrue(lan.authorized(lan_os.snapshot("eth0", time.monotonic() + 1, None), lan.load(self.config())[1]["home"]))
        info = {"adapters": [{"InterfaceGuid": "abc", "ifIndex": 4, "HardwareInterface": True, "InterfaceType": 6, "Status": "Up"}],
                "addresses": [{"InterfaceIndex": 4, "IPAddress": "192.168.10.20", "AddressState": 4}],
                "routes": [{"InterfaceIndex": 4, "DestinationPrefix": "192.168.10.0/24", "NextHop": "0.0.0.0"}],
                "neighbors": [{"InterfaceIndex": 4, "IPAddress": "192.168.10.2", "LinkLayerAddress": "02-00-00-00-00-02", "State": 4},
                              {"InterfaceIndex": 9, "IPAddress": "10.1.0.1", "LinkLayerAddress": "02-00-00-00-00-03", "State": 4}]}
        with patch("pc_scanner.lan_os.platform.system", return_value="Windows"), patch("pc_scanner.lan_os.windows", return_value=info):
            snap = lan_os.snapshot("{ABC}", time.monotonic() + 1, None)
            self.assertEqual(snap["index"], 4)
            self.assertEqual([r["ip"] for r in lan_os.neighbors("{ABC}", snap, time.monotonic() + 1, None)], ["192.168.10.2"])

    def test_secondary_self_addresses_are_not_listed(self):
        snap = {**self.snapshot(), "addresses": ["192.168.10.20", "192.168.10.21"]}
        with patch("pc_scanner.lan_os.snapshot", return_value=snap), patch("pc_scanner.lan_os.neighbors", return_value=[
                {"ip": "192.168.10.21", "method": "neighbor_cache"}]):
            report = Scanner(self.config()).invoke("discover_lan_devices", network_alias="home")
        self.assertEqual(report["data"]["device_count"], 0)

    def test_real_cli_rejects_disabled_lan_without_network_access(self):
        with tempfile.TemporaryDirectory() as d:
            config = Path(d) / "scanner.toml"; config.write_text('[history]\nenabled=false\n')
            p = subprocess.run([sys.executable, "-m", "pc_scanner.cli", "--config", str(config), "lan-devices", "home", "--json"],
                               capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode, 2)
        self.assertIn("disabled", json.loads(p.stdout)["error"])

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "agent extra not installed")
    def test_real_mcp_schema_disclosure_gate_and_result(self):
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server
        async def exercise():
            scanner = Scanner(self.config()); scanner.via = "mcp"
            async with create_connected_server_and_client_session(create_server(scanner)) as session:
                tools = {t.name: t for t in (await session.list_tools()).tools}
                tool = tools["discover_lan_devices"]
                self.assertEqual(set(tool.inputSchema["properties"]), {"network_alias"})
                self.assertFalse(tool.annotations.idempotentHint)
                self.assertTrue(tool.annotations.openWorldHint)
                with patch("pc_scanner.lan_os.snapshot", side_effect=AssertionError("forbidden")):
                    reply = await session.call_tool("discover_lan_devices", {"network_alias": "home"})
                self.assertIn("not authorized for MCP", json.loads(reply.content[0].text)["error"])
                scanner.lan_settings["expose_identifiers_to_mcp"] = True
                with patch("pc_scanner.lan_os.snapshot", return_value=self.snapshot()), patch("pc_scanner.lan_os.neighbors", return_value=[]):
                    reply = await session.call_tool("discover_lan_devices", {"network_alias": "home"})
                self.assertEqual(json.loads(reply.content[0].text)["status"], "completed")
        asyncio.run(exercise())

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "agent extra not installed")
    def test_real_mcp_busy_cancel_and_progress_do_not_expose_identifiers(self):
        import anyio
        import mcp.types as types
        from mcp.shared.exceptions import McpError
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server
        config = self.config(expose_identifiers_to_mcp=True)
        config["history"] = {"enabled": False}
        config["lan_networks"]["home"]["mdns"] = True
        started, stopped = threading.Event(), threading.Event()
        def collector(spec, snap, deadline, cancel, guard, rows, progress):
            rows.append({"ip": "192.168.10.2", "name": "Secret.local", "method": "mdns"})
            progress.update(observed_records=1)
            started.set()
            try:
                while True:
                    if cancel.wait(.01): raise lan.Stopped("cancelled")
                    guard()
            finally: stopped.set()
        async def exercise():
            scanner = Scanner(config); scanner.via = "mcp"
            async with create_connected_server_and_client_session(create_server(scanner)) as session:
                request_id = session._request_id
                async def call():
                    with self.assertRaises(McpError):
                        await session.call_tool("discover_lan_devices", {"network_alias": "home"})
                async with anyio.create_task_group() as group:
                    group.start_soon(call)
                    self.assertTrue(await anyio.to_thread.run_sync(started.wait, 2))
                    busy = await session.call_tool("discover_lan_devices", {"network_alias": "home"})
                    self.assertIn("busy", json.loads(busy.content[0].text)["error"])
                    before = time.monotonic()
                    await session.send_notification(types.ClientNotification(types.CancelledNotification(
                        params=types.CancelledNotificationParams(requestId=request_id))))
                # The SDK answers "Request cancelled" at once; the worker notices on its next poll.
                self.assertTrue(await anyio.to_thread.run_sync(stopped.wait, 1))
                self.assertLess(time.monotonic() - before, 1)
                with anyio.fail_after(3):
                    while True:
                        progress = await session.call_tool("get_scan_progress", {})
                        if json.loads(progress.content[0].text)["data"]["stage"] == "cancelled":
                            break
                        await anyio.sleep(0.01)
                text = progress.content[0].text
                self.assertNotIn("Secret", text)
                self.assertNotIn("192.168.10.2", text)
                self.assertEqual(json.loads(text)["data"]["stage"], "cancelled")
        with patch("pc_scanner.lan_os.snapshot", return_value=self.snapshot()), patch(
                "pc_scanner.lan_os.neighbors", return_value=[]), patch("pc_scanner.lan_mdns.collect", side_effect=collector):
            asyncio.run(exercise())


class MDNSTests(unittest.TestCase):
    def answer(self, records):
        data = struct.pack("!6H", 0, 0x8400, 0, len(records), 0, 0)
        for name, typ, ttl, value in records:
            if typ == 12:
                raw = mdns.wire(value)
            elif typ == 33:
                raw = struct.pack("!HHH", 0, 0, value[0]) + mdns.wire(value[1])
            elif typ in (1, 28):
                raw = ipaddress.ip_address(value).packed
            else:
                raw = value
            data += mdns.wire(name) + struct.pack("!HHIH", typ, 1, ttl, len(raw)) + raw
        return data

    def fixture(self, ttl=120):
        typ, instance, host = (b"_http", b"_tcp", b"local"), (b"test", b"_http", b"_tcp", b"local"), (b"test", b"local")
        return [(mdns.META, 12, ttl, typ), (typ, 12, ttl, instance), (instance, 33, ttl, (8080, host)),
                (host, 1, ttl, "192.168.10.2"), ((b"unrelated", b"local"), 1, ttl, "192.168.10.3"),
                (host, 16, ttl, b"secret=must-not-be-retained")]

    def spec(self):
        return lan.load(LANTests().config())[1]["home"]

    def test_related_records_resolve_service_and_ignore_txt_and_unrelated_addresses(self):
        packet = self.answer(self.fixture())
        answers = mdns.Answers(); answers.add(mdns.records(packet), 1000)
        rows = answers.rows(self.spec(), 1001)
        self.assertEqual([r["ip"] for r in rows], ["192.168.10.2"])
        self.assertEqual(rows[0]["services"][0]["port"], 8080)
        self.assertNotIn("secret", repr(answers.values))
        self.assertEqual(len(answers.wanted(1001)[0]), 5)

    def test_ttl_expiry_and_goodbye_remove_current_advertisements(self):
        answers = mdns.Answers(); answers.add(mdns.records(self.answer(self.fixture())), 1000)
        self.assertEqual(answers.rows(self.spec(), 1120), [])
        answers.add(mdns.records(self.answer(self.fixture())), 2000)
        answers.add(mdns.records(self.answer(self.fixture(ttl=0))), 2001)
        self.assertEqual(answers.rows(self.spec(), 2001), [])

    def test_peer_records_cannot_expand_scope_or_trigger_external_name_queries(self):
        fixture = self.fixture(); fixture[3] = (fixture[3][0], 1, 120, "8.8.8.8")
        answers = mdns.Answers(); answers.add(mdns.records(self.answer(fixture)), 1000)
        self.assertEqual(answers.rows(self.spec(), 1001), [])
        answers.add([((b"test", b"_http", b"_tcp", b"local"), 33, 120, (80, (b"example", b"com")), False)], 1001)
        self.assertNotIn(((b"example", b"com"), 1), answers.wanted(1001)[0])

    def test_malformed_compression_and_record_lengths_are_rejected(self):
        for data in (b"\xc0\x00", b"\xc0\xff", b"\x40", b"\x3fabc"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                mdns.name_at(data, 0)
        packet = self.answer(self.fixture())
        for data in (packet[:5], packet[:-1], packet + b"x", struct.pack("!6H", 0, 0x8600, 0, 0, 0, 0)):
            with self.subTest(length=len(data)), self.assertRaises((ValueError, struct.error)):
                mdns.records(data)

    def test_record_cap_does_not_grow_unbounded(self):
        a = mdns.Answers()
        with patch.object(mdns, "MAX_RECORDS", 1):
            a.add([((b"one", b"local"), 1, 120, "192.168.10.2", False)], 1000)
            with self.assertRaises(lan.Stopped):
                a.add([((b"two", b"local"), 1, 120, "192.168.10.3", False)], 1001)
        self.assertEqual(len(a.values), 1)

    def test_cache_flush_spares_shared_service_records_and_answers_from_the_last_second(self):
        typ, instance, host = (b"_http", b"_tcp", b"local"), (b"test", b"_http", b"_tcp", b"local"), (b"test", b"local")
        a = mdns.Answers(); a.add(mdns.records(self.answer(self.fixture())), 1000)
        # Another device's PTRs with the cache-flush bit must not erase this device's service.
        a.add([(typ, 12, 120, (b"other",) + typ, True), (mdns.META, 12, 120, typ, True)], 1010)
        self.assertIn((typ, 12, instance), a.values)
        # A unique record replaces the same name and type only when the old copy is over a second old.
        a.add([(host, 1, 120, "192.168.10.4", True)], 1010.5)
        a.add([(host, 1, 120, "192.168.10.5", True)], 1011)
        self.assertEqual(sorted(v for n, t, v in a.values if (n, t) == (host, 1)), ["192.168.10.4", "192.168.10.5"])
        a.add([(host, 1, 120, "192.168.10.6", True)], 1012.5)
        self.assertEqual([v for n, t, v in a.values if (n, t) == (host, 1)], ["192.168.10.6"])

    def test_receive_interface_and_hop_limit_are_required_on_each_os(self):
        for system, kind, pkt in (("Linux", 8, struct.pack("=I", 4) + b"\0" * 8),
                                  ("Darwin", 20, b"\0\0" + struct.pack("=H", 4)),
                                  ("Windows", 19, b"\0" * 4 + struct.pack("=I", 4))):
            with self.subTest(system=system), patch("pc_scanner.lan_mdns.platform.system", return_value=system):
                self.assertEqual(mdns.receiving_interface([(socket.IPPROTO_IP, kind, pkt),
                    (socket.IPPROTO_IP, socket.IP_TTL, struct.pack("=i", 255))], 4), (4, 255))
                self.assertEqual(mdns.receiving_interface([], 4), (None, None))

    def test_collector_closes_all_sockets_on_cancel_before_first_send(self):
        class Fake:
            closed = False
            def close(self): self.closed = True
            def sendto(self, *a): raise AssertionError("no send after cancel")
        sock = Fake()
        def guard(): raise lan.Stopped("cancelled")
        with patch.object(mdns, "open_socket", return_value=(sock, ("224.0.0.251", 5353))):
            with self.assertRaises(lan.Stopped):
                mdns.collect(self.spec(), {"index": 4}, time.monotonic() + 10, None, guard, [])
        self.assertTrue(sock.closed)

    def test_collector_drops_wrong_interface_and_off_scope_packets_and_bounds_traffic(self):
        packet = self.answer(self.fixture())
        outer = self
        class Fake:
            def __init__(self): self.index = 0; self.sent = []; self.closed = False
            def close(self): self.closed = True
            def sendto(self, data, dest): self.sent.append((data, dest))
            def recvmsg(self, *args):
                self.index += 1
                peer = ("8.8.8.8" if self.index == 2 else "192.168.10.2", 5353)
                return packet, [], 0, peer
        sock = Fake(); rows = []
        def guard():
            if sock.index >= 3: raise lan.Stopped("cancelled")
        # First packet has a different interface, second an unauthorized sender, only the third is adopted.
        with patch.object(mdns, "open_socket", return_value=(sock, ("224.0.0.251", 5353))), \
                patch.object(mdns.select, "select", return_value=([sock], [], [])), \
                patch.object(mdns, "receiving_interface", side_effect=[(9, 255), (4, 255), (4, 255)]):
            with self.assertRaises(lan.Stopped):
                mdns.collect(self.spec(), {"index": 4}, time.monotonic() + 10, None, guard, rows)
        self.assertEqual([r["ip"] for r in rows], ["192.168.10.2"])
        self.assertTrue(sock.closed)
        self.assertEqual(len(sock.sent), 1)
        self.assertEqual(sock.sent[0][1], ("224.0.0.251", 5353))

    def collect_queues(self, queues, spec):
        """Runs the collector on a fake clock over queued (payload, flags, peer, interface) datagrams per IP version."""
        class Fake:
            def __init__(self, items): self.items = list(items); self.closed = False
            def close(self): self.closed = True
            def sendto(self, *args): pass
            def sendmsg(self, *args): pass
            def recvmsg(self, *args):
                if not self.items: raise BlockingIOError
                payload, flags, peer, interface = self.items.pop(0)
                return payload, [interface], flags, peer
        socks, ticks, rows = {version: Fake(items) for version, items in queues.items()}, iter(range(10 ** 7)), []
        clock = SimpleNamespace(monotonic=lambda: 1000 + next(ticks) / 4000, time=time.time)
        with patch.object(mdns, "open_socket", side_effect=lambda ip, index: (socks[ip.version], None)), \
                patch.object(mdns, "time", clock), \
                patch.object(mdns.select, "select", side_effect=lambda r, w, x, t: ([s for s in r if s.items], [], [])), \
                patch.object(mdns, "receiving_interface", side_effect=lambda ancillary, version: (ancillary[0], 255)):
            result = mdns.collect(spec, {"index": 4}, 1010, None, lambda: None, rows)
        self.assertTrue(all(s.closed for s in socks.values()))
        return result, rows

    def test_traffic_from_other_links_or_senders_cannot_use_up_the_receive_limits(self):
        packet, truncated = self.answer(self.fixture()), getattr(socket, "MSG_TRUNC", 0x0100)
        outside = [(b"x" * 9000, truncated, ("192.168.11.5", 5353), 4),  # another subnet
                   (b"x" * 9000, truncated, ("192.168.10.2", 5353), 9)]  # another interface
        outside += [(b"junk", 0, ("192.168.11.5", 5353), 4)] * (mdns.MAX_PACKETS + 1)
        result, rows = self.collect_queues({4: outside + [(packet, 0, ("192.168.10.2", 5353), 4)]}, self.spec())
        self.assertEqual([r["ip"] for r in rows], ["192.168.10.2"])
        self.assertEqual((result["received_packets"], result["ignored_packets"], result["receive_path"]),
                         (1, mdns.MAX_PACKETS + 3, "observed"))
        # The same truncated datagram from an authorized sender on this link still stops the run.
        with self.assertRaises(lan.Stopped) as stop:
            self.collect_queues({4: [(b"x" * 9000, truncated, ("192.168.10.2", 5353), 4)]}, self.spec())
        self.assertEqual(stop.exception.reason, "byte_limit")

    def test_each_ip_version_must_verify_its_own_reception(self):
        spec = lan.load({"lan_networks": {"home": {"interface": "en0", "local_addresses": ["192.168.10.20", "fd00::20"],
                                                   "cidrs": ["192.168.10.0/24", "fd00::/64"], "mdns": True}}})[1]["home"]
        packet = self.answer(self.fixture())
        v4, v6 = (packet, 0, ("192.168.10.2", 5353), 4), (packet, 0, ("fd00::2", 5353, 0, 4), 4)
        # IPv4 replies blocked, IPv6 ones arrive: IPv4-only devices would be missing, so reception is unverified.
        result, rows = self.collect_queues({4: [], 6: [v6]}, spec)
        self.assertEqual((result["receive_path"], result["validated_by_family"]), ("unverified", {"ipv4": 0, "ipv6": 1}))
        self.assertEqual([r["ip"] for r in rows], ["192.168.10.2"])
        result, _ = self.collect_queues({4: [v4], 6: [v6]}, spec)
        self.assertEqual((result["receive_path"], result["validated_by_family"]), ("observed", {"ipv4": 1, "ipv6": 1}))

    def test_socket_setup_fails_closed_and_releases_socket(self):
        class Fake:
            closed = False
            def setsockopt(self, *args): raise OSError("option unsupported")
            def close(self): self.closed = True
        sock = Fake()
        with patch.object(mdns.socket, "socket", return_value=sock), patch.object(mdns.platform, "system", return_value="Linux"):
            with self.assertRaises(OSError): mdns.open_socket(ipaddress.ip_address("192.168.10.20"), 4)
        self.assertTrue(sock.closed)

    def test_ipv6_query_pins_authorized_source_and_interface(self):
        class Fake:
            def __init__(self): self.sent = []; self.closed = False
            def sendmsg(self, *args): self.sent.append(args)
            def close(self): self.closed = True
        sock = Fake(); spec = {"addresses": [ipaddress.ip_address("fd00::20")]}
        calls = 0
        def guard():
            nonlocal calls
            calls += 1
            if calls > 1: raise lan.Stopped("cancelled")
        with patch.object(mdns, "open_socket", return_value=(sock, ("ff02::fb", 5353, 0, 4))), \
                patch.object(mdns.select, "select", return_value=([], [], [])):
            with self.assertRaises(lan.Stopped):
                mdns.collect(spec, {"index": 4}, time.monotonic() + 10, None, guard, [])
        self.assertTrue(sock.closed)
        self.assertEqual(len(sock.sent), 1)
        ancillary = sock.sent[0][1][0]
        self.assertEqual(ancillary[2], ipaddress.ip_address("fd00::20").packed + struct.pack("=I", 4))
        self.assertEqual(sock.sent[0][3], ("ff02::fb", 5353, 0, 4))

    def test_windows_control_header_has_pointer_alignment_and_length_checks(self):
        from pc_scanner.lan_windows import controls
        for word in (4, 8):
            header = word + 8
            payload = struct.pack("=I", 255)
            length = header + len(payload)
            data = length.to_bytes(word, "little") + struct.pack("=ii", 0, 21) + payload
            self.assertEqual(controls(data, word), [(0, 21, payload)])
            with self.assertRaises(OSError):
                controls((999).to_bytes(word, "little") + data[word:], word)

    def test_windows_oversized_datagram_is_reported_truncated_instead_of_failing(self):
        from pc_scanner import lan_windows
        receiver = lan_windows.Receiver.__new__(lan_windows.Receiver)
        receiver.socket = SimpleNamespace(fileno=lambda: 3)
        def receive(fd, message, count, overlapped, routine):
            # Winsock fills the buffer with the start of the datagram, then reports the error.
            msg = message._obj
            ctypes.memmove(msg.buffers[0].buf, b"x" * msg.buffers[0].len, msg.buffers[0].len)
            peer = struct.pack("=H", socket.AF_INET) + struct.pack("!H", 5353) + socket.inet_aton("192.168.10.2")
            ctypes.memmove(msg.name, peer, len(peer))
            msg.control.len = 0
            return -1
        receiver.receive = receive
        receiver.ws = SimpleNamespace(WSAGetLastError=lambda: 10040)  # WSAEMSGSIZE
        packet, ancillary, flags, peer = receiver.recvmsg(16, 64)
        self.assertEqual((packet, ancillary, peer), (b"x" * 16, [], ("192.168.10.2", 5353)))
        self.assertTrue(flags & 0x0100)
        receiver.ws = SimpleNamespace(WSAGetLastError=lambda: 10054)  # any other error still fails
        with self.assertRaises(OSError):
            receiver.recvmsg(16, 64)

    def test_native_packet_interface_and_ttl_on_loopback_only(self):
        import platform
        import select
        system = platform.system()
        if system not in {"Darwin", "Linux", "Windows"}: self.skipTest("supported socket OS required")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            interface_option, ttl_option = {"Darwin": (20, 24), "Linux": (8, 12), "Windows": (19, 21)}[system]
            receiver.setsockopt(socket.IPPROTO_IP, interface_option, 1)
            receiver.setsockopt(socket.IPPROTO_IP, ttl_option, 1)
            receiver.bind(("127.0.0.1", 0)); receiver.setblocking(False)
            sender.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)
            if system == "Windows":
                from pc_scanner.lan_windows import Receiver
                adapter = Receiver(receiver)
            else:
                adapter = receiver
            sender.sendto(b"metadata-test", receiver.getsockname())
            self.assertTrue(select.select([adapter], [], [], 2)[0])
            packet, ancillary, flags, peer = adapter.recvmsg(1024, 256)
            index, ttl = mdns.receiving_interface(ancillary, 4)
            self.assertEqual(packet, b"metadata-test")
            self.assertEqual(ttl, 255)
            self.assertIsNotNone(index)
            self.assertGreater(index, 0)
            self.assertEqual(peer[0], "127.0.0.1")

    @unittest.skipUnless(os.name == "nt", "native Windows Winsock")
    def test_windows_native_receiver_on_loopback(self):
        from pc_scanner.lan_windows import Receiver
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            receiver.bind(("127.0.0.1", 0)); receiver.setblocking(False)
            adapter = Receiver(receiver)
            sender.sendto(b"test", receiver.getsockname())
            import select
            self.assertTrue(select.select([adapter], [], [], 2)[0])
            packet, _, _, peer = adapter.recvmsg(1024, 256)
            self.assertEqual(packet, b"test")
            self.assertEqual(peer[0], "127.0.0.1")
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as receiver, socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sender:
            receiver.bind(("::1", 0)); receiver.settimeout(2)
            adapter = Receiver(sender)
            pktinfo = socket.inet_pton(socket.AF_INET6, "::1") + struct.pack("=I", 0)
            adapter.sendmsg([b"v6-test"], [(socket.IPPROTO_IPV6, 19, pktinfo)], 0, ("::1", receiver.getsockname()[1], 0, 0))
            self.assertEqual(receiver.recvfrom(1024)[0], b"v6-test")
