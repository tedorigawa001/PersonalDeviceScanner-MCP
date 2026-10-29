"""Bounded, opt-in socket observations. No packet, payload, DNS or reputation collection."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import ipaddress
import json
import math
import platform
import re
import secrets
import time

from .core import ScannerError, clean_text, result, run_bounded

# With the bounded growth below, 2000 ordinary records fit the 2 MiB result; very long names can still stop it earlier.
MAX_CONNECTIONS = 2000
DEFAULTS = {"enabled": False, "duration_seconds": 10, "interval_seconds": 1,
            "max_connections": MAX_CONNECTIONS, "expose_identifiers_to_mcp": False, "save_details": False}
# Every TCP state osquery names is at most 12 characters, and there are 13 of them.
MAX_STATES, MAX_STATE_CHARS = 16, 16
# A record grows only by later states, a last time that gains microseconds and a longer sample count.
GROWTH = (MAX_STATES - 1) * (MAX_STATE_CHARS + 4) + 16
# MCP clients cap tool results (Claude Code at 25,000 tokens by default), so MCP gets counts and a bounded excerpt.
MCP_RECORDS, MCP_BYTES = 100, 64 * 1024
ORDER = {"internet_candidate": 0, "private_or_local": 1, "unknown": 2}
BASE_LIMITS = ["observed_only", "short_lived_connections_may_be_missed", "direction_unknown",
               "no_byte_counts", "os_visible_scope_only", "process_join_not_atomic",
               "process_start_resolution_seconds", "not_a_security_assessment", "udp_destinations_may_be_missing"]
REASONS = {"cancelled", "timeout", "network_changed", "read_failed", "read_limit", "total_byte_limit",
           "connection_limit", "result_size_limit", "invalid_rows", "attribution_unavailable",
           "classification_unknown", "sampling_delayed", "self_addresses_unavailable", "engine_warning"}
PRIVATE = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10", "169.254.0.0/16"))
# Fixed conservative special-use rules, independent of Python's changing is_global tables.
SPECIAL = tuple(ipaddress.ip_network(n) for n in ("0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
    "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"))
SOCKET_SQL = ("SELECT s.pid, s.family, s.protocol, s.local_address, s.local_port, s.remote_address, "
              "s.remote_port, s.state, p.name AS process, p.start_time FROM process_open_sockets s "
              "LEFT JOIN processes p USING (pid) WHERE s.protocol IN (6,17) LIMIT 10001;")
ADDRESS_SQL = "SELECT interface, address, broadcast FROM interface_addresses LIMIT 10001;"


class Stopped(ScannerError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def check(deadline, cancel):
    if cancel is not None and cancel.is_set():
        raise Stopped("cancelled")
    if time.monotonic() >= deadline:
        raise Stopped("timeout")


def load(config):
    raw = config.get("outbound_connections", {})
    if not isinstance(raw, dict):
        raise ScannerError("outbound_connections must be a table")
    settings = {**DEFAULTS, **{k: v for k, v in raw.items() if k in DEFAULTS}}
    for k in ("enabled", "expose_identifiers_to_mcp", "save_details"):
        if type(settings[k]) is not bool:
            raise ScannerError(f"outbound_connections.{k} must be true or false")
    for k, maximum in (("duration_seconds", 60), ("interval_seconds", 10), ("max_connections", MAX_CONNECTIONS)):
        if type(settings[k]) is not int or not 1 <= settings[k] <= maximum:
            raise ScannerError(f"outbound_connections.{k} must be 1..{maximum}")
    if settings["interval_seconds"] > settings["duration_seconds"]:
        raise ScannerError("outbound_connections.interval_seconds must not exceed duration_seconds")
    return settings


def now():
    return datetime.now(timezone.utc).isoformat()


def ip(value):
    if not isinstance(value, str) or len(value) > 128:
        raise ValueError
    host, sep, scope = value.partition("%")
    if sep and not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", scope):
        raise ValueError
    addr = ipaddress.ip_address(host)
    if sep and addr.version != 6:
        raise ValueError
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr), scope or None


def classify(host, self_ips, broadcasts):
    addr = ipaddress.ip_address(host)
    if host in self_ips or addr.is_loopback:
        return "self_or_loopback"
    if addr.is_multicast or host in broadcasts or host == "255.255.255.255":
        return "multicast_or_broadcast"
    if any(addr.version == n.version and addr in n for n in PRIVATE):
        return "private_or_local"
    if addr.is_unspecified or any(addr.version == n.version and addr in n for n in SPECIAL):
        return "unknown"
    if addr.version == 6 and addr not in ipaddress.ip_network("2000::/3"):
        return "unknown"
    return "internet_candidate"


def number(value, maximum):
    if type(value) is int:
        value = str(value)
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,12}", value) or not 0 <= int(value) <= maximum:
        raise ValueError
    return int(value)


class Backend:
    """Only fixed projections enter memory; no select *, process command line or packet API."""
    def __init__(self, scanner, deadline, cancel):
        self.binary = scanner.binary("osquery_binary")
        self.deadline, self.cancel, self.total = deadline, cancel, 0
        self.limits = set()

    def query(self, sql):
        check(self.deadline, self.cancel)
        read_deadline = min(self.deadline, time.monotonic() + 2)
        try:
            code, output, diagnostic = run_bounded([self.binary, "-S", "--json", "--disable_extensions=true",
                "--disable_logging=true", "--disable_events=true", sql],
                max(0.001, read_deadline - time.monotonic()), min(2 * 1024 * 1024, 16 * 1024 * 1024 - self.total), self.cancel)
        except ScannerError as exc:
            check(self.deadline, self.cancel)
            if "output exceeded limits" in str(exc):
                raise Stopped("read_limit") from None
            raise ScannerError("Connection observation read failed or exceeded its limits") from None
        check(self.deadline, self.cancel)
        self.total += len(output.encode("utf-8")) + len(diagnostic.encode("utf-8"))
        if self.total >= 16 * 1024 * 1024:
            raise Stopped("total_byte_limit")
        if time.monotonic() >= read_deadline or code:
            raise ScannerError("Connection observation read failed or exceeded its limits")
        if diagnostic.strip():
            self.limits.add("engine_warning")
        try:
            rows = json.loads(output)
            if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
                raise ValueError
        except (ValueError, RecursionError):
            raise ScannerError("Connection observation returned an invalid schema") from None
        if len(rows) > 10000:
            self.limits.add("read_limit")
        return rows[:10000]

    def addresses(self):
        rows = self.query(ADDRESS_SQL)
        if not rows:
            raise ScannerError("Self addresses unavailable")
        addresses, broadcasts, fingerprint = set(), set(), set()
        for r in rows:
            try:
                address, scope = ip(r["address"])
                interface = r["interface"]
                if not isinstance(interface, str) or not interface or len(interface) > 256:
                    raise ValueError
                broadcast = ip(r["broadcast"])[0] if r.get("broadcast") else None
            except (ValueError, KeyError, TypeError):
                raise ScannerError("Self addresses unavailable") from None
            addresses.add(address)
            if broadcast:
                broadcasts.add(broadcast)
            fingerprint.add((interface, address, scope, broadcast))
        return addresses, broadcasts, fingerprint

    def sockets(self):
        return self.query(SOCKET_SQL)


def normalize(row, self_ips, broadcasts, sample, stamp):
    protocol = number(row["protocol"], 255)
    if protocol not in (6, 17):
        raise ValueError
    family = number(row["family"], 64)
    if family not in (2, 10, 23, 30):
        return None, "non_ip"
    remote, rscope = ip(row["remote_address"])
    # Some OS tables use an IPv4 unspecified placeholder for an unconnected IPv6
    # UDP socket. It has no destination, so do not infer a family mismatch (or a
    # destination). Only accept this representation with a valid, zero port.
    if protocol == 17 and ipaddress.ip_address(remote).is_unspecified and number(row["remote_port"], 65535) == 0:
        return None, "destination_unavailable"
    original_version = ipaddress.ip_address(row["remote_address"].split("%", 1)[0]).version
    if (family == 2) != (original_version == 4):
        raise ValueError
    if ipaddress.ip_address(remote).is_unspecified:
        return None, "destination_unavailable" if protocol == 17 else "listening_or_unconnected"
    local, lscope = ip(row["local_address"])
    if ipaddress.ip_address(remote).version != ipaddress.ip_address(local).version:
        raise ValueError
    lp, rp = number(row["local_port"], 65535), number(row["remote_port"], 65535)
    if not rp:
        return None, "destination_unavailable"
    classification = classify(remote, self_ips, broadcasts)
    if ipaddress.ip_address(remote).version == 6 and ipaddress.ip_address(remote).is_link_local and not rscope:
        classification = "unknown"
    if classification in {"self_or_loopback", "multicast_or_broadcast"}:
        return None, classification
    pid = None
    try:
        pid = number(row.get("pid"), 2147483647) or None
    except ValueError:
        pass
    start = None
    try:
        start = number(row.get("start_time"), 253402300799) or None
    except ValueError:
        pass
    name = row.get("process")
    name = name if isinstance(name, str) and name else None
    # osquery's process name may be a path. Never expose full paths or argv.
    if name:
        name = name.replace("\\", "/").rsplit("/", 1)[-1]
    if not pid or not start or not name:
        start = None
    quality = "start_time_observed_nonatomic" if start else "unverified"
    identity = (pid, start) if start else (sample, pid, name)
    key = (identity, protocol, local, lscope, lp, remote, rscope, rp)
    state = row.get("state", "")
    state = state if isinstance(state, str) and re.fullmatch(r"[A-Za-z0-9_ -]{0,%d}" % MAX_STATE_CHARS, state) else "unknown"
    return (key, {"pid": pid, "process_started_at_epoch": start, "process": clean_text(name, 256) if name else None,
        "attribution_quality": quality, "protocol": "TCP" if protocol == 6 else "UDP",
        "family": "IPv4" if ipaddress.ip_address(remote).version == 4 else "IPv6",
        "local_ip": local, "local_scope": lscope, "local_port": lp, "remote_ip": remote, "remote_scope": rscope,
        "remote_port": rp, "classification": classification, "direction": "unknown", "states": [state],
        "first_observed_at": stamp, "last_observed_at": stamp, "sample_count": 1}), None


def order(row):
    """Internet candidates first, then by process and destination: one fixed order for the CLI, MCP and dashboard."""
    remote, local = ipaddress.ip_address(row["remote_ip"]), ipaddress.ip_address(row["local_ip"])
    return (ORDER[row["classification"]], row["process"] is None, row["process"] or "", row["pid"] or 0,
            row["process_started_at_epoch"] or 0, remote.version, int(remote), row["remote_scope"] or "",
            row["remote_port"], row["protocol"], local.version, int(local), row["local_scope"] or "",
            row["local_port"], row["first_observed_at"])


def observe(scanner, cancel=None, progress=None):
    settings = scanner.connection_settings
    if not settings["enabled"]:
        raise ScannerError("Outbound connection observation is disabled")
    if scanner.via == "mcp" and not settings["expose_identifiers_to_mcp"]:
        raise ScannerError("Connection identifiers are not authorized for MCP; owner must enable their disclosure")
    if not scanner._connection_lock.acquire(False):
        raise ScannerError("Connection observation is busy")
    begin, started = time.monotonic(), now()
    deadline = begin + settings["duration_seconds"] + 5
    window_end = begin + settings["duration_seconds"]
    planned = math.ceil(settings["duration_seconds"] / settings["interval_seconds"])
    records, excluded, unavailable = {}, Counter(), Counter()
    limits, stop, successes, failures, attempted, skipped = set(), None, 0, 0, 0, 0
    backend = None
    result_bytes = 2
    def emit(stage):
        if progress:
            progress.update(stage=stage, observed_records=len(records), samples_completed=successes,
                            samples_failed=failures, samples_planned=planned, checkpoint="not_applicable",
                            persistence="not_saved")
    try:
        if progress:
            progress.set_deadline(deadline)
        emit("authorizing")
        check(deadline, cancel)
        if platform.system() not in {"Darwin", "Linux", "Windows"}:
            raise ScannerError("Connection observation is unsupported on this platform")
        backend = Backend(scanner, deadline, cancel)
        before = None
        next_due = begin
        while attempted + skipped < planned:
            check(deadline, cancel)
            current = time.monotonic()
            if current < next_due:
                delay = min(next_due - current, 0.05)
                if cancel is not None:
                    cancel.wait(delay)
                else:
                    time.sleep(delay)
                continue
            if current >= next_due + settings["interval_seconds"]:
                missed = min(planned - attempted - skipped - 1, int((current - next_due) // settings["interval_seconds"]))
                if missed > 0:
                    skipped += missed
                    next_due += missed * settings["interval_seconds"]
                    limits.add("sampling_delayed")
            attempted += 1
            emit("observing")
            try:
                ips, broadcasts, fingerprint = backend.addresses()
                if before is not None and before != fingerprint:
                    raise Stopped("network_changed")
                before = fingerprint
                rows = backend.sockets()
                after = backend.addresses()
                if after[2] != before:
                    raise Stopped("network_changed")
            except Stopped:
                raise
            except (ScannerError, OSError):
                check(deadline, cancel)
                failures += 1
                limits.add("read_failed")
                next_due += settings["interval_seconds"]
                continue
            successes += 1
            stamp, seen = now(), set()
            for raw in rows:
                check(deadline, cancel)
                try:
                    normalized, reason = normalize(raw, ips, broadcasts, attempted, stamp)
                except (ValueError, KeyError, TypeError):
                    unavailable["invalid_rows"] += 1
                    limits.add("invalid_rows")
                    continue
                if reason:
                    (unavailable if reason == "destination_unavailable" else excluded)[reason] += 1
                    continue
                key, row = normalized
                if key in seen:
                    continue
                seen.add(key)
                if row["attribution_quality"] == "unverified":
                    unavailable["attribution_unavailable"] += 1
                    limits.add("attribution_unavailable")
                if row["classification"] == "unknown":
                    limits.add("classification_unknown")
                if key in records:
                    old = records[key]
                    old["last_observed_at"] = stamp
                    old["sample_count"] += 1
                    old["states"] = sorted(set(old["states"] + row["states"]))[:MAX_STATES]
                else:
                    if len(records) >= settings["max_connections"]:
                        raise Stopped("connection_limit")
                    row["connection_id"] = secrets.token_hex(8)
                    # Reserve enough for state/time/counter growth of already retained rows.
                    size = len(json.dumps(row, ensure_ascii=True).encode()) + GROWTH
                    if result_bytes + size > 2 * 1024 * 1024:
                        raise Stopped("result_size_limit")
                    result_bytes += size
                    records[key] = row
            next_due += settings["interval_seconds"]
            emit("observing")
        # Observe the full requested window, even when the last sample is earlier than its end.
        while time.monotonic() < window_end:
            check(deadline, cancel)
            delay = min(0.05, window_end - time.monotonic())
            if cancel is not None:
                cancel.wait(max(0, delay))
            else:
                time.sleep(max(0, delay))
        if before is not None:
            try:
                if backend.addresses()[2] != before:
                    raise Stopped("network_changed")
            except Stopped:
                raise
            except (ScannerError, OSError):
                limits.add("self_addresses_unavailable")
        check(deadline, cancel)
    except Stopped as exc:
        stop = exc.reason
        limits.add(stop)
    finally:
        scanner._connection_lock.release()
    emit("aggregating")
    if backend:
        limits.update(backend.limits)
    rows = sorted(records.values(), key=order)
    status = "partial" if limits else "completed"
    if not successes and stop not in {"cancelled", "timeout"}:
        status = "error"
    return result("connections", status, data={"observation_id": secrets.token_hex(16), "started_at": started,
        "finished_at": now(), "duration_seconds": round(time.monotonic() - begin, 3), "backend": "osquery_fixed_projection",
        "coverage": list(BASE_LIMITS), "sampling": {"planned": planned, "successful": successes, "failed": failures,
            "attempted": attempted, "skipped": skipped, "interval_seconds": settings["interval_seconds"]},
        "connection_count": len(rows), "process_count": len({(r["pid"], r["process_started_at_epoch"])
            for r in rows if r["process_started_at_epoch"] is not None}),
        "connections": rows, "excluded_counts": dict(excluded), "unavailable_counts": dict(unavailable),
        "limitations": sorted(set(BASE_LIMITS) | limits), "stop_reason": stop, "persistence": "not_saved"},
        warnings=["Socket observations only: direction, actual transmissions and safety are unverified; short-lived connections may be missed"])


def mcp_bytes(value):
    # The MCP SDK sends a dict result as UTF-8 JSON indented by 2.
    return len(json.dumps(value, ensure_ascii=False, indent=2).encode())


def for_mcp(report):
    """Counts first, then the first records in the fixed order within MCP_RECORDS and MCP_BYTES.

    The CLI and saved details keep the full list; omitted_count says how much MCP did not get.
    """
    data = report.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("connections"), list):
        return report
    rows = data["connections"]
    processes = {}
    for row in rows:
        if row["attribution_quality"] == "unverified":
            continue  # counted apart, never added to a known process
        entry = processes.setdefault((row["pid"], row["process_started_at_epoch"]), {
            "pid": row["pid"], "process_started_at_epoch": row["process_started_at_epoch"], "process": row["process"],
            "records": 0, "by_classification": Counter()})
        entry["records"] += 1
        entry["by_classification"][row["classification"]] += 1
    process_rows = sorted(({**p, "by_classification": dict(p["by_classification"])} for p in processes.values()),
                          key=lambda p: (-p["records"], p["process"] or "", p["pid"], p["process_started_at_epoch"]))
    # The omitted counts start at their largest and the warning is in place, so the final reply can only be smaller.
    view = {**data, "classification_counts": dict(Counter(r["classification"] for r in rows)),
            "unattributed_records": sum(r["attribution_quality"] == "unverified" for r in rows),
            "process_counts": [], "omitted_process_count": len(process_rows), "connections": [], "omitted_count": len(rows)}
    omitted = ("MCP returns counts and only the first records; the CLI or saved details have the full list "
               "(see omitted_count and omitted_process_count)")
    out = {**report, "data": view, "warnings": report["warnings"] + [omitted]}
    # An item costs its indented text, 6 more spaces per line at its depth, a newline and a comma;
    # 16 covers both lists' closing brackets.
    size = mcp_bytes(out) + 16
    for name, values in (("process_counts", process_rows), ("connections", rows)):
        for value in values[:MCP_RECORDS]:
            text = json.dumps(value, ensure_ascii=False, indent=2)
            cost = len(text.encode()) + 6 * (text.count("\n") + 1) + 2
            if size + cost > MCP_BYTES:
                break
            view[name].append(value)
            size += cost
    view["omitted_process_count"] = len(process_rows) - len(view["process_counts"])
    view["omitted_count"] = len(rows) - len(view["connections"])
    if not view["omitted_count"] and not view["omitted_process_count"]:
        out["warnings"] = report["warnings"]
    return out


def summary(data):
    """Name-free allowlist for both writing and re-reading potentially edited history."""
    if not isinstance(data, dict):
        return {}
    data = data.get("connection_observation", data)
    if not isinstance(data, dict) or not isinstance(data.get("observation_id"), str) or not re.fullmatch(r"[0-9a-f]{32}", data["observation_id"]):
        return {}
    counts = {k: data.get(k) for k in ("connection_count", "process_count")}
    if any(type(v) is not int or not 0 <= v <= MAX_CONNECTIONS for v in counts.values()):
        return {}
    limits = data.get("limitations", [])
    return {"connection_observation": {"observation_id": data["observation_id"], **counts,
        "backend": "osquery_fixed_projection", "limitations": [v for v in limits if isinstance(v, str) and v in set(BASE_LIMITS) | REASONS]
        if isinstance(limits, list) else [], "stop_reason": data.get("stop_reason") if data.get("stop_reason") in REASONS else None}}
