"""Opt-in, offline destination checks; only the separate local updater accesses a fixed public feed."""
from __future__ import annotations

from contextlib import contextmanager
import base64
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import time
from urllib.request import ProxyHandler, Request, build_opener

from . import connections as c, history, process_store as private
from .core import ScannerError, NoRedirect, TrackedHTTPSHandler, fetch_bounded, result

DEFAULTS = {"enabled": False, "allow_updates": False, "cache_directory": "", "max_age_hours": 48, "save_details": False}
URLS = {v: f"https://www.spamhaus.org/drop/drop_v{v}.json" for v in (4, 6)}
TERMS = "https://www.spamhaus.org/drop/terms/"
SOURCE = "Spamhaus Project DROP"
FEED_LIMIT, BUNDLE_LIMIT, MAX_NETWORKS = 4 * 1024 * 1024, 12 * 1024 * 1024, 50000
STATES = {"matched", "not_listed", "unverified", "not_applicable"}
NOTICE = "Public threat-list matches are warnings, not proof of infection or transmission. No match does not prove safety."
HISTORICAL = ("Some destinations matched only an out-of-date public threat list and remain unverified; "
              "update the list locally and check again")
# Fixed per-reason counts of observed rows that could not be used, safe for the anonymous reply.
UNAVAILABLE = {"invalid_rows", "destination_unavailable", "attribution_unavailable"}
# Observation limits under which seen connections were dropped before matching: "none listed" is then incomplete.
DROPPED = {"invalid_rows", "connection_limit", "result_size_limit", "read_limit", "total_byte_limit",
           "network_changed", "timeout", "cancelled"}
HISTORICAL_UNKNOWN = ("Historical match count unavailable in this older saved summary; do not assume zero. "
                      "Update the list locally and check again")


class RateLimited(Exception):
    pass

class InvalidAttempt(Exception):
    pass


def load(config):
    raw = config.get("ip_threats", {})
    if not isinstance(raw, dict):
        raise ScannerError("ip_threats must be a table")
    settings = {**DEFAULTS, **{k: v for k, v in raw.items() if k in DEFAULTS}}
    for key in ("enabled", "allow_updates", "save_details"):
        if type(settings[key]) is not bool:
            raise ScannerError("Invalid ip_threats boolean settings")
    if type(settings["max_age_hours"]) is not int or not 1 <= settings["max_age_hours"] <= 168:
        raise ScannerError("ip_threats.max_age_hours must be 1..168")
    path = settings["cache_directory"]
    if not isinstance(path, str) or len(path) > 4096 or "\0" in path or (path and (
            not Path(path).is_absolute() or ".." in Path(path).parts)):
        raise ScannerError("Invalid ip_threats.cache_directory")
    return settings


def clock():
    return datetime.now(timezone.utc)


def stamp(value):
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def cache_settings(scanner):
    cfg = scanner.ip_threat_settings
    folder = cfg["cache_directory"] or str(history.default_file().parent / "ip-threats")
    return {"directory": folder, "max_total_mb": 32}


class Cache(private.Store):
    """Select pinned POSIX storage or the dedicated owner-private Windows cache."""
    def __init__(self, settings, cancel=None, deadline=None):
        super().__init__(settings, cancel)
        if deadline is not None:
            self.deadline = deadline

    @contextmanager
    def open(self, create=False, file_lock=True):
        if os.name == "nt":
            from .windows_ip_cache import Store
            with Store(self.settings, self.cancel, self.deadline).open(create, file_lock) as cache:
                yield cache
        else:
            with super().open(create, file_lock) as cache:
                yield cache

    def used(self):
        total = 0
        for name in self.names():
            if name in {"current.json", "previous.json", "attempt.json", ".lock"} or re.fullmatch(r"\.[0-9a-f]{32}\.tmp", name):
                info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                self.safe(info)
                total += info.st_size
        return total

    def cleanup(self):
        for name in self.names():
            if re.fullmatch(r"\.[0-9a-f]{32}\.tmp", name):
                _, info = self.read(name, BUNDLE_LIMIT)
                self.unchanged()
                current = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns):
                    raise OSError("Cache temporary file changed")
                os.unlink(name, dir_fd=self.fd)
                self.sync()


def parse_feed(body, version, check=lambda: None):
    if not isinstance(body, bytes) or len(body) > FEED_LIMIT:
        raise ValueError("feed size")
    lines = body.splitlines()
    if not 2 <= len(lines) <= MAX_NETWORKS + 1 or any(not line or len(line) > 4096 for line in lines):
        raise ValueError("feed rows")
    metadata = private.decode(lines[-1])
    if (not isinstance(metadata, dict) or metadata.get("type") != "metadata"
            or metadata.get("terms") != TERMS or type(metadata.get("timestamp")) is not int
            or not 946684800 <= metadata["timestamp"] <= 253402300799
            or type(metadata.get("records")) is not int or metadata["records"] != len(lines) - 1
            or type(metadata.get("size")) is not int or not 1 <= metadata["size"] <= FEED_LIMIT
            or not isinstance(metadata.get("copyright"), str)
            or not re.fullmatch(r"\(c\) [0-9]{4} The Spamhaus Project SLU", metadata["copyright"])):
        raise ValueError("feed metadata")
    # The provider counts the byte size of the records, before the metadata line.
    if metadata["size"] != sum(len(line) + 1 for line in lines[:-1]):
        raise ValueError("feed byte count")
    index = {}
    for line in lines[:-1]:
        check()
        row = private.decode(line)
        if (not isinstance(row, dict) or not isinstance(row.get("cidr"), str)
                or len(row["cidr"]) > 64 or not isinstance(row.get("sblid"), str)
                or not re.fullmatch(r"SBL[0-9]{1,12}", row["sblid"])
                or row.get("rir") not in {"afrinic", "apnic", "arin", "lacnic", "ripencc"}):
            raise ValueError("feed network")
        network = ipaddress.ip_network(row["cidr"], strict=True)
        if network.version != version or not network.prefixlen:
            raise ValueError("feed family")
        if any(c.classify(str(addr), set(), set()) != "internet_candidate"
               for addr in (network.network_address, network.broadcast_address)):
            raise ValueError("feed special network")
        # Exclude a range covering a special-use subnet even if both endpoints are public.
        if any(network.version == n.version and network.overlaps(n) for n in (*c.PRIVATE, *c.SPECIAL)):
            raise ValueError("feed special overlap")
        key = network.prefixlen, int(network.network_address)
        index.setdefault(key, set()).add(row["sblid"])
    published = datetime.fromtimestamp(metadata["timestamp"], timezone.utc)
    return {"index": index, "published": published, "records": metadata["records"],
            "copyright": metadata["copyright"], "sha256": hashlib.sha256(body).hexdigest()}


def bundle(raw, check=lambda: None):
    obj = private.decode(raw)
    if not isinstance(obj, dict) or type(obj.get("schema")) is not int or obj["schema"] != 1 or set(obj.get("feeds", {})) != {"4", "6"}:
        raise ValueError("cache schema")
    retrieved = private.date(obj["retrieved_at"])
    feeds = {}
    for version in (4, 6):
        check()
        entry = obj["feeds"][str(version)]
        encoded = entry["body"]
        if not isinstance(encoded, str) or len(encoded) > (FEED_LIMIT + 2) // 3 * 4:
            raise ValueError("cache size")
        body = base64.b64decode(encoded, validate=True)
        feed = parse_feed(body, version, check)
        if feed["sha256"] != entry["sha256"] or feed["published"] > retrieved:
            raise ValueError("cache integrity or dates")
        feeds[version] = feed
    return feeds, retrieved


def download(version, deadline, cancel):
    c.check(deadline, cancel)
    handler = TrackedHTTPSHandler(ssl.create_default_context())
    opener = build_opener(ProxyHandler({}), handler, NoRedirect("Public threat list"))
    request = Request(URLS[version], headers={"User-Agent": "personal-device-scanner-mcp", "Accept-Encoding": "identity"})
    return fetch_bounded(opener, handler, request, min(15, max(.001, deadline - time.monotonic())), FEED_LIMIT,
                         cancel, service="Public threat list")


def update(scanner, cancel=None, progress=None):
    if scanner.via != "cli" or not scanner.ip_threat_settings["allow_updates"]:
        raise ScannerError("Public threat-list updates require explicit local CLI permission")
    deadline = time.monotonic() + 30
    if progress:
        progress.set_deadline(deadline)
        progress.update(stage="updating", persistence="not_saved")
    try:
        with Cache(cache_settings(scanner), cancel, deadline).open(create=True) as cache:
            cache.cleanup()
            when = clock()
            try:
                raw = cache.read("attempt.json", 1024)[0]
            except FileNotFoundError:
                raw = None
            if raw is not None:
                try:
                    last = private.date(private.decode(raw)["attempted_at"])
                except (ValueError, KeyError, TypeError, RecursionError, OverflowError):
                    last = None
                if last is None or last > when:
                    # No request this time, but the interval restarts now instead of blocking updates indefinitely.
                    cache.atomic("attempt.json", private.encode({"attempted_at": stamp(when)}), 1024)
                    raise InvalidAttempt
                if when - last < timedelta(hours=1):
                    raise RateLimited
            cache.atomic("attempt.json", private.encode({"attempted_at": stamp(when)}), 1024)
            feeds, entries = {}, {}
            for version in (4, 6):
                c.check(deadline, cancel)
                body = download(version, deadline, cancel)
                feeds[version] = parse_feed(body, version, lambda: c.check(deadline, cancel))
                entries[str(version)] = {"body": base64.b64encode(body).decode("ascii"), "sha256": feeds[version]["sha256"]}
            received = clock()
            if any(feed["published"] > received for feed in feeds.values()) or received < when:
                raise ValueError("feed future dates")
            new = private.encode({"schema": 1, "retrieved_at": stamp(received), "feeds": entries})
            c.check(deadline, cancel)
            try:
                old = cache.read("current.json", BUNDLE_LIMIT)[0]
            except FileNotFoundError:
                old = None
            if old is not None:
                # Do not replace the last valid backup with damaged data.
                try:
                    bundle(old, lambda: c.check(deadline, cancel))
                except (ValueError, KeyError, TypeError, RecursionError, OverflowError):
                    pass
                else:
                    old_feeds, _ = bundle(old, lambda: c.check(deadline, cancel))
                    if any(feeds[v]["published"] < old_feeds[v]["published"] for v in (4, 6)):
                        raise ValueError("feed publication rollback")
                    cache.atomic("previous.json", old, BUNDLE_LIMIT)
            c.check(deadline, cancel)
            cache.atomic("current.json", new, BUNDLE_LIMIT)
        if progress:
            progress.update(persistence="cache_saved")
        description = describe(feeds, received, received, scanner.ip_threat_settings["max_age_hours"])
        fresh = all(v["freshness"] == "fresh" for v in description.values())
        return result("connections", "completed" if fresh else "partial", data={"updated": True, "persistence": "cache_saved",
            "feeds": description}, warnings=[NOTICE] + ([] if fresh else ["Downloaded public threat lists are stale or unverified"]))
    except RateLimited:
        reason = "rate_limited_no_request_sent"
    except InvalidAttempt:
        reason = "attempt_record_invalid"
    except private.MissingParent:
        reason = "cache_parent_missing"
    except (c.Stopped, ScannerError):
        # Only fixed messages: response URLs and socket errors must not reach reports.
        if cancel is not None and cancel.is_set():
            reason = "cancelled"
        else:
            reason = "timeout" if time.monotonic() >= deadline else "update_unavailable_or_rate_limited"
    except (OSError, ValueError, KeyError, TypeError, RecursionError, OverflowError):
        reason = ("cancelled" if cancel is not None and cancel.is_set() else
                  "timeout" if time.monotonic() >= deadline else "cache_or_feed_unavailable")
    warnings = ["Public threat-list update did not complete; the previous current generation was retained", NOTICE]
    if reason == "attempt_record_invalid":
        warnings.insert(1, "The last update attempt time was invalid or in the future; no request was sent and "
                           "it was reset to now, so the next update can run after one hour")
    return result("connections", "partial", data={"updated": False, "persistence": "not_saved", "stop_reason": reason},
                  warnings=warnings)


def describe(feeds, retrieved, checked, hours):
    output = {}
    for version, feed in feeds.items():
        expiry = feed["published"] + timedelta(hours=hours)
        state = "fresh" if feed["published"] <= retrieved <= checked < expiry else "unverified"
        if feed["published"] <= retrieved <= checked and checked >= expiry:
            state = "stale"
        output[str(version)] = {"source": SOURCE, "published_at": stamp(feed["published"]),
            "retrieved_at": stamp(retrieved), "expires_at": stamp(expiry), "freshness": state,
            "records": feed["records"], "copyright": feed["copyright"]}
    return output


def lookup(feed, addr, deadline, cancel):
    found, total = [], 0
    bits = addr.max_prefixlen
    value = int(addr)
    for prefix in range(bits, -1, -1):
        c.check(deadline, cancel)
        start = (value >> (bits - prefix)) << (bits - prefix)
        ids = feed["index"].get((prefix, start), ())
        network_type = ipaddress.IPv4Network if addr.version == 4 else ipaddress.IPv6Network
        total += len(ids)
        found.extend({"cidr": str(network_type((start, prefix))), "reference": ref}
                     for ref in sorted(ids)[:max(0, 4-len(found))])
    return found, total - len(found)


def enrich(scanner, report, deadline, cancel=None, progress=None):
    data = report["data"]
    rows = data.get("connections", [])
    checked = clock()
    feeds, retrieved, metadata = {}, None, {}
    reason = None
    try:
        c.check(deadline, cancel)
        if progress:
            progress.update(stage="checking_destinations")
        # One atomic bundle; readers never create a folder, lock file or cache entry.
        with Cache(cache_settings(scanner), cancel, deadline).open(file_lock=False) as cache:
            if cache is None:
                raise FileNotFoundError
            feeds, retrieved = bundle(cache.read("current.json", BUNDLE_LIMIT)[0], lambda: c.check(deadline, cancel))
        metadata = describe(feeds, retrieved, checked, scanner.ip_threat_settings["max_age_hours"])
    except c.Stopped as exc:
        reason = exc.reason
    except (OSError, ValueError, KeyError, TypeError, RecursionError, OverflowError):
        reason = ("cancelled" if cancel is not None and cancel.is_set() else
                  "timeout" if time.monotonic() >= deadline else "cache_unavailable")
    destinations = {}
    for row in rows:
        # Public addresses share a lookup; link-local/private scopes are separate destinations.
        key = (row["remote_ip"], None if row["classification"] == "internet_candidate" else row.get("remote_scope"))
        if key in destinations:
            row["threat"] = destinations[key]
            continue
        assessment = {"state": "unverified", "reason": reason or "feed_unverified", "historical_match": False,
                      "evidence": [], "omitted_evidence_count": 0}
        destinations[key] = row["threat"] = assessment
        if row["classification"] != "internet_candidate":
            assessment.update(state="not_applicable", reason="not_public_candidate")
            continue
        if reason:
            continue
        try:
            c.check(deadline, cancel)
            addr = ipaddress.ip_address(key[0])
            evidence, omitted = lookup(feeds[addr.version], addr, deadline, cancel)
            freshness = metadata[str(addr.version)]["freshness"]
            if freshness == "fresh":
                assessment.update(state="matched" if evidence else "not_listed", reason="fresh_feed")
            else:
                assessment.update(reason="feed_" + freshness, historical_match=bool(evidence))
            assessment.update(evidence=evidence, omitted_evidence_count=omitted)
        except c.Stopped as exc:
            reason = exc.reason
            assessment["reason"] = reason
    # Freshness is evaluated at completion, never frozen at the first read before a long observation/check.
    try:
        c.check(deadline, cancel)
    except c.Stopped as exc:
        reason = exc.reason
    checked = clock()
    if feeds:
        metadata = describe(feeds, retrieved, checked, scanner.ip_threat_settings["max_age_hours"])
        for key, assessment in destinations.items():
            if assessment["state"] in {"matched", "not_listed"} and metadata[str(ipaddress.ip_address(key[0]).version)]["freshness"] != "fresh":
                assessment.update(state="unverified", reason="feed_unverified_at_completion",
                                  historical_match=bool(assessment["evidence"]))
    if reason in {"timeout", "cancelled"}:
        data["stop_reason"] = reason
    counts = dict(Counter(a["state"] for a in destinations.values()))
    matched = [r for r in rows if r["threat"]["state"] == "matched"]
    historical = sum(a["historical_match"] for a in destinations.values())
    summary = {"checked_at": stamp(checked), "feeds": metadata, "destination_counts": counts,
        "unique_destinations": len(destinations), "historical_match_destinations": historical,
        "matched_connection_records": len(matched),
        "matched_processes": len({(r["pid"], r["process_started_at_epoch"]) for r in matched if r["attribution_quality"] != "unverified"}),
        "matched_unattributed_records": sum(r["attribution_quality"] == "unverified" for r in matched),
        "coverage": "unverified" if reason or any(f["freshness"] != "fresh" for f in metadata.values()) or not metadata
                    or DROPPED & set(data.get("limitations", [])) else "checked",
        "notice": NOTICE}
    data["destination_threats"] = summary
    if counts.get("unverified") or summary["coverage"] == "unverified":
        if report["status"] != "error":
            report["status"] = "partial"
        report["warnings"].append("Destination threat-list coverage is incomplete; stale, unavailable or unfinished checks "
                                  "and connections the observation dropped are unverified")
    if matched:
        report["warnings"].append("Observed destinations match public threat-list networks; review the local evidence and process attribution")
    if historical:
        report["warnings"].append(HISTORICAL)
    report["warnings"].append(NOTICE)


def anonymous(report):
    """Build from scratch, including errors, warnings and progress: no raw report can escape."""
    data = report.get("data", {})
    value = summary(data).get("destination_threats", {})
    processes = {}
    for row in data.get("connections", []):
        key = (row["pid"], row["process_started_at_epoch"]) if row["attribution_quality"] != "unverified" else ("unattributed",)
        state = row["threat"]["state"]
        processes.setdefault(key, Counter())[state if state in STATES else "unverified"] += 1
    rows = [{"label": f"P{i:02}", "attribution": "unverified" if key == ("unattributed",) else "os_reported_start_time",
             "connection_states": dict(counts)} for i, (key, counts) in enumerate(processes.items(), 1)]
    # Fixed codes and counts only, so a partial result explains itself without any identifier.
    limits = data.get("limitations", [])
    unavailable = data.get("unavailable_counts", {})
    out = result("connections", report["status"], data={"destination_threats": value,
        "processes": rows[:100], "omitted_process_count": max(0, len(rows) - 100),
        "connection_count": data.get("connection_count", 0), "stop_reason": data.get("stop_reason") if data.get("stop_reason") in c.REASONS else None,
        "observation_limitations": sorted({v for v in limits if v in set(c.BASE_LIMITS) | c.REASONS}) if isinstance(limits, list) else [],
        "unavailable_counts": {k: v for k, v in unavailable.items() if k in UNAVAILABLE and type(v) is int and v >= 0}
                              if isinstance(unavailable, dict) else {},
        "persistence": data.get("persistence", "not_saved")},
        error="Destination check did not complete; check local permissions and configuration" if report.get("error") else None,
        warnings=[NOTICE, "Anonymous summary only; real destinations and process identifiers remain local"])
    if value.get("destination_counts", {}).get("matched"):
        out["warnings"].append("Warning: observed destinations match public threat-list networks; review local evidence")
    if value.get("historical_match_destinations"):
        out["warnings"].append(HISTORICAL)
    elif value and value.get("historical_match_destinations") is None:
        out["warnings"].append(HISTORICAL_UNKNOWN)
    if value.get("coverage") == "unverified":
        out["warnings"].append("Destination threat-list coverage is unverified; do not treat this as a negative result")
    return out


def summary(data):
    """Validate anonymous saved summaries again on read, never importing names or arbitrary text."""
    value = data.get("destination_threats") if isinstance(data, dict) else None
    if not isinstance(value, dict):
        return {}
    try:
        checked = private.date(value["checked_at"])
        counts = value["destination_counts"]
        if not isinstance(counts, dict) or set(counts) - STATES:
            return {}
        clean = {k: private.integer(v, c.MAX_CONNECTIONS) for k, v in counts.items()}
        total = private.integer(value["unique_destinations"], c.MAX_CONNECTIONS)
        if sum(clean.values()) != total:
            return {}
        # Matches against an expired list are a subset of the unverified destinations, never a separate total.
        # Older saved summaries did not record this count. Keep their evidence, without guessing zero,
        # unless no destination was unverified: then none can have matched only an expired list.
        historical = value.get("historical_match_destinations")
        if historical is not None:
            historical = private.integer(historical, clean.get("unverified", 0))
        elif not clean.get("unverified"):
            historical = 0
        out = {"checked_at": stamp(checked), "destination_counts": clean, "unique_destinations": total,
               "historical_match_destinations": historical,
               "coverage": private.choice(value["coverage"], {"checked", "unverified"}), "notice": NOTICE,
               **{k: private.integer(value[k], c.MAX_CONNECTIONS) for k in
                  ("matched_connection_records", "matched_processes", "matched_unattributed_records")}}
        feeds = {}
        for version, feed in value.get("feeds", {}).items():
            if version not in {"4", "6"}:
                raise ValueError
            feeds[version] = {"source": SOURCE, "freshness": private.choice(feed["freshness"], {"fresh", "stale", "unverified"}),
                **{k: stamp(private.date(feed[k])) for k in ("published_at", "retrieved_at", "expires_at")},
                "records": private.integer(feed["records"], MAX_NETWORKS)}
            copyright = feed.get("copyright", "")
            if not isinstance(copyright, str) or not re.fullmatch(r"\(c\) [0-9]{4} The Spamhaus Project SLU", copyright):
                raise ValueError
            feeds[version]["copyright"] = copyright
        out["feeds"] = feeds
        return {"destination_threats": out}
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return {}
