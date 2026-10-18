"""Whether the engines on this PC are their latest releases (only with updates.lookup = true).

Only the official release lists are read: the GitHub releases of osquery and ClamAV, and Google's
Android SDK repository for Platform-Tools (adb). Nothing is downloaded or installed and nothing about
this PC is sent; an older engine is reported with a warning that says where to update it. What was
found is kept beside the scan history for a day, so most scans make no request at all.
"""
from __future__ import annotations

import http.client
import json
import re
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

from . import history
from .core import NoRedirect, ScannerError, TrackedHTTPSHandler, check_cancel, fetch_bounded, run_bounded

# The scans that run each engine; Wazuh runs on its own server and the router check runs none.
ENGINES = {"inventory": "osquery", "malware": "clamav", "android": "adb", "android_check": "adb"}
NAMES = {"osquery": "osquery", "clamav": "ClamAV", "adb": "adb (Platform-Tools)"}
# Ten releases reach back past the last release round of every ClamAV line still updated.
RELEASES = {"osquery": "https://api.github.com/repos/osquery/osquery/releases?per_page=10",
            "clamav": "https://api.github.com/repos/Cisco-Talos/clamav/releases?per_page=10",
            "adb": "https://dl.google.com/android/repository/repository2-3.xml"}
SOURCES = {"osquery": "GitHub releases of osquery/osquery", "clamav": "GitHub releases of Cisco-Talos/clamav",
           "adb": "Google's Android SDK repository"}
UPDATE_FROM = {"osquery": "https://osquery.io/downloads/",
               "clamav": "https://docs.clamav.net/manual/Installing.html",
               "adb": "https://developer.android.com/tools/releases/platform-tools"}
TAGS = {"osquery": re.compile(r"(\d{1,6})\.(\d{1,6})\.(\d{1,6})"),
        "clamav": re.compile(r"clamav-(\d{1,6})\.(\d{1,6})\.(\d{1,6})")}
# What each engine prints for its version; ClamAV marks test releases with -rc, -beta or -alpha.
INSTALLED = {"osquery": re.compile(r"osquery[di]? version (\d{1,6})\.(\d{1,6})\.(\d{1,6})"),
             "clamav": re.compile(r"ClamAV (\d{1,6})\.(\d{1,6})\.(\d{1,6})(-(?:rc|beta|alpha))?"),
             "adb": re.compile(r"^Version (\d{1,6})\.(\d{1,6})\.(\d{1,6})", re.MULTILINE)}
VERSION_TEXT = re.compile(r"(\d{1,6})\.(\d{1,6})\.(\d{1,6})")
LINE_TEXT = re.compile(r"\d{1,6}\.\d{1,6}")
DAY_TEXT = re.compile(r"\d{4}-\d{2}-\d{2}")
MAX_CACHE_BYTES = 64 * 1024
# The ClamAV list is about 0.4 MB for ten releases, Google's about 0.4 MB.
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
FRESH = timedelta(days=1)
RETRY = timedelta(hours=1)
# Older information is not shown as the latest: a release may have come out since.
USABLE = timedelta(days=30)
CLOCK_SKEW = timedelta(days=1)
# Patches of each ClamAV line still updated come out on the same day, give or take a time zone.
ROUND = timedelta(days=2)
LOOKUP_SECONDS, VERSION_SECONDS = 15, 10
_lock = threading.Lock()


class Unavailable(Exception):
    """The release list could not be read; the message says why, in fixed words."""


def version(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in VERSION_TEXT.fullmatch(text).groups())


def shown(parts: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in parts)


def installed(scanner, engine: str, cancel: threading.Event | None) -> tuple[tuple[int, ...], str] | None:
    """The engine's version and the mark of a test release ("-rc" or the like), from its own version output."""
    argv = {"osquery": lambda: [scanner.binary("osquery_binary"), "-S", "--version"],
            "clamav": lambda: [scanner.binary("clamav_binary"), "--version"],
            "adb": lambda: [scanner.binary("adb_binary", scanner.android), "version"]}[engine]()
    code, output, _ = run_bounded(argv, min(VERSION_SECONDS, scanner.timeout), scanner.limit, cancel=cancel)
    match = INSTALLED[engine].search(output) if code == 0 else None
    if not match:
        return None
    return tuple(int(part) for part in match.groups()[:3]), (match.group(4) or "") if engine == "clamav" else ""


def https(url: str, cancel: threading.Event | None) -> bytes:
    service = "Google" if url.startswith("https://dl.google.com/") else "GitHub"
    handler = TrackedHTTPSHandler(ssl.create_default_context())
    opener = build_opener(ProxyHandler({}), handler, NoRedirect(service))
    headers = {"User-Agent": "personal-device-scanner-mcp"}
    if service == "GitHub":
        headers.update({"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    return fetch_bounded(opener, handler, Request(url, headers=headers), LOOKUP_SECONDS, MAX_RESPONSE_BYTES,
                         cancel, service=service)


def github_releases(body: bytes, engine: str) -> list[tuple[tuple[int, ...], datetime]]:
    """Published releases only: drafts and pre-releases (osquery's 5.24.0 was one) are not the latest."""
    try:
        items = json.loads(body)
    except (ValueError, RecursionError):
        raise Unavailable("unexpected answer") from None
    if not isinstance(items, list):
        raise Unavailable("unexpected answer")
    found = []
    for item in items:
        if not isinstance(item, dict) or item.get("draft") is not False or item.get("prerelease") is not False:
            continue
        tag, published = item.get("tag_name"), item.get("published_at")
        match = TAGS[engine].fullmatch(tag) if isinstance(tag, str) else None
        if not match or not isinstance(published, str):
            continue
        try:
            when = datetime.fromisoformat(published)
        except ValueError:
            continue
        if when.tzinfo is None:
            continue
        found.append((tuple(int(part) for part in match.groups()), when.astimezone(timezone.utc)))
    if not found:
        raise Unavailable("no published release in the list")
    return found


def clamav_lines(found: list[tuple[tuple[int, ...], datetime]]) -> dict:
    """The newest release of each line, and which lines were updated in the latest round.

    ClamAV patches every line it still supports on the same day, so a line left out of the
    latest round that covered two or more lines is probably no longer supported. Without such
    a round in the list, nothing is said about it.
    """
    lines: dict[str, tuple[tuple[int, ...], datetime]] = {}
    for parts, when in found:
        line = shown(parts[:2])
        newest, last = lines.get(line, (parts, when))
        lines[line] = (max(newest, parts), max(last, when))
    start = None
    for _, when in sorted(found, key=lambda item: item[1], reverse=True):
        if len({shown(p[:2]) for p, w in found if when - ROUND <= w <= when}) >= 2:
            start = when - ROUND
            break
    newest = max(parts for parts, _ in found)
    updated = None
    if start is not None:
        updated = sorted((line for line, (_, last) in lines.items()
                          if last >= start or line == shown(newest[:2])), key=lambda line: version(line + ".0"),
                         reverse=True)
    return {"newest": shown(newest), "lines": {line: shown(parts) for line, (parts, _) in lines.items()},
            "updated_lines": updated, "round": start and (start + ROUND).date().isoformat()}


def platform_tools(body: bytes) -> str:
    """The stable Platform-Tools revision in Google's SDK repository list."""
    from .router import Stop, local, parse_xml
    try:
        root = parse_xml(body)
    except Stop:
        raise Unavailable("unexpected answer") from None
    found = []
    for package in root.iter():
        if local(package.tag) != "remotePackage" or package.get("path") != "platform-tools":
            continue
        channel = next((node.get("ref") for node in package if local(node.tag) == "channelRef"), None)
        revision = next((node for node in package if local(node.tag) == "revision"), None)
        if channel != "channel-0" or revision is None:
            continue
        numbers = {local(node.tag): (node.text or "").strip() for node in revision}
        if all(re.fullmatch(r"\d{1,6}", numbers.get(key, "")) for key in ("major", "minor", "micro")):
            found.append(tuple(int(numbers[key]) for key in ("major", "minor", "micro")))
    if not found:
        raise Unavailable("no stable Platform-Tools in the list")
    return shown(max(found))


def lookup(engine: str, cancel: threading.Event | None) -> dict:
    try:
        body = https(RELEASES[engine], cancel)
    except HTTPError as exc:
        exc.close()  # it holds the connection the answer came on
        raise Unavailable(f"HTTP {exc.code}") from None
    except ScannerError:
        # A cancel is not a failure to remember; otherwise it was too slow, too large or redirected.
        check_cancel(cancel)
        raise Unavailable("no complete answer") from None
    except (OSError, URLError, ValueError, http.client.HTTPException):
        raise Unavailable("connection failed") from None
    if engine == "adb":
        return {"latest": platform_tools(body)}
    found = github_releases(body, engine)
    if engine == "clamav":
        return clamav_lines(found)
    return {"latest": shown(max(parts for parts, _ in found))}


def stamp(entry: dict, key: str) -> datetime | None:
    value = entry.get(key)
    try:
        when = datetime.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        return None
    return when if when is not None and when.tzinfo is not None else None


def usable(engine: str, entry) -> bool:
    """Information read back from the cache file, which anything running as the owner could have edited."""
    if not isinstance(entry, dict) or stamp(entry, "checked_at") is None:
        return False
    if engine != "clamav":
        return isinstance(entry.get("latest"), str) and bool(VERSION_TEXT.fullmatch(entry["latest"]))
    lines, updated, day = entry.get("lines"), entry.get("updated_lines"), entry.get("round")
    return (isinstance(entry.get("newest"), str) and bool(VERSION_TEXT.fullmatch(entry["newest"]))
            and isinstance(lines, dict) and 0 < len(lines) <= 20
            and all(isinstance(k, str) and LINE_TEXT.fullmatch(k) and isinstance(v, str) and VERSION_TEXT.fullmatch(v)
                    and v.startswith(k + ".") for k, v in lines.items())
            and (updated is None or (isinstance(updated, list) and all(line in lines for line in updated)))
            and (updated is None) == (day is None)
            and (day is None or (isinstance(day, str) and bool(DAY_TEXT.fullmatch(day)))))


def cache_file(scanner) -> Path:
    return history.releases_file(scanner.history_path())


def load(path: Path) -> dict:
    data = history.read_private(path, MAX_CACHE_BYTES)
    try:
        cache = json.loads(data) if data is not None else {}
    except (ValueError, RecursionError):
        return {}
    return cache if isinstance(cache, dict) and cache.get("version") == 1 else {}


def releases(scanner, engine: str, cancel: threading.Event | None, now: datetime) -> tuple[dict | None, str, list[str]]:
    """The latest releases, from the saved information while it is fresh, or looked up again.

    Also the reason a lookup failed, and warnings about the saved information.
    """
    warnings: list[str] = []
    try:
        path = cache_file(scanner)
    except ScannerError:
        path = None
    with _lock:
        saved = load(path) if path is not None else {}
        entry = saved.get(engine)
        remembered = scanner.release_info.get(engine)
        # The newer of what this process looked up and what the file holds.
        candidates = [e for e in (entry, remembered) if isinstance(e, dict)]
        entry = max(candidates, key=lambda e: max(stamp(e, "checked_at") or datetime.min.replace(tzinfo=timezone.utc),
                                                  stamp(e, "failed_at") or datetime.min.replace(tzinfo=timezone.utc)),
                    default=None)

        def recent(key: str, within: timedelta) -> bool:
            when = stamp(entry, key) if entry is not None else None
            return when is not None and now - within < when <= now + CLOCK_SKEW

        reason = ""
        if not (recent("checked_at", FRESH) and usable(engine, entry)) and not recent("failed_at", RETRY):
            try:
                entry = {"checked_at": now.isoformat(timespec="seconds"), **lookup(engine, cancel)}
            except Unavailable as exc:
                reason = str(exc)
                kept = {key: value for key, value in entry.items() if key != "failed_at"} if entry else {}
                entry = {**kept, "failed_at": now.isoformat(timespec="seconds")}
            scanner.release_info[engine] = entry
            if path is not None:
                try:
                    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    saved = {key: value for key, value in saved.items() if key in NAMES}
                    history.replace_private(path, json.dumps({**saved, "version": 1, engine: entry}).encode("ascii"))
                except OSError:
                    warnings.append("The latest-release information could not be saved; it is looked up again "
                                    "on the next scan")
        elif recent("failed_at", RETRY):
            reason = "an earlier attempt failed; it is retried an hour later"
    if not (usable(engine, entry) and recent("checked_at", USABLE)):
        return None, reason or "no information", warnings
    if reason:
        warnings.append(f"The latest {NAMES[engine]} release could not be checked again ({reason}); compared "
                        f"with the information from {stamp(entry, 'checked_at').date().isoformat()}")
    return entry, reason, warnings


def compare(engine: str, current: tuple[int, ...], test_release: str, entry: dict) -> tuple[dict, list[str]]:
    name, where = NAMES[engine], UPDATE_FROM[engine]
    text = shown(current)
    if engine != "clamav":
        latest = version(entry["latest"])
        status = "outdated" if current < latest else "newer" if current > latest else "current"
        warnings = ([f"{name} {text} is older than the latest release, {entry['latest']}; update it from {where}"]
                    if status == "outdated" else [])
        return {"latest": entry["latest"], "status": status}, warnings
    line = shown(current[:2])
    newest, in_line, updated = version(entry["newest"]), entry["lines"].get(line), entry["updated_lines"]
    info = {"latest": entry["newest"], "line": line, "latest_in_line": in_line,
            "line_updated": None if updated is None else line in updated}
    if in_line is None:
        if current > newest:
            return {**info, "line_updated": None, "status": "newer"}, []
        return {**info, "status": "outdated"}, [
            f"ClamAV {line} has no release among the latest ten (the newest is {entry['newest']}); it may no "
            f"longer be supported. Update ClamAV from {where}"]
    latest = version(in_line)
    # A test release comes before the release of the same number.
    older = current < latest or (current == latest and bool(test_release))
    status = "outdated" if older else "newer" if current > latest else "current"
    warnings = ([f"ClamAV {text}{test_release} is older than {in_line}, the latest "
                 f"release of ClamAV {line}; update it from {where}"] if older else [])
    if updated is not None and line not in updated:
        status = "outdated"
        warnings.append(f"ClamAV {line} was not updated in the latest release round ({entry['round']}, for "
                        f"{', '.join(updated)}); it may no longer be supported. The newest release is "
                        f"{entry['newest']}")
    return {**info, "status": status}, warnings


def check(scanner, operation: str, report: dict, cancel: threading.Event | None) -> None:
    """Adds data.engine_update and, for an engine that is not the latest, a warning; the status stays as it is."""
    engine = ENGINES[operation]
    info = {"engine": engine, "installed": None, "latest": None, "status": "unknown", "checked_at": None,
            "source": SOURCES[engine]}
    warnings: list[str] = []
    entry, reason = None, ""
    try:
        found = installed(scanner, engine, cancel)
        # Without the installed version there is nothing to compare, so nothing is looked up.
        if found is not None:
            entry, reason, warnings = releases(scanner, engine, cancel, datetime.now(timezone.utc))
    except ScannerError:
        if cancel is not None and cancel.is_set():
            return  # the scan itself finished; the client gave up waiting for it
        found = None
    if found is None:
        warnings.append(f"The {NAMES[engine]} version could not be read; it was not compared with the latest release")
    elif entry is None:
        info["installed"] = shown(found[0]) + found[1]
        warnings.append(f"The latest {NAMES[engine]} release could not be checked ({reason}); the installed "
                        f"version {info['installed']} was not compared")
    else:
        info["installed"] = shown(found[0]) + found[1]
        compared, notes = compare(engine, found[0], found[1], entry)
        info.update(compared, checked_at=entry["checked_at"])
        warnings += notes
    report.setdefault("data", {})["engine_update"] = info
    report["warnings"] += warnings
