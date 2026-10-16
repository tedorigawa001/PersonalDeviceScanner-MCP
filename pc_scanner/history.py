"""Scan history kept on this PC: one summary line per scan, read by the owner with `history`.

The summary holds only what was run and how it ended, never findings (file, app or package names,
CVEs). Full results are kept beside it only when the owner turns on history.details. The MCP server
offers no tool to read either, so the AI never sees them.
"""
from __future__ import annotations

import contextlib
import json
import math
import os
import platform
import re
import secrets
import stat
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from .core import NAME_CHARS, PATH_CHARS, ScannerError, clean_text, decode_cursor

if os.name == "nt":
    import msvcrt
else:
    import fcntl

FOLDER = "personal-device-scanner-mcp"
# Each of the two files; when the current one is full it replaces the older one.
FILE_BYTES = 1024 * 1024
MAX_LIMIT = 1000
ERROR_CHARS = 500
OPERATIONS = {"inventory", "malware", "vulnerabilities", "android", "android_check"}
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
# What identifies the target. The Wazuh cursor names records, so only whether one was passed and the
# page it leads to are kept.
TARGETS = {"inventory": ("query_id", "offset"), "malware": ("root_alias", "relative_path"),
           "android": ("device_alias", "query_id"), "android_check": ("device_alias",)}
# Where a paged result says that another page can be fetched.
NEXT_PAGE = {"inventory": "next_offset", "vulnerabilities": "next_cursor"}
# A link is refused, so a history file in a shared folder cannot be pointed at another file.
NO_FOLLOW = getattr(os, "O_NOFOLLOW", 0)
# Opening a FIFO put in its place fails or returns at once instead of holding up the scan; regular files ignore it.
NO_WAIT = getattr(os, "O_NONBLOCK", 0)
# The lock is held for one size check, rename and write; waiting longer means another process is stuck.
LOCK_ATTEMPTS, LOCK_INTERVAL = 200, 0.01
# Named by the time it was saved, so names sort oldest first.
DETAILS_ID = re.compile(r"[0-9]{8}T[0-9]{6}\.[0-9]{6}Z-[0-9a-f]{8}")
# Results are far smaller; a larger file was not written by this program.
MAX_DETAILS_BYTES = 32 * 1024 * 1024
BINARY = getattr(os, "O_BINARY", 0)
# The MCP server runs a local engine and a Wazuh request at the same time.
_lock = threading.Lock()


def default_file(env=os.environ, system: str | None = None, home: Path | None = None) -> Path:
    """The per-user state folder of each OS; only an absolute override is honoured."""
    system = system or platform.system()
    home = Path.home() if home is None else home
    if system == "Darwin":
        base = home / "Library" / "Application Support"
    elif system == "Windows":
        local = env.get("LOCALAPPDATA", "")
        base = Path(local) if local and Path(local).is_absolute() else home / "AppData" / "Local"
    else:
        state = env.get("XDG_STATE_HOME", "")
        base = Path(state) if state and Path(state).is_absolute() else home / ".local" / "state"
    return base / FOLDER / "history.jsonl"


def older(path: Path) -> Path:
    return path.with_name(path.name + ".1")


def lock_file(path: Path) -> Path:
    return path.with_name(path.name + ".lock")


def details_folder(path: Path) -> Path:
    return path.with_name(path.name + ".details")


@contextlib.contextmanager
def locked(path: Path):
    """Held across processes: a CLI and MCP servers that both find the file full must not rotate it twice."""
    fd = os.open(lock_file(path), os.O_RDWR | os.O_CREAT | NO_FOLLOW, 0o600)
    try:
        for attempt in range(LOCK_ATTEMPTS):
            try:
                if os.name == "nt":
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if attempt == LOCK_ATTEMPTS - 1:
                    raise
                time.sleep(LOCK_INTERVAL)
        try:
            yield
        finally:
            if os.name == "nt":
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    finally:
        os.close(fd)


def private(fd: int) -> None:
    """Also for a file that already existed, as the 0600 given to open applies only when it creates one."""
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise OSError("The history file is not a regular file")
    if os.name != "nt" and info.st_mode & 0o077:
        # Fails, so nothing is written, when another user owns the file.
        os.fchmod(fd, 0o600)


def make_private(name: Path) -> None:
    fd = os.open(name, os.O_RDONLY | NO_FOLLOW | NO_WAIT)
    try:
        private(fd)
    finally:
        os.close(fd)


def entry(operation: str, arguments: dict, report: dict, started: datetime, seconds: float, via: str) -> dict:
    target = {}
    if operation == "vulnerabilities":
        target["continued"] = bool(arguments.get("cursor"))
        try:
            target["page"] = decode_cursor(arguments.get("cursor", ""))[0]
        except ScannerError:
            pass  # refused before anything was fetched
    for key in TARGETS.get(operation, ()):
        if key in arguments:
            value = arguments[key]
            target[key] = value if type(value) is int else clean_text(value, PATH_CHARS)
    data, follows = report.get("data"), NEXT_PAGE.get(operation)
    more = {"more": data[follows] is not None} if follows and isinstance(data, dict) and follows in data else {}
    findings = {}
    for finding in report["findings"]:
        severity = finding.get("severity") if isinstance(finding, dict) else None
        severity = severity if severity in SEVERITIES else "unknown"
        findings[severity] = findings.get(severity, 0) + 1
    return {"version": 1, "started_at": started.isoformat(timespec="seconds"), "seconds": round(seconds, 1),
            "via": via, "operation": operation, "target": target, "status": report["status"],
            "findings": findings, "warnings": len(report["warnings"]), **more,
            **({"error": clean_text(report["error"], ERROR_CHARS)} if report.get("error") else {})}


def save_details(path: Path, report: dict, max_bytes: int) -> str:
    """Keeps a full result, then removes the oldest ones until all fit in max_bytes; the newest always stays."""
    folder = details_folder(path)
    folder.mkdir(exist_ok=True, mode=0o700)
    info = folder.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise OSError("The details folder is not a folder")
    if os.name != "nt" and info.st_mode & 0o077:
        os.chmod(folder, 0o700)
    name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ") + "-" + secrets.token_hex(4)
    # ASCII only: a result is never refused for text it cannot encode.
    data = json.dumps(report, ensure_ascii=True).encode("ascii")
    fd = os.open(folder / f"{name}.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | NO_FOLLOW | BINARY, 0o600)
    try:
        with open(fd, "wb") as f:
            f.write(data)
    except BaseException:
        (folder / f"{name}.json").unlink(missing_ok=True)
        raise
    kept = []
    for child in folder.iterdir():
        if child.suffix == ".json" and DETAILS_ID.fullmatch(child.stem):
            try:
                kept.append((child.name, child.lstat().st_size, child))
            except FileNotFoundError:
                continue
    total = sum(size for _, size, _ in kept)
    for _, size, child in sorted(kept):
        if total <= max_bytes:
            break
        if child.stem == name:
            continue
        try:
            child.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            # On Windows, open in a reader that could not take the lock: removed by a later scan.
            continue
        total -= size
    return name


def load_details(path: Path, name: str | None) -> tuple[dict | None, str]:
    """A kept result, or why there is none: "off", "removed" or "unreadable"."""
    if name is None:
        return None, "off"
    if not DETAILS_ID.fullmatch(name):
        return None, "unreadable"
    try:
        fd = os.open(details_folder(path) / f"{name}.json", os.O_RDONLY | NO_FOLLOW | NO_WAIT | BINARY)
    except FileNotFoundError:
        return None, "removed"
    except OSError:
        return None, "unreadable"
    with open(fd, "rb") as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_DETAILS_BYTES:
            return None, "unreadable"
        data = f.read(MAX_DETAILS_BYTES + 1)
    try:
        report = json.loads(data)
    except (ValueError, RecursionError):
        return None, "unreadable"
    return (report, "") if isinstance(report, dict) else (None, "unreadable")


def append(path: Path, record: dict, details: dict | None = None, details_bytes: int = 0) -> None:
    with _lock:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with locked(path):
            if details is not None:
                record = {**record, "details": save_details(path, details, details_bytes)}
            line = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
            # The older file is never opened for writing, so it and the file about to become it are checked here.
            for name in (older(path), path):
                try:
                    info = name.lstat()
                except FileNotFoundError:
                    continue
                if os.name != "nt" and stat.S_ISREG(info.st_mode) and info.st_mode & 0o077:
                    make_private(name)
            try:
                if path.lstat().st_size >= FILE_BYTES:
                    os.replace(path, older(path))
            except OSError:
                # Missing, or on Windows open in a reader that could not take the lock: rotate on a later scan.
                pass
            with open(path, "ab", buffering=0,
                      opener=lambda name, flags: os.open(name, flags | NO_FOLLOW | NO_WAIT, 0o600)) as f:
                private(f.fileno())
                f.write(line)


def text(value, limit: int = NAME_CHARS) -> str:
    if not isinstance(value, str):
        raise TypeError("not text")
    return clean_text(value, limit)


def parse(line: str) -> dict | None:
    """One recorded scan, checked and cleaned again: the file may have been edited or damaged."""
    try:
        record = json.loads(line)
        started = datetime.fromisoformat(record["started_at"])
        seconds, warnings, findings, target = (record["seconds"], record["warnings"], record["findings"],
                                               record["target"])
        if (started.tzinfo is None or type(seconds) not in (int, float) or not math.isfinite(seconds)
                or seconds < 0 or type(warnings) is not int or warnings < 0
                or not isinstance(findings, dict) or not isinstance(target, dict)
                or not all(type(count) is int and count >= 0 for count in findings.values())):
            return None
        error, details, more = record.get("error"), record.get("details"), record.get("more")
        return {"started_at": started.isoformat(), "seconds": seconds, "via": text(record["via"]),
                "operation": text(record["operation"]), "status": text(record["status"]),
                "target": {text(key): value if type(value) in (int, bool) else text(value, PATH_CHARS)
                           for key, value in target.items()},
                "findings": {text(key): count for key, count in findings.items()}, "warnings": warnings,
                "error": None if error is None else text(error, ERROR_CHARS),
                "more": more if isinstance(more, bool) else None,
                "details": details if isinstance(details, str) and DETAILS_ID.fullmatch(details) else None}
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return None


def read(path: Path, limit: int) -> tuple[list[dict], int]:
    """The latest scans, oldest first, and how many damaged lines were skipped."""
    entries, skipped = deque(maxlen=limit), 0
    with contextlib.ExitStack() as stack:
        try:
            # So no rotation falls between reading the two files.
            stack.enter_context(locked(path))
        except OSError:
            # No history folder yet, one this user may read but not write, or a stuck writer.
            pass
        for name in (older(path), path):
            try:
                f = open(name, encoding="utf-8", errors="replace")
            except FileNotFoundError:
                continue
            with f:
                for line in f:
                    if not line.strip():
                        continue
                    parsed = parse(line)
                    if parsed is None:
                        skipped += 1
                    else:
                        entries.append(parsed)
    return list(entries), skipped


def describe_target(item: dict) -> str:
    target, operation = item["target"], item["operation"]
    if operation == "malware" and "root_alias" in target:
        relative = target.get("relative_path", ".")
        return f"{target['root_alias']}" if relative == "." else f"{target['root_alias']}/{relative}"
    if operation == "inventory" and "query_id" in target:
        return f"{target['query_id']}" + (f" offset {target['offset']}" if target.get("offset") else "")
    if operation == "vulnerabilities":
        page = target.get("page")
        if type(page) is int and page > 1:
            return f"page {page}"
        return "next page" if target.get("continued") else "first page"
    return " ".join(str(value) for value in target.values()) or "-"


def describe_findings(item: dict) -> str:
    findings = item["findings"]
    total = sum(findings.values())
    if not total:
        # An operation that did not run found nothing because it looked at nothing.
        return "-" if item["status"] == "error" else "0"
    order = [*SEVERITIES, *sorted(set(findings) - set(SEVERITIES))]
    return f"{total} (" + ", ".join(f"{name} {findings[name]}" for name in order if findings.get(name)) + ")"


def table(entries: list[dict]) -> str:
    rows = [("TIME", "VIA", "OPERATION", "STATUS", "FINDINGS", "SECONDS", "TARGET")]
    errors = [None]
    for item in entries:
        when = datetime.fromisoformat(item["started_at"]).astimezone().strftime("%Y-%m-%d %H:%M:%S")
        rows.append((when, item["via"], item["operation"], item["status"], describe_findings(item),
                     f"{item['seconds']:.1f}", describe_target(item)))
        errors.append(item["error"])
    # The target goes last: folder names can be wide characters that would break the alignment.
    widths = [max(len(row[column]) for row in rows) for column in range(len(rows[0]) - 1)]
    lines = []
    for row, error in zip(rows, errors):
        cells = [cell.rjust(width) if column == 5 else cell.ljust(width)
                 for column, (cell, width) in enumerate(zip(row, widths))]
        lines.append("  ".join([*cells, row[-1]]).rstrip())
        if error:
            lines.append(" " * (widths[0] + 2) + f"error: {error}")
    return "\n".join(lines)
