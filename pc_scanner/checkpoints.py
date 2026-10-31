"""Local-only checkpoint inventory and single-selection deletion. Never a scan plan or MCP tool."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

from . import core, history, malware_batch as batch, coverage

ID = re.compile(r"[0-9a-f]{64}\Z")
MAX_ENTRIES = 256
MAX_READ_BYTES = 32 * 1024 * 1024
SECONDS = 5


def local_only(scanner):
    if scanner.via == "mcp":
        raise core.ScannerError("Checkpoint management is available only through the local CLI")


def check(deadline):
    if time.monotonic() >= deadline:
        raise core.ScannerError("Checkpoint management time limit reached; retry locally")


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def safe_file(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or getattr(info, "st_file_attributes", 0) & (0x400 | core.WINDOWS_RECALL_ATTRIBUTES)
            or getattr(info, "st_flags", 0) & core.SF_DATALESS):
        raise OSError("Checkpoint must be a local regular file without links")
    if os.name != "nt" and info.st_mode & 0o077:
        raise OSError("Checkpoint must be private to its owner")
    if info.st_size > batch.MAX_STATE_BYTES:
        raise OSError("Checkpoint exceeds the read limit")


@contextmanager
def store(scanner):
    folder = batch.checkpoint_directory(scanner)
    if folder is None:
        yield None, None, None
        return
    info = folder.lstat()
    if core.cloud_placeholder(folder):
        raise core.ScannerError("Checkpoint directory must be locally available")
    fd = None
    try:
        if os.name != "nt":
            fd = os.open(folder, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | history.NO_FOLLOW | history.NO_WAIT)
            current = os.fstat(fd)
            if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino) or not history.owned(fd, current):
                raise OSError("Checkpoint directory changed")
        yield folder, fd, info
    finally:
        if fd is not None:
            os.close(fd)


def unchanged_directory(folder, info):
    current = folder.lstat()
    if (core.is_link(folder) or not stat.S_ISDIR(current.st_mode)
            or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)):
        raise OSError("Checkpoint directory changed")
    if os.name != "nt" and (current.st_uid != os.geteuid() or current.st_mode & 0o077):
        raise OSError("Checkpoint directory is not private")


@contextmanager
def exclusive(folder):
    """Same locks as batch scans, never a long wait or stale PID-file heuristic."""
    if not batch._lock.acquire(False):
        raise history.Busy("A batch scan or checkpoint operation is running")
    try:
        until = time.monotonic() + .05
        def waiting():
            if time.monotonic() >= until:
                raise history.Busy("A batch scan or checkpoint operation is running")
        with history.locked(folder / ".active", check_wait=waiting):
            yield
    finally:
        batch._lock.release()


def entry_stat(folder, dirfd, name):
    return os.stat(name, dir_fd=dirfd, follow_symlinks=False) if dirfd is not None else (folder / name).lstat()


@contextmanager
def opened(folder, dirfd, name, deadline, delete=False):
    before = entry_stat(folder, dirfd, name)
    safe_file(before)
    if os.name == "nt":
        from .windows_owner import open_checkpoint
        fd = open_checkpoint(folder / name, delete)
    else:
        fd = os.open(name, os.O_RDONLY | history.NO_FOLLOW | history.NO_WAIT, dir_fd=dirfd)
    try:
        info = os.fstat(fd)
        safe_file(info)
        if identity(before) != identity(info) or not history.owned(fd, info):
            raise OSError("Checkpoint changed or belongs to another user")
        chunks, remaining = [], batch.MAX_STATE_BYTES + 1
        while remaining:
            check(deadline)
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > batch.MAX_STATE_BYTES or identity(os.fstat(fd)) != identity(info):
            raise OSError("Checkpoint changed or exceeds the read limit")
        token = hashlib.sha256(repr(identity(info)).encode() + b"\0" + raw).hexdigest()
        yield fd, info, raw, token
    finally:
        os.close(fd)


def label(state, show_paths):
    target = state.get("target")
    if not isinstance(target, dict):
        return {}
    alias, relative = target.get("root_alias"), target.get("relative_path")
    if (not isinstance(alias, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", alias)
            or not isinstance(relative, str) or len(relative) > 32768 or "\x00" in relative):
        return {}
    path = Path(relative)
    if path.is_absolute() or path.drive or path.root or ".." in path.parts:
        return {}
    return {"root_alias": alias, **({"relative_path": core.clean_text(relative, core.PATH_CHARS)} if show_paths else {})}


def describe(raw, show_paths):
    try:
        state = json.loads(raw)
        if (not isinstance(state, dict) or type(state.get("schema")) is not int or state["schema"] not in (1, 2)
                or not isinstance(state.get("parts"), dict) or len(state["parts"]) > batch.MAX_PARTS):
            raise ValueError
        parts = state["parts"]
        out = {"state": "valid", "schema": state["schema"], "saved_parts": len(parts),
               "finished_parts": sum(isinstance(p, dict) and p.get("finished") is True for p in parts.values()),
               **label(state, show_paths)}
        if state["schema"] == 2:
            ledger = coverage.validate(state["coverage"])
            out.update(scan_group_id=ledger["group"], coverage_revision=ledger["revision"],
                       unresolved_scopes=coverage.summary(ledger)["unresolved"]["count"])
        return out
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
        # An owned bounded corrupt file can still be explicitly removed to free its slot.
        return {"state": "invalid"}


def inventory(folder, dirfd, info, busy, show_paths, deadline):
    names, count, complete, unmanaged = [], 0, True, 0
    with os.scandir(dirfd if dirfd is not None else folder) as entries:
        for entry in entries:
            check(deadline)
            count += 1
            if count > MAX_ENTRIES:
                complete = False
                break
            if entry.name.endswith(".json"):
                if ID.fullmatch(entry.name[:-5]):
                    names.append(entry.name)
                else:
                    unmanaged += 1
    rows, read_bytes = [], 0
    for name in sorted(names):
        row = {"checkpoint_id": name[:-5], "state": "unavailable", "deletable": False}
        try:
            unchanged_directory(folder, info)
            file_info = entry_stat(folder, dirfd, name)
            safe_file(file_info)
            if read_bytes + file_info.st_size > MAX_READ_BYTES:
                complete = False
                rows.append({**row, "reason": "read_budget"})
                continue
            with opened(folder, dirfd, name, deadline) as (_, file_info, raw, token):
                read_bytes += len(raw)
                row.update(describe(raw, show_paths), revision=token, bytes=len(raw),
                           last_saved_at=datetime.fromtimestamp(file_info.st_mtime, timezone.utc).isoformat(),
                           deletable=not busy)
        except (OSError, ValueError, OverflowError):
            row["reason"] = "unsafe_or_unreadable"
        rows.append(row)
    return {"checkpoints": rows, "checkpoint_count": len(names), "unmanaged_json_count": unmanaged,
            "capacity_count": len(names) + unmanaged, "capacity": batch.MAX_CHECKPOINTS,
            "enumeration_complete": complete, "scan_running": busy}


def list_checkpoints(scanner, show_paths=False):
    local_only(scanner)
    if type(show_paths) is not bool:
        raise core.ScannerError("show_paths must be true or false")
    deadline = time.monotonic() + SECONDS
    try:
        with store(scanner) as (folder, dirfd, info):
            if folder is None:
                data = {"checkpoints": [], "checkpoint_count": 0, "unmanaged_json_count": 0,
                        "capacity_count": 0, "capacity": batch.MAX_CHECKPOINTS,
                        "enumeration_complete": True, "scan_running": False}
            else:
                # Only a probe: a starting batch scan waits about 2 seconds for this lock, a full read can
                # take 5, and deletion checks everything again under the lock anyway.
                busy = False
                try:
                    with exclusive(folder):
                        pass
                except history.Busy:
                    busy = True
                data = inventory(folder, dirfd, info, busy, show_paths, deadline)
    except OSError:
        raise core.ScannerError("Checkpoint inventory could not be read safely; check local permissions") from None
    partial = data["scan_running"] or not data["enumeration_complete"] or any(r["state"] == "unavailable" for r in data["checkpoints"])
    return core.result("bridge", "partial" if partial else "completed", data=data,
        warnings=(["A batch scan is running; all checkpoint deletions are protected until it finishes"] if data["scan_running"] else [])
        + (["Some entries could not be safely listed; no unavailable entries can be deleted through this command"] if partial and not data["scan_running"] else []))


def delete_checkpoint(scanner, checkpoint_id, revision):
    local_only(scanner)
    if not all(isinstance(v, str) and ID.fullmatch(v) for v in (checkpoint_id, revision)):
        raise core.ScannerError("Use the exact checkpoint ID and revision from the local checkpoint list")
    deadline = time.monotonic() + SECONDS
    try:
        with store(scanner) as (folder, dirfd, info):
            if folder is None:
                raise core.ScannerError("Checkpoint no longer exists; list checkpoints again")
            with exclusive(folder):
                unchanged_directory(folder, info)
                name = checkpoint_id + ".json"
                with opened(folder, dirfd, name, deadline, delete=True) as (fd, file_info, raw, current):
                    if current != revision:
                        raise core.ScannerError("Checkpoint changed since listing; list again before deleting")
                    check(deadline)
                    unchanged_directory(folder, info)
                    if identity(entry_stat(folder, dirfd, name)) != identity(file_info):
                        raise core.ScannerError("Checkpoint changed since listing; list again before deleting")
                    if os.name == "nt":
                        from .windows_owner import delete_checkpoint_handle
                        delete_checkpoint_handle(fd)
                    else:
                        os.unlink(name, dir_fd=dirfd)
    except history.Busy:
        raise core.ScannerError("A batch scan or checkpoint operation is running; nothing was deleted") from None
    except OSError:
        raise core.ScannerError("Checkpoint could not be safely deleted; list again and check local permissions") from None
    return core.result("bridge", "completed", data={"deleted": True, "checkpoint_id": checkpoint_id},
                       warnings=["Saved progress and findings in this checkpoint were removed; a later batch scan must inspect the target again. Scan files and history were not deleted."])
