"""Owner-only maintenance. No downloads, promotion, clock overrides or recursive link following."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import math
import os
import re
import stat
import time

from . import core, history, process_store, signature_update as update

ENTRY = re.compile(r"(?:stage-)?[0-9a-f]{32}\Z")
REV = re.compile(r"[0-9a-f]{64}\Z")
PROVIDER_LIMIT = 65536


def attempt(path):
    obj = update.read_json(path / "attempt.json")
    if obj is not None and (not isinstance(obj, dict) or set(obj) != {"pending", "next_attempt"}
            or type(obj["pending"]) is not bool or type(obj["next_attempt"]) not in (int, float)
            or not math.isfinite(obj["next_attempt"]) or not 0 < obj["next_attempt"] < 1e12):
        raise OSError("Invalid signature wait state; preserve it for owner investigation")
    return obj


def provider_bytes(file, normalize=False):
    if core.cloud_placeholder(file):
        raise OSError("Cloud provider state refused")
    if normalize:
        history.make_private(file)
    fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = process_store.Store({}).private(fd)
        if not 1 <= info.st_size <= PROVIDER_LIMIT:
            raise OSError("Provider wait state size unavailable")
        data = os.read(fd, PROVIDER_LIMIT + 1)
        after = os.fstat(fd)
        if len(data) != info.st_size or (info.st_mtime_ns, info.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns):
            raise OSError("Provider wait state changed")
        return data
    finally:
        os.close(fd)


def preserve_provider(root, db):
    """Called after freshclam stops, including errors, before another attempt can be allowed."""
    # freshclam can leave a successfully downloaded 0644 CVD when a later download fails.
    # Normalize only known generated files, after owner/link/ACL checks, inside this private staging DB.
    for child in db.iterdir():
        if child.name in set(update.DATABASES) | {"freshclam.dat", "mirrors.dat"} or re.fullmatch(
                r"(?:main|daily|bytecode)(?:-[0-9]+)?\.cvd\.sign", child.name):
            if core.cloud_placeholder(child):
                raise OSError("Cloud updater output refused")
            history.make_private(child)
    file = db / "freshclam.dat"
    if file.exists() or file.is_symlink():
        history.replace_private(root / "provider.dat", provider_bytes(file, normalize=True))
        fd = os.open(root / "provider.dat", os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        update.sync_dir(root)


def identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def tree(path, deadline):
    """Metadata-only bounded snapshot, checked through descriptors before a single deletion."""
    rows = []
    def visit(fd, prefix="", depth=0):
        if depth > 3 or len(rows) > 128 or time.monotonic() >= deadline:
            raise OSError("Signature maintenance enumeration limit")
        process_store.Store({}).private(fd, True)
        rows.append([prefix, identity(os.fstat(fd))])
        for name in sorted(os.listdir(fd)):
            if len(rows) >= 128 or time.monotonic() >= deadline:
                raise OSError("Signature maintenance enumeration limit")
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if getattr(info, "st_flags", 0) & core.SF_DATALESS or stat.S_ISLNK(info.st_mode):
                raise OSError("Cloud or linked entry refused")
            folder = stat.S_ISDIR(info.st_mode)
            allowed = (name in {"db", "candidate"} if folder else name in set(update.DATABASES) | {
                "freshclam.conf", "freshclam.dat", "mirrors.dat", "validation.txt"}
                or re.fullmatch(r"(?:main|daily|bytecode)(?:-[0-9]+)?\.cvd\.sign", name))
            if not allowed:
                raise OSError("Unknown signature maintenance entry")
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if folder else 0), dir_fd=fd)
            try:
                process_store.Store({}).private(child, folder)
                if folder:
                    visit(child, prefix + name + "/", depth + 1)
                else:
                    rows.append([prefix + name, identity(os.fstat(child))])
            finally:
                os.close(child)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        visit(fd)
    finally:
        os.close(fd)
    return rows


@contextmanager
def exclusive_lease(path):
    import fcntl
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        process_store.Store({}).private(fd)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise history.Busy("Generation is in use") from None
        yield
    finally:
        os.close(fd)


def inventory(path, deadline):
    state, current = attempt(path), update.pointer(path)
    names = []
    for f in path.iterdir():
        if len(names) >= 128:
            raise OSError("Signature inventory limit")
        names.append(f.name)
    managed = sorted(n for n in names if ENTRY.fullmatch(n))
    previous = [n for n in managed if update.GEN.fullmatch(n) and (not current or n != current["generation"])]
    rows = []
    for name in managed:
        row = dict(id=name, kind="stage" if name.startswith("stage-") else "generation", revision=None,
                   current=bool(current and name == current["generation"]), in_use=None, deletable=False)
        try:
            metadata = tree(path / name, deadline)
            row["revision"] = hashlib.sha256(json.dumps(metadata).encode()).hexdigest()
            row["bytes"] = sum(r[1][5] for r in metadata if stat.S_ISREG(r[1][2]))
            row["reason"] = "current" if row["current"] else "pending_recovery" if state and state["pending"] and row["kind"] == "stage" else "last_previous" if current and name in previous and len(previous) == 1 else None
            # Scans lease only the current generation, which is protected anyway; probing it would fail their start.
            if row["kind"] == "generation" and not row["current"]:
                try:
                    with exclusive_lease(path / (name + ".lease")):
                        row["in_use"] = False
                except history.Busy:
                    row["in_use"] = True
                    row["reason"] = "in_use"
            row["deletable"] = row["reason"] is None
        except OSError:
            row["reason"] = "unavailable"
        rows.append(row)
    provider = path / "provider.dat"
    token = [state, current, rows, hashlib.sha256(provider_bytes(provider)).hexdigest() if provider.exists() or provider.is_symlink() else None]
    revision = hashlib.sha256(json.dumps(token, sort_keys=True).encode()).hexdigest()
    return dict(entries=rows, attempt=state, recovery_revision=revision,
                next_attempt_at=state["next_attempt"] if state else None,
                minimum_not_before=datetime.fromtimestamp(math.ceil(state["next_attempt"]), timezone.utc).isoformat() if state else None,
                waiting=bool(state and time.time() < state["next_attempt"]))


def remove_tree(path, expected, deadline):
    if hashlib.sha256(json.dumps(tree(path, deadline)).encode()).hexdigest() != expected:
        raise OSError("Selected signature entry changed; list again")
    # All descendants were validated before the first unlink. Only owner-controlled paths can change this tree.
    # Descriptor-relative traversal and NOFOLLOW prevent following a replaced descendant even then.
    def erase(fd):
        for name in os.listdir(fd):
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    erase(child)
                finally:
                    os.close(child)
                os.rmdir(name, dir_fd=fd)
            else:
                os.unlink(name, dir_fd=fd)
        os.fsync(fd)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        erase(fd)
    finally:
        os.close(fd)
    path.rmdir()
    update.sync_dir(path.parent)


def manage(scanner, action, entry_id=None, revision=None, not_before=None):
    if scanner.via != "cli":
        raise core.ScannerError("Signature maintenance is available only through the owner CLI")
    if action not in {"list", "recover", "delete"}:
        raise core.ScannerError("Invalid signature maintenance action")
    if action != "list" and (not isinstance(revision, str) or not REV.fullmatch(revision)):
        raise core.ScannerError("Exact revision from the signature store list is required")
    if action == "delete" and (not isinstance(entry_id, str) or not ENTRY.fullmatch(entry_id)):
        raise core.ScannerError("Invalid signature entry ID")
    deadline = time.monotonic() + 30
    try:
        # The updater lock freezes publication for this operation. Do not hold the short publication
        # lock while verifying large databases or deleting files: readers may still pin the current generation.
        with update.root(scanner) as path, history.locked(path / "update", attempts=1):
            info = inventory(path, deadline)
            if action == "list":
                return core.result("clamav", "completed", data=info)
            if action == "recover":
                if revision != info["recovery_revision"]:
                    raise core.ScannerError("Signature recovery state changed; list again")
                state = info["attempt"]
                if not state or not state["pending"]:
                    raise core.ScannerError("No pending signature update to recover")
                # Explicit owner acknowledgement of provider instructions; only an extension is permitted.
                try:
                    when = datetime.fromisoformat(not_before)
                    if when.tzinfo is None:
                        raise ValueError
                    until = when.timestamp()
                except (ValueError, TypeError, OverflowError):
                    raise core.ScannerError("--not-before requires an explicit timezone timestamp after all provider waits") from None
                if until < state["next_attempt"] or time.time() < until:
                    if until > state["next_attempt"]:
                        update.write_json(path / "attempt.json", {"pending": True, "next_attempt": until})
                    return core.result("clamav", "partial", data={"recovered": False, "next_attempt_at": max(until, state["next_attempt"])},
                                       warnings=["Recovery cannot shorten or bypass the update/provider wait; retry after the acknowledged deadline"])
                if info["entries"] and any(r["reason"] == "unavailable" for r in info["entries"]):
                    raise core.ScannerError("Unverified signature entries require owner investigation")
                update.current(path, deadline)  # Do not silently promote an orphan or accept a corrupt active generation.
                provider = path / "provider.dat"
                # provider.dat is refreshed after every freshclam run, failures included, so it supersedes stage copies.
                # Only stages from before it existed carry the sole wait state.
                if not (provider.exists() or provider.is_symlink()):
                    legacy = [path / r["id"] / "db" / "freshclam.dat" for r in info["entries"] if r["kind"] == "stage"]
                    legacy = [f for f in legacy if f.exists() or f.is_symlink()]
                    if len(legacy) > 1:
                        raise core.ScannerError("Ambiguous provider wait state; preserve stages for investigation")
                    if legacy:
                        preserve_provider(path, legacy[0].parent)
                update.write_json(path / "attempt.json", {"pending": False, "next_attempt": until})
                return core.result("clamav", "completed", data={"recovered": True, "next_attempt_at": until,
                                   "provider_state_preserved": (path / "provider.dat").exists(), "update_performed": False})
            row = next((r for r in info["entries"] if r["id"] == entry_id), None)
            if row is None or row["revision"] != revision:
                raise core.ScannerError("Selected signature entry is missing or changed; list again")
            if not row["deletable"]:
                raise core.ScannerError("Selected entry is protected: " + row["reason"])
            update.current(path, deadline)
            if row["kind"] == "generation":
                lease = path / (entry_id + ".lease")
                with exclusive_lease(lease):
                    remove_tree(path / entry_id, revision, deadline)
                    # IDs are never reused and only the current generation is ever leased, so nothing can lock
                    # this file again; removing it keeps the store under the inventory limit.
                    lease.unlink()
                update.sync_dir(path)
            else:
                remove_tree(path / entry_id, revision, deadline)
            return core.result("clamav", "completed", data={"deleted": entry_id, "update_performed": False})
    except history.Busy:
        return core.result("clamav", "partial", warnings=["Signature update, publication or selected generation is busy; no maintenance completed"])
    except OSError:
        raise core.ScannerError("Signature maintenance could not complete; preserve state and check private permissions") from None
