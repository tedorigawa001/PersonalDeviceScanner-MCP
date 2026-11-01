"""Owner CLI updater. Private CVD generations; no privilege elevation or MCP writes."""
from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import time

from . import core, history, process_store

DEFAULTS = dict(enabled=False, directory="", freshclam_binary="", sigtool_binary="", timeout_seconds=1800)
DATABASES = ("main.cvd", "daily.cvd", "bytecode.cvd")
GEN = re.compile(r"[0-9a-f]{32}\Z")
MAX_BYTES = 2 * 1024 ** 3
MAX_GENERATIONS = 4  # No automatic deletion in phase one; never remove a pinned generation.


def configure(scanner):
    raw = scanner.config.get("clamav_updates", {})
    if not isinstance(raw, dict) or set(raw) - DEFAULTS.keys():
        raise core.ScannerError("Invalid clamav_updates settings")
    cfg = {**DEFAULTS, **raw}
    if type(cfg["enabled"]) is not bool or type(cfg["timeout_seconds"]) is not int or not 1 <= cfg["timeout_seconds"] <= 3600:
        raise core.ScannerError("Invalid clamav_updates settings")
    for key in ("directory", "freshclam_binary", "sigtool_binary"):
        v = cfg[key]
        if not isinstance(v, str) or any(c in v for c in '\0\r\n"') or (v and (not Path(v).is_absolute() or ".." in Path(v).parts)):
            raise core.ScannerError("Invalid clamav_updates path")
        if cfg["enabled"] and not v:
            raise core.ScannerError("Enabled clamav_updates requires fixed paths")
    if cfg["enabled"] and scanner.local.get("clamav_database_directory"):
        raise core.ScannerError("Private generations cannot share an OS-managed database directory")
    scanner.signature_update_settings = cfg


@contextmanager
def root(scanner, create=False):
    cfg = scanner.signature_update_settings
    if not cfg["enabled"] or os.name != "posix" or os.geteuid() == 0:
        raise core.ScannerError("Private signature updates require an enabled, non-administrator POSIX account")
    # Reuse the descriptor-based ancestor, local filesystem, cloud, owner and ACL checks.
    with process_store.Store({"directory": cfg["directory"]}).open(create=create, file_lock=False) as store:
        if store is None:
            raise core.ScannerError("Private signature store is not initialized; run the owner update CLI")
        path = store.path
    yield path


def read_json(path):
    if path.exists() or path.is_symlink():
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            process_store.Store({}).private(fd)
        finally:
            os.close(fd)
    raw = history.read_private(path, 65536)
    if raw is None:
        if path.exists() or path.is_symlink():
            raise OSError("Private signature metadata unavailable")
        return None
    return json.loads(raw)


def write_json(path, obj):
    history.replace_private(path, json.dumps(obj, sort_keys=True).encode())
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    sync_dir(path.parent)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        process_store.Store({}).private(fd, True)
    finally:
        os.close(fd)


def digest_directory(path, deadline, cancel=None):
    private_dir(path)
    names = sorted(p.name for p in path.iterdir())
    if names != sorted(DATABASES):
        raise OSError("Only the three official complete CVD databases are allowed")
    total, versions, hashes = 0, {}, {}
    for name in DATABASES:
        file = path / name
        if core.cloud_placeholder(file):
            raise OSError("Cloud database refused")
        fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = process_store.Store({}).private(fd)
            if not 512 <= before.st_size <= MAX_BYTES:
                raise OSError("Database size limit")
            total += before.st_size
            if total > MAX_BYTES:
                raise OSError("Database size limit")
            header = os.read(fd, 512).decode("ascii").split(":")
            if len(header) < 4 or header[0] != "ClamAV-VDB" or not header[2].isdigit():
                raise OSError("Invalid CVD header")
            versions[name] = int(header[2])
            os.lseek(fd, 0, os.SEEK_SET)
            h = hashlib.sha256()
            while True:
                core.check_cancel(cancel)
                if time.monotonic() >= deadline:
                    raise core.ScannerError("Signature operation timed out")
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
            after = os.fstat(fd)
            if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise OSError("Database changed")
            hashes[name] = h.hexdigest()
        finally:
            os.close(fd)
    return dict(content=hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest(), versions=versions)


def pointer(path):
    """The published reference only; contents are verified separately."""
    obj = read_json(path / "current.json")
    if obj is None:
        return None
    if not isinstance(obj, dict) or set(obj) != {"generation", "content", "versions"} or not GEN.fullmatch(str(obj["generation"])):
        raise OSError("Invalid current generation")
    return obj


def verify(path, obj, deadline, cancel=None):
    actual = digest_directory(path / obj["generation"], deadline, cancel)
    if actual != {k: obj[k] for k in ("content", "versions")}:
        raise OSError("Current generation changed")
    return obj


def current(path, deadline, cancel=None):
    obj = pointer(path)
    return None if obj is None else verify(path, obj, deadline, cancel)


@contextmanager
def generation_lease(path):
    import fcntl
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        process_store.Store({}).private(fd)
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


@contextmanager
def pin(scanner, cancel=None):
    """Pin one generation on a scanner copy; caller's mutable configuration is untouched."""
    deadline = time.monotonic() + scanner.timeout
    with root(scanner) as path:
        # Keep the publication lock short (reference and lease only) so simultaneous starts wait instead of failing.
        with history.locked(path / "publish"):
            obj = pointer(path)
            if obj is None:
                raise core.ScannerError("Private signature store has no published generation")
            lease = generation_lease(path / (obj["generation"] + ".lease"))
            lease.__enter__()
        try:
            # The lease keeps this generation; hashing it no longer blocks other scans or publication.
            verify(path, obj, deadline, cancel)
            local = copy.copy(scanner)
            local.local = dict(scanner.local, clamav_database_directory=str(path / obj["generation"]))
            local._signature_generation = obj
            yield local
        finally:
            lease.__exit__(None, None, None)


def executable(value):
    p = Path(value)
    info = p.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or info.st_uid not in {0, os.geteuid()} or not os.access(p, os.X_OK):
        raise core.ScannerError("Updater executable is not owner-approved")
    return str(p)


def update(scanner, cancel=None, progress=None):
    """Only the local CLI calls this function. Never add it to Scanner.invoke or MCP."""
    if scanner.via != "cli":
        raise core.ScannerError("Signature updates are available only through the owner CLI")
    cfg = scanner.signature_update_settings
    deadline = time.monotonic() + cfg["timeout_seconds"]
    if progress:
        progress.set_deadline(deadline)
        progress.update(stage="preparing", checkpoint="not_applicable")
    published = False
    data = dict(update_status="failed", published=False, previous_preserved=False, resume_recheck_required=False)
    def run(argv):
        core.check_cancel(cancel)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise core.ScannerError("Signature update timed out")
        rc, out, err = core.run_bounded(argv, remaining, scanner.limit, cancel)
        if rc != 0:
            raise core.ScannerError("Signature update or validation failed; active definitions were not replaced")
        return out
    try:
        with root(scanner, True) as path, history.locked(path / "update", attempts=1):
            freshclam, sigtool = (executable(cfg[k]) for k in ("freshclam_binary", "sigtool_binary"))
            binary = scanner.binary("clamav_binary")
            old = current(path, deadline, cancel)
            data["previous_preserved"] = old is not None
            state = read_json(path / "attempt.json")
            now = time.time()
            if state is not None:
                if not isinstance(state, dict) or set(state) != {"pending", "next_attempt"} or type(state["pending"]) is not bool:
                    raise OSError("Invalid update interval")
                if state.get("pending") is True:
                    raise core.ScannerError("A prior update was interrupted or failed; owner recovery is required before another download")
                until = state["next_attempt"]
                if type(until) not in (int, float) or not 0 < until < 1e12:
                    raise OSError("Invalid update interval")
                if now < until:
                    data.update(update_status="rate_limited", next_attempt_at=until)
                    return core.result("clamav", "partial", data=data, warnings=["Update retry interval has not elapsed"])
            generations = [p for p in path.iterdir() if GEN.fullmatch(p.name) or p.name.startswith("stage-")]
            if len(generations) >= MAX_GENERATIONS or shutil.disk_usage(path).free < MAX_BYTES * 2:
                raise core.ScannerError("Private signature store capacity exhausted; owner maintenance is required")
            # Persist a conservative 24h guard before any network call. Includes failures/cancellation/429.
            write_json(path / "attempt.json", {"next_attempt": now + 86400, "pending": True})
            stage = path / ("stage-" + secrets.token_hex(16))
            stage.mkdir(mode=0o700)
            db = stage / "db"
            db.mkdir(mode=0o700)
            if old:
                for name in DATABASES:
                    with open(path / old["generation"] / name, "rb", opener=history.opener) as source:
                        with open(db / name, "xb", opener=history.opener) as dest:
                            while True:
                                core.check_cancel(cancel)
                                if time.monotonic() >= deadline:
                                    raise core.ScannerError("Signature update timed out")
                                block = source.read(1024 * 1024)
                                if not block:
                                    break
                                dest.write(block)
            config = stage / "freshclam.conf"
            history.replace_private(config, b"DatabaseMirror database.clamav.net\nScriptedUpdates no\nTestDatabases yes\nBytecode yes\nMaxAttempts 1\nConnectTimeout 30\nReceiveTimeout 120\n")
            if progress:
                progress.update(stage="running", checkpoint="not_applicable")
            run([freshclam, "--config-file=" + str(config), "--datadir=" + str(db)])
            if progress:
                progress.update(stage="validating")
            # Move only the required databases to a private candidate. Bookkeeping stays in the unpublished stage.
            candidate = stage / "candidate"
            candidate.mkdir(mode=0o700)
            allowed = set(DATABASES) | {"freshclam.dat", "mirrors.dat"}
            for file in db.iterdir():
                if file.name not in allowed and not re.fullmatch(r"(?:main|daily|bytecode)(?:-[0-9]+)?\.cvd\.sign", file.name):
                    raise OSError("Unexpected updater output")
                history.make_private(file)
            for name in DATABASES:
                file = db / name
                history.make_private(file)
                output = run([sigtool, "--info=" + str(file)])
                if "Digital signature:" not in output or "Verification OK" not in output:
                    raise core.ScannerError("Complete signed CVD verification was not confirmed")
                os.rename(file, candidate / name)
            observed = digest_directory(candidate, deadline, cancel)
            if old and any(observed["versions"][k] < old["versions"][k] for k in DATABASES):
                raise core.ScannerError("Definition version rollback refused")
            fixture = stage / "validation.txt"
            history.replace_private(fixture, b"pc-scanner harmless database load validation\n")
            run([binary, "--database=" + str(candidate), "--no-summary", "--", str(fixture)])
            signatures = core.clamav_signatures(binary, deadline, scanner.limit, cancel, database=str(candidate))
            built = signatures["built_at"]
            age = (core.datetime.now(core.timezone.utc) - built).total_seconds() if built else None
            freshness = "unknown" if age is None or age < 0 else "stale" if age > scanner.max_signature_age * 86400 else "fresh"
            data["signature_check"] = {"engine": signatures["engine"], "version": signatures["version"],
                                       "built_at": built.isoformat() if built else None, "freshness": freshness}
            if old and observed["content"] == old["content"]:
                data.update(update_status="unchanged")
            else:
                generation = secrets.token_hex(16)
                if progress:
                    progress.update(stage="publishing")
                # Flush before taking the publication lock; scans waiting to start only wait for the switch itself.
                for file in candidate.iterdir():
                    fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                sync_dir(candidate)
                with history.locked(path / "publish"):
                    core.check_cancel(cancel)
                    if time.monotonic() >= deadline:
                        raise core.ScannerError("Signature update timed out")
                    os.rename(candidate, path / generation)
                    sync_dir(path)
                    # Once this write starts, cancellation cannot roll back an already published generation.
                    try:
                        write_json(path / "current.json", dict(generation=generation, **observed))
                    except OSError:
                        data["update_status"] = "unknown"
                        raise
                    published = True
                    if read_json(path / "current.json") != dict(generation=generation, **observed):
                        raise OSError("Published generation could not be confirmed")
                data.update(update_status="updated", published=True, resume_recheck_required=old is not None)
            # No recursive cleanup of unknown paths; failed stages remain private for owner maintenance.
            data["next_attempt_at"] = now + 86400
            write_json(path / "attempt.json", {"next_attempt": now + 86400, "pending": False})
            shutil.rmtree(stage)
            data["cancellation_requested_after_publication"] = bool(published and cancel is not None and cancel.is_set())
            return core.result("clamav", "completed" if freshness == "fresh" else "partial", data=data,
                               warnings=[] if freshness == "fresh" else ["Published definitions are stale or their date is unverified; check freshness before scanning"])
    except history.Busy:
        data["update_status"] = "busy"
    except (core.ScannerError, OSError, ValueError, KeyError, TypeError):
        # An uncertain pointer replacement stays unknown even if cancellation or the deadline arrives meanwhile.
        if published or data["update_status"] == "unknown":
            data["update_status"] = "unknown"
        elif cancel is not None and cancel.is_set():
            data["update_status"] = "cancelled"
        elif time.monotonic() >= deadline:
            data["update_status"] = "timeout"
    # replace may have succeeded before fsync/read-back failed: never claim "not published" then.
    data["published"] = None if data["update_status"] == "unknown" and not published else published
    if data["update_status"] == "unknown":
        data["resume_recheck_required"] = None
    return core.result("clamav", "partial" if data["update_status"] in {"busy", "cancelled", "timeout"} else "error",
                       data=data, warnings=["Signature operation did not complete; check the private store and owner configuration. No administrator credentials were requested."])
