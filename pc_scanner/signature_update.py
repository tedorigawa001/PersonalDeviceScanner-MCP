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
import threading
import time

from . import core, history, process_store

TRACKED_FIRST = "tracked-first-v1"
DEFAULTS = dict(enabled=False, directory="", freshclam_binary="", sigtool_binary="", timeout_seconds=1800, store_format="")
DATABASES = ("main.cvd", "daily.cvd", "bytecode.cvd")
GEN = re.compile(r"[0-9a-f]{32}\Z")
CONTENT = re.compile(r"[0-9a-f]{64}\Z")
RECORD_KEYS = {"generation", "content", "versions"}
METADATA_LIMIT = 65536
INVENTORY_LIMIT = 128
MAX_BYTES = 2 * 1024 ** 3
MAX_GENERATIONS = 4  # No automatic deletion in phase one; never remove a pinned generation.
UPDATE_SLOTS = 2  # Every update needs room for its work stage and the new generation.
# FreshClam also prints each database header's "builder" name on its normal update lines, so that name can match
# too. Such a match stops without publishing and keeps pending; missing a real 429 would be worse.
PROVIDER_WAIT = re.compile(
    r"\bFreshClam (?:previously )?received error code 429\b"
    r"|\bYou are(?: still)? on cool-down until after:", re.IGNORECASE)


def counts_toward_capacity(name):
    """Every generation or work stage name, even one the owner CLI cannot manage, holds space until inspected."""
    return bool(GEN.fullmatch(name)) or name.startswith("stage-")


def configure(scanner):
    raw = scanner.config.get("clamav_updates", {})
    if not isinstance(raw, dict) or set(raw) - DEFAULTS.keys():
        raise core.ScannerError("Invalid clamav_updates settings")
    cfg = {**DEFAULTS, **raw}
    if type(cfg["enabled"]) is not bool or type(cfg["timeout_seconds"]) is not int or not 1 <= cfg["timeout_seconds"] <= 3600:
        raise core.ScannerError("Invalid clamav_updates settings")
    if cfg["store_format"] not in ("", TRACKED_FIRST):
        raise core.ScannerError("Invalid clamav_updates store format")
    for key in ("directory", "freshclam_binary", "sigtool_binary"):
        v = cfg[key]
        if not isinstance(v, str) or any(c in v for c in '\0\r\n"') or (v and (not Path(v).is_absolute() or ".." in Path(v).parts)):
            raise core.ScannerError("Invalid clamav_updates path")
        if cfg["enabled"] and not v:
            raise core.ScannerError("Enabled clamav_updates requires fixed paths")
    if cfg["enabled"] and scanner.local.get("clamav_database_directory"):
        raise core.ScannerError("Private generations cannot share an OS-managed database directory")
    scanner.signature_update_settings = cfg


class SignatureStore(process_store.Store):
    """Path validation only, so scans never queue behind a threat-list download or process review."""
    thread_lock = threading.Lock()


@contextmanager
def root(scanner, create=False):
    cfg = scanner.signature_update_settings
    if not cfg["enabled"] or os.name != "posix" or os.geteuid() == 0:
        raise core.ScannerError("Private signature updates require an enabled, non-administrator POSIX account")
    # Validated once through descriptors (ancestors, local filesystem, cloud, owner and ACL); the descriptors close
    # before use. Later steps use paths: other users cannot redirect them because every ancestor is writable only by
    # the owner or root (or is root-owned and sticky), with no macOS ACL entry letting others add, remove or rename
    # entries, and each file is rechecked as private when opened.
    # Same-user processes are outside this boundary.
    with SignatureStore({"directory": cfg["directory"]}).open(create=create, file_lock=False) as store:
        if store is None:
            raise core.ScannerError("Private signature store is not initialized; run the owner update CLI")
        path = store.path
        if store.created and cfg["store_format"] == TRACKED_FIRST:
            from . import signature_first_publication

            with history.locked(path / "update", attempts=1):
                # A scan or definition check that starts meanwhile leaves only the publication lock file, which holds
                # no state; refusing it would let any MCP call in this moment make the new store unusable.
                if set(store.names()) - {"publish.lock"} != {"update.lock"}:
                    raise OSError("New signature store is no longer empty")
                history.flush_to_disk(store.parent)
                signature_first_publication.initialize(path)
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
    # Wait and publication state: after a power loss it must read as the last complete write, never an empty file.
    history.replace_private(path, json.dumps(obj, sort_keys=True).encode(), durable=True)
    sync_dir(path.parent)


def verification_file(generation):
    return generation.with_name(generation.name + ".verification.json")


def verification_snapshot(file):
    """Private, bounded evidence bytes and identity; missing evidence supports legacy stores."""
    try:
        listed = os.lstat(file)
    except FileNotFoundError:
        return None
    if getattr(listed, "st_flags", 0) & core.SF_DATALESS:
        raise OSError("Cloud signature metadata refused")
    fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = process_store.Store({}).private(fd)
        if before.st_size > METADATA_LIMIT:
            raise OSError("Signature metadata size limit")
        raw = os.read(fd, METADATA_LIMIT + 1)
        snapshot = identity(before)
        if (len(raw) != before.st_size or snapshot != identity(listed)
                or snapshot != identity(os.fstat(fd)) or snapshot != identity(os.lstat(file))):
            raise OSError("Signature metadata changed")
        return raw, snapshot
    finally:
        os.close(fd)


def detached_evidence(path, obj):
    """Only a record bound to these exact verified CVD bytes can authenticate their date."""
    unknown = dict.fromkeys(DATABASES, "unverified")
    try:
        snapshot = verification_snapshot(verification_file(path / obj["generation"]))
        if snapshot is None:
            return unknown
        record = json.loads(snapshot[0])
        if (not isinstance(record, dict) or set(record) != {"schema", "content", "versions", "detached_signatures"}
                or type(record["schema"]) is not int or record["schema"] != 1
                or record["content"] != obj["content"] or record["versions"] != obj["versions"]
                or not isinstance(record["versions"], dict) or set(record["versions"]) != set(DATABASES)
                or any(type(v) is not int for v in record["versions"].values())
                or not isinstance(record["detached_signatures"], dict)
                or set(record["detached_signatures"]) != set(DATABASES)
                or any(v not in ("verified", "absent") for v in record["detached_signatures"].values())):
            return unknown
        return record["detached_signatures"]
    except (OSError, ValueError, TypeError, RecursionError):
        return unknown


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        history.flush_to_disk(fd)
    finally:
        os.close(fd)


def private_dir(path):
    listed = os.lstat(path)
    if getattr(listed, "st_flags", 0) & core.SF_DATALESS:
        raise OSError("Cloud signature directory refused")
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = process_store.Store({}).private(fd, True)
        if identity(before) != identity(listed):
            raise OSError("Signature directory changed")
        return before
    finally:
        os.close(fd)


def identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns]


class InvalidGeneration(OSError):
    """A stable read established that this generation cannot match its publication."""


def check_deadline(deadline, cancel=None):
    core.check_cancel(cancel)
    if time.monotonic() >= deadline:
        raise core.ScannerError("Signature operation timed out")


def store_names(path, deadline, cancel=None):
    names = []
    with os.scandir(path) as entries:
        for entry in entries:
            check_deadline(deadline, cancel)
            if len(names) == INVENTORY_LIMIT:
                raise OSError("Signature inventory limit")
            names.append(entry.name)
    return names


def content_hash(hashes):
    return hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()


def digest_files(path, deadline, cancel=None, *, expected=DATABASES):
    check_deadline(deadline, cancel)
    folder = identity(private_dir(path))
    names = set()
    with os.scandir(path) as entries:
        for entry in entries:
            names.add(entry.name)
            if entry.name not in expected:
                break
    if names != set(expected):
        if identity(os.lstat(path)) != folder:
            raise OSError("Database directory changed")
        raise InvalidGeneration("Only the three official complete CVD databases are allowed")
    total, versions, hashes, snapshots = 0, {}, {}, {}
    for name in expected:
        check_deadline(deadline, cancel)
        file = path / name
        listed = os.lstat(file)
        if getattr(listed, "st_flags", 0) & core.SF_DATALESS:
            raise OSError("Cloud database refused")
        fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = process_store.Store({}).private(fd)
            snapshot = identity(before)
            if snapshot != identity(listed):
                raise OSError("Database changed")
            total += before.st_size
            if before.st_size < 512 or total > MAX_BYTES:
                if snapshot != identity(os.fstat(fd)) or snapshot != identity(os.lstat(file)):
                    raise OSError("Database changed")
                raise InvalidGeneration("Database size limit")
            raw = os.read(fd, 512)
            if len(raw) != 512:
                raise OSError("Short database header read")
            h = hashlib.sha256(raw)
            size = len(raw)
            while size < before.st_size:
                check_deadline(deadline, cancel)
                requested = min(1024 * 1024, before.st_size - size)
                chunk = os.read(fd, requested)
                if len(chunk) != requested:
                    raise OSError("Short database read")
                size += len(chunk)
                h.update(chunk)
            check_deadline(deadline, cancel)
            if snapshot != identity(os.fstat(fd)) or snapshot != identity(os.lstat(file)):
                raise OSError("Database changed")
            try:
                header = raw.decode("ascii").split(":")
            except UnicodeDecodeError:
                raise InvalidGeneration("Invalid CVD header") from None
            if len(header) < 4 or header[0] != "ClamAV-VDB" or not header[2].isdigit():
                raise InvalidGeneration("Invalid CVD header")
            versions[name] = int(header[2])
            hashes[name] = h.hexdigest()
            snapshots[name] = snapshot
        finally:
            os.close(fd)
    if identity(os.lstat(path)) != folder or any(identity(os.lstat(path / name)) != snap for name, snap in snapshots.items()):
        raise OSError("Database generation changed")
    check_deadline(deadline, cancel)
    return dict(content=content_hash(hashes), versions=versions), hashes


def digest_directory(path, deadline, cancel=None):
    return digest_files(path, deadline, cancel)[0]


def strict_object(pairs):
    values = dict(pairs)
    if len(values) != len(pairs):
        raise ValueError("Duplicate signature metadata key")
    return values


def valid_generation_id(value):
    return isinstance(value, str) and GEN.fullmatch(value) is not None


def valid_record(record):
    return (valid_generation_id(record["generation"]) and isinstance(record["content"], str)
            and CONTENT.fullmatch(record["content"]) is not None
            and isinstance(record["versions"], dict) and set(record["versions"]) == set(DATABASES)
            and all(type(v) is int and v >= 0 for v in record["versions"].values()))


def validate_pointer(obj):
    if not isinstance(obj, dict) or set(obj) not in (RECORD_KEYS, RECORD_KEYS | {"schema", "previous", "legacy_untracked"}):
        raise OSError("Invalid current generation")
    if not valid_record(obj):
        raise OSError("Invalid current generation")
    if "schema" not in obj:
        return
    previous, legacy = obj["previous"], obj["legacy_untracked"]
    if (type(obj["schema"]) is not int or obj["schema"] != 2 or not isinstance(previous, list)
            or not isinstance(legacy, list) or 1 + len(previous) + len(legacy) > INVENTORY_LIMIT
            or any(not isinstance(r, dict) or set(r) != RECORD_KEYS or not valid_record(r) for r in previous)
            or not all(valid_generation_id(g) for g in legacy)):
        raise OSError("Invalid signature publication history")
    ids = [obj["generation"], *(r["generation"] for r in previous), *legacy]
    if len(ids) != len(set(ids)):
        raise OSError("Duplicate signature publication ID")


def pointer_snapshot(path):
    saved = verification_snapshot(path / "current.json")
    if saved is None:
        return None, None
    raw, snapshot = saved
    try:
        obj = json.loads(raw, object_pairs_hook=strict_object)
    except (ValueError, RecursionError):
        raise OSError("Invalid signature publication history") from None
    validate_pointer(obj)
    return obj, snapshot


def pointer(path):
    """The published reference only; contents are verified separately."""
    return pointer_snapshot(path)[0]


def publication(old, generation, observed, previous, legacy):
    if old:
        previous = [{k: old[k] for k in RECORD_KEYS}, *previous]
    obj = dict(generation=generation, **observed, schema=2, previous=previous, legacy_untracked=legacy)
    validate_pointer(obj)
    if len(json.dumps(obj, sort_keys=True).encode()) > METADATA_LIMIT:
        raise OSError("Signature publication history size limit")
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
            detached = detached_evidence(path, obj)
        try:
            # The lease keeps this generation; hashing it no longer blocks other scans or publication.
            verify(path, obj, deadline, cancel)
            local = copy.copy(scanner)
            local.local = dict(scanner.local, clamav_database_directory=str(path / obj["generation"]))
            local._signature_generation = obj
            local._signature_detached = detached
            yield local
        finally:
            lease.__exit__(None, None, None)


def executable(value):
    """Follow the configured path one entry at a time and return the real file, so the path that runs is the path
    that was checked.

    Every folder entered on the way, including each folder that holds a link, and the file itself pass the store's
    rule: owned by this user or root, with no group/other write bit (except a root-owned sticky folder), no macOS ACL
    entry letting others change the file or a folder's entries, and not on a volume that ignores ownership. Each link
    must be owned by this user or root, because in a sticky folder its owner can replace it. Other users then cannot
    replace the file or point a link at another program between this check and its run. Same-user processes are
    outside this boundary.
    """
    from .posix_acl import acl_allows_redirect

    def check(path, folder):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if folder else 0))
        try:
            info = os.fstat(fd)
            if (info.st_uid not in {0, os.geteuid()} or acl_allows_redirect(fd) or process_store.ownership_ignored(fd)
                    or (info.st_mode & 0o022 and not (folder and info.st_uid == 0 and info.st_mode & stat.S_ISVTX))):
                raise core.ScannerError("Updater executable is not owner-approved")
            return info
        finally:
            os.close(fd)

    real, info, links = Path("/"), None, 0
    check(real, True)
    parts = list(Path(value).parts[1:])
    while parts:
        name = parts.pop(0)
        if name == "..":
            real, info = real.parent, None  # every folder above real was checked on the way in
            continue
        entry = real / name
        found = os.lstat(entry)  # real was checked, so only this user or root can change its entries
        if stat.S_ISLNK(found.st_mode):
            links += 1
            if links > 32 or found.st_uid not in {0, os.geteuid()}:
                raise core.ScannerError("Updater executable is not owner-approved")
            target = Path(os.readlink(entry))
            if target.is_absolute():
                real = Path("/")
            parts[:0] = target.parts[1:] if target.is_absolute() else target.parts
            continue
        info = check(entry, bool(parts))
        real = entry
    if info is None or not stat.S_ISREG(info.st_mode) or not os.access(real, os.X_OK):
        raise core.ScannerError("Updater executable is not owner-approved")
    return str(real)


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
    def run(argv, *, provider_check=False):
        core.check_cancel(cancel)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise core.ScannerError("Signature update timed out")
        rc, out, err = core.run_bounded(argv, remaining, scanner.limit, cancel)
        # FreshClam can exit zero after a 429 or while already cooling down.
        # Inspect both streams only for the updater; never treat this as a successful check.
        if provider_check and PROVIDER_WAIT.search(out + "\n" + err):
            return None
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
            from . import signature_first_publication, signature_maintenance

            store_entries = store_names(path, deadline, cancel)
            journal, _ = signature_first_publication.load(path, cfg["store_format"])
            phase = signature_first_publication.phase(journal, old)
            held = "First publication cannot be confirmed; preserve the signature store and its wait state"
            if phase == "unavailable":
                blocked = held
            elif old is None and signature_first_publication.unfinished_deletion(journal):
                # The listing still offers this candidate, so the owner can finish it instead of abandoning the store.
                blocked = "A selected first-publication cleanup is unfinished; list the store and retry that deletion"
            elif old is None and signature_first_publication.unknown_generations(path, store_entries, journal, deadline, cancel):
                blocked = held
            else:
                blocked = None
            if blocked:
                return core.result("clamav", "error", data=data, warnings=[blocked])
            generations = [name for name in store_entries if counts_toward_capacity(name)]
            # The work stage stays until the switch succeeds, so a failed switch leaves both it and the new generation.
            if (signature_first_publication.used_slots(store_entries, journal) + UPDATE_SLOTS > MAX_GENERATIONS
                    or shutil.disk_usage(path).free < MAX_BYTES * 2):
                return core.result("clamav", "error", data=data, warnings=[
                    "Private signature store capacity exhausted; list the store to review protected entries and owner maintenance options"])
            if phase == "confirm_published":
                # The pointer from an interrupted switch must be durable before advancing the journal.
                sync_dir(path)
                signature_first_publication.published(path, journal)
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
            provider = path / "provider.dat"
            if provider.exists() or provider.is_symlink():
                history.replace_private(db / "freshclam.dat", signature_maintenance.provider_bytes(provider))
            signature_maintenance.begin_provider_sync(path, stage.name)
            try:
                fetched = run([freshclam, "--config-file=" + str(config), "--datadir=" + str(db)], provider_check=True)
            finally:
                # Provider cooldown survives errors, recovery, stage deletion and the next freshclam invocation.
                signature_maintenance.finish_provider_sync(path, stage.name)
            if fetched is None:
                # Only report the retained wait after provider synchronization succeeds. Its binary
                # format and the log's local-time date stay opaque; the owner confirms all deadlines.
                data.update(update_status="rate_limited", next_attempt_at=now + 86400, recovery_required=True)
                return core.result("clamav", "partial", data=data, warnings=[
                    "FreshClam reported rate limiting or an active provider cooldown; a successful update check was not confirmed. "
                    "Pending state, work stage and any saved provider state were retained. "
                    "Confirm all provider waits, which may exceed the stored minimum, before using the owner recovery CLI."])
            if progress:
                progress.update(stage="validating")
            # Move only the required databases to a private candidate. Bookkeeping stays in the unpublished stage.
            candidate = stage / "candidate"
            candidate.mkdir(mode=0o700)
            allowed = set(DATABASES) | {"freshclam.dat", "mirrors.dat"}
            names = []
            for file in db.iterdir():
                if file.name not in allowed and not re.fullmatch(r"(?:main|daily|bytecode)(?:-[0-9]+)?\.cvd\.sign", file.name):
                    raise OSError("Unexpected updater output")
                history.make_private(file)
                names.append(file.name)
            detached = {}
            for name in DATABASES:
                file = db / name
                history.make_private(file)
                output = run([sigtool, "--info=" + str(file)])
                if "Digital signature:" not in output or "Verification OK" not in output:
                    raise core.ScannerError("Complete signed CVD verification was not confirmed")
                # The embedded signature leaves the header's build time uncovered; the detached .sign covers it.
                # sigtool finds the signature named for the header's version next to the file, so any signature
                # left for this database must verify, or the update fails closed.
                stem = name.removesuffix(".cvd")
                if any(re.fullmatch(re.escape(stem) + r"(?:-[0-9]+)?\.cvd\.sign", n) for n in names):
                    if "Successfully verified" not in run([sigtool, "--verify", str(file)]):
                        raise core.ScannerError("Detached CVD signature verification was not confirmed")
                    detached[name] = "verified"
                else:
                    detached[name] = "absent"
                os.rename(file, candidate / name)
            observed = digest_directory(candidate, deadline, cancel)
            if old and any(observed["versions"][k] < old["versions"][k] for k in DATABASES):
                raise core.ScannerError("Definition version rollback refused")
            unchanged = bool(old and observed["content"] == old["content"])
            if unchanged:
                previous = detached_evidence(path, old)
                # A later freshclam may not fetch .sign for unchanged bytes. Retain their earlier proof,
                # but never transfer it to a different content digest, even when the versions match.
                detached = {name: "verified" if previous[name] == "verified" else detached[name] for name in DATABASES}
            evidence = dict(schema=1, **observed, detached_signatures=detached)
            fixture = stage / "validation.txt"
            history.replace_private(fixture, b"pc-scanner harmless database load validation\n")
            run([binary, "--database=" + str(candidate), "--no-summary", "--", str(fixture)])
            signatures = core.clamav_signatures(binary, deadline, scanner.limit, cancel, database=str(candidate))
            built = signatures["built_at"]
            age = (core.datetime.now(core.timezone.utc) - built).total_seconds() if built else None
            freshness = "unknown" if age is None or age < 0 else "stale" if age > scanner.max_signature_age * 86400 else "fresh"
            # clamscan reports daily's build time. Without its verified .sign, an old genuine daily could carry a newer
            # date, so a date that looks fresh is reported as unverified (still published; the version cannot go back).
            if freshness == "fresh" and detached["daily.cvd"] != "verified":
                freshness = "unverified"
            data["signature_check"] = {"engine": signatures["engine"], "version": signatures["version"],
                                       "built_at": built.isoformat() if built else None, "freshness": freshness,
                                       "detached_signatures": detached}
            if unchanged:
                with history.locked(path / "publish"):
                    write_json(verification_file(path / old["generation"]), evidence)
                data.update(update_status="unchanged")
            else:
                generation = secrets.token_hex(16)
                if old and "schema" in old:
                    previous = signature_maintenance.prune_missing_history(path, old, deadline, cancel)
                    legacy = signature_maintenance.prune_missing_legacy(path, old, deadline, cancel)
                else:
                    previous = []
                    # Migration applies to an existing legacy reference. With no reference, preflight
                    # already refused any generation whose publication status could not be confirmed.
                    legacy = sorted(name for name in generations if GEN.fullmatch(name)
                                    and name != old["generation"]) if old else []
                reference = publication(old, generation, observed, previous, legacy)
                write_json(stage / "verification.json", evidence)
                if progress:
                    progress.update(stage="publishing")
                # Flush before taking the publication lock; scans waiting to start only wait for the switch itself.
                for file in candidate.iterdir():
                    fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW)
                    try:
                        history.flush_to_disk(fd)
                    finally:
                        os.close(fd)
                sync_dir(candidate)
                first = old is None and journal is not None
                if first:
                    journal = signature_first_publication.prepare(path, journal, store_entries, generation, stage, observed)
                with history.locked(path / "publish"):
                    check_deadline(deadline, cancel)
                    if pointer(path) != old:
                        raise OSError("Signature publication reference changed")
                    if not signature_maintenance.absent(path / generation) or not signature_maintenance.absent(
                            verification_file(path / generation)):
                        raise OSError("Signature generation destination already exists")
                    os.rename(candidate, path / generation)
                    os.rename(stage / "verification.json", verification_file(path / generation))
                    if first:
                        sync_dir(stage)
                    sync_dir(path)
                    if first:
                        journal = signature_first_publication.start_switch(path, journal, generation)
                    # Once this write starts, cancellation cannot roll back an already published generation.
                    try:
                        write_json(path / "current.json", reference)
                    except OSError:
                        data["update_status"] = "unknown"
                        raise
                    published = True
                    if pointer(path) != reference:
                        raise OSError("Published generation could not be confirmed")
                    if first:
                        signature_first_publication.published(path, journal)
                data.update(update_status="updated", published=True, resume_recheck_required=old is not None)
            # No recursive cleanup of unknown paths; failed stages remain private for owner maintenance.
            data["next_attempt_at"] = now + 86400
            write_json(path / "attempt.json", {"next_attempt": now + 86400, "pending": False})
            shutil.rmtree(stage)
            data["cancellation_requested_after_publication"] = bool(published and cancel is not None and cancel.is_set())
            return core.result("clamav", "completed" if freshness == "fresh" else "partial", data=data, warnings=
                               [] if freshness == "fresh" else
                               ["The daily database has no verified detached signature (.cvd.sign), so its build date is unverified; "
                                "check freshness before scanning"] if freshness == "unverified" else
                               ["Published definitions are stale or their date is unverified; check freshness before scanning"])
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
