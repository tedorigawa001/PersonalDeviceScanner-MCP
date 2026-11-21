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
from . import signature_first_publication as first

ENTRY = re.compile(r"(?:stage-)?[0-9a-f]{32}\Z")
REV = re.compile(r"[0-9a-f]{64}\Z")
CLEANUP_SUFFIX = ".cleanup.json"
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
        history.replace_private(root / "provider.dat", provider_bytes(file, normalize=True), durable=True)
        update.sync_dir(root)


def provider_sync(path):
    obj = update.read_json(path / "provider-sync.json")
    if obj is not None and (not isinstance(obj, dict) or set(obj) != {"stage", "status", "provider_hash"}
            or not isinstance(obj["stage"], str) or not re.fullmatch(r"stage-[0-9a-f]{32}", obj["stage"])
            or obj["status"] not in {"pending", "synced"}
            or (obj["provider_hash"] is not None and (not isinstance(obj["provider_hash"], str) or not REV.fullmatch(obj["provider_hash"])))
            or (obj["status"] == "pending" and obj["provider_hash"] is not None)):
        raise OSError("Invalid provider synchronization evidence")
    return obj


def begin_provider_sync(path, stage):
    # Must be durable before freshclam starts, so an interrupted/failed copy cannot look like an older success.
    update.write_json(path / "provider-sync.json", {"stage": stage, "status": "pending", "provider_hash": None})


def finish_provider_sync(path, stage):
    db = path / stage / "db"
    update.private_dir(path / stage)
    update.private_dir(db)
    source, canonical = db / "freshclam.dat", path / "provider.dat"
    expected = hashlib.sha256(provider_bytes(source, normalize=True)).hexdigest() if source.exists() or source.is_symlink() else None
    if expected is None and (canonical.exists() or canonical.is_symlink()):
        raise OSError("Provider source is missing; old canonical state is not evidence of synchronization")
    preserve_provider(path, db)
    actual = hashlib.sha256(provider_bytes(canonical)).hexdigest() if canonical.exists() or canonical.is_symlink() else None
    if actual != expected:
        raise OSError("Provider synchronization could not be verified")
    update.write_json(path / "provider-sync.json", {"stage": stage, "status": "synced", "provider_hash": actual})


def recover_provider(path, entries):
    sync = provider_sync(path)
    if sync is not None:
        if sync["status"] == "pending":
            # The exact attempted stage survives and remains protected until this durable copy succeeds.
            if not any(r["id"] == sync["stage"] for r in entries):
                raise OSError("Pending provider synchronization stage unavailable")
            finish_provider_sync(path, sync["stage"])
            sync = provider_sync(path)
        file = path / "provider.dat"
        actual = hashlib.sha256(provider_bytes(file)).hexdigest() if file.exists() or file.is_symlink() else None
        if actual != sync["provider_hash"]:
            raise OSError("Provider canonical state no longer matches synchronization evidence")
        return
    # Legacy stores have no per-attempt evidence: canonical existence alone is insufficient.
    sources = [r["id"] for r in entries if r["kind"] == "stage" and (
        (path / r["id"] / "db/freshclam.dat").exists() or (path / r["id"] / "db/freshclam.dat").is_symlink())]
    if len(sources) > 1:
        raise core.ScannerError("Ambiguous provider wait state; preserve stages for investigation")
    if sources:
        begin_provider_sync(path, sources[0])
        finish_provider_sync(path, sources[0])
    elif (path / "provider.dat").exists() or (path / "provider.dat").is_symlink():
        raise OSError("Legacy canonical wait state lacks synchronization evidence")


def tree(path, deadline):
    """Metadata-only bounded snapshot, checked through descriptors before a single deletion."""
    rows = []
    def visit(fd, prefix="", depth=0):
        if depth > 3 or len(rows) > 128 or time.monotonic() >= deadline:
            raise OSError("Signature maintenance enumeration limit")
        process_store.Store({}).private(fd, True)
        rows.append([prefix, update.identity(os.fstat(fd))])
        for name in sorted(os.listdir(fd)):
            if len(rows) >= 128 or time.monotonic() >= deadline:
                raise OSError("Signature maintenance enumeration limit")
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if getattr(info, "st_flags", 0) & core.SF_DATALESS or stat.S_ISLNK(info.st_mode):
                raise OSError("Cloud or linked entry refused")
            folder = stat.S_ISDIR(info.st_mode)
            allowed = (name in {"db", "candidate"} if folder else name in set(update.DATABASES) | {
                "freshclam.conf", "freshclam.dat", "mirrors.dat", "validation.txt", "verification.json"}
                or re.fullmatch(r"(?:main|daily|bytecode)(?:-[0-9]+)?\.cvd\.sign", name)
                # A kill or power loss inside history.replace_private leaves its private temporary file; it belongs
                # to the failed stage, which must stay recoverable and deletable.
                or re.fullmatch(r"\.(?:freshclam\.conf|freshclam\.dat|validation\.txt|verification\.json)\.[0-9a-f]{8}\.tmp", name))
            if not allowed:
                raise OSError("Unknown signature maintenance entry")
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if folder else 0), dir_fd=fd)
            try:
                process_store.Store({}).private(child, folder)
                if folder:
                    visit(child, prefix + name + "/", depth + 1)
                else:
                    snapshot = update.identity(os.fstat(child))
                    if snapshot != update.identity(info):
                        raise OSError("Signature maintenance entry changed")
                    rows.append([prefix + name, snapshot])
            finally:
                os.close(child)
    listed = os.lstat(path)
    if getattr(listed, "st_flags", 0) & core.SF_DATALESS:
        raise OSError("Cloud signature directory refused")
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        visit(fd)
        if rows[0][1] != update.identity(listed) or rows[0][1] != update.identity(os.lstat(path)):
            raise OSError("Signature maintenance directory changed")
    finally:
        os.close(fd)
    return rows


@contextmanager
def open_lease(path, flags):
    try:
        listed = os.lstat(path)
    except FileNotFoundError:
        yield None, None
        return
    if not stat.S_ISREG(listed.st_mode) or getattr(listed, "st_flags", 0) & core.SF_DATALESS:
        raise OSError("Invalid signature lease")
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        observed = update.identity(process_store.Store({}).private(fd))
        if observed != update.identity(listed) or observed != update.identity(os.lstat(path)):
            raise OSError("Signature lease changed")
        yield fd, observed
    finally:
        os.close(fd)


@contextmanager
def exclusive_lease(path):
    import fcntl
    # Only the current generation can get a new scan lease. The updater lock prevents a switch.
    with open_lease(path, os.O_RDWR) as (fd, observed):
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise history.Busy("Generation is in use") from None
        yield observed


def checked_generation(path, name, deadline, cancel=None):
    """Metadata around a full digest; None means a stable read proved the folder cannot be a valid generation."""
    folder = path / name
    metadata = tree(folder, deadline)
    try:
        observed = update.digest_directory(folder, deadline, cancel)
    except update.InvalidGeneration:
        observed = None
    if tree(folder, deadline) != metadata:
        raise OSError("Previous generation changed")
    update.check_deadline(deadline, cancel)
    return metadata, observed


def legacy_protection(path, current, names, deadline, cancel=None):
    """Before the first publication that records history, keep the earlier release's rule so a full store can still
    free a slot and migrate. A structurally valid generation whose versions are not newer than the current ones and
    whose content differs counts as a rollback, and when exactly one does, it is kept. Bodies cannot be checked against
    a record yet. A read that cannot be completed holds every generation deletion."""
    checks, rollbacks = [], []
    for name in sorted(n for n in names if update.GEN.fullmatch(n) and n != current["generation"]):
        try:
            metadata, observed = checked_generation(path, name, deadline, cancel)
        except (OSError, core.ScannerError):
            checks.append((name, "unavailable", None))
            return "previous_unavailable", checks
        rollback = (observed is not None and observed["content"] != current["content"]
                    and all(observed["versions"][k] <= current["versions"][k] for k in update.DATABASES))
        if rollback:
            rollbacks.append(len(checks))
        checks.append((name, "usable" if rollback else "invalid", metadata))
    if len(rollbacks) == 1:
        name, _, metadata = checks[rollbacks[0]]
        checks[rollbacks[0]] = (name, "last_previous", metadata)
    return "legacy_history", checks


def previous_protection(path, current, deadline, cancel=None, names=()):
    """Return a verdict and identities of every past generation the verdict relied on."""
    if current is None:
        return "missing_history", []
    if "schema" not in current:
        return legacy_protection(path, current, names, deadline, cancel)
    if not current["previous"]:
        return "no_previous", []
    checks = []
    for record in current["previous"]:
        name = record["generation"]
        try:
            metadata, observed = checked_generation(path, name, deadline, cancel)
        except (OSError, core.ScannerError):
            checks.append((name, "unavailable", None))
            return "previous_unavailable", checks
        matches = observed == {k: record[k] for k in ("content", "versions")}
        if matches and observed["content"] != current["content"]:
            checks.append((name, "last_previous", metadata))
            return "protected", checks
        checks.append((name, "duplicate" if matches else "invalid", metadata))
    return "no_valid_previous", checks


def absent(path):
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True
    except OSError:
        pass
    return False


def gone(path, name):
    """The generation, its record and its lease are all confirmed absent."""
    folder = path / name
    return all(absent(p) for p in (folder, update.verification_file(folder), path / (name + ".lease")))


def prune_missing_legacy(path, current, deadline, cancel):
    """An unrecorded ID only holds its own folder; once everything under it is gone, it holds nothing."""
    legacy = []
    for name in current["legacy_untracked"]:
        update.check_deadline(deadline, cancel)
        if not gone(path, name):
            legacy.append(name)
    return legacy


def prune_missing_history(path, current, deadline, cancel):
    """Prune crash leftovers only behind a predecessor we can still prove."""
    previous = current["previous"]
    missing = set()
    for record in previous:
        update.check_deadline(deadline, cancel)
        if gone(path, record["generation"]):
            missing.add(record["generation"])
    if not missing:
        return previous
    status, checks = previous_protection(path, current, deadline, cancel)
    if status != "protected":
        return previous
    for name in tuple(missing):
        if not gone(path, name):
            missing.remove(name)
    return [record for index, record in enumerate(previous)
            if index < len(checks) or record["generation"] not in missing]


def inventory(path, deadline, *, store_format="", list_cleanup=False):
    state = attempt(path)
    names = update.store_names(path, deadline)
    try:
        reference = update.pointer_snapshot(path)
    except OSError:
        reference = None
    current = reference[0] if reference is not None else None
    snapshot = (None, None)
    try:
        snapshot = first.load(path, store_format)
        first_phase = first.phase(snapshot[0], current) if reference is not None else "unavailable"
    except OSError:
        first_phase = "unavailable"
    journal = snapshot[0]
    entries = journal["entries"] if first_phase == "open" else {}
    provider = path / "provider.dat"
    sync = provider_sync(path)
    provider_hash = hashlib.sha256(provider_bytes(provider)).hexdigest() if not absent(provider) else None
    provider_state = [state, sync, provider_hash]
    status, checks = previous_protection(path, current, deadline, names=names) if reference is not None else ("history_unavailable", [])
    protected = next((g for g, verdict, _ in checks if verdict == "last_previous"), None)
    managed = {n for n in names if ENTRY.fullmatch(n)}
    managed.update(name for name, entry in entries.items() if entry["deleting"] is not None)
    # The updater counts these toward its limit, but this CLI neither lists nor deletes them.
    unrecognized = sum(1 for n in names if update.counts_toward_capacity(n) and not ENTRY.fullmatch(n))
    rows, revisions, plans = [], {}, {}
    for name in sorted(managed):
        row = dict(id=name, kind="stage" if name.startswith("stage-") else "generation", revision=None,
                   current=bool(current and name == current["generation"]), in_use=None, deletable=False)
        try:
            if first_phase == "open" and name in entries:
                if not absent(path / (name + ".lease")):
                    row["reason"] = "lease_present"
                elif first.unexpected_sidecars(names, name):
                    row["reason"] = "unknown_publication"
                else:
                    plan = first.inspect_candidate(path, name, entries[name], deadline)
                    metadata, evidence, _ = plan
                    target = entry_revision(metadata, evidence)
                    row.update(reason=first.UNPUBLISHED, deletable=True, in_use=False,
                               revision=revision_for([name, target, snapshot, reference, "no_lease", provider_state]),
                               bytes=sum(info[5] for key, info in (metadata or []) if stat.S_ISREG(info[2]))
                               + (len(evidence[0]) if evidence is not None else 0),
                               incomplete=not metadata or len(metadata) != len(update.DATABASES) + 1)
                    plans[name] = plan
                rows.append(row)
                continue
            metadata = tree(path / name, deadline)
            evidence = update.verification_snapshot(update.verification_file(path / name)) if row["kind"] == "generation" else None
            revisions[name] = entry_revision(metadata, evidence)
            row["revision"] = revisions[name]
            files = {name: info[5] for name, info in metadata if stat.S_ISREG(info[2])}
            row["bytes"] = sum(files.values())
            if evidence is not None:
                row["bytes"] += len(evidence[0])
            if row["kind"] == "generation":
                row["incomplete"] = not all(database in files for database in update.DATABASES)
            row["reason"] = None
            if first_phase == "unavailable":
                row["reason"] = "history_unavailable" if reference is None else "first_publication_unavailable"
            elif first_phase == "open" and current is None and row["kind"] == "generation":
                row["reason"] = "unknown_publication"
            elif first_phase == "open" and sync and name == sync["stage"]:
                row["reason"] = "provider_sync_stage"
            elif row["kind"] == "stage" and state and state["pending"]:
                row["reason"] = "pending_recovery"
            elif row["kind"] == "generation":
                row["revision"] = revision_for([revisions[name], reference, status, checks])
                if row["current"]:
                    row["reason"] = "current"
                elif name == protected:
                    row["reason"] = "last_previous"
                elif status != "protected" and current and name in current.get("legacy_untracked", ()):
                    # These predate the first recorded switch. Once an intact recorded predecessor is protected, they
                    # are older or were never published, so they no longer guard anything.
                    row["reason"] = "legacy_untracked"
                elif status not in {"protected", "no_previous", "legacy_history"}:
                    row["reason"] = status
            # Scans lease only the current generation, which is protected anyway; probing it would fail their start.
            if row["kind"] == "generation" and current is not None and not row["current"]:
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
    token = [reference, rows, provider_state, snapshot]
    used = first.used_slots(names, journal)
    required = None if reference is None else (2 if current is None else 1)
    result = dict(entries=rows, unrecognized_entries=unrecognized, attempt=state, recovery_revision=revision_for(token),
                first_publication=first_phase,
                capacity=dict(used_slots=used, max_slots=update.MAX_GENERATIONS, required_slots=required),
                previous_protection=dict(status=status, generation=protected,
                                         checks=[dict(id=g, status=verdict) for g, verdict, _ in checks]),
                next_attempt_at=state["next_attempt"] if state else None,
                minimum_not_before=datetime.fromtimestamp(math.ceil(state["next_attempt"]), timezone.utc).isoformat() if state else None,
                provider_sync=sync,
                waiting=bool(state and time.time() < state["next_attempt"]))
    if list_cleanup:
        result["cleanup"] = cleanup_inventory(path, names, reference, status, checks, deadline) if first_phase != "unavailable" else []
    return result, reference, checks, revisions, (snapshot, plans)


def revision_for(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def entry_revision(metadata, evidence):
    proof = [hashlib.sha256(evidence[0]).hexdigest(), evidence[1]] if evidence is not None else None
    return hashlib.sha256(json.dumps([metadata, proof]).encode()).hexdigest()


def remove_tree(path, expected, deadline, *, generation=False, check_reference=None):
    sidecar = update.verification_file(path) if generation else None
    evidence = update.verification_snapshot(sidecar) if sidecar is not None else None
    if entry_revision(tree(path, deadline), evidence) != expected:
        raise OSError("Selected signature entry changed; list again")
    if check_reference is not None:
        check_reference()
    update.check_deadline(deadline)
    # Validate both before the first unlink. Removing proof first is safe if a later directory deletion
    # fails: the surviving generation becomes unverified, never a falsely fresh orphaned record.
    if evidence is not None:
        sidecar.unlink()
        update.sync_dir(path.parent)
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


def storage_check(path, reference, checks, deadline):
    active = reference[0]["generation"]
    active_metadata = tree(path / active, deadline)
    update.verify(path, reference[0], deadline)

    def check_reference():
        if update.pointer_snapshot(path) != reference or tree(path / active, deadline) != active_metadata:
            raise OSError("Current generation changed; list again")
        for generation, _, metadata in checks:
            if tree(path / generation, deadline) != metadata:
                raise OSError("Previous generation changed; list again")
    return check_reference


def without_generation(current, name):
    if "schema" not in current:
        return current
    return dict(current, previous=[record for record in current["previous"] if record["generation"] != name],
                legacy_untracked=[generation for generation in current["legacy_untracked"] if generation != name])


def cleanup_record(file, name):
    saved = update.verification_snapshot(file)
    if saved is None:
        return None, None
    try:
        record = json.loads(saved[0], object_pairs_hook=update.strict_object)
        if (set(record) == {"generation", "before", "after"} and record["generation"] == name
                and all(REV.fullmatch(record[key]) for key in ("before", "after"))):
            return record, saved[1]
    except (ValueError, TypeError, KeyError, RecursionError):
        pass
    raise OSError("Invalid signature cleanup record")


def record_cleanup(file, name, current, revised):
    record = dict(generation=name, before=revision_for(current), after=revision_for(revised))
    update.write_json(file, record)
    return record


def cleanup_plan(path, name, reference, status, checks, deadline):
    """Only a durable delete record or an older publication entry can identify a removed generation."""
    current = reference[0] if reference is not None else None
    folder = path / name
    if (current is None or current["generation"] == name or not absent(folder)
            or not absent(update.verification_file(folder))):
        return None
    record_file = path / (name + CLEANUP_SUFFIX)
    record, record_identity = cleanup_record(record_file, name)
    revised = without_generation(current, name)
    current_hash = revision_for(current)
    matches_record = record is not None and (
        (record["before"], record["after"]) == (current_hash, revision_for(revised))
        or (record["after"] == current_hash and revised == current))
    if not matches_record:
        # With a different reference, independently verify the current predecessor. Older versions also
        # need a publication entry, since they left no deletion record.
        if (status != "protected" or any(generation == name for generation, _, _ in checks)
                or (record is None and revised == current)):
            return None
    elif status == "previous_unavailable" and checks[-1][:2] == (name, "unavailable"):
        # A known deletion can have removed a corrupt entry ahead of the intact predecessor.
        status, checks = previous_protection(path, revised, deadline)
    if (status not in {"protected", "no_previous", "legacy_history"}
            or any(generation == name and verdict == "last_previous" for generation, verdict, _ in checks)):
        return None
    if revised != current and status != "protected":
        return None
    with open_lease(path / (name + ".lease"), os.O_RDONLY) as (_, lease):
        pass
    pending = ["directory_sync"]
    if lease is not None:
        pending.insert(0, "lease_removal")
    if revised != current or (record is not None and record["before"] != record["after"]):
        pending.append("history_update")
    row = dict(id=name, pending=pending, revision=revision_for([name, reference, checks, record, record_identity, lease]))
    return row, revised, checks, (record, record_identity), lease


def cleanup_inventory(path, store_names, reference, status, checks, deadline):
    names = {n.removesuffix(CLEANUP_SUFFIX) for n in store_names if n.endswith(CLEANUP_SUFFIX)}
    current = reference[0] if reference is not None else None
    if current and "schema" in current:
        names.update(record["generation"] for record in current["previous"])
        names.update(current["legacy_untracked"])
    rows = []
    for name in sorted(n for n in names if update.GEN.fullmatch(n)):
        update.check_deadline(deadline)
        try:
            plan = cleanup_plan(path, name, reference, status, checks, deadline)
        except OSError:
            continue  # Unreadable or unsafe evidence cannot authorize a cleanup.
        if plan is not None:
            rows.append(plan[0])
    return rows


def remove_lease(lease, observed):
    if observed is not None:
        if update.identity(os.lstat(lease)) != observed:
            raise OSError("Signature lease changed")
        lease.unlink()
    elif not absent(lease):
        raise OSError("Signature lease changed")


def finish_cleanup(path, name, reference, revised, record, lease_removed, warnings, deadline, *, retry=False):
    """Report the removed generation separately from the remaining cleanup."""
    directory_synced = False
    try:
        update.check_deadline(deadline)
        update.sync_dir(path)
        directory_synced = True
    except (OSError, core.ScannerError):
        warnings.append("The parent directory sync could not be confirmed")

    history_updated = None
    if record["before"] != record["after"]:
        history_updated = False
        if not warnings:
            try:
                # Only the short reference update needs the publication lock.
                with history.locked(path / "publish", check_wait=lambda: update.check_deadline(deadline)):
                    if update.pointer_snapshot(path) != reference or not gone(path, name):
                        raise OSError("Signature cleanup state changed")
                    if revised != reference[0]:
                        update.write_json(path / "current.json", revised)
                    if update.pointer(path) != revised:
                        raise OSError("Signature history deletion could not be confirmed")
                history_updated = True
            except (OSError, core.ScannerError):
                pass
        if not history_updated:
            warnings.append("Generation deleted, but its publication history entry removal could not be confirmed")
    if not warnings:
        try:
            file = path / (name + CLEANUP_SUFFIX)
            if cleanup_record(file, name)[0] != record:
                raise OSError("Signature cleanup record changed")
            file.unlink()
            update.sync_dir(path)
        except OSError:
            warnings.append("The cleanup record removal could not be confirmed")
    data = {"deleted": name, "update_performed": False}
    if warnings:
        warnings.append("List the signature store again before further maintenance")
    if warnings or retry:
        data.update(directory_synced=directory_synced, lease_removed=lease_removed, history_updated=history_updated)
    return core.result("clamav", "partial" if warnings else "completed", data=data, warnings=warnings)


def delete_generation(path, name, reference, checks, revision, deadline):
    current = reference[0]
    check_reference = storage_check(path, reference, checks, deadline)
    revised = without_generation(current, name)
    record_file = path / (name + CLEANUP_SUFFIX)
    lease = path / (name + ".lease")
    removed, lease_removed = False, False
    warnings = []
    try:
        with exclusive_lease(lease) as observed:
            check_reference()
            cleanup_record(record_file, name)  # Preserve a malformed or unsafe record for investigation.
            update.check_deadline(deadline)
            record = record_cleanup(record_file, name, current, revised)
            remove_tree(path / name, revision, deadline, generation=True, check_reference=check_reference)
            removed = True
            remove_lease(lease, observed)
            lease_removed = True
    except OSError:
        if not removed:
            raise
        warnings.append("The lease release could not be confirmed" if lease_removed else
                        "The lease file removal could not be confirmed")
    return finish_cleanup(path, name, reference, revised, record, lease_removed, warnings, deadline)


def retry_cleanup(path, name, revision, reference, status, checks, deadline):
    plan = cleanup_plan(path, name, reference, status, checks, deadline)
    if plan is None or plan[0]["revision"] != revision:
        raise core.ScannerError("Selected signature cleanup is unavailable or changed; list again")
    _, revised, checks, saved, expected_lease = plan
    check_reference = storage_check(path, reference, checks, deadline)
    lease = path / (name + ".lease")
    file = path / (name + CLEANUP_SUFFIX)
    lease_removed, warnings = False, []
    try:
        with exclusive_lease(lease) as observed:
            check_reference()
            folder = path / name
            if (observed != expected_lease or cleanup_record(file, name) != saved
                    or not absent(folder) or not absent(update.verification_file(folder))):
                raise core.ScannerError("Selected signature cleanup changed; list again")
            update.check_deadline(deadline)
            record = saved[0]
            if record is None or (revised != reference[0] and record["before"] != revision_for(reference[0])):
                record = record_cleanup(file, name, reference[0], revised)
            try:
                remove_lease(lease, observed)
                lease_removed = True
            except OSError:
                warnings.append("The lease file removal could not be confirmed")
    except OSError:
        if not lease_removed:
            raise
        warnings.append("The lease release could not be confirmed")
    return finish_cleanup(path, name, reference, revised, record, lease_removed, warnings, deadline, retry=True)


def manage(scanner, action, entry_id=None, revision=None, not_before=None):
    if scanner.via != "cli":
        raise core.ScannerError("Signature maintenance is available only through the owner CLI")
    if action not in {"list", "recover", "delete", "cleanup"}:
        raise core.ScannerError("Invalid signature maintenance action")
    if action != "list" and (not isinstance(revision, str) or not REV.fullmatch(revision)):
        raise core.ScannerError("Exact revision from the signature store list is required")
    if action in {"delete", "cleanup"} and (
            not isinstance(entry_id, str) or not (ENTRY if action == "delete" else update.GEN).fullmatch(entry_id)):
        raise core.ScannerError("Invalid signature entry ID")
    deadline = time.monotonic() + 30
    try:
        # The updater lock freezes publication for this operation. Do not hold the short publication
        # lock while verifying large databases or deleting files: readers may still pin the current generation.
        with update.root(scanner) as path, history.locked(path / "update", attempts=1):
            info, reference, checks, revisions, (journal_snapshot, first_plans) = inventory(
                path, deadline, store_format=scanner.signature_update_settings["store_format"], list_cleanup=action == "list")
            status = info["previous_protection"]["status"]
            if action == "list":
                return core.result("clamav", "completed", data=info, warnings=[
                    "Entries named stage-* that this CLI cannot manage count toward the generation limit; inspect them manually"
                ] if info["unrecognized_entries"] else [])
            if reference is None or info["first_publication"] == "unavailable":
                raise core.ScannerError("Signature publication history unavailable; preserve the store and investigate")
            if action == "cleanup":
                return retry_cleanup(path, entry_id, revision, reference, status, checks, deadline)
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
                recover_provider(path, info["entries"])
                update.write_json(path / "attempt.json", {"pending": False, "next_attempt": until})
                return core.result("clamav", "completed", data={"recovered": True, "next_attempt_at": until,
                                   "provider_state_preserved": (path / "provider.dat").exists(), "update_performed": False})
            row = next((r for r in info["entries"] if r["id"] == entry_id), None)
            if row is None or row["revision"] != revision:
                raise core.ScannerError("Selected signature entry is missing or changed; list again")
            if not row["deletable"]:
                raise core.ScannerError("Selected entry is protected: " + row["reason"])
            if entry_id in first_plans:
                return first.delete(path, entry_id, journal_snapshot, first_plans[entry_id], deadline)
            if row["kind"] == "generation":
                return delete_generation(path, entry_id, reference, checks, revisions[entry_id], deadline)
            update.current(path, deadline)
            remove_tree(path / entry_id, revision, deadline)
            data = {"deleted": entry_id, "update_performed": False}
            try:
                update.sync_dir(path)
            except OSError:
                # The stage is already gone, so this must not read as a failed deletion.
                return core.result("clamav", "partial", data=dict(data, directory_synced=False), warnings=[
                    "The parent directory sync could not be confirmed",
                    "List the signature store again before further maintenance"])
            return core.result("clamav", "completed", data=data)
    except history.Busy:
        return core.result("clamav", "partial", warnings=["Signature update, publication or selected generation is busy; no maintenance completed"])
    except OSError:
        raise core.ScannerError("Signature maintenance could not complete; preserve state and check private permissions") from None
