"""Durable proof for selecting unpublished first-generation candidates."""
import hashlib
import json
import secrets

from . import core, history, signature_update as update

JOURNAL = "first-publication.json"
UNPUBLISHED = "unpublished_before_first_switch"


valid_id = update.valid_generation_id


def valid_hash(value):
    return isinstance(value, str) and update.CONTENT.fullmatch(value) is not None


def valid_identity(value, length):
    return isinstance(value, list) and len(value) == length and all(type(n) is int for n in value)


def valid_entry(name, entry):
    if (not valid_id(name) or not isinstance(entry, dict)
            or set(entry) != {"stage", "content", "versions", "verification", "deleting"}
            or not isinstance(entry["stage"], str) or not entry["stage"].startswith("stage-")
            or not valid_id(entry["stage"][6:]) or not valid_hash(entry["verification"])
            or not update.valid_record(dict(entry, generation=name))):
        return False
    removal = entry["deleting"]
    return removal is None or (
        isinstance(removal, dict) and set(removal) == {"directory", "files", "hashes", "sidecar"}
        and valid_identity(removal["directory"], 4)
        and isinstance(removal["files"], dict) and set(removal["files"]) == set(update.DATABASES)
        and all(valid_identity(info, 8) for info in removal["files"].values())
        and isinstance(removal["hashes"], dict) and set(removal["hashes"]) == set(update.DATABASES)
        and all(valid_hash(digest) for digest in removal["hashes"].values())
        and update.content_hash(removal["hashes"]) == entry["content"]
        and (removal["sidecar"] is None or valid_identity(removal["sidecar"], 8)))


def valid_journal(obj):
    if (not isinstance(obj, dict) or set(obj) != {"schema", "store_id", "phase", "target", "entries"}
            or type(obj["schema"]) is not int or obj["schema"] != 1 or not valid_id(obj["store_id"])
            or not isinstance(obj["entries"], dict) or len(obj["entries"]) > update.MAX_GENERATIONS
            or not all(valid_entry(name, entry) for name, entry in obj["entries"].items())):
        return False
    entries, target = obj["entries"], obj["target"]
    if len({entry["stage"] for entry in entries.values()}) != len(entries):
        return False
    if obj["phase"] == "open":
        return target is None
    if not valid_id(target):
        return False
    if obj["phase"] == "switch_started":
        return target in entries and all(entry["deleting"] is None for entry in entries.values())
    return obj["phase"] == "published" and not entries


def load(path, store_format):
    saved = update.verification_snapshot(path / JOURNAL)
    if (saved is not None) != (store_format == update.TRACKED_FIRST):
        raise OSError("First publication journal or configured store format unavailable")
    if saved is None:
        return None, None
    try:
        obj = json.loads(saved[0], object_pairs_hook=update.strict_object)
        if valid_journal(obj):
            return obj, saved[1]
    except (ValueError, RecursionError):
        pass
    raise OSError("Invalid first publication journal")


def save(path, obj):
    if not valid_journal(obj):
        raise OSError("Invalid first publication journal")
    update.write_json(path / JOURNAL, obj)
    if load(path, update.TRACKED_FIRST)[0] != obj:
        raise OSError("First publication journal write was not confirmed")
    return obj


def initialize(path):
    save(path, dict(schema=1, store_id=secrets.token_hex(16), phase="open", target=None, entries={}))


def phase(journal, current):
    if journal is None:
        return "legacy"
    if journal["phase"] == "open" and current is None:
        return "open"
    if journal["phase"] == "published" and current is not None:
        return "published"
    if journal["phase"] == "switch_started" and current is not None and current["generation"] == journal["target"]:
        entry = journal["entries"][journal["target"]]
        if all(current[key] == entry[key] for key in ("content", "versions")):
            return "confirm_published"
    return "unavailable"


def used_slots(names, journal):
    from .signature_maintenance import CLEANUP_SUFFIX

    occupied = {name for name in names if update.counts_toward_capacity(name)}
    # A generation deletion keeps its record until the parent sync and the history update are confirmed. Until then
    # a crash could bring the folder back, so its slot stays occupied.
    occupied.update(name.removesuffix(CLEANUP_SUFFIX) for name in names
                    if name.endswith(CLEANUP_SUFFIX) and valid_id(name.removesuffix(CLEANUP_SUFFIX)))
    if journal is not None:
        occupied.update(name for name, row in journal["entries"].items() if row["deleting"] is not None)
    return len(occupied)


def generation_names(names):
    return {name.split(".", 1)[0] for name in names if valid_id(name.split(".", 1)[0])}


def unexpected_sidecars(names, generation):
    return any(name.startswith(generation + ".") and name != generation + ".verification.json" for name in names)


def prepare(path, journal, names, generation, stage, observed):
    source = update.verification_snapshot(stage / "verification.json")
    if source is None or generation in journal["entries"] or generation in generation_names(names):
        raise OSError("First publication candidate cannot be recorded")
    existing = generation_names(names)
    entries = {name: row for name, row in journal["entries"].items() if name in existing}
    entries[generation] = dict(observed, stage=stage.name, verification=hashlib.sha256(source[0]).hexdigest(), deleting=None)
    return save(path, dict(journal, entries=entries))


def start_switch(path, journal, generation):
    return save(path, dict(journal, phase="switch_started", target=generation))


def published(path, journal):
    save(path, dict(journal, phase="published", entries={}))


def unfinished_deletion(journal):
    return journal is not None and any(row["deleting"] is not None for row in journal["entries"].values())


def unknown_generations(path, names, journal, deadline, cancel):
    candidates = generation_names(names)
    if journal is None:
        return bool(candidates)
    if unfinished_deletion(journal):
        return True
    try:
        for name in sorted(candidates):
            if unexpected_sidecars(names, name):
                return True
            entry = journal["entries"].get(name)
            if entry is None or inspect_candidate(path, name, entry, deadline, cancel)[0] is None:
                return True
    except OSError:
        return True
    return False


def inspect_candidate(path, name, entry, deadline, cancel=None):
    from . import signature_maintenance as maintenance

    folder = path / name
    evidence = update.verification_snapshot(update.verification_file(folder))
    if evidence is not None and hashlib.sha256(evidence[0]).hexdigest() != entry["verification"]:
        raise OSError("First publication evidence changed")
    removal = entry["deleting"]
    if maintenance.absent(folder):
        if removal is None or evidence is not None:
            raise OSError("First publication candidate is unavailable")
        return None, None, removal

    metadata = maintenance.tree(folder, deadline)
    file_ids = dict(metadata[1:])
    expected = tuple(key for key in update.DATABASES if key in file_ids)
    if set(file_ids) != set(expected):
        raise OSError("Unexpected first publication candidate contents")
    directory = metadata[0][1][:4]  # APFS can change the directory link count when a regular file is removed.
    if removal is not None:
        if (directory != removal["directory"]
                or any(removal["files"][key] != info for key, info in file_ids.items())
                or (evidence is not None and evidence[1] != removal["sidecar"])):
            raise OSError("First publication candidate changed during removal")
    elif expected != update.DATABASES:
        raise OSError("Incomplete first publication candidate")
    observed, hashes = update.digest_files(folder, deadline, cancel, expected=expected)
    if removal is not None:
        if any(removal["hashes"][key] != value for key, value in hashes.items()):
            raise OSError("First publication candidate content changed during removal")
    elif any(observed[key] != entry[key] for key in ("content", "versions")):
        raise OSError("First publication candidate contents do not match its record")
    if maintenance.tree(folder, deadline) != metadata or evidence != update.verification_snapshot(update.verification_file(folder)):
        raise OSError("First publication candidate changed while reading")
    if removal is None:
        removal = dict(directory=directory, files=file_ids, hashes=hashes,
                       sidecar=evidence[1] if evidence is not None else None)
    return metadata, evidence, removal


def delete(path, name, journal_snapshot, plan, deadline):
    from . import signature_maintenance as maintenance

    journal = journal_snapshot[0]
    folder = path / name
    lease = path / (name + ".lease")
    sidecar = update.verification_file(folder)
    metadata, evidence, removal = plan
    recorded = journal_snapshot

    def check_reference():
        if (update.pointer_snapshot(path) != (None, None) or not maintenance.absent(lease)
                or load(path, update.TRACKED_FIRST) != recorded):
            raise OSError("First publication state changed; list again")

    with history.locked(path / "publish", check_wait=lambda: update.check_deadline(deadline)):
        check_reference()
    entries = dict(journal["entries"])
    if entries[name]["deleting"] is None:
        entries[name] = dict(entries[name], deleting=removal)
        saved = save(path, dict(journal, entries=entries))
        recorded = load(path, update.TRACKED_FIRST)
        if recorded[0] != saved:
            raise OSError("First publication deletion intent changed")
    else:
        # The record can be visible after a replacement whose directory sync failed.
        update.check_deadline(deadline)
        update.sync_dir(path)
        check_reference()

    data = {"update_performed": False, "directory_synced": False}
    try:
        if metadata is not None:
            revision = maintenance.entry_revision(metadata, evidence)
            maintenance.remove_tree(folder, revision, deadline, generation=True, check_reference=check_reference)
        check_reference()
        if not maintenance.absent(folder) or not maintenance.absent(sidecar):
            raise OSError("First publication candidate removal was not confirmed")
        data["deleted"] = name
        update.check_deadline(deadline)
        update.sync_dir(path)
        if not maintenance.absent(folder) or not maintenance.absent(sidecar):
            raise OSError("First publication candidate removal was not confirmed")
        data["directory_synced"] = True
        del entries[name]
        save(path, dict(journal, entries=entries))
    except (OSError, core.ScannerError):
        if maintenance.absent(folder):
            data["deleted"] = name
        else:
            data.pop("deleted", None)
        return core.result("clamav", "partial", data=data,
                           warnings=["First publication candidate cleanup was not confirmed; list again before retrying"])
    return core.result("clamav", "completed", data=data)
