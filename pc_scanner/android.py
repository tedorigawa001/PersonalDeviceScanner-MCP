"""Read-only inspection of an owner-registered Android device over USB (ADB).

Design: docs/android-design.md. Only fixed commands run on the device. Values read from the
device never go into a device command line, except user and transport IDs checked to be numbers.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import queue
import re
import subprocess
import threading
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from .core import (CANCEL_POLL_SECONDS, PAGE_SIZE, PATH_CHARS, ProcessTree, ScannerError, check_cancel,
                   clean_text, engine_environment, result, run_bounded)

PROPERTIES = {"ro.build.version.release": "android_version", "ro.build.version.sdk": "sdk",
              "ro.build.version.security_patch": "security_patch", "ro.product.manufacturer": "manufacturer",
              "ro.product.model": "model"}
# Android package names: dot-separated parts that start with a letter ("android" itself has one part).
PACKAGE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*")
# Java class names; inner classes use "$".
CLASS_NAME = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*")
PLAY_STORE = "com.android.vending"
PACKAGE_INSTALLERS = {"com.google.android.packageinstaller", "com.android.packageinstaller"}
MANAGED_PROFILE_FLAG = 0x20
# After the ADB server starts, a device can be missing or offline for a moment.
DEVICE_WAIT_SECONDS = 5
MAX_INDICATOR_BYTES = 32 * 1024 * 1024
# Clock skew allowed before a future timestamp counts as invalid.
FUTURE_TOLERANCE = timedelta(days=1)
LAUNCHER = ("cmd package query-activities --brief --user {user} "
            "-a android.intent.action.MAIN -c android.intent.category.LAUNCHER")
CATEGORIES = {"Stalkerware application": "stalkerware", "Watchware application": "watchware"}
INDICATOR_SOURCE = "Echap stalkerware-indicators (CC-BY 4.0)"
APP_PATTERN = re.compile(r"\[\s*app:id\s*=\s*'((?:[^'\\]|\\.)*)'\s*\]")
COMMON_WARNINGS = ["Read-only ADB inspection; nothing on the device was changed",
                   "USB debugging widens the device's attack surface; turn it off and revoke USB debugging "
                   "authorizations when the check is done"]


# --- Connection -------------------------------------------------------------------------------

def parse_device_list(text: str) -> list[dict]:
    """Devices in one `adb track-devices --proto-text` list."""
    if text.strip() and not text.lstrip().startswith("device {"):
        raise ValueError("not a protobuf device list")
    devices = []
    for block in re.findall(r"device \{(.*?)\n\}", text, re.S):
        fields = {}
        for key, quoted, plain in re.findall(r'^\s*(\w+): (?:"((?:[^"\\]|\\.)*)"|(\S+))\s*$', block, re.M):
            fields[key] = re.sub(r"\\(.)", r"\1", quoted) if quoted or not plain else plain
        devices.append(fields)
    return devices


def find_usb_transport(argv: list[str], serial: str, wait: float, limit: int,
                       cancel: threading.Event | None = None) -> str:
    """The transport ID of `serial`, once adb reports it ready and connected over USB.

    `adb track-devices --proto-text` never exits: it prints the device list, then a new list on
    every change, each as 4 hex digits of length and protobuf text. Lists are read until the
    device is ready, can be ruled out, or `wait` runs out; then the command is stopped.
    """
    check_cancel(cancel)
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=False, env=engine_environment(),
                                   start_new_session=os.name != "nt")
    except OSError:
        raise ScannerError("Configured adb could not be started") from None
    tree = ProcessTree(process)
    chunks: queue.Queue = queue.Queue()

    def pump(stream, keep):
        try:
            while chunk := stream.read1(65536) if hasattr(stream, "read1") else stream.read(65536):
                if keep:
                    chunks.put(chunk)
        finally:
            if keep:
                chunks.put(b"")
            stream.close()

    readers = [threading.Thread(target=pump, args=(process.stdout, True), daemon=True),
               threading.Thread(target=pump, args=(process.stderr, False), daemon=True)]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + wait
    buffer, received, last_state = b"", 0, None
    try:
        while True:
            check_cancel(cancel)
            if time.monotonic() >= deadline:
                break
            try:
                chunk = chunks.get(timeout=CANCEL_POLL_SECONDS)
            except queue.Empty:
                continue
            if not chunk:
                if not received:
                    raise ScannerError("adb track-devices printed nothing; check the adb installation (Android SDK "
                                       "Platform-Tools 37.0.1 or later is known to work)")
                break  # adb exited
            received += len(chunk)
            if received > limit:
                raise ScannerError("adb device list exceeded limits")
            # The lengths count "\n" line ends. A Windows console layer may have written them as
            # "\r\n"; the protobuf text itself never holds "\r", so turning "\r\n" back is safe. A
            # trailing "\r" waits for the next chunk, which may start with its "\n".
            buffer = (buffer + chunk).replace(b"\r\n", b"\n")
            held = b""
            if buffer.endswith(b"\r"):
                buffer, held = buffer[:-1], b"\r"
            while len(buffer) >= 4:
                if not re.fullmatch(rb"[0-9a-fA-F]{4}", buffer[:4]):
                    raise ScannerError("adb did not report connection types; update Android SDK Platform-Tools "
                                       "(37.0.1 or later is known to work)")
                length = int(buffer[:4], 16)
                if len(buffer) < 4 + length:
                    break
                payload, buffer = buffer[4:4 + length], buffer[4 + length:]
                try:
                    devices = parse_device_list(payload.decode("utf-8", "replace"))
                except ValueError:
                    raise ScannerError("adb did not report connection types; update Android SDK Platform-Tools "
                                       "(37.0.1 or later is known to work)") from None
                entry = next((d for d in devices if d.get("serial") == serial), None)
                if entry is None:
                    last_state = None
                    continue
                if entry.get("connection_type") != "USB":
                    raise ScannerError("The device is not connected over USB "
                                       f"(connection: {clean_text(entry.get('connection_type', 'unknown'), 32)}); "
                                       "only USB-connected devices are inspected")
                state = entry.get("state", "")
                if state == "DEVICE":
                    transport = entry.get("transport_id", "")
                    if not re.fullmatch(r"[0-9]{1,10}", transport):
                        raise ScannerError("adb reported an invalid transport ID")
                    return transport
                if state == "UNAUTHORIZED":
                    raise ScannerError("USB debugging is not authorized on the device; approve this computer "
                                       "on the device and try again")
                if state == "NOPERMISSION":
                    raise ScannerError("No permission to use the USB device (on Linux, check the udev rules)")
                last_state = clean_text(state, 32)
            buffer += held
    finally:
        tree.stop()
        process.wait()
        tree.close()
    if last_state:
        raise ScannerError(f"The device did not become ready (state {last_state})")
    raise ScannerError("The device is not connected, or USB debugging is off")


class Session:
    """Fixed commands on one verified USB transport; what cannot be read is recorded, not guessed."""

    def __init__(self, adb: str, transport: str, deadline: float, limit: int,
                 cancel: threading.Event | None = None):
        self.adb, self.transport, self.deadline, self.limit, self.cancel = adb, transport, deadline, limit, cancel
        self.unavailable: list[dict] = []
        self.usable = 0  # commands whose output could be used; none at all makes the result an error

    def missing(self, item: str, user: int | None, reason: str) -> None:
        self.unavailable.append({"item": item, "user_id": user, "reason": reason})

    def reject(self, item: str, user: int | None, reason: str) -> None:
        """The command ran, but its output was not in a form that can be read."""
        self.missing(item, user, reason)
        self.usable -= 1

    def shell(self, item: str, command: str, user: int | None = None) -> str | None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            self.missing(item, user, "time limit reached")
            return None
        try:
            code, output, _ = run_bounded([self.adb, "-t", self.transport, "shell", command],
                                          remaining, self.limit, cancel=self.cancel)
        except ScannerError as exc:
            if self.cancel is not None and self.cancel.is_set():
                raise
            self.missing(item, user, str(exc))
            return None
        if code != 0:
            self.missing(item, user, f"command failed (exit code {code})")
            return None
        self.usable += 1
        return output


def connect(scanner, device_alias: str, cancel: threading.Event | None) -> Session:
    if device_alias not in scanner.android_devices:
        raise ScannerError("Android device alias is not registered")
    adb = scanner.binary("adb_binary", scanner.android)
    deadline = time.monotonic() + scanner.timeout
    transport = find_usb_transport([adb, "track-devices", "--proto-text"], scanner.android_devices[device_alias],
                                   min(DEVICE_WAIT_SECONDS, scanner.timeout), scanner.limit, cancel)
    return Session(adb, transport, deadline, scanner.limit, cancel)


# --- Parsing ----------------------------------------------------------------------------------

def parse_properties(text: str) -> dict:
    values = dict(re.findall(r"^\[([^\]]+)\]: \[([^\]]*)\]$", text, re.M))
    return {name: clean_text(values[key], 128) for key, name in PROPERTIES.items() if key in values}


def parse_users(pm_users: str, user_list: str | None) -> list[dict]:
    """User IDs and kinds; names are never returned (a user's name may be a person's name)."""
    users = {}
    for line in pm_users.splitlines():
        match = re.search(r"UserInfo\{(\d+):.*:([0-9a-fA-F]+)\}", line)
        if match:
            users[int(match.group(1))] = {"user_id": int(match.group(1)), "flags": int(match.group(2), 16)}
    details = {}
    for line in (user_list or "").splitlines():
        # Read from the end: the name before it may contain anything, even ", type=".
        match = re.search(r"\bid=(\d+), .*, type=([\w.]+), flags=[A-Z_|]*((?: \([^()]*\))*)\s*$", line)
        if match:
            parent = re.search(r"\(parentId=(\d+)\)", match.group(3))
            details[int(match.group(1))] = (match.group(2), int(parent.group(1)) if parent else None)
    for user_id, user in users.items():
        kind_type, parent = details.get(user_id, (None, None))
        if kind_type:
            kind = ("managed_profile" if kind_type == "profile.MANAGED" else
                    "profile" if kind_type.startswith("profile.") else "full")
        else:
            kind = "managed_profile" if user["flags"] & MANAGED_PROFILE_FLAG else "full"
        user.update(kind=kind, parent_user_id=parent)
    full = [u for u in users.values() if u["kind"] == "full"]
    for user in users.values():
        if user["kind"] != "full" and user["parent_user_id"] is None and len(full) == 1:
            user["parent_user_id"] = full[0]["user_id"]
        if user["kind"] == "full":
            user["parent_user_id"] = None
        del user["flags"]
    return [users[key] for key in sorted(users)]


def installer_category(installer: str | None) -> str:
    if not installer or installer == "null":
        return "unknown"
    if installer == PLAY_STORE:
        return "play_store"
    if installer in PACKAGE_INSTALLERS:
        return "package_installer"
    return "other_installer" if PACKAGE_NAME.fullmatch(installer) else "unknown"


def parse_packages(text: str) -> tuple[dict[str, dict], list[str]]:
    """`pm list packages -i -U --show-versioncode`: packages by name, and names that break the rules."""
    packages, invalid = {}, []
    for line in text.splitlines():
        match = re.match(r"\s*package:(\S+)(.*)$", line)
        if not match:
            continue
        name, rest = match.groups()
        if not PACKAGE_NAME.fullmatch(name):
            invalid.append(clean_text(name))
            continue
        installer = re.search(r"\binstaller=(\S+)", rest)
        version = re.search(r"\bversionCode:(\d+)", rest)
        value = installer.group(1) if installer else None
        packages[name] = {"version_code": int(version.group(1)) if version else None,
                          "installer": clean_text(value) if value and value != "null" else None,
                          "installer_category": installer_category(value)}
    return packages, invalid


def parse_package_names(text: str) -> set[str]:
    return {m for m in re.findall(r"^\s*package:(\S+)\s*$", text, re.M) if PACKAGE_NAME.fullmatch(m)}


def parse_component(text: str) -> dict:
    """`package/class`, with a short class (".Name") expanded; the class is for display only."""
    package, slash, cls = text.strip().partition("/")
    if not slash or not PACKAGE_NAME.fullmatch(package):
        return {"package": None, "component": clean_text(text.strip(), PATH_CHARS)}
    if cls.startswith("."):
        cls = package + cls
    return {"package": package, "class": clean_text(cls, PATH_CHARS), "class_valid": bool(CLASS_NAME.fullmatch(cls))}


def parse_launcher(text: str) -> set[str]:
    components = [parse_component(m) for m in re.findall(r"^\s+(\S+/\S+)\s*$", text, re.M)]
    return {c["package"] for c in components if c["package"]}


def parse_setting_components(text: str) -> list[dict]:
    value = text.strip()
    if not value or value == "null":
        return []
    return [parse_component(part) for part in value.split(":") if part.strip()]


def parse_device_policy(text: str) -> tuple[dict[int, list[dict]], list[dict], int]:
    """Enabled device admins by user, device or profile owners, and owners whose admin was not found.

    Raises ValueError when the output has no device admin section at all: an unexpected format
    must not read as "no device admins".
    """
    admins: dict[int, list[dict]] = {}
    owners: list[dict] = []
    unread_owners = 0
    section, section_indent, owner = None, 0, None
    for line in text.splitlines():
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        header = re.match(r"Enabled Device Admins \(User (\d+)", stripped)
        if header:
            unread_owners += owner is not None
            section, section_indent, owner = int(header.group(1)), indent, None
            admins.setdefault(section, [])
            continue
        if section is not None and stripped and indent <= section_indent:
            section = None
        if section is not None:
            entry = re.fullmatch(r"([^\s{}:/]+/[^\s{}:]+):", stripped)
            if entry:
                admins[section].append(parse_component(entry.group(1)))
            continue
        if stripped.startswith("Device Owner") and not stripped.startswith("Device Owner Type"):
            unread_owners += owner is not None
            owner = {"kind": "device_owner", "user_id": None}
            continue
        profile_owner = re.match(r"Profile Owner \(User (\d+)\)", stripped)
        if profile_owner:
            unread_owners += owner is not None
            owner = {"kind": "profile_owner", "user_id": int(profile_owner.group(1))}
            continue
        admin = re.match(r"admin=ComponentInfo\{([^}]+)\}", stripped)
        if owner is not None and admin:
            owners.append({**owner, **parse_component(admin.group(1))})
            owner = None
    if not admins:
        raise ValueError("no device admin section")
    return admins, owners, unread_owners + (owner is not None)


# --- Indicators -------------------------------------------------------------------------------

def parse_time(value) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


def load_indicators(path: str, max_age_days: int, now: datetime | None = None) -> tuple[dict, dict, list[str]]:
    """Package names of known monitoring apps from the Echap STIX2 bundle.

    Returns (packages, metadata, issues); every issue makes the check incomplete. Freshness
    comes from the indicators' `modified` time, which the provider sets when it generates the
    file, never from the file's mtime: re-downloading an old copy must not make it look new.
    """
    now = now or datetime.now(timezone.utc)
    source = Path(path)
    if source.stat().st_size > MAX_INDICATOR_BYTES:
        raise ValueError("indicator file is too large")
    data = source.read_bytes()
    bundle = json.loads(data)
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("not a STIX2 bundle")
    # The file is untrusted: an object whose identifying fields are not strings is skipped and counted.
    def strings(item, *keys):
        return all(isinstance(item.get(key), str) for key in keys)

    malware, indicators, issues = {}, {}, []
    times, untimed, skipped = [], 0, 0
    for item in bundle["objects"]:
        kind = item.get("type") if isinstance(item, dict) else None
        if kind == "malware":
            if not strings(item, "id"):
                skipped += 1
                continue
            description = item.get("description")
            name = item.get("name") if isinstance(item.get("name"), str) else ""
            malware[item["id"]] = {"name": clean_text(name),
                                   "category": CATEGORIES.get(description, "unknown") if isinstance(description, str)
                                   else "unknown"}
        elif kind == "indicator":
            modified = parse_time(item.get("modified"))
            if modified is None:
                untimed += 1
            else:
                times.append(modified)
            if not strings(item, "id", "pattern"):
                skipped += 1
                continue
            match = APP_PATTERN.fullmatch(item["pattern"])
            if match:
                package = re.sub(r"\\(.)", r"\1", match.group(1))
                if PACKAGE_NAME.fullmatch(package):
                    indicators[item["id"]] = package
        elif kind is None:
            skipped += 1
    apps: dict[str, list[dict]] = {}
    for item in bundle["objects"]:
        if isinstance(item, dict) and item.get("type") == "relationship" and item.get("relationship_type") == "indicates":
            if not strings(item, "source_ref", "target_ref"):
                skipped += 1
                continue
            package = indicators.get(item["source_ref"])
            family = malware.get(item["target_ref"])
            if package and family and family not in apps.setdefault(package, []):
                apps[package].append(family)
    if skipped:
        issues.append(f"{skipped} indicator objects with unexpected field types were ignored")
    counts = {category: sum(1 for families in apps.values() if any(f["category"] == category for f in families))
              for category in ("stalkerware", "watchware", "unknown")}
    if counts["unknown"]:
        issues.append(f"{counts['unknown']} indicator packages belong to apps of an unknown category")
    generated = max(times) if times and not untimed else None
    meta = {"source": INDICATOR_SOURCE, "file": clean_text(source.name), "sha256": hashlib.sha256(data).hexdigest(),
            "app_packages": len(apps), "app_packages_by_category": counts,
            "generated_at": generated.isoformat() if generated else None,
            "retrieved_at": datetime.fromtimestamp(source.stat().st_mtime, timezone.utc).isoformat(),
            "max_age_days": max_age_days}
    if generated is None:
        meta.update(freshness="unknown", age_days=None)
        issues.append("Indicator update time could not be determined; update the indicator file")
    elif generated - now > FUTURE_TOLERANCE:
        meta.update(freshness="unknown", age_days=None)
        issues.append("Indicator update time is in the future; the file or this computer's clock is wrong")
    else:
        age_seconds = max(0.0, (now - generated).total_seconds())
        # Decide on the exact age; show it rounded up to 0.1 day, so a stale file never shows
        # an age at or under the limit.
        meta["age_days"] = math.ceil(age_seconds / 8640) / 10
        stale = age_seconds > max_age_days * 86400
        meta["freshness"] = "stale" if stale else "fresh"
        if stale:
            issues.append(f"Indicators are {meta['age_days']} days old (limit {max_age_days} days); update them "
                            "(the provider may also not have updated them recently)")
    if not apps:
        issues.append("The indicator file has no app package indicators")
    return apps, meta, issues


# --- Collection -------------------------------------------------------------------------------

def patch_age(security_patch: str | None, today: date | None = None) -> int | None:
    today = today or datetime.now(timezone.utc).date()
    try:
        patched = date.fromisoformat(security_patch or "")
    except ValueError:
        return None
    if patched > today + timedelta(days=1):
        return None
    return max(0, (today - patched).days)


def read_device(session: Session, max_patch_age: int) -> tuple[dict, list[dict]]:
    output = session.shell("device", "getprop")
    if output is None:
        return {}, []
    device = parse_properties(output)
    if not device:
        session.reject("device", None, "none of the expected properties in the output")
        return {}, []
    findings = []
    age = patch_age(device.get("security_patch"))
    device["security_patch_age_days"] = age
    if age is None:
        session.missing("security_patch", None, "the security patch date could not be read")
    elif age > max_patch_age:
        findings.append({"kind": "outdated_patch", "severity": "medium", "security_patch": device["security_patch"],
                         "age_days": age, "max_age_days": max_patch_age})
    return device, findings


def read_users(session: Session) -> list[dict]:
    output = session.shell("users", "pm list users")
    if output is None:
        return []
    detail = session.shell("user_types", "cmd user list -v")
    users = parse_users(output, detail)
    if not users:
        session.reject("users", None, "no users in the output")
    for user in users:
        if user["kind"] != "full" and user["parent_user_id"] is None:
            session.missing("profile_parent", user["user_id"], "the profile's parent user could not be determined")
    return users


def read_apps(session: Session, users: list[dict]) -> tuple[dict, list[str]]:
    """All packages per user, marked as system or not, with their install source and launcher activity."""
    apps, invalid = {}, []
    for user in users:
        uid = user["user_id"]
        listed = session.shell("packages", f"pm list packages -i -U --show-versioncode --user {uid}", uid)
        if listed is None:
            continue
        packages, bad = parse_packages(listed)
        invalid += bad
        if not packages and not bad:
            # Every user has system packages: an empty list means the output was not understood.
            session.reject("packages", uid, "no packages in the output")
            continue
        system_output = session.shell("system_packages", f"pm list packages -s --user {uid}", uid)
        system = parse_package_names(system_output) if system_output is not None else None
        if system is not None and not system:
            session.reject("system_packages", uid, "no system packages in the output")
            system = None
        launcher_output = session.shell("launcher_activities", LAUNCHER.format(user=uid), uid)
        launcher = None
        if launcher_output is not None:
            if re.search(r"^\s*(?:\d+ activities found|No activities found)", launcher_output, re.M):
                launcher = parse_launcher(launcher_output)
            else:
                session.reject("launcher_activities", uid, "unexpected output format")
        for name, info in packages.items():
            apps[(uid, name)] = {"user_id": uid, "package": name, **info,
                                 "is_system": None if system is None else name in system,
                                 "has_launcher_activity": None if launcher is None else name in launcher}
    return apps, invalid


def read_privileged(session: Session, users: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    """Accessibility, notification access and device admin, per user; owners; shared settings."""
    entries, shared = [], []
    for user in users:
        uid = user["user_id"]
        if user["kind"] == "managed_profile":
            # Android shares accessibility between a work profile and its parent user.
            shared.append({"user_id": uid, "setting": "accessibility", "shared_with_user_id": user["parent_user_id"]})
        else:
            value = session.shell("accessibility", f"settings --user {uid} get secure enabled_accessibility_services", uid)
            for component in parse_setting_components(value) if value is not None else []:
                entries.append({"user_id": uid, "access": "accessibility", **component})
        value = session.shell("notification_listeners",
                              f"settings --user {uid} get secure enabled_notification_listeners", uid)
        for component in parse_setting_components(value) if value is not None else []:
            entries.append({"user_id": uid, "access": "notification_listener", **component})
    owners = []
    policy = session.shell("device_admins", "dumpsys device_policy")
    if policy is not None:
        try:
            admins, owners, unread_owners = parse_device_policy(policy)
        except ValueError:
            session.reject("device_admins", None, "unexpected output format")
        else:
            if unread_owners:
                session.missing("owners", None, f"{unread_owners} device or profile owners could not be read")
            for user in users:
                if user["user_id"] not in admins:
                    session.missing("device_admins", user["user_id"], "the output has no section for this user")
            for uid, components in admins.items():
                entries += [{"user_id": uid, "access": "device_admin", **component} for component in components]
    return entries, owners, shared


def describe(entries: list[dict], apps: dict) -> tuple[list[dict], list[dict], list[str]]:
    """Attach what is known about each entry's app; split off components with no attributable package.

    Returns (attributed, unattributed, issues). A class name that breaks the rules is kept
    (dropping it would hide a privileged app) but makes the result incomplete.
    """
    attributed, unattributed, issues = [], [], []
    for entry in entries:
        if entry.get("package") is None:
            unattributed.append({"user_id": entry["user_id"], "access": entry["access"], "component": entry["component"]})
            continue
        app = apps.get((entry["user_id"], entry["package"]))
        if not entry.pop("class_valid", True):
            issues.append(f"A component class name of {entry['package']} does not follow Java naming; kept as is")
        attributed.append({**entry, "in_package_list": app is not None,
                           "is_system": app["is_system"] if app else None,
                           "installer_category": app["installer_category"] if app else None})
    return attributed, unattributed, issues


def finish(session: Session, data: dict, findings: list[dict], notes: list[str], issues: list[str],
           invalid: list[str], unattributed: list[dict]) -> dict:
    """Notes inform; issues, unread items, invalid names and unattributed components make it partial.

    When nothing at all could be read from the device, the result is an error instead.
    """
    if session.usable <= 0:
        reason = session.unavailable[0]["reason"] if session.unavailable else "no output"
        raise ScannerError(f"Nothing could be read from the device ({reason})")
    issues = list(issues)
    if invalid:
        data["invalid_package_names"] = invalid[:PAGE_SIZE]
        issues.append(f"{len(invalid)} package names do not follow Android naming rules and were not matched")
    if unattributed:
        data["unattributed_components"] = unattributed[:PAGE_SIZE]
        issues.append(f"{len(unattributed)} components could not be attributed to a package")
    data["unavailable"] = session.unavailable
    if session.unavailable:
        issues.append(f"{len(session.unavailable)} items could not be read; they are listed in data.unavailable "
                      "and are not treated as absent")
    if len(findings) > PAGE_SIZE:
        issues.append(f"Findings capped at {PAGE_SIZE}")
    partial = bool(issues)
    return result("adb", "partial" if partial else "completed", findings=findings[:PAGE_SIZE], data=data,
                  warnings=COMMON_WARNINGS + notes + issues
                  + (["Results are incomplete; do not report this device as clean"] if partial else []))


def collect(scanner, device_alias: str, query_id: str, cancel: threading.Event | None = None) -> dict:
    if query_id not in ("device", "apps", "privileged_access"):
        raise ScannerError("Unsupported Android query_id")
    session = connect(scanner, device_alias, cancel)
    data: dict = {"device_alias": device_alias, "query_id": query_id}
    findings, notes, issues, invalid, unattributed = [], [], [], [], []
    if query_id == "device":
        data["device"], findings = read_device(session, scanner.max_patch_age)
    else:
        users = read_users(session)
        data["users"] = users
        apps, invalid = read_apps(session, users)
        if query_id == "apps":
            listed = sorted((app for app in apps.values() if app["is_system"] is False),
                            key=lambda a: (a["user_id"], a["package"]))
            data["apps"] = listed[:PAGE_SIZE]
            data["system_apps_hidden"] = sum(1 for app in apps.values() if app["is_system"])
            if len(listed) > PAGE_SIZE:
                session.missing("apps", None, f"only the first {PAGE_SIZE} apps are listed")
            notes.append("Install sources are what the device recorded; 'unknown' does not mean sideloaded, and "
                         "no launcher activity does not mean the app hides its icon")
        else:
            entries, owners, shared = read_privileged(session, users)
            data["privileged_access"], unattributed, issues = describe(entries, apps)
            data["owners"], data["shared_settings"] = owners, shared
            if owners:
                notes.append("A device or profile owner is present; the device or a profile may be managed "
                             "by an employer or school")
    return finish(session, data, findings, notes, issues, invalid, unattributed)


def check(scanner, device_alias: str, cancel: threading.Event | None = None) -> dict:
    """Match every package against known monitoring apps, and list apps to review."""
    if device_alias not in scanner.android_devices:
        raise ScannerError("Android device alias is not registered")
    notes: list[str] = []
    issues: list[str] = []
    indicators, meta = {}, {"source": INDICATOR_SOURCE, "freshness": "unknown"}
    path = scanner.android.get("indicators_file", "")
    if not path:
        issues.append("No indicator file is configured; known monitoring apps were not matched")
    else:
        try:
            indicators, meta, indicator_issues = load_indicators(path, scanner.max_indicator_age)
            issues += indicator_issues
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            # Whatever the file holds, the device check goes on, as partial.
            issues.append("The indicator file could not be read as a STIX2 bundle; known monitoring apps were "
                          "not matched")
    session = connect(scanner, device_alias, cancel)
    device, findings = read_device(session, scanner.max_patch_age)
    users = read_users(session)
    apps, invalid = read_apps(session, users)
    # A work profile's accessibility was read from its parent user, so it is matched with the
    # parent's packages (read_privileged).
    entries, owners, shared = read_privileged(session, users)
    privileged, unattributed, entry_issues = describe(entries, apps)
    issues += entry_issues
    access: dict[tuple[int, str], set[str]] = {}
    for entry in privileged:
        access.setdefault((entry["user_id"], entry["package"]), set()).add(entry["access"])
    for (uid, package), app in sorted(apps.items()):
        families = indicators.get(package)
        if families:
            categories = sorted({f["category"] for f in families})
            findings.append({"kind": "monitoring_app_indicator",
                             "severity": "high" if "stalkerware" in categories else "medium",
                             "user_id": uid, "package": package, "categories": categories,
                             "names": sorted({f["name"] for f in families}), "is_system": app["is_system"],
                             "installer_category": app["installer_category"]})
    for (uid, package), kinds in sorted(access.items()):
        app = apps.get((uid, package))
        if app and app["is_system"] is False and app["installer_category"] != "play_store":
            findings.append({"kind": "review", "severity": "medium", "user_id": uid, "package": package,
                             "access": sorted(kinds), "installer_category": app["installer_category"],
                             "installer": app["installer"], "has_launcher_activity": app["has_launcher_activity"]})
    severity = {"high": 0, "medium": 1}
    kind = {"monitoring_app_indicator": 0, "review": 1, "outdated_patch": 2}
    findings.sort(key=lambda f: (severity.get(f["severity"], 2), kind[f["kind"]], f.get("user_id") or 0,
                                 f.get("package", "")))
    if any(f["kind"] == "monitoring_app_indicator" and "watchware" in f["categories"] for f in findings):
        notes.append("Watchware matches are monitoring apps sold for parents or employers; check whether you or "
                        "your family installed it knowingly")
    if any(f["kind"] == "review" for f in findings):
        notes.append("Review findings are prompts to check, not verdicts: device management, assistive and work "
                        "apps can appear here")
    if owners:
        notes.append("A device or profile owner is present; the device or a profile may be managed by an "
                     "employer or school")
    notes.append("Matches only monitoring apps in the indicator file; no finding does not prove the device is safe")
    data = {"device_alias": device_alias, "device": device, "users": users, "indicators": meta,
            "packages_checked": len(apps), "owners": owners, "shared_settings": shared}
    return finish(session, data, findings, notes, issues, invalid, unattributed)
