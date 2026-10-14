"""Android (ADB) inspection against recorded command output; no device is needed.

The output formats follow what Android 10 and 16 emulators printed (docs/acceptance/
android-emulator-2026-10-14.json); names and values are synthetic.
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from pc_scanner import android
from pc_scanner.core import Scanner, ScannerError


def frame(text):
    return f"{len(text.encode()):04x}{text}"


def device(serial, state="DEVICE", connection="USB", transport=3):
    return (f'device {{\n  serial: "{serial}"\n  state: {state}\n  product: "sdk"\n  model: "Phone"\n'
            f'  device: "dev"\n  connection_type: {connection}\n  transport_id: {transport}\n}}\n')


# A stand-in for `adb track-devices --proto-text`: prints lists, then keeps running like adb.
STREAM = """
import sys, time
for delay, text in {frames!r}:
    time.sleep(delay)
    sys.stdout.write(text)
    sys.stdout.flush()
time.sleep(60)
"""


def stream(*frames):
    return [sys.executable, "-c", STREAM.format(frames=list(frames))]


class ConnectionTests(unittest.TestCase):
    def find(self, argv, serial="R58TEST", wait=3.0, cancel=None):
        return android.find_usb_transport(argv, serial, wait, 1 << 20, cancel)

    def test_usb_device_that_is_ready_gives_its_transport(self):
        started = time.monotonic()
        lists = frame(device("emulator-5554", connection="SOCKET", transport=1) + device("R58TEST", transport=7))
        self.assertEqual(self.find(stream((0, lists))), "7")
        self.assertLess(time.monotonic() - started, 2.5, "must not wait once the device is ready")

    def test_waits_while_the_device_is_offline(self):
        argv = stream((0, frame("")), (0.3, frame(device("R58TEST", state="OFFLINE"))), (0.3, frame(device("R58TEST"))))
        self.assertEqual(self.find(argv), "3")

    def test_wireless_devices_are_refused_whatever_their_serial(self):
        # Wireless debugging serials can be mDNS names without ':', so only the type decides.
        for serial in ("adb-R58TEST-AbCdEf._adb-tls-connect._tcp", "192.168.1.20:5555", "emulator-5554"):
            with self.subTest(serial=serial), self.assertRaisesRegex(ScannerError, "not connected over USB"):
                self.find(stream((0, frame(device(serial, connection="SOCKET")))), serial=serial)

    def test_unauthorized_device_asks_for_approval(self):
        with self.assertRaisesRegex(ScannerError, "approve this computer"):
            self.find(stream((0, frame(device("R58TEST", state="UNAUTHORIZED")))))

    def test_missing_device_is_an_error_after_the_wait(self):
        started = time.monotonic()
        with self.assertRaisesRegex(ScannerError, "not connected"):
            self.find(stream((0, frame(""))), wait=0.5)
        self.assertLess(time.monotonic() - started, 2.5)
        with self.assertRaisesRegex(ScannerError, r"did not become ready \(state OFFLINE\)"):
            self.find(stream((0, frame(device("R58TEST", state="OFFLINE")))), wait=0.5)

    def test_text_output_means_platform_tools_too_old(self):
        # What `adb track-devices -l` (or an adb without --proto-text) prints.
        text = frame("R58TEST          device usb:1-1 product:sdk model:Phone transport_id:3\n")
        with self.assertRaisesRegex(ScannerError, "Platform-Tools"):
            self.find(stream((0, text)))
        with self.assertRaisesRegex(ScannerError, "Platform-Tools"):
            self.find(stream((0, "not a length prefix")))
        with self.assertRaisesRegex(ScannerError, "printed nothing"):
            self.find([sys.executable, "-c", "pass"])

    def test_cancel_stops_waiting(self):
        cancel = threading.Event()
        threading.Timer(0.3, cancel.set).start()
        started = time.monotonic()
        with self.assertRaisesRegex(ScannerError, "cancelled"):
            self.find(stream((0, frame(""))), wait=10, cancel=cancel)
        self.assertLess(time.monotonic() - started, 2)


ANDROID_10_USERS = "Users:\n\tUserInfo{0:Owner:13} running\n\tUserInfo{10:Work:30} running\n"
ANDROID_16_USERS = "Users:\n\tUserInfo{0:Taro Yamada:4c13} running\n\tUserInfo{10:Work:1030} running\n"
ANDROID_16_USER_LIST = (
    "2 users:\n\n"
    "0: id=0, name=Taro Yamada, type=full.SYSTEM, flags=ADMIN|FULL|INITIALIZED|MAIN|PRIMARY|SYSTEM (running) (current)\n"
    "1: id=10, name=Work, type=profile.MANAGED, flags=INITIALIZED|MANAGED_PROFILE|PROFILE (parentId=0) (running)\n")
POLICY = """Current Device Policy Manager state:
  Immutable state:
    mHasFeature=true
  Device Owner Type: 0
  Profile Owner (User 10):
    admin=ComponentInfo{com.work.mdm/com.work.mdm.Receiver}
    name=Work MDM
    package=com.work.mdm
  Enabled Device Admins (User 0, provisioningState: 0):
    com.vendor.preloaded.watch/.Admin:
      uid=10050
      policies:
        force-lock
  Enabled Device Admins (User 10, provisioningState: 3):
    com.work.mdm/com.work.mdm.Receiver:
      uid=1010100
  Constants:
    DAS_DIED_SERVICE_RECONNECT_BACKOFF_SEC: 3600
"""


class ParserTests(unittest.TestCase):
    def test_users_and_profile_parents_without_names(self):
        android_16 = android.parse_users(ANDROID_16_USERS, ANDROID_16_USER_LIST)
        self.assertEqual(android_16, [{"user_id": 0, "kind": "full", "parent_user_id": None},
                                      {"user_id": 10, "kind": "managed_profile", "parent_user_id": 0}])
        # Android 10: no types or parents, only flags (0x20 = managed profile); one full user is the parent.
        android_10 = android.parse_users(ANDROID_10_USERS, ANDROID_10_USERS)
        self.assertEqual(android_10, android_16)
        self.assertNotIn("Taro", json.dumps(android_16))
        # A name cannot pose as the type or parent: they are read from the end of the line.
        tricky = ("1: id=10, name=x, type=full.SYSTEM, flags=ADMIN (parentId=7), type=profile.MANAGED, "
                  "flags=MANAGED_PROFILE|PROFILE (parentId=0) (running)\n")
        self.assertEqual(android.parse_users("UserInfo{0:a:13}\nUserInfo{10:b:1030}", tricky)[1]["parent_user_id"], 0)

    def test_profile_parent_unknown_with_two_full_users(self):
        users = android.parse_users("UserInfo{0:a:13}\nUserInfo{11:b:10}\nUserInfo{12:c:30}", "")
        self.assertEqual(users[2], {"user_id": 12, "kind": "managed_profile", "parent_user_id": None})

    def test_packages_keep_the_recorded_install_source(self):
        text = ("package:com.android.settings versionCode:36  installer=null uid:1000\n"
                "package:com.store.app versionCode:9  installer=com.android.vending uid:10202\n"
                "package:com.from.apk versionCode:5  installer=com.google.android.packageinstaller uid:10200\n"
                "package:com.other versionCode:1  installer=org.fdroid.fdroid uid:10203\n"
                "package:1bad.name versionCode:1  installer=null uid:10204\n")
        packages, invalid = android.parse_packages(text)
        self.assertEqual({name: p["installer_category"] for name, p in packages.items()},
                         {"com.android.settings": "unknown", "com.store.app": "play_store",
                          "com.from.apk": "package_installer", "com.other": "other_installer"})
        self.assertIsNone(packages["com.android.settings"]["installer"])
        self.assertEqual(packages["com.store.app"]["version_code"], 9)
        self.assertEqual(invalid, ["1bad.name"])

    def test_components_are_split_and_short_classes_expanded(self):
        self.assertEqual(android.parse_component("com.a/.Svc"),
                         {"package": "com.a", "class": "com.a.Svc", "class_valid": True})
        self.assertEqual(android.parse_component("com.a/com.a.Outer$Inner")["class_valid"], True)
        # A class that breaks Java naming is kept with its package, flagged.
        self.assertEqual(android.parse_component("com.a/1Bad")["class_valid"], False)
        self.assertEqual(android.parse_component("com.a/1Bad")["package"], "com.a")
        self.assertIsNone(android.parse_component("no-slash")["package"])
        self.assertIsNone(android.parse_component("1bad/.X")["package"])
        self.assertEqual(android.parse_setting_components("null"), [])
        self.assertEqual([c["package"] for c in android.parse_setting_components("com.a/.A:com.b/com.b.B$C\n")],
                         ["com.a", "com.b"])

    def test_launcher_activities(self):
        text = ("12 activities found:\n  Activity #0:\n    priority=0 preferredOrder=0 match=0x108000 "
                "specificIndex=-1 isDefault=true\n    com.android.calendar/.AllInOneActivity\n"
                "  Activity #1:\n    com.example.store/com.example.store.Main\n")
        self.assertEqual(android.parse_launcher(text), {"com.android.calendar", "com.example.store"})

    def test_device_policy_admins_and_owners(self):
        admins, owners, unread = android.parse_device_policy(POLICY)
        self.assertEqual({uid: [a["package"] for a in found] for uid, found in admins.items()},
                         {0: ["com.vendor.preloaded.watch"], 10: ["com.work.mdm"]})
        self.assertEqual(owners, [{"kind": "profile_owner", "user_id": 10, "package": "com.work.mdm",
                                   "class": "com.work.mdm.Receiver", "class_valid": True}])
        empty = "Current Device Policy Manager state:\n\n  Enabled Device Admins (User 0, provisioningState: 0):\n \n" \
                "    mPasswordOwner=-1\n\n  Constants:\n"
        self.assertEqual(android.parse_device_policy(empty), ({0: []}, [], 0))
        self.assertEqual(unread, 0)
        # An unexpected format is not "no device admins".
        with self.assertRaises(ValueError):
            android.parse_device_policy("Can't find service: device_policy\n")
        # An owner whose admin line is missing is counted, not dropped silently.
        odd_owner = "  Device Owner: \n    name=x\n  Enabled Device Admins (User 0, provisioningState: 0):\n"
        self.assertEqual(android.parse_device_policy(odd_owner)[2], 1)

    def test_properties_are_limited_to_the_chosen_ones(self):
        props = android.parse_properties("[ro.build.version.release]: [16]\n[ro.serialno]: [SECRET]\n"
                                         "[ro.build.version.security_patch]: [2025-07-05]\n")
        self.assertEqual(props, {"android_version": "16", "security_patch": "2025-07-05"})

    def test_patch_age(self):
        today = date(2026, 10, 14)
        self.assertEqual(android.patch_age("2026-07-16", today), 90)
        self.assertEqual(android.patch_age("2026-07-15", today), 91)
        self.assertIsNone(android.patch_age("unknown", today))
        self.assertIsNone(android.patch_age("2026-10-20", today))  # in the future: not trusted


def bundle(entries, modified="2026-10-09T15:13:08.136715Z", untimed=False):
    objects = []
    for index, (package, name, description) in enumerate(entries):
        objects.append({"type": "malware", "id": f"malware--{index}", "name": name, "description": description})
        indicator = {"type": "indicator", "id": f"indicator--{index}", "pattern": f"[app:id='{package}']"}
        if modified and not (untimed and index == 0):
            indicator["modified"] = modified
        objects.append(indicator)
        objects.append({"type": "relationship", "relationship_type": "indicates",
                        "source_ref": f"indicator--{index}", "target_ref": f"malware--{index}"})
    objects.append({"type": "indicator", "id": "indicator--domain", "pattern": "[domain-name:value='example.com']",
                    "modified": modified})
    return {"type": "bundle", "id": "bundle--1", "objects": objects}


class IndicatorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "stalkerware.stix2"

    def load(self, data, now, max_age=30):
        self.path.write_text(json.dumps(data))
        return android.load_indicators(str(self.path), max_age, now)

    def test_categories_are_kept(self):
        generated = datetime(2026, 10, 9, 15, 13, 8, 136715, tzinfo=timezone.utc)
        apps, meta, issues = self.load(bundle([("com.spy", "TheSpy", "Stalkerware application"),
                                               ("com.kids", "KidWatch", "Watchware application"),
                                               ("com.odd", "Odd", "Something else")]), generated)
        self.assertEqual(apps["com.spy"], [{"name": "TheSpy", "category": "stalkerware"}])
        self.assertEqual(apps["com.kids"][0]["category"], "watchware")
        self.assertEqual(apps["com.odd"][0]["category"], "unknown")
        self.assertEqual(meta["app_packages_by_category"], {"stalkerware": 1, "watchware": 1, "unknown": 1})
        self.assertTrue(any("unknown category" in issue for issue in issues))
        self.assertEqual(meta["freshness"], "fresh")
        self.assertEqual(meta["source"], "Echap stalkerware-indicators (CC-BY 4.0)")
        self.assertEqual(len(meta["sha256"]), 64)

    def test_pattern_spacing_is_tolerated(self):
        data = bundle([("com.spy", "TheSpy", "Stalkerware application")])
        data["objects"][1]["pattern"] = "[ app:id = 'com.spy' ]"
        apps, _, _ = self.load(data, datetime(2026, 10, 9, tzinfo=timezone.utc))
        self.assertIn("com.spy", apps)

    def test_freshness_comes_from_the_indicators_not_the_file(self):
        data = bundle([("com.spy", "TheSpy", "Stalkerware application")], modified="2026-09-01T00:00:00Z")
        generated = datetime(2026, 9, 1, tzinfo=timezone.utc)
        cases = [(generated + timedelta(days=30), "fresh"), (generated + timedelta(days=30, seconds=1), "stale"),
                 (generated - timedelta(hours=12), "fresh")]
        for now, freshness in cases:
            with self.subTest(now=now.isoformat()):
                _, meta, issues = self.load(data, now)
                self.assertEqual(meta["freshness"], freshness)
                self.assertEqual(bool(issues), freshness != "fresh")
        # A re-downloaded old copy has a new mtime but stays stale.
        now = generated + timedelta(days=60)
        os.utime(self.path, (now.timestamp(), now.timestamp()))
        self.path.write_text(json.dumps(data))
        _, meta, _ = android.load_indicators(str(self.path), 30, now)
        self.assertEqual(meta["freshness"], "stale")
        self.assertEqual(meta["age_days"], 60.0)
        self.assertNotEqual(meta["retrieved_at"], meta["generated_at"])

    def test_missing_or_future_times_are_unknown(self):
        now = datetime(2026, 10, 14, tzinfo=timezone.utc)
        _, meta, issues = self.load(bundle([("com.spy", "S", "Stalkerware application")], untimed=True), now)
        self.assertEqual(meta["freshness"], "unknown")
        self.assertTrue(issues)
        _, meta, issues = self.load(bundle([("com.spy", "S", "Stalkerware application")],
                                           modified="2026-10-16T00:00:00Z"), now)
        self.assertEqual(meta["freshness"], "unknown")
        self.assertTrue(any("future" in issue for issue in issues))

    def test_unusable_files_are_refused(self):
        self.path.write_text('{"type": "not-a-bundle"}')
        with self.assertRaises(ValueError):
            android.load_indicators(str(self.path), 30)
        self.path.write_text(json.dumps(bundle([("com.spy", "S", "Stalkerware application")])))
        with patch("pc_scanner.android.MAX_INDICATOR_BYTES", 10), self.assertRaises(ValueError):
            android.load_indicators(str(self.path), 30)


class FakeDevice:
    """Answers the fixed commands; records what was run."""

    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def __call__(self, argv, timeout, limit, cancel=None):
        self.calls.append(argv)
        assert argv[1:4] == ["-t", "3", "shell"], argv
        answer = self.answers.get(argv[4])
        if answer is None:
            raise AssertionError(f"unexpected command: {argv[4]}")
        if isinstance(answer, Exception):
            raise answer
        return answer if isinstance(answer, tuple) else (0, answer, "")


def answers():
    return {
        "getprop": "[ro.build.version.release]: [16]\n[ro.build.version.sdk]: [36]\n"
                   "[ro.build.version.security_patch]: [2025-07-05]\n[ro.product.manufacturer]: [Maker]\n"
                   "[ro.product.model]: [Phone 9]\n[ro.serialno]: [SECRET123]\n",
        "pm list users": ANDROID_16_USERS,
        "cmd user list -v": ANDROID_16_USER_LIST,
        "pm list packages -i -U --show-versioncode --user 0": (
            "package:com.android.settings versionCode:36  installer=null uid:1000\n"
            "package:com.spy.hidden versionCode:5  installer=com.google.android.packageinstaller uid:10200\n"
            "package:com.example.helper versionCode:2  installer=null uid:10201\n"
            "package:com.example.store versionCode:9  installer=com.android.vending uid:10202\n"
            "package:com.vendor.preloaded.watch versionCode:1  installer=null uid:10050\n"),
        "pm list packages -s --user 0": "package:com.android.settings\npackage:com.vendor.preloaded.watch\n",
        android.LAUNCHER.format(user=0): "3 activities found:\n  Activity #0:\n    com.android.settings/.Settings\n"
                                         "  Activity #1:\n    com.example.store/.Main\n"
                                         "  Activity #2:\n    com.example.helper/.Main\n",
        "settings --user 0 get secure enabled_accessibility_services":
            "com.spy.hidden/.Svc:com.example.store/com.example.store.A11y$Inner\n",
        "settings --user 0 get secure enabled_notification_listeners": "com.example.helper/.Listener\n",
        "pm list packages -i -U --show-versioncode --user 10": (
            "package:com.android.settings versionCode:36  installer=null uid:1010000\n"
            "package:com.work.mail versionCode:3  installer=com.android.vending uid:1010210\n"
            "package:com.work.mdm versionCode:4  installer=com.android.vending uid:1010100\n"),
        "pm list packages -s --user 10": "package:com.android.settings\n",
        android.LAUNCHER.format(user=10): "1 activities found:\n  Activity #0:\n    com.work.mail/.Main\n",
        "settings --user 10 get secure enabled_notification_listeners": "com.work.mail/.Listener\n",
        "dumpsys device_policy": POLICY,
    }


class DeviceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        indicators = Path(self.directory.name) / "stalkerware.stix2"
        modified = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat().replace("+00:00", "Z")
        indicators.write_text(json.dumps(bundle([("com.spy.hidden", "TheSpy", "Stalkerware application"),
                                                 ("com.vendor.preloaded.watch", "KidWatch", "Watchware application")],
                                                modified=modified)))
        self.scanner = Scanner({"android": {"adb_binary": sys.executable, "indicators_file": str(indicators)},
                                "android_devices": {"phone": "R58TEST"}})

    def run_with(self, device, operation, **kwargs):
        with patch("pc_scanner.android.find_usb_transport", return_value="3") as find, \
                patch("pc_scanner.android.run_bounded", side_effect=device):
            report = self.scanner.invoke(operation, device_alias="phone", **kwargs)
        self.assertEqual(find.call_args.args[0][1:], ["track-devices", "--proto-text"])
        self.assertEqual(find.call_args.args[1], "R58TEST")
        return report

    def test_check_finds_known_monitoring_apps_and_apps_to_review(self):
        fake = FakeDevice(answers())
        report = self.run_with(fake, "android_check")
        self.assertEqual(report["status"], "completed", report["warnings"])
        found = [(f["kind"], f["severity"], f.get("user_id"), f.get("package")) for f in report["findings"]]
        self.assertEqual(found, [
            ("monitoring_app_indicator", "high", 0, "com.spy.hidden"),
            # A system app is still matched against the indicators.
            ("monitoring_app_indicator", "medium", 0, "com.vendor.preloaded.watch"),
            ("review", "medium", 0, "com.example.helper"),
            ("review", "medium", 0, "com.spy.hidden"),
            ("outdated_patch", "medium", None, None),
        ])
        # Not reviewed: Play Store apps (com.example.store, com.work.*) and system apps with privileges.
        spy = report["findings"][0]
        self.assertEqual((spy["categories"], spy["names"], spy["is_system"], spy["installer_category"]),
                         (["stalkerware"], ["TheSpy"], False, "package_installer"))
        self.assertEqual(report["findings"][1]["categories"], ["watchware"])
        helper = report["findings"][2]
        self.assertEqual((helper["access"], helper["installer_category"], helper["has_launcher_activity"]),
                         (["notification_listener"], "unknown", True))
        self.assertEqual(report["findings"][3]["has_launcher_activity"], False)
        self.assertTrue(any("Watchware" in w for w in report["warnings"]))
        self.assertTrue(any("profile owner" in w for w in report["warnings"]))
        self.assertEqual(report["data"]["indicators"]["freshness"], "fresh")
        self.assertEqual(report["data"]["packages_checked"], 8)
        # Owner names, the serial and unselected properties never leave the device.
        text = json.dumps(report)
        for secret in ("Taro", "R58TEST", "SECRET123", "Work MDM"):
            self.assertNotIn(secret, text)

    def test_work_profile_accessibility_is_the_parents(self):
        fake = FakeDevice(answers())
        report = self.run_with(fake, "android", query_id="privileged_access")
        commands = [argv[4] for argv in fake.calls]
        self.assertNotIn("settings --user 10 get secure enabled_accessibility_services", commands)
        self.assertIn("settings --user 10 get secure enabled_notification_listeners", commands)
        self.assertEqual(report["data"]["shared_settings"],
                         [{"user_id": 10, "setting": "accessibility", "shared_with_user_id": 0}])
        entries = {(e["user_id"], e["access"], e["package"]): e for e in report["data"]["privileged_access"]}
        self.assertEqual(entries[(0, "accessibility", "com.spy.hidden")]["class"], "com.spy.hidden.Svc")
        self.assertEqual(entries[(0, "accessibility", "com.example.store")]["class"], "com.example.store.A11y$Inner")
        self.assertTrue(entries[(10, "notification_listener", "com.work.mail")]["in_package_list"])
        self.assertTrue(entries[(0, "device_admin", "com.vendor.preloaded.watch")]["is_system"])
        self.assertEqual(report["data"]["owners"][0]["package"], "com.work.mdm")
        self.assertEqual(report["status"], "completed")
        # Per-user items of a user all use that user's ID.
        for uid in (0, 10):
            self.assertIn(f"pm list packages -i -U --show-versioncode --user {uid}", commands)
            self.assertIn(android.LAUNCHER.format(user=uid), commands)

    def test_apps_list_hides_system_apps_and_keeps_facts(self):
        report = self.run_with(FakeDevice(answers()), "android", query_id="apps")
        listed = {(a["user_id"], a["package"]): a for a in report["data"]["apps"]}
        self.assertEqual(sorted(listed), [(0, "com.example.helper"), (0, "com.example.store"), (0, "com.spy.hidden"),
                                          (10, "com.work.mail"), (10, "com.work.mdm")])
        self.assertEqual(report["data"]["system_apps_hidden"], 3)
        self.assertEqual(listed[(0, "com.example.helper")]["installer_category"], "unknown")
        self.assertTrue(any("does not mean sideloaded" in w for w in report["warnings"]))
        self.assertEqual(report["findings"], [])

    def test_unread_items_are_not_treated_as_absent(self):
        broken = answers()
        broken[android.LAUNCHER.format(user=0)] = ScannerError("Engine output exceeded limits; scan was not completed")
        broken["settings --user 0 get secure enabled_notification_listeners"] = (255, "", "error")
        report = self.run_with(FakeDevice(broken), "android_check")
        self.assertEqual(report["status"], "partial")
        unread = {(u["item"], u["user_id"]) for u in report["data"]["unavailable"]}
        self.assertEqual(unread, {("launcher_activities", 0), ("notification_listeners", 0)})
        spy_review = next(f for f in report["findings"] if f["kind"] == "review" and f["package"] == "com.spy.hidden")
        self.assertIsNone(spy_review["has_launcher_activity"])
        # The helper's notification access could not be read, so it is not reviewed, and not called absent.
        self.assertFalse(any(f["kind"] == "review" and f["package"] == "com.example.helper" for f in report["findings"]))
        self.assertTrue(any("not treated as absent" in w for w in report["warnings"]))

    def test_odd_component_names_make_the_result_partial_but_are_kept(self):
        odd = answers()
        odd["settings --user 0 get secure enabled_accessibility_services"] = "com.spy.hidden/1Bad:junk-without-slash\n"
        report = self.run_with(FakeDevice(odd), "android", query_id="privileged_access")
        self.assertEqual(report["status"], "partial")
        kept = [e for e in report["data"]["privileged_access"] if e["access"] == "accessibility"]
        self.assertEqual([e["package"] for e in kept], ["com.spy.hidden"])
        self.assertEqual(report["data"]["unattributed_components"][0]["component"], "junk-without-slash")

    def test_unreadable_output_is_not_an_empty_result(self):
        cases = {
            "dumpsys device_policy": ("Can't find service: device_policy\n", {("device_admins", None)}),
            "pm list packages -i -U --show-versioncode --user 0": ("Error: java.lang.SecurityException\n",
                                                                  {("packages", 0)}),
            android.LAUNCHER.format(user=0): ("Error: unknown command\n", {("launcher_activities", 0)}),
            "pm list packages -s --user 10": ("\n", {("system_packages", 10)}),
        }
        for command, (output, unread) in cases.items():
            with self.subTest(command=command):
                device = answers()
                device[command] = output
                report = self.run_with(FakeDevice(device), "android_check")
                self.assertEqual(report["status"], "partial")
                self.assertEqual({(u["item"], u["user_id"]) for u in report["data"]["unavailable"]}, unread)
        # The user whose packages could not be read is not reported as having no monitoring apps.
        device = answers()
        device["pm list packages -i -U --show-versioncode --user 0"] = "Error: java.lang.SecurityException\n"
        report = self.run_with(FakeDevice(device), "android_check")
        self.assertFalse(any(f.get("user_id") == 0 and f["kind"] == "monitoring_app_indicator" for f in report["findings"]))
        self.assertTrue(any("not treated as absent" in w for w in report["warnings"]))

    def test_device_admin_section_missing_for_a_user(self):
        device = answers()
        device["dumpsys device_policy"] = POLICY.replace("  Enabled Device Admins (User 10, provisioningState: 3):\n"
                                                         "    com.work.mdm/com.work.mdm.Receiver:\n      uid=1010100\n", "")
        report = self.run_with(FakeDevice(device), "android", query_id="privileged_access")
        self.assertEqual(report["status"], "partial")
        self.assertIn(("device_admins", 10), {(u["item"], u["user_id"]) for u in report["data"]["unavailable"]})

    def test_nothing_read_is_an_error_not_partial(self):
        failed = {command: (1, "", "error") for command in answers()}
        self.assertEqual(self.run_with(FakeDevice(failed), "android", query_id="device")["status"], "error")
        garbage = answers()
        garbage["getprop"] = "unexpected\n"
        report = self.run_with(FakeDevice(garbage), "android", query_id="device")
        self.assertEqual(report["status"], "error")
        self.assertIn("Nothing could be read", report["error"])
        report = self.run_with(FakeDevice(failed), "android_check")
        self.assertEqual(report["status"], "error")
        # One readable item is enough for a partial result.
        one = dict(failed, getprop=answers()["getprop"])
        self.assertEqual(self.run_with(FakeDevice(one), "android_check")["status"], "partial")

    def test_malformed_indicator_file_does_not_stop_the_device_check(self):
        path = Path(self.scanner.android["indicators_file"])
        data = json.loads(path.read_text())
        data["objects"][0]["id"] = ["malware--0"]          # malware id that is not a string
        data["objects"][4]["pattern"] = 12                  # indicator pattern that is not a string
        data["objects"][5]["target_ref"] = {"id": "x"}      # relationship reference that is not a string
        data["objects"].append("not an object")
        path.write_text(json.dumps(data))
        report = self.run_with(FakeDevice(answers()), "android_check")
        self.assertEqual(report["status"], "partial")
        self.assertTrue(any("unexpected field types were ignored" in w for w in report["warnings"]))
        self.assertTrue(report["data"]["packages_checked"])
        # Whatever else the file holds, the check still runs and reports partial.
        with patch("pc_scanner.android.load_indicators", side_effect=TypeError("odd")):
            report = self.run_with(FakeDevice(answers()), "android_check")
        self.assertEqual(report["status"], "partial")
        self.assertTrue(any("could not be read as a STIX2 bundle" in w for w in report["warnings"]))

    def test_missing_or_old_indicators_make_the_check_partial(self):
        self.scanner.android["indicators_file"] = ""
        report = self.run_with(FakeDevice(answers()), "android_check")
        self.assertEqual(report["status"], "partial")
        self.assertTrue(any("No indicator file" in w for w in report["warnings"]))
        self.assertFalse(any(f["kind"] == "monitoring_app_indicator" for f in report["findings"]))

    def test_device_query(self):
        report = self.run_with(FakeDevice(answers()), "android", query_id="device")
        self.assertEqual(report["data"]["device"]["android_version"], "16")
        self.assertNotIn("ro.serialno", json.dumps(report))
        self.assertEqual([f["kind"] for f in report["findings"]], ["outdated_patch"])

    def test_cancel_stops_the_check(self):
        cancel = threading.Event()
        cancel.set()
        cancelled = answers()
        cancelled["getprop"] = ScannerError("Scan cancelled; engine stopped before completing")
        with patch("pc_scanner.android.find_usb_transport", return_value="3"), \
                patch("pc_scanner.android.run_bounded", side_effect=FakeDevice(cancelled)):
            report = self.scanner.invoke("android_check", device_alias="phone", cancel=cancel)
        self.assertEqual(report["status"], "error")
        self.assertIn("cancelled", report["error"])

    def test_unregistered_alias_and_missing_adb(self):
        report = self.scanner.invoke("android", device_alias="someone-elses-phone", query_id="device")
        self.assertIn("not registered", report["error"])
        unconfigured = Scanner({"android_devices": {"phone": "R58TEST"}})
        self.assertIn("adb_binary is not configured", unconfigured.invoke("android_check", device_alias="phone")["error"])


class SettingsTests(unittest.TestCase):
    def test_android_settings_are_known_and_checked(self):
        scanner = Scanner({"android": {"adb_binary": "", "max_patch_age_days": 30}, "android_devices": {}})
        self.assertEqual(scanner.config_warnings, [])
        self.assertTrue(any("android.adb_binary" in w for w in Scanner({"android": {"adb_bin": ""}}).config_warnings))
        for bad in ({"android": {"adb_binary": "adb"}}, {"android": {"max_indicator_age_days": 0}},
                    {"android_devices": {"my phone": "R58"}}, {"android_devices": {"phone": "two words"}}):
            with self.subTest(bad=bad), self.assertRaises(ScannerError):
                Scanner(bad)

    def test_cli_runs_android_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "scanner.toml"
            config.write_text('[android_devices]\nphone = "R58TEST"\n')
            for args in (["android", "phone", "apps"], ["android-check", "phone"]):
                with self.subTest(args=args):
                    run = subprocess.run([sys.executable, "-m", "pc_scanner.cli", "--config", str(config), *args],
                                         capture_output=True, text=True)
                    self.assertEqual(run.returncode, 2)
                    self.assertIn("adb_binary is not configured", json.loads(run.stdout)["error"])


if __name__ == "__main__":
    unittest.main()
