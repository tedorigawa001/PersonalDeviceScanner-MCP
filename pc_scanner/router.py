"""Home routers, checked without contacting them: what the owner entered, matched against published data.

The owner writes the maker, model and firmware version, and the settings seen in the router's admin
screen. Those are matched against JVN iPedia (the MyJVN API, only when the owner turned it on), the
CISA KEV catalog (a file the owner downloads) and public guidance on router settings. Nothing is sent
to the router, and the result never says a router is safe. Design: docs/router-design.md.
"""
from __future__ import annotations

import difflib
import json
import math
import re
import ssl
import threading
import time
import unicodedata
import xml.etree.ElementTree as ET
import xml.parsers.expat
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

from .core import (NoRedirect, ScannerError, TrackedHTTPSHandler, check_cancel, clean_text, fetch_bounded,
                   result)

MYJVN = "https://jvndb.jvn.jp/myjvn"
ATTRIBUTION = "MyJVN API (IPA)"
# Per request, as the API allows: overviews 50, details 10 (getVulnOverviewList / getVulnDetailInfo docs).
OVERVIEW_PAGE, DETAIL_BATCH = 50, 10
# Advisories one check handles; a model has far fewer, and the API asks for few requests.
MAX_ADVISORIES = 200
# Below the 2-3 requests a second the MyJVN FAQ allows for short collections.
REQUEST_INTERVAL = 1.0
JVN_BUDGET = 120
MAX_KEV_BYTES = 32 * 1024 * 1024
TEXT_CHARS = 500
# Makers registered in JVN iPedia (vendorId checked against the API on 2026-10-17), and the names
# other sources use for them.
MAKERS = {"buffalo": ("86", {"buffalo", "buffaloinc"}), "nec": ("89", {"nec"}),
          "iodata": ("385", {"iodata", "iodatadevice"}), "elecom": ("18753", {"elecom"})}
ROUTER_KEYS = {"jvn_lookup", "kev_file", "max_kev_age_days", "max_check_age_days"}
ENTRY_KEYS = {"maker", "model", "firmware", "jvn_cpes", "support", "checked_on", "settings"}
SUPPORT = {"supported", "ended", "unknown"}
WIFI = {"wpa3": None, "wpa2-aes": None, "wpa2-tkip": "medium", "wep": "high", "open": "high"}
# Setting, the value public guidance recommends, the severity when it is not, and the advice.
CHECKLIST = [
    ("admin_password_changed", True, "high",
     "The admin password is still the initial one; change it to a long, unique one"),
    ("auto_update", True, "medium", "Automatic firmware updates are off; turn them on, or check for updates regularly"),
    ("remote_admin", False, "medium", "Administration from the internet is on; turn it off unless you use it"),
    ("vpn_server", False, "medium", "The VPN server is on; turn it off unless you use it"),
    ("ddns", False, "medium", "DDNS is on; turn it off unless you use it"),
    ("unknown_vpn_accounts", False, "high",
     "There are VPN accounts you do not recognise; reset the router, update its firmware and set a new admin password"),
    ("upnp", False, "low", "UPnP is on; turn it off unless a device needs it"),
    ("wps", False, "low", "WPS is on; turn it off unless you use it"),
]
SETTING_KEYS = {key for key, *_ in CHECKLIST} | {"wifi_security"}
# vendor:product of a CPE 2.2 name; the part (h, o or a) is left out, as JVN mixes h and o for one model.
CPE = re.compile(r"cpe:/[aho*]?:([a-z0-9._~%-]+):([a-z0-9._~%+-]+)")
LABEL = re.compile(r"[^\x00-\x1f\x7f]{1,64}")
SEVERITIES = {"critical", "high", "medium", "low"}
NOT_FETCHED = ("limit", "deadline", "error", "inconsistent")
END_OF_LIFE = re.compile(r"end[- ]of[- ](?:life|service|support)|\beol\b|\beos\b", re.IGNORECASE)
STATIC_WARNINGS = ["Based on the maker, model and firmware version the owner entered; the router itself was not contacted",
                   "Only published vulnerabilities are matched; no finding does not prove the router is safe"]


class Stop(Exception):
    """Fetching from MyJVN ended early, for one of NOT_FETCHED."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def did_you_mean(word: str, candidates) -> str:
    guess = difflib.get_close_matches(word, sorted(candidates), n=1)
    return f"; did you mean {guess[0]!r}?" if guess else ""


def cpe_key(text: str) -> str | None:
    match = CPE.fullmatch(text.strip().lower()) if isinstance(text, str) else None
    return f"{match.group(1)}:{match.group(2)}" if match else None


def load(config: dict) -> tuple[dict, dict, list[str]]:
    """Checks [router] and [routers.<alias>]; returns the settings, the routers and warnings."""
    settings, routers = config.get("router", {}), config.get("routers", {})
    if not isinstance(settings, dict) or not isinstance(routers, dict):
        raise ScannerError("Configuration sections must be tables")
    warnings = []

    def password_hint(name: str, key: str) -> bool:
        if "pass" in key.lower() and key != "admin_password_changed":
            warnings.append(f"Unknown setting {name[:80]!r} is ignored; router passwords are never needed, "
                            "remove it from the file")
            return True
        return False

    jvn_lookup = settings.get("jvn_lookup", False)
    if type(jvn_lookup) is not bool:
        raise ScannerError("router.jvn_lookup must be true or false")
    kev_file = settings.get("kev_file", "")
    if not isinstance(kev_file, str) or (kev_file and not Path(kev_file).is_absolute()):
        raise ScannerError("router.kev_file must be an absolute path")
    ages = {}
    for key, default, top in (("max_kev_age_days", 30, 365), ("max_check_age_days", 180, 3650)):
        ages[key] = settings.get(key, default)
        if type(ages[key]) is not int or not 1 <= ages[key] <= top:
            raise ScannerError(f"router.{key} must be 1..{top}")
    loaded = {}
    for alias, entry in routers.items():
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", alias):
            raise ScannerError("Invalid router alias")
        if not isinstance(entry, dict):
            raise ScannerError("Each router must be a table")
        for key in entry:
            if key not in ENTRY_KEYS and not password_hint(f"routers.{alias}.{key}", key):
                warnings.append(f"Unknown setting {f'routers.{alias}.{key}'[:80]!r} is ignored"
                                + did_you_mean(key, ENTRY_KEYS))
        for key in ("maker", "model", "firmware"):
            if not isinstance(entry.get(key), str) or not LABEL.fullmatch(entry[key].strip()):
                raise ScannerError(f"routers.{alias}.{key} must be text of 1..64 characters")
        cpes = entry.get("jvn_cpes", [])
        if not isinstance(cpes, list) or len(cpes) > 10 or not all(cpe_key(c) for c in cpes):
            raise ScannerError(f"routers.{alias}.jvn_cpes must be up to 10 CPE names such as "
                               "'cpe:/h:buffalo_inc:wsr-0000ax'")
        support = entry.get("support", "unknown")
        if support not in SUPPORT:
            raise ScannerError(f"routers.{alias}.support must be supported, ended or unknown")
        checked_on = entry.get("checked_on")
        if checked_on is not None and (type(checked_on) is not date):
            raise ScannerError(f"routers.{alias}.checked_on must be a date such as 2026-10-17")
        answers = entry.get("settings", {})
        if not isinstance(answers, dict):
            raise ScannerError(f"routers.{alias}.settings must be a table")
        for key, value in answers.items():
            if key not in SETTING_KEYS:
                if not password_hint(f"routers.{alias}.settings.{key}", key):
                    warnings.append(f"Unknown setting {f'routers.{alias}.settings.{key}'[:80]!r} is ignored"
                                    + did_you_mean(key, SETTING_KEYS))
            elif key == "wifi_security" and value not in WIFI:
                raise ScannerError(f"routers.{alias}.settings.wifi_security must be one of {', '.join(WIFI)}")
            elif key != "wifi_security" and type(value) is not bool:
                raise ScannerError(f"routers.{alias}.settings.{key} must be true or false")
        loaded[alias] = {"maker": entry["maker"].strip(), "model": entry["model"].strip(),
                         "firmware": entry["firmware"].strip(), "cpes": list(dict.fromkeys(cpe_key(c) for c in cpes)),
                         "support": support, "checked_on": checked_on,
                         "settings": {k: v for k, v in answers.items() if k in SETTING_KEYS}}
    return {"jvn_lookup": jvn_lookup, "kev_file": kev_file, **ages}, loaded, warnings


# --- Settings the owner confirmed ------------------------------------------------------------------

def review_settings(entry: dict, max_age: int, today: date) -> tuple[list, list, list]:
    """Findings, unchecked items and warnings from what the owner saw in the admin screen."""
    findings, unchecked, warnings = [], [], []
    answers = entry["settings"]
    for key, recommended, severity, advice in CHECKLIST:
        if key not in answers:
            unchecked.append(key)
        elif answers[key] is not recommended:
            findings.append({"kind": "setting", "severity": severity, "item": key, "value": answers[key],
                             "advice": advice})
    wifi = answers.get("wifi_security")
    if wifi is None:
        unchecked.append("wifi_security")
    elif WIFI[wifi]:
        findings.append({"kind": "setting", "severity": WIFI[wifi], "item": "wifi_security", "value": wifi,
                         "advice": "Use WPA3, or WPA2 with AES, and switch off networks that use older encryption"})
    if entry["support"] == "ended":
        findings.append({"kind": "end_of_support", "severity": "high",
                         "advice": "The maker no longer fixes this model; replace it"})
    elif entry["support"] == "unknown":
        unchecked.append("support")
    checked_on = entry["checked_on"]
    if checked_on is None:
        warnings.append("When the settings were checked is not recorded (checked_on)")
    elif checked_on > today + timedelta(days=1):
        warnings.append("checked_on is in the future; record the day the settings were checked")
    elif (today - checked_on).days > max_age:
        warnings.append(f"The settings were checked {(today - checked_on).days} days ago; check them again")
    return findings, unchecked, warnings


# --- CISA KEV --------------------------------------------------------------------------------------

def normalized(text: str) -> str:
    return re.sub(r"[^0-9a-z]", "", unicodedata.normalize("NFKC", text).lower())


# Words of a KEV product: "DIR-859 and DIR-818LW Routers", "Archer C7 / Archer A7".
PRODUCT_WORDS = re.compile(r"[\s,/;()&+]+")
MODEL_WORDS = 4


def names_model(product: str, model: str) -> bool:
    """Whether the product text names the model as whole words, so "DIR-85" is not taken for "DIR-859"."""
    words = [w for w in PRODUCT_WORDS.split(unicodedata.normalize("NFKC", product).lower()) if w]
    return bool(model) and any(normalized("".join(words[start:end])) == model
                               for start in range(len(words))
                               for end in range(start + 1, min(start + MODEL_WORDS, len(words)) + 1))


def maker_names(maker: str) -> set[str]:
    return {normalized(maker)} | MAKERS.get(maker.lower(), ("", set()))[1]


def load_kev(path: str) -> tuple[dict, list, int]:
    with open(path, "rb") as f:
        data = f.read(MAX_KEV_BYTES + 1)
    if len(data) > MAX_KEV_BYTES:
        raise ValueError("too large")
    catalog = json.loads(data)
    if not isinstance(catalog, dict) or not isinstance(catalog.get("vulnerabilities"), list):
        raise ValueError("not a KEV catalog")
    entries, skipped = [], 0
    for item in catalog["vulnerabilities"]:
        if (isinstance(item, dict) and all(isinstance(item.get(k), str) for k in ("cveID", "vendorProject", "product"))
                and all(isinstance(item.get(k, ""), str) for k in ("vulnerabilityName", "shortDescription",
                                                                    "requiredAction", "notes"))):
            entries.append(item)
        else:
            skipped += 1
    return catalog, entries, skipped


def kev_matches(entry: dict, path: str, max_age: int, now: datetime) -> tuple[list, dict, list]:
    try:
        catalog, entries, skipped = load_kev(path)
    except (OSError, ValueError, TypeError, RecursionError):
        return [], {"configured": True, "loaded": False}, ["The KEV catalog could not be read; it was not matched"]
    warnings = []
    released = catalog.get("dateReleased")
    try:
        released_at = datetime.fromisoformat(released.replace("Z", "+00:00"))
        if released_at.tzinfo is None:
            released_at = released_at.replace(tzinfo=timezone.utc)
    except (AttributeError, ValueError):
        released_at = None
    if released_at is None:
        warnings.append("The KEV catalog has no release time, so its age is unknown")
    elif released_at > now + timedelta(days=1):
        warnings.append("The KEV catalog's release time is in the future")
    elif now - released_at > timedelta(days=max_age):
        age_days = math.ceil((now - released_at).total_seconds() / 8640) / 10
        warnings.append(f"The KEV catalog is {age_days} days old (limit {max_age} days); download it again")
    if skipped:
        warnings.append(f"{skipped} malformed KEV entries were skipped")
    makers, model = maker_names(entry["maker"]), normalized(entry["model"])
    findings = []
    for item in entries:
        vendors = {normalized(part) for part in re.split(r"\s+and\s+|[/,]", item["vendorProject"])}
        if not vendors & makers:
            continue
        product = item["product"]
        if names_model(product, model):
            match = "model"
        elif "multiple" in product.lower() and "router" in product.lower():
            # Only the maker's routers as a group ("Multiple Routers"); not its NAS, cameras or other products.
            match = "maker_only"
        else:
            continue
        notes = " ".join(item.get(k, "") for k in ("requiredAction", "shortDescription", "notes"))
        findings.append({
            "kind": "known_exploited", "severity": "high" if match == "model" else "medium",
            "cve": clean_text(item["cveID"], 64), "vendor": clean_text(item["vendorProject"]),
            "product": clean_text(product), "name": clean_text(item.get("vulnerabilityName", ""), TEXT_CHARS),
            "match": match, "end_of_life_noted": bool(END_OF_LIFE.search(notes)),
            "required_action": clean_text(item.get("requiredAction", ""), TEXT_CHARS),
            "advice": "Listed in CISA KEV by maker and product name only; check the maker's advisory to see "
                      "whether your firmware version is affected"})
    info = {"configured": True, "loaded": True, "catalog_version": clean_text(catalog.get("catalogVersion", ""), 64),
            "released": released_at.isoformat() if released_at else None, "matches": len(findings),
            "skipped_entries": skipped}
    return findings, info, warnings


# --- JVN iPedia through the MyJVN API ----------------------------------------------------------------

def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def descendants(element, name: str) -> list:
    return [node for node in element.iter() if local(node.tag) == name]


def child_text(element, name: str) -> str:
    for node in element:
        if local(node.tag) == name:
            return (node.text or "").strip()
    return ""


def refuse(*args) -> None:
    raise Stop("error")


def parse_xml(body: bytes):
    """No document type at all: entity declarations can only appear in one, and expanding them is an attack.

    expat reads the declaration in whatever encoding the document is in (UTF-16 included), so it
    looks for one first; searching the bytes would miss it.
    """
    scout = xml.parsers.expat.ParserCreate()
    scout.StartDoctypeDeclHandler = refuse
    try:
        scout.Parse(body, True)
        return ET.fromstring(body)
    except (xml.parsers.expat.ExpatError, ET.ParseError, RecursionError, ValueError):
        raise Stop("error") from None


class MyJVN:
    """Fixed, read-only requests to the MyJVN API, spaced out, within one deadline."""

    def __init__(self, limit: int, timeout: int, cancel: threading.Event | None, transport=None):
        self.limit, self.cancel = limit, cancel
        self.deadline = time.monotonic() + min(timeout, JVN_BUDGET)
        self.last = None
        self.transport = transport or self.https
        self.requests = 0

    def https(self, url: str, budget: int) -> bytes:
        handler = TrackedHTTPSHandler(ssl.create_default_context())
        opener = build_opener(ProxyHandler({}), handler, NoRedirect("MyJVN"))
        request = Request(url, headers={"User-Agent": "personal-device-scanner-mcp"})
        return fetch_bounded(opener, handler, request, budget, self.limit, self.cancel, service="MyJVN")

    def get(self, params: dict):
        if self.last is not None:
            wait_until = self.last + REQUEST_INTERVAL
            while time.monotonic() < wait_until:
                check_cancel(self.cancel)
                time.sleep(min(0.1, max(0.0, wait_until - time.monotonic())))
        check_cancel(self.cancel)
        remaining = self.deadline - time.monotonic()
        if remaining < 1:
            raise Stop("deadline")
        self.last = time.monotonic()
        self.requests += 1
        try:
            body = self.transport(f"{MYJVN}?{urlencode(params)}", int(remaining))
        except ScannerError:
            check_cancel(self.cancel)
            raise Stop("deadline" if time.monotonic() >= self.deadline else "error") from None
        except (OSError, URLError, ValueError):
            raise Stop("error") from None
        root = parse_xml(body)
        status = next(iter(descendants(root, "Status")), None)
        if status is None or status.get("retCd") != "0" or status.get("errCd", "") != "":
            raise Stop("error")
        try:
            counts = {key: int(status.get(key, "")) for key in ("totalRes", "totalResRet", "firstRes")}
        except ValueError:
            raise Stop("inconsistent") from None
        return root, counts


def overview_item(item) -> dict:
    severity, version = "unknown", -1.0
    for cvss in descendants(item, "cvss"):
        try:
            number = float(cvss.get("version", "0"))
        except ValueError:
            continue
        if number > version and cvss.get("severity", "").lower() in SEVERITIES:
            severity, version = cvss.get("severity").lower(), number
    link = child_text(item, "link")
    return {"id": child_text(item, "identifier"), "title": clean_text(child_text(item, "title"), TEXT_CHARS),
            "severity": severity,
            "link": link if link.startswith("https://jvndb.jvn.jp/") and len(link) < 200 else None,
            "cves": sorted({clean_text(ref.get("id", ""), 32) for ref in descendants(item, "references")
                            if ref.get("source") == "CVE"})[:20]}


def fetch_advisories(client: MyJVN, cpes: list[str]) -> tuple[dict, dict]:
    """Every advisory for the models, oldest included; what could not be fetched is counted, never dropped."""
    advisories, queries, stop = {}, [], None
    for key in cpes:
        query = {"cpe": f"cpe:/*:{key}", "total": None, "fetched": 0}
        queries.append(query)
        start = 1
        try:
            while True:
                root, counts = client.get({
                    "method": "getVulnOverviewList", "feed": "hnd", "cpeName": query["cpe"],
                    # Left out, each date defaults to the past week and old unfixed advisories are missed.
                    "rangeDatePublic": "n", "rangeDatePublished": "n", "rangeDateFirstPublished": "n",
                    "startItem": start, "maxCountItem": OVERVIEW_PAGE})
                items = [node for node in root if local(node.tag) == "item"]
                total, returned = counts["totalRes"], counts["totalResRet"]
                if query["total"] not in (None, total):
                    raise Stop("inconsistent")
                query["total"] = total
                if total == 0 and returned == 0:
                    break
                if counts["firstRes"] != start or returned != len(items) or not 0 < returned <= OVERVIEW_PAGE:
                    raise Stop("inconsistent")
                for item in items:
                    parsed = overview_item(item)
                    if not re.fullmatch(r"JVNDB-\d{4}-\d{6}", parsed["id"]):
                        raise Stop("inconsistent")
                    if parsed["id"] not in advisories:
                        if len(advisories) >= MAX_ADVISORIES:
                            raise Stop("limit")
                        advisories[parsed["id"]] = parsed
                    query["fetched"] += 1
                start += returned
                if start > total:
                    break
        except Stop as exc:
            stop = exc.reason
            break
    not_fetched = sum(max(0, (q["total"] or 0) - q["fetched"]) for q in queries)
    unqueried = len(cpes) - len(queries) + sum(1 for q in queries if q["total"] is None)
    return advisories, {"queries": queries, "not_fetched": not_fetched, "unqueried_cpes": unqueried,
                        "reason": stop}


def fetch_details(client: MyJVN, ids: list[str]) -> tuple[dict, str | None]:
    details, incomplete = {}, None
    for start in range(0, len(ids), DETAIL_BATCH):
        batch = ids[start:start + DETAIL_BATCH]
        try:
            root, counts = client.get({"method": "getVulnDetailInfo", "feed": "hnd", "vulnId": "+".join(batch)})
            infos = descendants(root, "Vulinfo")
            if counts["totalResRet"] != len(infos):
                raise Stop("inconsistent")
            for info in infos:
                vuln_id = child_text(info, "VulinfoID")
                if vuln_id not in batch:
                    raise Stop("inconsistent")
                items = [{"cpe": child_text(item, "Cpe"),
                          "versions": [(node.text or "").strip() for node in item if local(node.tag) == "VersionNumber"]}
                         for item in descendants(info, "AffectedItem")]
                severity, version = None, -1.0
                for cvss in descendants(info, "Cvss"):
                    level = next((node.text or "" for node in cvss if local(node.tag) == "Severity"), "").lower()
                    try:
                        number = float(cvss.get("version", "0"))
                    except ValueError:
                        continue
                    if number > version and level in SEVERITIES:
                        severity, version = level, number
                details[vuln_id] = {"items": items, "severity": severity}
            if not set(batch) <= set(details):
                incomplete = "inconsistent"  # the rest stay unknown; later batches are still fetched
        except Stop as exc:
            return details, exc.reason
    return details, incomplete


# Affected versions, as JVN writes them, e.g. "ファームウェア Ver.1.71より前のバージョン" or "2.30 およびそれ以前".
VERSION = r"(?:ver\.?\s*|v)?(\d+(?:\.\d+)*)"
PREFIX = re.compile(r"^(?:ファームウェア|ファームウエア|firmware)\s*", re.IGNORECASE)
RULES = [
    (re.compile(rf"^{VERSION}\s*(?:およびそれ以前|以前|and earlier|or earlier)(?:のバージョン)?$"), "le"),
    (re.compile(rf"^{VERSION}\s*(?:より前|未満)(?:のバージョン)?$"), "lt"),
    (re.compile(rf"^(?:versions?\s+)?(?:prior to|before|earlier than)\s+{VERSION}$"), "lt"),
    (re.compile(rf"^{VERSION}$"), "eq"),
]
ALL_VERSIONS = re.compile(r"^(?:すべてのバージョン|全てのバージョン|全バージョン|all versions)$")


def firmware_version(text: str) -> tuple[str, ...] | None:
    match = re.fullmatch(VERSION, unicodedata.normalize("NFKC", text).strip().lower())
    return tuple(match.group(1).split(".")) if match else None


def ordered(rule: str, left: tuple[int, ...], right: tuple[int, ...]) -> bool:
    return {"le": left <= right, "lt": left < right, "eq": left == right}[rule]


def in_range(rule: str, firmware: tuple[str, ...], bound: tuple[str, ...]) -> bool | None:
    """Compares as version numbers and as decimals; when they disagree ("2.6" and "2.55", "1.07" and "1.7"),
    the answer depends on how the maker numbers versions, so there is none."""
    width = max(len(firmware), len(bound))
    left, right = firmware + ("0",) * (width - len(firmware)), bound + ("0",) * (width - len(bound))
    as_versions = ordered(rule, tuple(map(int, left)), tuple(map(int, right)))
    digits = [max(len(a), len(b)) for a, b in zip(left, right)]
    as_decimals = ordered(rule, *(tuple(int(part if n == 0 else part.ljust(digits[n], "0")) for n, part in enumerate(side))
                                  for side in (left, right)))
    return as_versions if as_versions == as_decimals else None


def affects(text: str, firmware: tuple[str, ...]) -> bool | None:
    """Whether the firmware is in the range the text describes, or None when the text is not a known form."""
    text = PREFIX.sub("", unicodedata.normalize("NFKC", text).strip().lower()).strip()
    if ALL_VERSIONS.fullmatch(text):
        return True
    for pattern, rule in RULES:
        match = pattern.fullmatch(text)
        if match:
            return in_range(rule, firmware, tuple(match.group(1).split(".")))
    return None


def compare(firmware: str, items: list[dict], cpes: list[str]) -> dict:
    """Compares only the affected items of the owner's models: another model's range could say "not affected"."""
    matched = [item for item in items if cpe_key(item["cpe"]) in cpes]
    if not matched:
        return {"comparison": "unknown", "reason": "product_not_matched", "matched_cpe": None, "affected_versions": []}
    versions = [text for item in matched for text in item["versions"]]
    outcome = {"matched_cpe": clean_text(matched[0]["cpe"], 128),
               "affected_versions": [clean_text(text, TEXT_CHARS) for text in versions][:20]}
    own = firmware_version(firmware)
    if own is None:
        return {"comparison": "unknown", "reason": "firmware_not_parsed", **outcome}
    # An entry for the model that gives no range could cover any version, so it is never skipped.
    results = [affects(text, own) for text in versions] + [None for item in matched if not item["versions"]]
    if any(results):
        return {"comparison": "affected", **outcome}
    if not results or None in results:
        return {"comparison": "unknown", "reason": "version_not_parsed", **outcome}
    return {"comparison": "not_affected", **outcome}


def jvn_matches(entry: dict, client: MyJVN) -> tuple[list, dict, list]:
    advisories, fetched = fetch_advisories(client, entry["cpes"])
    details, detail_stop = fetch_details(client, list(advisories))
    findings, not_affected = [], []
    for vuln_id, advisory in advisories.items():
        detail = details.get(vuln_id)
        if detail is None:
            outcome = {"comparison": "unknown", "reason": "detail_missing", "matched_cpe": None, "affected_versions": []}
        else:
            outcome = compare(entry["firmware"], detail["items"], entry["cpes"])
        if outcome["comparison"] == "not_affected":
            not_affected.append(vuln_id)
            continue
        severity = (detail or {}).get("severity") or advisory["severity"]
        findings.append({"kind": "known_vulnerability", "severity": severity if severity in SEVERITIES else "unknown",
                         "id": vuln_id, "title": advisory["title"], "cves": advisory["cves"], "link": advisory["link"],
                         **outcome})
    missing = len(advisories) - len(details)
    info = {"queried": True, "attribution": ATTRIBUTION, "date_range": "all", "requests": client.requests,
            "queries": [{"cpe": q["cpe"], "total": q["total"], "fetched": q["fetched"]} for q in fetched["queries"]],
            "advisories": len(advisories), "not_fetched": fetched["not_fetched"],
            "not_fetched_reason": fetched["reason"], "unqueried_cpes": fetched["unqueried_cpes"],
            "details_missing": missing, "details_reason": detail_stop if missing else None,
            "not_affected": not_affected}
    warnings = []
    if fetched["reason"]:
        warnings.append(f"JVN lookup stopped early ({fetched['reason']}): {fetched['not_fetched']} advisories and "
                        f"{fetched['unqueried_cpes']} CPE queries were not fetched and are not counted as not affected")
    if missing:
        warnings.append(f"Details of {missing} advisories could not be fetched ({detail_stop}); "
                        "their versions were not compared")
    return findings, info, warnings


# --- The check --------------------------------------------------------------------------------------

ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def check(scanner, router_alias: str, cancel: threading.Event | None = None, transport=None) -> dict:
    if not isinstance(router_alias, str) or router_alias not in scanner.routers:
        raise ScannerError("Router alias is not registered")
    check_cancel(cancel)
    settings, entry = scanner.router_settings, scanner.routers[router_alias]
    now = datetime.now(timezone.utc)
    findings, unchecked, warnings = review_settings(entry, settings["max_check_age_days"], now.astimezone().date())
    partial = bool(unchecked or warnings)
    sources = {}
    if settings["kev_file"]:
        found, sources["kev"], kev_warnings = kev_matches(entry, settings["kev_file"], settings["max_kev_age_days"], now)
        findings += found
        warnings += kev_warnings
        partial = partial or bool(kev_warnings)
    else:
        sources["kev"] = {"configured": False}
        warnings.append("No KEV catalog is configured (router.kev_file); "
                        "actively exploited vulnerabilities were not matched")
        partial = True
    if not settings["jvn_lookup"]:
        sources["jvn"] = {"queried": False}
        warnings.append("JVN lookup is off (router.jvn_lookup); published vulnerabilities were not matched")
        partial = True
    elif not entry["cpes"]:
        sources["jvn"] = {"queried": False}
        warnings.append(f"No jvn_cpes are registered for {router_alias}; find them with router-products")
        partial = True
    else:
        found, sources["jvn"], jvn_warnings = jvn_matches(entry, MyJVN(scanner.limit, scanner.timeout, cancel, transport))
        findings += found
        warnings += jvn_warnings
        partial = partial or bool(jvn_warnings)
    if unchecked:
        warnings.append("Not confirmed by the owner: " + ", ".join(unchecked))
    findings.sort(key=lambda f: (ORDER.get(f["severity"], 4), f["kind"]))
    return result("router", "partial" if partial else "completed", findings=findings,
                  warnings=STATIC_WARNINGS + warnings,
                  data={"router_alias": router_alias, "maker": clean_text(entry["maker"]),
                        "model": clean_text(entry["model"]), "firmware": clean_text(entry["firmware"]),
                        "support": entry["support"],
                        "checked_on": entry["checked_on"].isoformat() if entry["checked_on"] else None,
                        "unchecked": unchecked, "sources": sources})


def products(scanner, maker: str, keyword: str, cancel: threading.Event | None = None, transport=None) -> dict:
    """Candidate models and their CPE names, for the owner to choose jvn_cpes; never used by the AI."""
    if not scanner.router_settings["jvn_lookup"]:
        raise ScannerError("Turn on router.jvn_lookup to look up products in JVN")
    if maker not in MAKERS:
        raise ScannerError(f"Products can be looked up for {', '.join(MAKERS)}")
    if not isinstance(keyword, str) or not LABEL.fullmatch(keyword.strip()):
        raise ScannerError("The keyword must be text of 1..64 characters")
    client = MyJVN(scanner.limit, scanner.timeout, cancel, transport)
    try:
        root, counts = client.get({"method": "getProductList", "feed": "hnd", "vendorId": MAKERS[maker][0],
                                   "keyword": keyword.strip()})
    except Stop as exc:
        raise ScannerError(f"JVN product lookup failed ({exc.reason})") from None
    found = []
    for node in descendants(root, "Product"):
        key = cpe_key(node.get("cpe", ""))
        if key:
            found.append({"name": clean_text(node.get("pname", "")), "cpe": node.get("cpe").strip().lower(),
                          "product_id": clean_text(node.get("pid", ""), 16)})
    complete = counts["totalRes"] == len(found) == counts["totalResRet"]
    return result("router", "completed" if complete else "partial", data={
        "maker": maker, "keyword": clean_text(keyword), "products": found, "attribution": ATTRIBUTION},
        warnings=[] if complete else [f"JVN reported {counts['totalRes']} products and {len(found)} were read; "
                                      "use a more specific keyword"])
