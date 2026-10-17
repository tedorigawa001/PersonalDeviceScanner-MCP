"""Home routers, checked without contacting them, against a stand-in MyJVN API and KEV catalog.

The XML follows what the real MyJVN API returned on 2026-10-17 (getVulnOverviewList, getVulnDetailInfo,
getProductList); the advisories, models and versions are invented.
"""
import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import importlib.util
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
from xml.sax.saxutils import escape

from pc_scanner import router
from pc_scanner.core import Scanner, ScannerError

TODAY = datetime.now().astimezone().date()
RSS = ('xmlns="http://purl.org/rss/1.0/" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" '
       'xmlns:sec="http://jvn.jp/rss/mod_sec/3.0/" xmlns:dcterms="http://purl.org/dc/terms/" '
       'xmlns:status="http://jvndb.jvn.jp/myjvn/Status"')
MODEL = "cpe:/h:buffalo_inc:wsr-0000ax"


def status(method, total, returned, first, ret_cd="0", err_cd=""):
    return (f'<status:Status version="3.3" method="{method}" lang="ja" retCd="{ret_cd}" retMax="50" errCd="{err_cd}" '
            f'errMsg="" totalRes="{total}" totalResRet="{returned}" firstRes="{first}" feed="hnd"/>')


class Advisory:
    def __init__(self, number, items, published=date(2017, 8, 8), severity="High", title="Example vulnerability"):
        self.id = f"JVNDB-{published.year}-{number:06d}"
        self.items, self.published, self.severity, self.title = items, published, severity, title

    def models(self):
        return {router.cpe_key(cpe) for cpe, _ in self.items}


class FakeMyJVN:
    """Answers like MyJVN: omitted dates default to the past week, at most 50 overviews and 10 details a call."""

    def __init__(self, advisories, faults=None, products=(), registered=("buffalo_inc:wsr-0000ax",)):
        self.advisories, self.faults, self.products = advisories, faults or {}, products
        self.registered = set(registered) | {key for a in advisories for key in a.models()}
        self.calls = []

    def __call__(self, url, budget):
        parts = urlsplit(url)
        assert (parts.scheme, parts.netloc, parts.path) == ("https", "jvndb.jvn.jp", "/myjvn"), url
        params = {key: values[0] for key, values in parse_qs(parts.query).items()}
        self.calls.append(params)
        fault = self.faults.get(len(self.calls))
        if isinstance(fault, BaseException):
            raise fault
        if isinstance(fault, bytes):
            return fault
        method = params["method"]
        if method == "getVulnOverviewList":
            body = self.overview(params, fault)
            if fault in ("doctype", "utf16-doctype"):
                # A well-formed answer, except that it declares an entity.
                body = body.replace("?>", '?><!DOCTYPE rdf:RDF [<!ENTITY name "Example">]>', 1)
            if fault in ("utf16", "utf16-doctype"):
                # The same answer in UTF-16, where the declaration is not a run of ASCII bytes.
                return body.replace('encoding="UTF-8"', 'encoding="UTF-16"', 1).encode("utf-16")
        elif method == "getVulnDetailInfo":
            body = self.detail(params, fault)
        else:
            body = self.product_list(params)
        return body.encode()

    def overview(self, params, fault):
        key = router.cpe_key(params["cpeName"])
        every_date = all(params.get(name) == "n" for name in
                         ("rangeDatePublic", "rangeDatePublished", "rangeDateFirstPublished"))
        found = [a for a in self.advisories if key in a.models()
                 and (every_date or (TODAY - a.published).days <= 7)]
        found.sort(key=lambda a: a.id, reverse=True)
        start, count = int(params.get("startItem", 1)), int(params.get("maxCountItem", 50))
        assert count <= 50
        page = found[start - 1:start - 1 + count]
        first = start + 1 if fault == "shift" else start
        returned = len(page) + 1 if fault == "count" else len(page)
        items = "".join(
            f'<item rdf:about="https://jvndb.jvn.jp/ja/contents/{a.published.year}/{a.id}.html">'
            f'<title>{escape(a.title)}</title><link>https://jvndb.jvn.jp/ja/contents/{a.published.year}/{a.id}.html</link>'
            f'<sec:identifier>{a.id}</sec:identifier>'
            f'<sec:references source="CVE" id="CVE-{a.published.year}-1{a.id[-4:]}">https://www.cve.org/</sec:references>'
            f'<sec:cvss score="5.0" severity="Medium" version="2.0" type="Base"/>'
            f'<sec:cvss score="8.8" severity="{a.severity}" version="3.0" type="Base"/>'
            f'<dcterms:issued>{a.published.isoformat()}T00:00:00+09:00</dcterms:issued></item>' for a in page)
        ret_cd = "1" if fault == "error" else "0"
        return (f'<?xml version="1.0" encoding="UTF-8" ?><rdf:RDF {RSS}><channel rdf:about="https://jvndb.jvn.jp/apis/myjvn">'
                f'<title>JVNDB</title></channel>{items}'
                f'{status("getVulnOverviewList", len(found), returned, first if found else 0, ret_cd)}</rdf:RDF>')

    def detail(self, params, fault):
        ids = params["vulnId"].split("+")
        assert len(ids) <= 10
        found = [a for a in self.advisories if a.id in ids]
        if fault == "drop":
            found = found[1:]
        infos = "".join(
            f'<Vulinfo><VulinfoID>{a.id}</VulinfoID><VulinfoData><Title>{escape(a.title)}</Title><Affected>'
            + "".join(f'<AffectedItem><Name>Maker</Name><ProductName>Model</ProductName>'
                      + (f'<Cpe version="2.2">{cpe}</Cpe>' if cpe else "")
                      + "".join(f"<VersionNumber>{escape(v)}</VersionNumber>" for v in versions) + "</AffectedItem>"
                      for cpe, versions in a.items)
            + f'</Affected><Impact><Cvss version="3.0"><Severity type="Base">{a.severity}</Severity></Cvss></Impact>'
            f'</VulinfoData></Vulinfo>' for a in found)
        return (f'<?xml version="1.0" encoding="UTF-8" ?><VULDEF-Document xmlns="http://jvn.jp/vuldef/" '
                f'xmlns:status="http://jvndb.jvn.jp/myjvn/Status">{infos}'
                f'{status("getVulnDetailInfo", len(found), len(found), 1)}</VULDEF-Document>')

    def product_list(self, params):
        found = self.products
        if "cpeName" in params:
            key = router.cpe_key(params["cpeName"])
            found = [("Model", f"cpe:/h:{key}", "1")] if key in self.registered else []
        products = "".join(f'<Product pname="{escape(name)}" cpe="{cpe}" pid="{pid}"/>' for name, cpe, pid in found)
        return (f'<?xml version="1.0" encoding="UTF-8" ?><Result xmlns="http://jvndb.jvn.jp/myjvn/Results" '
                f'xmlns:status="http://jvndb.jvn.jp/myjvn/Status"><VendorInfo><Vendor vname="Maker" '
                f'cpe="cpe:/:buffalo_inc" vid="{params.get("vendorId", "86")}">{products}</Vendor></VendorInfo>'
                f'{status("getProductList", len(found), len(found), 1)}</Result>')


def settings(**changes):
    answers = {"auto_update": True, "admin_password_changed": True, "remote_admin": False, "vpn_server": False,
               "ddns": False, "upnp": False, "wps": False, "wifi_security": "wpa3", "unknown_vpn_accounts": False}
    answers.update(changes)
    return {key: value for key, value in answers.items() if value is not None}


def kev_catalog(entries, released=None):
    released = released or datetime.now(timezone.utc)
    return {"title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2026.10.16",
            "dateReleased": released.isoformat().replace("+00:00", "Z"), "count": len(entries),
            "vulnerabilities": entries}


def kev_entry(vendor, product, cve="CVE-2026-0001", action="Apply mitigations per vendor instructions."):
    return {"cveID": cve, "vendorProject": vendor, "product": product, "vulnerabilityName": f"{vendor} {product} flaw",
            "dateAdded": "2026-01-01", "shortDescription": "A flaw.", "requiredAction": action,
            "dueDate": "2026-01-22", "knownRansomwareCampaignUse": "Unknown", "notes": "", "cwes": []}


class RouterTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        interval = patch.object(router, "REQUEST_INTERVAL", 0)
        interval.start()
        self.addCleanup(interval.stop)
        self.kev = self.root / "kev.json"
        self.kev.write_text(json.dumps(kev_catalog([])))

    def scanner(self, jvn=True, kev=True, **entry):
        home = {"maker": "buffalo", "model": "WSR-0000AX", "firmware": "2.50", "jvn_cpes": [MODEL],
                "support": "supported", "checked_on": TODAY, "settings": settings()}
        home.update(entry)
        return Scanner({"router": {"jvn_lookup": jvn, "kev_file": str(self.kev) if kev else ""},
                        "routers": {"home": {k: v for k, v in home.items() if v is not None}}})

    def check(self, scanner, fake):
        return router.check(scanner, "home", transport=fake)

    def jvn(self, report):
        return [f for f in report["findings"] if f["kind"] == "known_vulnerability"]

    # --- Searching every date -------------------------------------------------------------------

    def test_old_unfixed_vulnerabilities_are_found_by_searching_every_date(self):
        old = Advisory(194, [(MODEL, ["ファームウエア 2.60 およびそれ以前"])], published=date(2017, 8, 8))
        fake = FakeMyJVN([old])
        report = self.check(self.scanner(), fake)
        [finding] = self.jvn(report)
        self.assertEqual((finding["id"], finding["comparison"]), ("JVNDB-2017-000194", "affected"))
        overview = fake.calls[0]
        for name in ("rangeDatePublic", "rangeDatePublished", "rangeDateFirstPublished"):
            self.assertEqual(overview[name], "n", name)
        self.assertEqual(overview["cpeName"], "cpe:/*:buffalo_inc:wsr-0000ax")
        self.assertEqual(report["status"], "completed")
        # Without the dates the same stand-in, like MyJVN, only looks at the past week.
        self.assertEqual(fake.overview({"cpeName": overview["cpeName"]}, None).count("<item "), 0)

    # --- Fetching everything, or saying what was not fetched ------------------------------------

    def test_pages_are_followed_to_the_total(self):
        advisories = [Advisory(n, [(MODEL, ["Ver.3.00より前のバージョン"])]) for n in range(1, 121)]
        fake = FakeMyJVN(advisories)
        report = self.check(self.scanner(), fake)
        overviews = [c for c in fake.calls if c["method"] == "getVulnOverviewList"]
        self.assertEqual([c["startItem"] for c in overviews], ["1", "51", "101"])
        self.assertEqual(len([c for c in fake.calls if c["method"] == "getVulnDetailInfo"]), 12)
        jvn = report["data"]["sources"]["jvn"]
        self.assertEqual((jvn["advisories"], jvn["not_fetched"], jvn["not_fetched_reason"]), (120, 0, None))
        self.assertEqual(len(self.jvn(report)), 120)
        self.assertEqual(report["status"], "completed")

    def test_the_limit_stops_fetching_and_says_how_many_are_left(self):
        advisories = [Advisory(n, [(MODEL, ["Ver.3.00より前のバージョン"])]) for n in range(1, 261)]
        fake = FakeMyJVN(advisories)
        report = self.check(self.scanner(), fake)
        jvn = report["data"]["sources"]["jvn"]
        self.assertEqual((jvn["advisories"], jvn["not_fetched"], jvn["not_fetched_reason"]), (200, 60, "limit"))
        self.assertEqual(report["status"], "partial")
        self.assertTrue(any("60 advisories" in w and "not counted as not affected" in w for w in report["warnings"]))
        self.assertEqual(len([c for c in fake.calls if c["method"] == "getVulnDetailInfo"]), 20)

    def test_errors_and_inconsistent_pages_stop_with_a_reason(self):
        advisories = [Advisory(n, [(MODEL, ["Ver.3.00より前のバージョン"])]) for n in range(1, 61)]
        cases = {"error": {2: "error"}, "inconsistent": {2: "shift"}, "count": {2: "count"},
                 "network": {2: OSError("connection reset")}, "doctype": {2: "doctype"},
                 "utf16-doctype": {2: "utf16-doctype"}}
        expected = {"error": "error", "inconsistent": "inconsistent", "count": "inconsistent", "network": "error",
                    "doctype": "error", "utf16-doctype": "error"}
        for name, faults in cases.items():
            with self.subTest(case=name):
                report = self.check(self.scanner(), FakeMyJVN(advisories, faults))
                jvn = report["data"]["sources"]["jvn"]
                self.assertEqual(jvn["not_fetched_reason"], expected[name])
                self.assertEqual(report["status"], "partial")
                self.assertEqual((jvn["advisories"], jvn["not_fetched"]), (50, 10))
                # What was fetched is still compared; nothing unfetched is called not affected.
                self.assertEqual(len(self.jvn(report)), 50)
                self.assertEqual(jvn["not_affected"], [])

    def test_document_types_are_refused_in_any_encoding(self):
        advisories = [Advisory(n, [(MODEL, ["Ver.3.00より前のバージョン"])]) for n in range(1, 61)]
        # A well-formed UTF-16 answer is read like any other.
        report = self.check(self.scanner(), FakeMyJVN(advisories, {2: "utf16"}))
        self.assertEqual(report["data"]["sources"]["jvn"]["advisories"], 60)
        self.assertEqual(report["status"], "completed")
        for body in ('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE r [<!ENTITY e "x">]><r>&e;</r>'.encode("utf-16"),
                     '<!DOCTYPE r [<!ENTITY e "x">]><r>&e;</r>'.encode("utf-16-le"),
                     b'<!DOCTYPE r><r/>', '<?xml version="1.0" encoding="UTF-32"?><!DOCTYPE r><r/>'.encode("utf-32")):
            with self.subTest(body=body[:24]), self.assertRaises(router.Stop):
                router.parse_xml(body)

    def test_the_deadline_stops_fetching(self):
        advisories = [Advisory(n, [(MODEL, ["Ver.3.00より前のバージョン"])]) for n in range(1, 61)]
        with patch.object(router, "JVN_BUDGET", 0):
            report = self.check(self.scanner(), FakeMyJVN(advisories))
        jvn = report["data"]["sources"]["jvn"]
        self.assertEqual((jvn["not_fetched_reason"], jvn["advisories"], jvn["unqueried_cpes"]), ("deadline", 0, 1))
        self.assertEqual(report["status"], "partial")

    def test_requests_are_spaced_out(self):
        advisories = [Advisory(n, [(MODEL, ["Ver.3.00より前のバージョン"])]) for n in range(1, 61)]
        times = []
        fake = FakeMyJVN(advisories)

        def timed(url, budget):
            times.append(time.monotonic())
            return fake(url, budget)

        with patch.object(router, "REQUEST_INTERVAL", 0.2):
            self.check(self.scanner(), timed)
        self.assertEqual(len(times), 2 + 6)
        self.assertGreaterEqual(min(b - a for a, b in zip(times, times[1:])), 0.19)

    def test_a_response_cut_short_is_an_error_not_a_crash(self):
        import http.client
        report = self.check(self.scanner(), FakeMyJVN([], {1: http.client.IncompleteRead(b"partial")}))
        self.assertEqual(report["data"]["sources"]["jvn"]["not_fetched_reason"], "error")
        self.assertEqual(report["status"], "partial")

    def test_a_cpe_name_jvn_does_not_know_is_reported(self):
        # Zero advisories and an unknown CPE name look the same; only the product list tells them apart.
        fake = FakeMyJVN([], registered=())
        report = self.check(self.scanner(jvn_cpes=["cpe:/h:buffalo_inc:wsr-0000ay"]), fake)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["data"]["sources"]["jvn"]["unknown_cpes"], ["cpe:/*:buffalo_inc:wsr-0000ay"])
        self.assertTrue(any("JVN does not list cpe:/*:buffalo_inc:wsr-0000ay" in w for w in report["warnings"]))
        self.assertEqual([(c["method"], c.get("cpeName")) for c in fake.calls],
                         [("getVulnOverviewList", "cpe:/*:buffalo_inc:wsr-0000ay"),
                          ("getProductList", "cpe:/*:buffalo_inc:wsr-0000ay")])
        # A listed model without advisories is complete.
        self.assertEqual(self.check(self.scanner(), FakeMyJVN([]))["status"], "completed")

    def test_a_cpe_of_another_vendor_is_warned_about(self):
        warnings = self.scanner(jvn_cpes=["cpe:/h:buffalo:wsr-0000ax"]).config_warnings
        self.assertTrue(any("'cpe:/h:buffalo:wsr-0000ax' is not a buffalo_inc CPE name" in w for w in warnings))
        self.assertEqual(self.scanner().config_warnings, [])
        self.assertEqual(self.scanner(maker="D-Link", jvn_cpes=["cpe:/h:d-link:dir-859"]).config_warnings, [])

    def test_cancelling_ends_the_check(self):
        cancel = threading.Event()
        cancel.set()
        with self.assertRaisesRegex(ScannerError, "cancelled"):
            router.check(self.scanner(), "home", cancel, transport=FakeMyJVN([]))

    def test_advisories_without_details_stay_unknown(self):
        advisories = [Advisory(n, [(MODEL, ["Ver.3.00より前のバージョン"])]) for n in range(1, 4)]
        report = self.check(self.scanner(), FakeMyJVN(advisories, {2: "drop"}))
        self.assertEqual(report["data"]["sources"]["jvn"]["details_reason"], "inconsistent")
        outcomes = sorted((f["comparison"], f.get("reason")) for f in self.jvn(report))
        self.assertEqual(outcomes, [("affected", None), ("affected", None), ("unknown", "detail_missing")])
        self.assertEqual(report["status"], "partial")
        report = self.check(self.scanner(), FakeMyJVN(advisories, {2: OSError("reset")}))
        self.assertEqual(report["data"]["sources"]["jvn"]["details_missing"], 3)

    # --- Comparing only the owner's model ---------------------------------------------------------

    def test_versions_are_compared_only_for_the_owners_model(self):
        both = Advisory(35794, [("cpe:/o:buffalo_inc:wex-g300", ["ファームウェア Ver.1.71より前のバージョン"]),
                                ("cpe:/h:buffalo_inc:wsr-0000ax", ["ファームウェア Ver.2.55より前のバージョン"])])
        report = self.check(self.scanner(firmware="2.50"), FakeMyJVN([both]))
        [finding] = self.jvn(report)
        # The other model's range (before 1.71) would wrongly say "not affected".
        self.assertEqual((finding["comparison"], finding["matched_cpe"]), ("affected", MODEL))
        self.assertEqual(finding["affected_versions"], ["ファームウェア Ver.2.55より前のバージョン"])
        report = self.check(self.scanner(firmware="2.55"), FakeMyJVN([both]))
        self.assertEqual(self.jvn(report), [])
        self.assertEqual(report["data"]["sources"]["jvn"]["not_affected"], [both.id])

    def test_an_advisory_without_the_owners_model_is_unknown(self):
        listed = Advisory(1, [(MODEL, ["Ver.1.00"])])
        other = Advisory(2, [("cpe:/h:buffalo_inc:wsr-0000ax2", ["Ver.9.00より前のバージョン"]), (None, ["Ver.9.00"])])
        fake = FakeMyJVN([listed, other])
        # The stand-in lists the second one for the owner's model, as an imprecise index might.
        fake.advisories[1].models = lambda: {"buffalo_inc:wsr-0000ax"}
        report = self.check(self.scanner(firmware="2.50"), fake)
        unknown = [f for f in self.jvn(report) if f["id"] == other.id]
        self.assertEqual(unknown[0]["comparison"], "unknown")
        self.assertEqual(unknown[0]["reason"], "product_not_matched")
        self.assertEqual(report["data"]["sources"]["jvn"]["not_affected"], [listed.id])

    def test_hardware_and_os_parts_of_one_model_match(self):
        listed = Advisory(1, [("cpe:/o:buffalo_inc:wsr-0000ax", ["Ver.3.00 およびそれ以前"])])
        [finding] = self.jvn(self.check(self.scanner(), FakeMyJVN([listed])))
        self.assertEqual(finding["comparison"], "affected")

    def test_several_ranges_for_the_model(self):
        cases = [(["Ver.1.00より前のバージョン", "Ver.2.60より前のバージョン"], "affected"),
                 (["Ver.1.00より前のバージョン", "Ver.2.00 から Ver.2.60 まで"], "unknown"),
                 (["Ver.1.00より前のバージョン", "Ver.2.00 およびそれ以前"], "not_affected"),
                 ([], "unknown")]
        for versions, expected in cases:
            with self.subTest(versions=versions):
                outcome = router.compare("2.50", [{"cpe": MODEL, "versions": versions}], ["buffalo_inc:wsr-0000ax"])
                self.assertEqual(outcome["comparison"], expected)
        self.assertEqual(router.compare("2.50 beta", [{"cpe": MODEL, "versions": ["Ver.3.00 以前"]}],
                                        ["buffalo_inc:wsr-0000ax"])["reason"], "firmware_not_parsed")

    def test_an_entry_for_the_model_without_a_range_is_never_skipped(self):
        items = [{"cpe": MODEL, "versions": ["Ver.2.00 以前"]}, {"cpe": "cpe:/o:buffalo_inc:wsr-0000ax", "versions": []}]
        model = ["buffalo_inc:wsr-0000ax"]
        # Outside the known range, but the entry without one could cover 3.00.
        outcome = router.compare("3.00", items, model)
        self.assertEqual((outcome["comparison"], outcome["reason"]), ("unknown", "version_not_parsed"))
        # Inside a known range is still affected.
        self.assertEqual(router.compare("1.00", items, model)["comparison"], "affected")
        # Through the whole check, the advisory stays a finding instead of becoming "not affected".
        both = Advisory(1, [(MODEL, ["Ver.2.00 以前"]), ("cpe:/o:buffalo_inc:wsr-0000ax", [])])
        report = self.check(self.scanner(firmware="3.00"), FakeMyJVN([both]))
        self.assertEqual([f["comparison"] for f in self.jvn(report)], ["unknown"])
        self.assertEqual(report["data"]["sources"]["jvn"]["not_affected"], [])

    def test_version_forms(self):
        table = [("ファームウェア Ver.1.71より前のバージョン", "1.70", True), ("ファームウェア Ver.1.71より前のバージョン", "1.71", False),
                 ("ファームウエア 2.30 およびそれ以前", "2.30", True), ("ファームウエア 2.30 およびそれ以前", "2.31", False),
                 ("Ver.2.55 未満", "2.54", True), ("2.55 and earlier", "2.55", True), ("2.55 or earlier", "2.60", False),
                 # Version numbers and decimals disagree, so it depends on how the maker numbers versions.
                 ("2.55 or earlier", "2.6", None), ("Ver.1.7より前", "1.07", None), ("Ver.1.10より前", "1.9", None),
                 ("Ver.1.7 以前", "1.07", True),
                 ("prior to 1.14", "1.13", True), ("versions before 1.14", "1.14", False), ("Ver.1.00", "1.0", True),
                 ("Ver.1.00", "1.01", False), ("すべてのバージョン", "9.9", True), ("Ｖｅｒ．２．００以前", "2.00", True),
                 ("1.10 Build 20230219 以前", "1.0", None), ("Ver.2.00 から Ver.2.60 まで", "2.10", None)]
        for text, firmware, expected in table:
            with self.subTest(text=text, firmware=firmware):
                self.assertEqual(router.affects(text, router.firmware_version(firmware)), expected)
        for firmware, parsed in (("Ver.2.50", ("2", "50")), ("v2.50", ("2", "50")), ("2.50", ("2", "50")),
                                 ("2.50 (beta)", None)):
            self.assertEqual(router.firmware_version(firmware), parsed)

    # --- Settings, support and KEV ----------------------------------------------------------------

    def test_settings_against_public_guidance(self):
        scanner = self.scanner(jvn=False, settings=settings(admin_password_changed=False, auto_update=False,
                                                            remote_admin=True, upnp=True, wifi_security="wep",
                                                            unknown_vpn_accounts=True))
        report = router.check(scanner, "home")
        severities = {f["item"]: f["severity"] for f in report["findings"] if f["kind"] == "setting"}
        self.assertEqual(severities, {"admin_password_changed": "high", "auto_update": "medium", "remote_admin": "medium",
                                      "upnp": "low", "wifi_security": "high", "unknown_vpn_accounts": "high"})
        self.assertEqual(report["findings"][0]["severity"], "high")

    def test_unanswered_settings_and_support_are_unchecked_not_fine(self):
        # JVN and KEV are complete, so only the unanswered items make it partial.
        report = self.check(self.scanner(support="unknown", settings=settings(wps=None, wifi_security=None)),
                            FakeMyJVN([]))
        self.assertEqual(report["data"]["unchecked"], ["wps", "wifi_security", "support"])
        self.assertIn("Not confirmed by the owner: wps, wifi_security, support", report["warnings"])
        self.assertEqual(report["status"], "partial")
        ended = router.check(self.scanner(jvn=False, support="ended"), "home")
        self.assertEqual(ended["findings"][0]["kind"], "end_of_support")

    def test_when_the_settings_were_checked(self):
        for checked_on, expected in ((None, "not recorded"), (TODAY - timedelta(days=200), "200 days ago"),
                                     (TODAY + timedelta(days=5), "in the future")):
            with self.subTest(checked_on=checked_on):
                report = self.check(self.scanner(checked_on=checked_on), FakeMyJVN([]))
                self.assertTrue(any(expected in w for w in report["warnings"]), report["warnings"])
                self.assertEqual(report["status"], "partial")

    def test_kev_matches_by_maker_and_model_only_as_review(self):
        self.kev.write_text(json.dumps(kev_catalog([
            kev_entry("D-Link", "DIR-859 Router", "CVE-2024-0001",
                      "The impacted product is end-of-life and should be disconnected if still in use."),
            kev_entry("D-Link and TRENDnet", "Multiple Routers", "CVE-2024-0002"),
            kev_entry("D-Link", "DIR-600 Router", "CVE-2024-0003"), kev_entry("TP-Link", "DIR-859", "CVE-2024-0004"),
            {"cveID": 5}, "not an entry"])))
        report = router.check(self.scanner(jvn=False, maker="D-Link", model="DIR-859", jvn_cpes=[]), "home")
        found = {f["cve"]: f for f in report["findings"] if f["kind"] == "known_exploited"}
        self.assertEqual(set(found), {"CVE-2024-0001", "CVE-2024-0002"})
        self.assertEqual((found["CVE-2024-0001"]["match"], found["CVE-2024-0001"]["severity"]), ("model", "high"))
        self.assertTrue(found["CVE-2024-0001"]["end_of_life_noted"])
        self.assertEqual((found["CVE-2024-0002"]["match"], found["CVE-2024-0002"]["severity"]), ("maker_only", "medium"))
        self.assertEqual(report["data"]["sources"]["kev"]["skipped_entries"], 2)
        self.assertIn("2 malformed KEV entries were skipped", report["warnings"])

    def test_kev_names_the_model_as_whole_words_and_groups_only_routers(self):
        # Found in acceptance: a NAS entry joined DIR-859's results, and "DIR-85" was taken for "DIR-859".
        self.kev.write_text(json.dumps(kev_catalog([
            kev_entry("D-Link", "DIR-859 Router", "CVE-1"), kev_entry("D-Link", "Multiple NAS Devices", "CVE-2"),
            kev_entry("D-Link", "Multiple Routers", "CVE-3"), kev_entry("D-Link", "DNS-320 NAS", "CVE-4"),
            kev_entry("D-Link", "DIR-859 and DIR-818LW Routers", "CVE-5"),
            kev_entry("TP-Link", "Archer C7 / Archer A7 Routers", "CVE-6")])))

        def matches(maker, model):
            report = router.check(self.scanner(jvn=False, maker=maker, model=model, jvn_cpes=[]), "home")
            return {f["cve"]: f["match"] for f in report["findings"] if f["kind"] == "known_exploited"}

        self.assertEqual(matches("D-Link", "DIR-859"), {"CVE-1": "model", "CVE-3": "maker_only", "CVE-5": "model"})
        self.assertEqual(matches("D-Link", "DIR-85"), {"CVE-3": "maker_only"})
        self.assertEqual(matches("D-Link", "DIR859"), {"CVE-1": "model", "CVE-3": "maker_only", "CVE-5": "model"})
        self.assertEqual(matches("D-Link", "DIR-818LW"), {"CVE-3": "maker_only", "CVE-5": "model"})
        self.assertEqual(matches("D-Link", "DIR-818"), {"CVE-3": "maker_only"})
        self.assertEqual(matches("D-Link", "DIR-859L"), {"CVE-3": "maker_only"})
        self.assertEqual(matches("TP-Link", "Archer C7"), {"CVE-6": "model"})
        self.assertEqual(matches("TP-Link", "Archer C"), {})
        # Whatever the model, the maker's routers as a group remain a prompt to check.
        self.assertEqual(matches("D-Link", "DNS-320"), {"CVE-3": "maker_only", "CVE-4": "model"})

    def test_a_stale_or_unreadable_kev_catalog_makes_the_check_partial(self):
        self.kev.write_text(json.dumps(kev_catalog([], datetime.now(timezone.utc) - timedelta(days=45))))
        report = router.check(self.scanner(jvn=False), "home")
        self.assertTrue(any(w.startswith("The KEV catalog is 45.") and w.endswith("days old (limit 30 days); download it "
                                                                               "again") for w in report["warnings"]),
                        report["warnings"])
        for text in ("not json", "[" * 100000, json.dumps({"vulnerabilities": "no"})):
            with self.subTest(text=text[:20]):
                self.kev.write_text(text)
                report = router.check(self.scanner(jvn=False), "home")
                self.assertEqual(report["data"]["sources"]["kev"], {"configured": True, "loaded": False})
                self.assertEqual(report["status"], "partial")
        with patch.object(router, "MAX_KEV_BYTES", 10):
            self.kev.write_text(json.dumps(kev_catalog([])))
            self.assertFalse(router.check(self.scanner(jvn=False), "home")["data"]["sources"]["kev"]["loaded"])

    def test_age_limits_are_exact(self):
        now = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
        entry = {"maker": "x", "model": "y"}
        for age, stale in ((timedelta(days=30), False), (timedelta(days=30, microseconds=1), True),
                           (timedelta(days=29, hours=23, minutes=59), False)):
            with self.subTest(kev_age=age):
                self.kev.write_text(json.dumps(kev_catalog([], now - age)))
                warnings = router.kev_matches(entry, str(self.kev), 30, now)[2]
                self.assertEqual(any("days old" in w for w in warnings), stale, warnings)
        today = date(2026, 10, 17)
        home = {"settings": settings(), "support": "supported"}
        for days, stale in ((180, False), (181, True)):
            with self.subTest(checked_days_ago=days):
                warnings = router.review_settings({**home, "checked_on": today - timedelta(days=days)}, 180, today)[2]
                self.assertEqual(any("check them again" in w for w in warnings), stale, warnings)

    def test_turned_off_or_unregistered_sources_send_nothing(self):
        fake = FakeMyJVN([Advisory(1, [(MODEL, ["Ver.9.00"])])])
        off = self.check(self.scanner(jvn=False, kev=False), fake)
        no_cpes = self.check(self.scanner(jvn_cpes=[]), fake)
        self.assertEqual(fake.calls, [])
        self.assertTrue(any("JVN lookup is off" in w for w in off["warnings"]))
        self.assertTrue(any("No KEV catalog is configured" in w for w in off["warnings"]))
        self.assertTrue(any("find them with router-products" in w for w in no_cpes["warnings"]))
        self.assertEqual(off["status"], "partial")

    def test_a_complete_check_is_completed_but_never_called_safe(self):
        report = self.check(self.scanner(), FakeMyJVN([]))
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["findings"], [])
        self.assertTrue(any("does not prove the router is safe" in w for w in report["warnings"]))
        self.assertEqual(report["data"]["sources"]["jvn"]["attribution"], "MyJVN API (IPA)")

    def test_only_plain_jvn_links_are_kept(self):
        def link(text):
            item = router.ET.fromstring(f'<item xmlns:sec="http://jvn.jp/rss/mod_sec/3.0/"><link>{escape(text)}</link>'
                                        '<sec:identifier>JVNDB-2026-000001</sec:identifier></item>')
            return router.overview_item(item)["link"]

        kept = "https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000001.html"
        self.assertEqual(link(kept), kept)
        for text in ("https://jvndb.jvn.jp/\u202eexe", "https://jvndb.jvn.jp/a\x85b", "https://jvndb.jvn.jp/a b",
                     "https://jvndb.jvn.jp.example.com/", "http://jvndb.jvn.jp/x", "https://jvndb.jvn.jp/" + "a" * 300):
            with self.subTest(text=text[:40]):
                self.assertIsNone(link(text))

    def test_text_from_jvn_and_kev_is_cleaned(self):
        hostile = Advisory(1, [(MODEL, ["Ver.9.00より前のバージョン‮"])], title="T‮itle​")
        [finding] = self.jvn(self.check(self.scanner(), FakeMyJVN([hostile])))
        self.assertEqual(finding["title"], "T\\u202eitle\\u200b")
        self.assertEqual(finding["comparison"], "unknown")

    # --- Settings file, the AI's input and the network --------------------------------------------

    def test_settings_are_checked(self):
        bad = [{"router": {"jvn_lookup": "yes"}}, {"router": {"kev_file": "kev.json"}},
               {"router": {"max_kev_age_days": 0}}, {"routers": {"my home": {}}},
               {"routers": {"home": {"maker": "", "model": "M", "firmware": "1"}}},
               {"routers": {"home": {"maker": "m", "model": "M", "firmware": "1", "jvn_cpes": ["buffalo"]}}},
               {"routers": {"home": {"maker": "m", "model": "M", "firmware": "1", "support": "maybe"}}},
               {"routers": {"home": {"maker": "m", "model": "M", "firmware": "1", "checked_on": "2026-10-17"}}},
               {"routers": {"home": {"maker": "m", "model": "M", "firmware": "1", "settings": {"upnp": "off"}}}},
               {"routers": {"home": {"maker": "m", "model": "M", "firmware": "1",
                                     "settings": {"wifi_security": "wpa4"}}}}]
        for config in bad:
            with self.subTest(config=config), self.assertRaises(ScannerError):
                Scanner(config)
        scanner = Scanner({"routers": {"home": {"maker": "m", "model": "M", "firmware": "1", "modle": "x",
                                                 "admin_password": "secret", "settings": {"upnpp": True}}}})
        warnings = scanner.config_warnings
        self.assertTrue(any("'routers.home.modle'" in w and "did you mean 'model'?" in w for w in warnings))
        self.assertTrue(any("'routers.home.admin_password'" in w and "never needed" in w for w in warnings))
        self.assertTrue(any("did you mean 'upnp'?" in w for w in warnings))
        self.assertTrue(any("'router.jvn'" in w for w in Scanner({"router": {"jvn": True}}).config_warnings))

    def test_only_registered_aliases_are_checked(self):
        for alias in ("garage", "../home", None, 3):
            with self.subTest(alias=alias), self.assertRaises(ScannerError):
                router.check(self.scanner(), alias)
        report = self.scanner().invoke("router_check", router_alias="garage")
        self.assertEqual((report["source"], report["status"]), ("router", "error"))

    def test_requests_use_https_without_proxy_or_redirect(self):
        built = {}

        def fake_build_opener(*handlers):
            built["handlers"] = handlers
            raise OSError("stop before connecting")

        with patch.object(router, "build_opener", fake_build_opener):
            report = router.check(self.scanner(), "home")
        types = [type(h).__name__ for h in built["handlers"]]
        self.assertEqual(types, ["ProxyHandler", "TrackedHTTPSHandler", "NoRedirect"])
        self.assertEqual(built["handlers"][0].proxies, {})
        self.assertEqual(report["data"]["sources"]["jvn"]["not_fetched_reason"], "error")

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "agent extra not installed")
    def test_the_mcp_tool_says_when_it_reaches_the_internet(self):
        import asyncio
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server

        async def annotations(scanner):
            async with create_connected_server_and_client_session(create_server(scanner)) as session:
                tools = {t.name: t for t in (await session.list_tools()).tools}
                return tools["check_router"]

        on, off = asyncio.run(annotations(self.scanner())), asyncio.run(annotations(self.scanner(jvn=False)))
        self.assertTrue(on.annotations.openWorldHint)
        self.assertFalse(off.annotations.openWorldHint)
        self.assertTrue(on.annotations.readOnlyHint)
        self.assertIn("Registered router aliases: home", on.description)
        self.assertEqual(list(on.inputSchema["properties"]), ["router_alias"])

    def test_products_for_choosing_jvn_cpes(self):
        fake = FakeMyJVN([], products=[("WSR-0000AX", MODEL, "29718"), ("bad", "not a cpe", "1")])
        report = router.products(self.scanner(), "buffalo", "WSR-0000", transport=fake)
        self.assertEqual(report["data"]["products"], [{"name": "WSR-0000AX", "cpe": MODEL, "product_id": "29718"}])
        self.assertEqual(report["status"], "partial")
        self.assertEqual((fake.calls[0]["vendorId"], fake.calls[0]["keyword"]), ("86", "WSR-0000"))
        for args in (("tplink", "x"), ("buffalo", ""), ("buffalo", "a\nb")):
            with self.subTest(args=args), self.assertRaises(ScannerError):
                router.products(self.scanner(), *args, transport=fake)
        with self.assertRaisesRegex(ScannerError, "Turn on router.jvn_lookup"):
            router.products(self.scanner(jvn=False), "buffalo", "WSR", transport=fake)

    def test_the_check_is_recorded_in_the_history_and_runs_from_the_cli(self):
        history_file = self.root / "history.jsonl"
        config = self.root / "scanner.toml"
        config.write_text(f'[history]\nfile = {json.dumps(str(history_file))}\n'
                          f'[routers.home]\nmaker = "buffalo"\nmodel = "WSR-0000AX"\nfirmware = "2.50"\n'
                          f'support = "supported"\nchecked_on = {TODAY.isoformat()}\n')
        run = subprocess.run([sys.executable, "-m", "pc_scanner.cli", "--config", str(config), "router-check", "home"],
                             capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(run.returncode, 2, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual((report["source"], report["status"]), ("router", "partial"))
        [line] = history_file.read_text(encoding="utf-8").splitlines()
        self.assertEqual(json.loads(line)["target"], {"router_alias": "home"})
        products = subprocess.run([sys.executable, "-m", "pc_scanner.cli", "--config", str(config), "router-products",
                                   "buffalo", "WSR"], capture_output=True, text=True, encoding="utf-8")
        self.assertIn("Turn on router.jvn_lookup", json.loads(products.stdout)["error"])
        self.assertEqual(len(history_file.read_text(encoding="utf-8").splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
