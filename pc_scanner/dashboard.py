"""The scan history as one HTML page on this PC, opened by the owner with `dashboard`.

The page runs no scripts and loads nothing: every value is escaped, and its Content Security Policy
allows only its own style sheet. The MCP server offers no tool for it, so the AI never sees it.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
import math
import unicodedata
from datetime import datetime
from pathlib import Path

from . import history
from .core import HIDDEN_CHARACTERS, clean_text, escaped

# One large result (a long app list, a full engine report) must not swamp the page.
DATA_CHARS = 50_000
CELL_CHARS = 2_000
STATUSES = {"completed", "partial", "error"}
# Worst first when pages are combined; anything unexpected ranks above an error.
STATUS_RANK = {"completed": 0, "partial": 1, "error": 2}
PAGING = ("offset", "continued", "page", "after")
# Text wider than this gets a wider column, so it is not wrapped a character at a time; a single word
# up to KEEP_CHARS (an ID, a CVE, a CPE) is kept on one line. Full-width characters count as two.
WIDE_CHARS, KEEP_CHARS = 40, 32
# A slice at least this share of the pie carries its severity and count: high and medium are close in colour.
LABEL_SHARE = 0.15
REASONS = {"off": "Details were not kept for this scan (history.details was off).",
           "removed": "Details were removed to stay within history.details_max_mb.",
           "unreadable": "The details file could not be read; it may have been damaged or edited."}

STYLE = """
:root{color-scheme:light dark;--bg:#f7f7f5;--panel:#fff;--text:#1d1d1b;--muted:#5f5f5a;--line:#deddd8;
--ok:#1f7a3d;--ok-bg:#e3f2e7;--warn:#8a5a00;--warn-bg:#fbefd5;--bad:#a8231c;--bad-bg:#fbe3e1;
--high:#9a3e0e;--high-bg:#fde8dc;--info:#2f5e9e;--info-bg:#e3ecf8;--code:#f0efeb;
--sev-critical:#d03b3b;--sev-high:#ec835a;--sev-medium:#fab219;--sev-low:#898781;--sev-unknown:#c3c2b7;
--sev-ink:#1d1d1b;--sev-unknown-ink:#1d1d1b}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--panel:#1f1f1d;--text:#ecebe6;--muted:#a3a29b;--line:#383834;
--ok:#7fd49a;--ok-bg:#1d3324;--warn:#f0c46a;--warn-bg:#3a2f16;--bad:#f2948d;--bad-bg:#3d1d1b;
--high:#f5a77e;--high-bg:#3f2417;--info:#9cbdf0;--info-bg:#1c2a40;--code:#262624;
--sev-unknown:#52514e;--sev-unknown-ink:#fff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI","Hiragino Sans","Noto Sans JP",sans-serif}
main{max-width:1120px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.15rem;margin:32px 0 12px}h3{font-size:1rem;margin:16px 0 8px}
.meta{color:var(--muted);font-size:.875rem;margin:0;overflow-wrap:anywhere}
.notice{background:var(--info-bg);color:var(--text);border-left:4px solid var(--info);padding:10px 14px;
border-radius:6px;margin:16px 0}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:.875rem}
.scroll>table{min-width:640px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:break-word}
td.time,td.op{white-space:nowrap}
th{color:var(--muted);font-weight:600;white-space:nowrap}
tr:last-child td{border-bottom:0}
a{color:var(--info)}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:.78rem;font-weight:600;white-space:nowrap}
.completed{background:var(--ok-bg);color:var(--ok)}.partial{background:var(--warn-bg);color:var(--warn)}
.error,.critical{background:var(--bad-bg);color:var(--bad)}.high{background:var(--high-bg);color:var(--high)}
.medium{background:var(--warn-bg);color:var(--warn)}
.low,.unknown,.other{background:var(--code);color:var(--muted)}
td.wide{min-width:16em}td.keep{white-space:nowrap}
h4{font-size:.875rem;margin:14px 0 6px;color:var(--muted)}
details.scan{margin:0 0 8px}
details.scan>summary{cursor:pointer;padding:10px 14px;display:flex;flex-wrap:wrap;gap:6px 14px;align-items:center}
details.scan[open]>summary{border-bottom:1px solid var(--line)}
details.scan:target{outline:2px solid var(--info)}
.time{font-variant-numeric:tabular-nums;color:var(--muted)}
.op{font-weight:600}.target{overflow-wrap:anywhere}
.body{padding:4px 14px 14px}
.callout{background:var(--bad-bg);color:var(--bad);padding:8px 12px;border-radius:6px;margin:10px 0}
.quiet{color:var(--muted)}
.retry-option{display:none}input:checked~.retry-option{display:inline}
input:focus-visible{outline:2px solid var(--info);outline-offset:2px}
ul{margin:6px 0;padding-left:20px}
pre{background:var(--code);padding:10px 12px;border-radius:6px;overflow-x:auto;font-size:.8rem;margin:6px 0}
.chart{display:flex;flex-wrap:wrap;gap:16px 32px;align-items:center;padding:16px}
svg.pie{width:200px;height:200px;flex:none}
.pie path,.pie circle{stroke:var(--panel);stroke-width:2;stroke-linejoin:round}
.pie path:hover,.pie circle:hover{opacity:.82}
.pie text{font-size:12px;font-weight:600;text-anchor:middle;fill:var(--sev-ink);pointer-events:none}
.pie text.on-critical{fill:#fff}.pie text.on-unknown{fill:var(--sev-unknown-ink)}
.s-critical{fill:var(--sev-critical);background:var(--sev-critical)}.s-high{fill:var(--sev-high);background:var(--sev-high)}
.s-medium{fill:var(--sev-medium);background:var(--sev-medium)}.s-low{fill:var(--sev-low);background:var(--sev-low)}
.s-unknown{fill:var(--sev-unknown);background:var(--sev-unknown)}
table.legend{width:auto;font-variant-numeric:tabular-nums}table.legend td{border:0;padding:3px 10px 3px 0}
.swatch{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:8px}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}td.src{font-weight:600;min-width:9em}td.target{min-width:9em}
@media (max-width:640px){main{padding:16px 16px 32px}details.scan>summary{gap:4px 10px}}
"""


def page_file(path: Path) -> Path:
    page = path.with_suffix(".html")
    return page if page != path else path.with_name(path.name + ".html")


def esc(value) -> str:
    return html.escape(clean_text(value, None), quote=True)


def shorten(text: str) -> str:
    return text if len(text) <= CELL_CHARS else text[:CELL_CHARS] + "…(truncated)"


def width(text: str) -> int:
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in text)


def fitted(lines: list[str]) -> str:
    """The class that keeps the cell readable: wide for long text, keep for short single words."""
    if max(width(line) for line in lines) > WIDE_CHARS:
        return ' class="wide"'
    if all(" " not in line and width(line) <= KEEP_CHARS for line in lines):
        return ' class="keep"'
    return ""


def cell(value) -> str:
    """One table cell; a list of strings (CVEs, affected versions) is one per line."""
    if value is None:
        return '<td><span class="quiet">—</span></td>'
    if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
        lines = [shorten(v) for v in value[:50]]
        return f"<td{fitted(lines)}>" + "<br>".join(esc(line) for line in lines) + "</td>"
    try:
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    except (ValueError, TypeError, RecursionError):
        text = "(cannot be shown)"
    text = shorten(text)
    return f"<td{fitted([text])}>{esc(text)}</td>"


def badge(value: str, known) -> str:
    # Only known names become classes; anything else is shown as text.
    return f'<span class="badge {value if value in known else "other"}">{esc(value)}</span>'


def local_time(item: dict) -> str:
    return datetime.fromisoformat(item["started_at"]).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def counts(item: dict) -> str:
    findings = item["findings"]
    if not sum(findings.values()):
        return '<span class="quiet">' + ("not checked" if item["status"] == "error" else "no findings") + "</span>"
    order = [*history.SEVERITIES, *sorted(set(findings) - set(history.SEVERITIES))]
    return " ".join(f"{badge(name, history.SEVERITIES)} {findings[name]}" for name in order if findings.get(name))


def data_block(data) -> str:
    try:
        text = json.dumps(data, ensure_ascii=False, indent=2)
    except (ValueError, TypeError, RecursionError):
        return '<p class="quiet">The data cannot be shown.</p>'
    # JSON already escapes line breaks inside strings, so the only raw ones are the layout's own.
    text = HIDDEN_CHARACTERS.sub(lambda m: m.group() if m.group() == "\n" else escaped(m), text)
    note = ""
    if len(text) > DATA_CHARS:
        text, note = text[:DATA_CHARS], f'<p class="quiet">Cut at {DATA_CHARS:,} characters.</p>'
    return f"<details><summary>Data</summary><pre>{html.escape(text)}</pre>{note}</details>"


def findings_table(findings: list) -> str:
    """One table per kind of finding, each with only its own columns."""
    rows = [finding for finding in findings if isinstance(finding, dict)]
    if not rows:
        return '<p class="quiet">No findings in this result.</p>'
    kinds = {}
    for row in rows:
        kinds.setdefault(row.get("kind") if isinstance(row.get("kind"), str) else "other", []).append(row)
    tables = []
    for kind, group in kinds.items():
        columns = ["severity"] if any("severity" in row for row in group) else []
        for row in group:
            columns += [key for key in row if key not in columns and key != "kind"]
        head = "".join(f"<th>{esc(key)}</th>" for key in columns)
        body = "".join("<tr>" + "".join(
            f"<td>{badge(row[key], history.SEVERITIES)}</td>" if key == "severity" and isinstance(row.get(key), str)
            else cell(row.get(key)) for key in columns) + "</tr>" for row in group)
        tables.append(f"<h4>{esc(kind)} ({len(group)})</h4>"
                      f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>')
    return "".join(tables)


def scan_body(item: dict, report: dict | None, reason: str) -> str:
    parts = [f'<div class="callout">Error: {esc(item["error"])}</div>'] if item["error"] else []
    parts.append(coverage_panel(item.get("coverage")))
    if report is None:
        parts.append(f'<p class="quiet">{esc(REASONS[reason])}</p>')
        return "".join(parts)
    warnings = report.get("warnings")
    if isinstance(warnings, list) and warnings:
        parts.append("<h3>Warnings</h3><ul>" + "".join(f"<li>{esc(shorten(w if isinstance(w, str) else str(w)))}</li>"
                                                     for w in warnings) + "</ul>")
    findings = report.get("findings")
    if item["operation"] in {"observe_outbound_connections", "check_connection_destinations"}:
        parts.append(connection_details(report.get("data", {})))
        return "".join(parts)
    if item["operation"] == "discover_lan_devices":
        parts.append(lan_details(report.get("data", {})))
        return "".join(parts)
    parts.append("<h3>Findings</h3>" + findings_table(findings if isinstance(findings, list) else []))
    if "data" in report:
        parts.append(coverage_selection(report["data"]))
        parts.append(data_block(report["data"]))
    return "".join(parts)


def first_page(item: dict) -> bool:
    if item["operation"] == "inventory":
        return not item["target"].get("offset")
    if item["operation"] == "vulnerabilities":
        return not item["target"].get("continued")
    return True


def page_number(item: dict) -> int | None:
    if item["operation"] == "inventory":
        return item["target"].get("offset") or 0
    if item["operation"] == "vulnerabilities":
        return item["target"].get("page")
    return None


def page_key(item: dict):
    """Which page of a paged result this is, when the history says so.

    A Wazuh page is its number and where it starts, so a forged cursor that only claims a page's number
    adds a page instead of replacing the one really fetched.
    """
    number = page_number(item)
    if item["operation"] == "vulnerabilities" and number is not None:
        return number, item["target"].get("after")
    return number


def run_label(item: dict) -> str:
    if item["operation"] == "vulnerabilities":
        return "configured agent"
    target = {key: value for key, value in item["target"].items() if key not in PAGING}
    return history.describe_target({**item, "target": target})


def latest_runs(entries: list[dict]) -> list[list[tuple[int, dict]]]:
    """The newest run of each target: a first page and the later pages fetched after it.

    Pages count together, so findings on the first page still show once a later page is fetched.
    """
    latest = {}
    best = {}
    conflicts = set()
    for index, item in enumerate(entries):
        value = item.get("coverage") if item["operation"] == "malware" else None
        if not value or not value.get("revision"):
            continue
        key = (json.dumps(item["target"], sort_keys=True), value["scan_group_id"])
        old = best.get(key)
        if old is None or value["revision"] > old[1]["coverage"]["revision"]:
            best[key] = (index, item)
            conflicts.discard(key)
        elif value["revision"] == old[1]["coverage"]["revision"]:
            if value != old[1]["coverage"] or item["findings"] != old[1]["findings"] or item["status"] != old[1]["status"]:
                conflicts.add(key)
    for index, item in enumerate(entries):
        value = item.get("coverage") if item["operation"] == "malware" else None
        if value and value.get("revision"):
            group_key = (json.dumps(item["target"], sort_keys=True), value["scan_group_id"])
            if best[group_key][0] != index:
                continue
            if group_key in conflicts:
                item = {**item, "status": "partial", "findings": {},
                        "coverage": {**value, "unresolved": {"count": 0, "quality": "unknown", "file_count": None},
                                     "by_reason": {}, "assessment_limits": ["conflicting_snapshot"]}}
        target = {key: value for key, value in item["target"].items() if key not in PAGING}
        key = (item["operation"], json.dumps(target, sort_keys=True))
        run = latest.get(key)
        if run and item["operation"] in {"observe_outbound_connections", "check_connection_destinations"}:
            # Re-reading an older observation must not replace the newer observation.
            if datetime.fromisoformat(item["started_at"]) < datetime.fromisoformat(run[-1][1]["started_at"]):
                continue
        if run and value and not value.get("revision"):
            previous = run[0][1].get("coverage")
            if previous and previous.get("revision") and previous["scan_group_id"] == value["scan_group_id"]:
                old_index, old_item = run[0]
                run[:] = [(old_index, {**old_item, "status": "partial", "coverage": {**previous,
                    "assessment_limits": sorted(set(previous["assessment_limits"] + ["unsaved_attempt"]))}})]
                continue
        if run and value and run[0][1].get("coverage"):
            previous = run[0][1]["coverage"]
            if value["group_started_at"] < previous["group_started_at"]:
                continue
        if run is None or first_page(item):
            latest[key] = [(index, item)]
            continue
        key = page_key(item)
        if key is not None:
            # The same page fetched again replaces the earlier attempt instead of counting twice.
            run[:] = [(i, page) for i, page in run if page_key(page) != key]
        elif len(run) > 1 and run[-1][1]["status"] == "error":
            # A Wazuh history line from 0.3.0 has no page number. A failed page gives no cursor,
            # so the page fetched next is that page again.
            run.pop()
        run.append((index, item))
    return sorted(latest.values(), key=lambda run: (run[0][1]["operation"], run_label(run[0][1])))


def combined(run: list[tuple[int, dict]]) -> dict:
    findings = {}
    for _, item in run:
        for name, count in item["findings"].items():
            findings[name] = findings.get(name, 0) + count
    return {"findings": findings,
            "status": max((item["status"] for _, item in run), key=lambda status: STATUS_RANK.get(status, 3))}


def run_notes(run: list[tuple[int, dict]]) -> str:
    notes = [f"{len(run)} pages"] if len(run) > 1 else []
    if not first_page(run[0][1]):
        notes.append("first page not in the shown history")
    # The furthest page says whether more remain, even when an earlier one was fetched again after it; when
    # several pages claim to be the furthest, any one saying so is enough.
    numbers = [page_number(item) for _, item in run]
    if all(number is None for number in numbers):
        more = run[-1][1]["more"]
    else:
        furthest = max(number or 0 for number in numbers)
        more = any(item["more"] for (_, item), number in zip(run, numbers) if (number or 0) == furthest)
    if more:
        notes.append("more pages remain")
    return "".join(f'<span class="quiet"> · {esc(note)}</span>' for note in notes)


def severity_totals(runs: list[list[tuple[int, dict]]]) -> dict[str, int]:
    """Findings by severity in the latest result of each target; a name the history does not know counts as unknown."""
    totals = dict.fromkeys(history.SEVERITIES, 0)
    for run in runs:
        for name, count in combined(run)["findings"].items():
            totals[name if name in totals else "unknown"] += count
    return totals


def share_text(count: int, total: int) -> str:
    share = count / total
    return "<1%" if share < 0.005 else f"{share:.0%}"


def pie(totals: dict[str, int]) -> str:
    """The severities as slices, clockwise from the top, most severe first; no script is needed to draw it."""
    total = sum(totals.values())
    center, radius = 100, 98
    shapes, labels, start = [], [], 0.0
    for name in history.SEVERITIES:
        count = totals[name]
        if not count:
            continue
        share = count / total
        end = start + share * 2 * math.pi
        tip = f"<title>{name}: {count} ({share_text(count, total)})</title>"
        if share == 1:
            shapes.append(f'<circle class="s-{name}" cx="{center}" cy="{center}" r="{radius}">{tip}</circle>')
        else:
            def point(angle):
                return f"{center + radius * math.sin(angle):.2f} {center - radius * math.cos(angle):.2f}"
            large = 1 if end - start > math.pi else 0
            shapes.append(f'<path class="s-{name}" d="M{center} {center} L{point(start)} '
                          f'A{radius} {radius} 0 {large} 1 {point(end)} Z">{tip}</path>')
        if share >= LABEL_SHARE:
            middle = (start + end) / 2 if share < 1 else 0.0
            x = center + 0.6 * radius * math.sin(middle) if share < 1 else center
            y = center - 0.6 * radius * math.cos(middle) if share < 1 else center
            labels.append(f'<text class="on-{name}" x="{x:.1f}" y="{y - 2:.1f}">{name}'
                          f'<tspan x="{x:.1f}" dy="15">{count}</tspan></text>')
        start = end
    described = ", ".join(f"{name} {totals[name]}" for name in history.SEVERITIES if totals[name])
    return (f'<svg class="pie" viewBox="0 0 200 200" role="img" aria-label="Findings by severity: {esc(described)}">'
            + "".join(shapes) + "".join(labels) + "</svg>")


def severity_section(runs: list[list[tuple[int, dict]]]) -> str:
    totals = severity_totals(runs)
    total = sum(totals.values())
    incomplete = sum(combined(run)["status"] != "completed" for run in runs)
    caveat = (f'<p class="quiet">{incomplete} of {len(runs)} latest results are partial or error, so these counts may '
              f'be incomplete.</p>' if incomplete else "")
    if total:
        legend = "".join(
            f'<tr><td><span class="swatch s-{name}"></span>{name}</td><td class="num">{totals[name]}</td>'
            f'<td class="num quiet">{share_text(totals[name], total)}</td></tr>'
            for name in history.SEVERITIES if totals[name])
        chart = (f'{pie(totals)}<div><table class="legend"><tbody>{legend}</tbody></table>'
                 f'<p class="quiet">{total} finding{"" if total == 1 else "s"} in total</p></div>')
    else:
        chart = '<p class="quiet">No findings in the latest results. This does not prove a device is safe.</p>'
    # Sources in a fixed order, so a source keeps its row from page to page; anything unexpected comes last.
    groups: dict[str, list] = {name: [] for name in dict.fromkeys(history.SOURCES.values())}
    for run in runs:
        groups.setdefault(history.source(run[-1][1]["operation"]), []).append(combined(run))
    groups = {name: results for name, results in groups.items() if results}
    head = "".join(f'<th class="num">{name}</th>' for name in history.SEVERITIES)
    rows = ""
    for name, results in groups.items():
        found = dict.fromkeys(history.SEVERITIES, 0)
        for result in results:
            for severity, count in result["findings"].items():
                found[severity if severity in found else "unknown"] += count
        cells = "".join(f'<td class="num{"" if found[s] else " quiet"}">{found[s]}</td>' for s in history.SEVERITIES)
        unfinished = sum(result["status"] != "completed" for result in results)
        rows += (f'<tr><td class="src">{esc(name)}</td><td class="num">{len(results)}</td>'
                 f'<td class="num{"" if unfinished else " quiet"}">{unfinished}</td>{cells}'
                 f'<td class="num">{sum(found.values())}</td></tr>')
    table = (f'<div class="scroll"><table><thead><tr><th>Source</th><th class="num">Targets</th>'
             f'<th class="num">Partial or error</th>{head}<th class="num">Total</th></tr></thead>'
             f'<tbody>{rows}</tbody></table></div>')
    return (f'<h2>Findings in the latest results</h2><div class="panel"><div class="chart">{chart}</div>'
            f'<div class="body">{caveat}{table}</div></div>')


def freshness_notes(run: list[tuple[int, dict]]) -> str:
    from .freshness import project
    evidence = [project(item.get('freshness_evidence')) for _, item in run]
    kept = [e for e in evidence if e is not None]
    if not kept:
        return ''
    rank = {'recent': 0, 'aged': 1, 'unknown': 2}
    notes = ['Vulnerability assessment completion: unverified',
             'Evidence checked (oldest page): ' + min(e['checked_at'] for e in kept)]
    observed = [e['index_observed_at'] for e in kept if 'index_observed_at' in e]
    if observed:
        notes.append('Index result retrieved (oldest page): ' + min(observed))
    for key, field, label in [('agent_connection', 'last_keepalive_at', 'Last communication'),
                               ('os_record', 'recorded_at', 'OS record')]:
        state = max((e[key]['state'] for e in kept), key=rank.get)
        dates = [e[key][field] for e in kept if e[key][field] is not None]
        notes.append(label + ': ' + (min(dates) if dates else 'unknown') + ' (' + state + ')')
    if len(kept) != len(evidence):
        notes.append('Some pages have no freshness evidence')
    return ''.join('<div class="quiet">' + esc(note) + '</div>' for note in notes)


def latest_row(run: list[tuple[int, dict]]) -> str:
    total, first, last = combined(run), run[0], run[-1][1]
    return (f'<tr><td class="op">{esc(last["operation"])}</td><td>{esc(history.source(last["operation"]))}</td>'
            f'<td class="target"><a href="#scan-{first[0]}">{esc(run_label(first[1]))}</a>{run_notes(run)}{freshness_notes(run)}{coverage_panel(last.get("coverage"))}</td>'
            f'<td>{badge(total["status"], STATUSES)}</td><td>{counts(total)}</td>'
            f'<td class="time">{esc(local_time(last))}</td></tr>')


def coverage_panel(value):
    from .coverage import project, LABELS
    info = project(value)
    if not info:
        return ""
    total = info["unresolved"]
    number = "unknown" if total["quality"] == "unknown" else str(total["count"])
    rows = "".join(f'<tr><td>{esc(LABELS[reason])}</td><td>{count}</td></tr>' for reason, count in info["by_reason"].items())
    attempt = info.get("attempt")
    note = (f'<div class="quiet">Selected attempt: {esc(attempt["status"])} · '
            f'{attempt["finished"]}/{attempt["selected"]} scopes returned</div>' if attempt else "")
    return (f'<div class="quiet">Unverified target scopes: {number} ({esc(total["quality"])}) · file count unknown</div>'
            + note + f'<div class="quiet">Last stop: {esc(info.get("stop_reason") or "none")}</div>'
            '<details><summary>Coverage reasons and assessment limits</summary>'
            '<p>Reasons may overlap; their sum is not a file total.</p>'
            f'<table><tbody>{rows}</tbody></table><p>{esc(", ".join(info["assessment_limits"]))}</p></details>')


def coverage_selection(data):
    from .coverage import ID, REASONS as CODES, LABELS, project
    if not isinstance(data, dict):
        return ""
    value = data.get("coverage")
    info = project(value)
    if not info or not value.get("selection_available") or not info["revision"]:
        return ""
    rows = data.get("coverage_targets")
    if not isinstance(rows, list):
        return ""
    pieces = []
    for row in rows[:100]:
        if not isinstance(row, dict) or not isinstance(row.get("target_id"), str) or not ID.fullmatch(row["target_id"]):
            continue
        reasons = row.get("reasons")
        if not isinstance(reasons, list) or not all(isinstance(r, str) and r in CODES for r in reasons):
            continue
        ident = row["target_id"]
        pieces.append(f'<label><input type="checkbox" aria-label="Select {ident}"> {ident} '
                      f'{esc("; ".join(LABELS[r] for r in reasons))}<code class="retry-option"> --target {ident}</code></label><br>')
    return ('<details><summary>Select retry targets (local CLI)</summary>'
            '<p>Saved snapshot only. Add these options to the original malware alias/path command. '
            'Run it in your terminal; this page never starts a scan. A stale revision is rejected.</p>'
            f'<pre>--retry {info["scan_group_id"]} --revision {info["revision"]}</pre>'
            + "".join(pieces) + '<p>Copy the visible --target options. Unknown or omitted details require '
            'malware-gaps in the local CLI. Cloud placeholders are only checked by metadata.</p></details>')


def lan_details(data):
    if not isinstance(data, dict):
        return '<p class="quiet">LAN details unavailable.</p>'
    rows = []
    def listing(obj, key, maximum=512):
        value = obj.get(key, [])
        return value[:maximum] if isinstance(value, list) else []
    def joined(obj, key):
        return ", ".join(str(v) for v in listing(obj, key))
    for device in listing(data, "devices"):
        if not isinstance(device, dict):
            continue
        addresses = ", ".join(str(a.get("ip", "")) + ("%" + str(a["scope"]) if a.get("scope") else "")
                              for a in listing(device, "addresses") if isinstance(a, dict))
        services = "".join(f'<li>{esc(s.get("instance", ""))} · {esc(s.get("type", ""))} · port {esc(s.get("port", ""))}</li>'
                           for s in listing(device, "services") if isinstance(s, dict))
        states = "; ".join(str(e.get("state", "")) + " · observed " + str(e.get("observed_at", ""))
                           + " · expires " + str(e.get("expires_at") or "unknown")
                           for e in listing(device, "evidence") if isinstance(e, dict))
        rows.append(f'<tr><td>{esc(addresses)}</td><td>{esc(joined(device, "names"))}</td>'
                    f'<td>{esc(device.get("mac") or "unknown")}</td><td>{esc(joined(device, "methods"))}</td>'
                    f'<td>{esc(states)}</td><td><details><summary>Advertised services</summary><ul>{services}</ul></details></td></tr>')
    return ('<p class="quiet">Observed devices only. Advertised ports were not probed; cached entries do not prove online status.</p>'
            + f'<p>Limitations: {esc(joined(data, "limitations"))}</p>'
            + ('<div class="scroll"><table><thead><tr><th>IP / scope</th><th>Names (self-reported)</th><th>MAC</th>'
               '<th>Methods</th><th>Observation evidence</th><th>Services</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>'
               if rows else '<p>No devices observed. This does not mean there are no devices.</p>'))


def lan_section(runs):
    rows = []
    for run in runs:
        index, item = run[-1]
        if item["operation"] != "discover_lan_devices":
            continue
        value = item.get("lan_observation", {})
        notes = "; ".join(k + "=" + v["status"] for k, v in value.get("methods", {}).items())
        notes += "; " + ", ".join(value.get("limitations", []))
        rows.append(f'<tr><td><a href="#scan-{index}">{esc(run_label(item))}</a></td><td>{badge(item["status"], STATUSES)}</td>'
                    f'<td>{esc(value.get("device_count", "unknown"))}</td><td>{esc(local_time(item))}</td>'
                    f'<td>{esc(value.get("stop_reason") or "—")}</td><td>{esc(notes)}</td></tr>')
    if not rows:
        return ""
    return ('<h2>Devices observed on LAN</h2><p class="quiet">Latest observation per authorized LAN; counts are not combined across runs. '
            'Check the observation time: these are saved results, not a live connection list.</p>'
            '<div class="panel scroll"><table><thead><tr><th>LAN</th><th>Status</th><th>Observed records</th>'
            '<th>Last observation</th><th>Stop reason</th><th>Methods / limitations</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>')


def connection_details(data):
    if not isinstance(data, dict):
        return '<p>Connection details unavailable.</p>'
    groups = {}
    values = data.get("connections", [])
    for row in values[:2000] if isinstance(values, list) else []:
        if not isinstance(row, dict):
            continue
        key = (str(row.get("pid")), str(row.get("process_started_at_epoch")), str(row.get("process")))
        if row.get("attribution_quality") == "unverified":
            key += (str(row.get("connection_id", len(groups))),)
        groups.setdefault(key, []).append(row)
    parts = ['<p>OS-visible socket observations only; direction and actual transmissions are unknown. '
             'Short-lived connections may be missed. No packet contents were collected.</p>']
    parts.append(destination_threat_summary(data))
    limits = data.get("limitations", [])
    parts.append('<p>Limitations: ' + esc(", ".join(str(v) for v in limits[:64]) if isinstance(limits, list) else "unknown") + '</p>')
    for key in ("sampling", "excluded_counts", "unavailable_counts"):
        counts_value = data.get(key, {})
        if isinstance(counts_value, dict):
            parts.append('<p>' + esc(key) + ': ' + esc(", ".join(
                str(k) + "=" + str(v) for k, v in list(counts_value.items())[:32])) + '</p>')
    for rows in groups.values():
        row = rows[0]
        title = str(row.get("pid") or "unknown PID") + " / " + str(row.get("process") or "unknown process")
        body = "".join('<tr>' + ''.join('<td>' + esc(r.get(k) if r.get(k) is not None else "unknown") + '</td>'
            for k in ("remote_ip", "remote_scope", "remote_port", "protocol", "classification", "attribution_quality",
                      "first_observed_at", "last_observed_at", "sample_count")) + '<td>' +
            esc(json.dumps(r.get("threat", {}), ensure_ascii=False)) + '</td></tr>' for r in rows)
        parts.append('<details><summary>' + esc(title) + '</summary><div class="scroll"><table><thead><tr>'
            '<th>Destination</th><th>Scope</th><th>Port</th><th>Protocol</th><th>Class</th><th>Attribution</th>'
            '<th>First observed</th><th>Last observed</th><th>Samples (not transmissions)</th><th>Destination list evidence</th></tr></thead><tbody>'
            + body + '</tbody></table></div></details>')
    if not groups:
        parts.append('<p>No connections observed. This does not establish absence of traffic or malware.</p>')
    return ''.join(parts)


def destination_threat_summary(data):
    from .ip_threats import summary
    value = summary(data).get("destination_threats")
    if value is None:
        return '<p>Destination threat-list summary unavailable.</p>' if "destination_threats" in data else ""
    body = '<p>' + esc(value["notice"]) + '</p><p>Historical check (UTC): ' + esc(value["checked_at"]) + ' · Coverage: ' + esc(value["coverage"]) + '</p>'
    if value["destination_counts"].get("matched"):
        body = '<p class="notice">Warning: observed destinations match public threat-list networks. Review the local evidence; this is not proof of infection.</p>' + body
    body += '<p>Unique destinations by state: ' + esc(json.dumps(value["destination_counts"], sort_keys=True)) + '</p>'
    body += '<p>Matched connection records: ' + str(value["matched_connection_records"]) + '; matched processes: ' + str(value["matched_processes"]) + '; matched records with unverified attribution: ' + str(value["matched_unattributed_records"]) + '</p>'
    for version, feed in value["feeds"].items():
        body += '<p>IPv' + version + ' source: ' + esc(feed["source"]) + ' · ' + esc(feed["copyright"]) + ' · Published: ' + esc(feed["published_at"]) + ' · Retrieved: ' + esc(feed["retrieved_at"]) + ' · Expires: ' + esc(feed["expires_at"]) + ' · Freshness at check: ' + esc(feed["freshness"]) + '</p>'
    return body + '<p>Saved observation, not a current safety verdict. Missing details require explicit local saving permission.</p>'


def connection_section(runs):
    for run in runs:
        index, item = run[-1]
        if item["operation"] not in {"observe_outbound_connections", "check_connection_destinations"}:
            continue
        value = item.get("connection_observation", {})
        return ('<h2>Connections observed on this PC</h2><p class="quiet">Latest saved observation only, not live traffic. '
                'Counts are observed records, not sessions or transmissions. History from multiple hosts is unsupported. '
                'Check the observation time; saved results become stale.</p><div class="panel">'
                f'<a href="#scan-{index}">This PC connection history</a> · {badge(item["status"], STATUSES)} · '
                f'Observed records: {esc(value.get("connection_count", "unknown"))} · '
                f'Processes with start time: {esc(value.get("process_count", "unknown"))} · '
                f'Observation: {esc(local_time(item))} · Stop reason: {esc(value.get("stop_reason") or "—")}'
                f'<p>Limitations: {esc(", ".join(value.get("limitations", [])))}</p>' + destination_threat_summary(item) + '</div>')
    return ""


def render(entries: list[dict], loaded: list[tuple[dict | None, str]], meta: dict) -> str:
    statuses = {status: sum(item["status"] == status for item in entries) for status in sorted(STATUSES)}
    summary = ", ".join(f"{name} {count}" for name, count in statuses.items())
    runs = latest_runs(entries)
    other_runs = [r for r in runs if r[-1][1]["operation"] not in {"discover_lan_devices", "observe_outbound_connections", "check_connection_destinations"}]
    latest_rows = "".join(latest_row(run) for run in other_runs)
    scans = "".join(
        f'<details class="scan panel" id="scan-{index}"><summary>'
        f'<span class="time">{esc(local_time(item))}</span>{badge(item["status"], STATUSES)}'
        f'<span class="op">{esc(item["operation"])}</span><span class="target">{esc(history.describe_target(item))}</span>'
        f'<span>{counts(item)}</span><span class="quiet">via {esc(item["via"])} · {item["seconds"]:.1f} s</span>'
        f'</summary><div class="body">{scan_body(item, *loaded[index])}</div></details>'
        for index, item in reversed(list(enumerate(entries))))
    details_note = (f"kept, up to {meta['details_mb']} MiB" if meta["details"]
                    else "not kept (turn on history.details to see findings here)")
    skipped = (f'<p class="meta">{meta["skipped"]} damaged lines in the history file were skipped.</p>'
               if meta["skipped"] else "")
    style_hash = base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode()
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'sha256-{style_hash}'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scan Dashboard</title><style>{STYLE}</style></head>
<body><main>
<h1>Personal Device Scanner</h1>
<p class="meta">Generated {esc(meta["generated"])} · {len(entries)} latest scan{"" if len(entries) == 1 else "s"} · {esc(summary)}</p>
<p class="meta">History: {esc(meta["file"])} · recording {"on" if meta["recording"] else "off"} · details {esc(details_note)}</p>
{skipped}
<div class="notice">This page holds results from this PC. Keep it to yourself. No finding does not prove a device is
safe, and <b>partial</b> or <b>error</b> means coverage was incomplete.</div>
{lan_section(runs)}
{connection_section(runs)}
{severity_section(other_runs) if other_runs else ""}
<h2>Latest result for each target</h2>
{f'<div class="panel scroll"><table><thead><tr><th>Operation</th><th>Source</th><th>Target</th><th>Status</th><th>Findings</th><th>Last scan</th></tr></thead><tbody>{latest_rows}</tbody></table></div>' if entries else '<p class="quiet">No scans recorded yet.</p>'}
<h2>Scans, newest first</h2>
{scans or '<p class="quiet">No scans recorded yet.</p>'}
</main></body></html>
"""


def write(page: Path, text: str) -> None:
    """Replaces the page in one step, private to the owner like the history it shows."""
    history.replace_private(page, text.encode("utf-8", "backslashreplace"))


def build(path: Path, limit: int, recording: bool, details: bool, details_mb: int) -> tuple[Path, int]:
    entries, skipped = history.read(path, limit)
    loaded = [history.load_details(path, item["details"]) for item in entries]
    page = page_file(path)
    page.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    write(page, render(entries, loaded, {
        "generated": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S"), "file": str(path),
        "recording": recording, "details": details, "details_mb": details_mb, "skipped": skipped}))
    return page, skipped
