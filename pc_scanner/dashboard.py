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
from .core import HIDDEN_CHARACTERS, clean_text

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
    text = HIDDEN_CHARACTERS.sub(lambda m: m.group() if m.group() == "\n" else f"\\u{ord(m.group()):04x}", text)
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
    if report is None:
        parts.append(f'<p class="quiet">{esc(REASONS[reason])}</p>')
        return "".join(parts)
    warnings = report.get("warnings")
    if isinstance(warnings, list) and warnings:
        parts.append("<h3>Warnings</h3><ul>" + "".join(f"<li>{esc(shorten(w if isinstance(w, str) else str(w)))}</li>"
                                                     for w in warnings) + "</ul>")
    findings = report.get("findings")
    parts.append("<h3>Findings</h3>" + findings_table(findings if isinstance(findings, list) else []))
    if "data" in report:
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
    for index, item in enumerate(entries):
        target = {key: value for key, value in item["target"].items() if key not in PAGING}
        key = (item["operation"], json.dumps(target, sort_keys=True))
        run = latest.get(key)
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


def latest_row(run: list[tuple[int, dict]]) -> str:
    total, first, last = combined(run), run[0], run[-1][1]
    return (f'<tr><td class="op">{esc(last["operation"])}</td><td>{esc(history.source(last["operation"]))}</td>'
            f'<td class="target"><a href="#scan-{first[0]}">{esc(run_label(first[1]))}</a>{run_notes(run)}</td>'
            f'<td>{badge(total["status"], STATUSES)}</td><td>{counts(total)}</td>'
            f'<td class="time">{esc(local_time(last))}</td></tr>')


def render(entries: list[dict], loaded: list[tuple[dict | None, str]], meta: dict) -> str:
    statuses = {status: sum(item["status"] == status for item in entries) for status in sorted(STATUSES)}
    summary = ", ".join(f"{name} {count}" for name, count in statuses.items())
    runs = latest_runs(entries)
    latest_rows = "".join(latest_row(run) for run in runs)
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
{severity_section(runs) if entries else ""}
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
