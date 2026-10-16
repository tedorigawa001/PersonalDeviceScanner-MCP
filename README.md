# Personal Device Scanner MCP

[![CI](https://github.com/tedorigawa001/PersonalDeviceScanner-MCP/actions/workflows/ci.yml/badge.svg)](https://github.com/tedorigawa001/PersonalDeviceScanner-MCP/actions/workflows/ci.yml)

**English** | [日本語](README.ja.md)

An MCP server that lets AI agents inspect your own computer (Windows / macOS / Linux) and Android device **read-only**.
It calls well-established open-source tools (osquery, ClamAV, Wazuh, adb) and returns the results as JSON that AI agents can work with.

Formerly *Personal PC Scanner MCP*. The npm package is now `personal-device-scanner-mcp`; the old package
`personal-pc-scanner-mcp` was removed from npm on 2026-10-15, so update any configuration that uses it.
Links to the old repository name are redirected.

> [!IMPORTANT]
> This tool **does not decide that a PC is safe**.
> Zero findings can still mean incomplete coverage, outdated signatures, or missing inventory.
> Treat results as observations, and leave the final judgment to the owner of the PC.

## Contents

- [Overview](#overview)
- [How it works](#how-it-works)
- [Features](#features)
- [Requirements](#requirements)
- [Setup](#setup)
- [Configuration reference](#configuration-reference)
- [Reading the results](#reading-the-results)
- [Limitations](#limitations)
- [Safety design](#safety-design)
- [Testing](#testing)
- [Related documents and license](#related-documents-and-license)

## Overview

**What it does**

- Lists the OS version, installed applications, and listening ports (osquery)
- Scans only the folders the owner has authorized for malware (ClamAV)
- Retrieves vulnerabilities (CVEs) already detected for a device registered in Wazuh (Wazuh indexer)
- Checks your own Android device, connected over USB, for known monitoring apps (stalkerware) and apps with
  strong permissions (ADB)
- Runs all of the above as MCP tools for AI agents, or from the command line (CLI)

**What it does not do**

- Change anything: no deleting, quarantining, or repairing files (everything is read-only)
- Real-time protection, automatic isolation, or EDR functions
- Its own matching of software names against CVEs
- Bundle or update scan engines and signatures (install and update them from their official sources)

Configure only the engines you want. For example, you can use osquery and ClamAV without Wazuh.

## How it works

```text
AI client (Claude Desktop, etc.)
   │  MCP over stdio (no network port is opened)
   ▼
Personal Device Scanner (this project)
   ├─ osqueryi ............ OS, applications, listening ports
   ├─ clamscan ............ malware scan of authorized folders
   ├─ Wazuh indexer ....... existing vulnerability data for a registered device (HTTPS)
   └─ adb ................. a registered Android device connected over USB
```

The AI can only choose which fixed query to run and which authorized folder to scan.
It cannot supply arbitrary SQL, paths, executables, or connection targets.

## Features

| MCP tool | CLI command | Engine | What it does |
|---|---|---|---|
| `scanner_status()` | `status` | none | Shows what is configured. Does not check engines or PC safety |
| `collect_inventory(query_id, offset=0)` | `inventory <query_id> [--offset N]` | osqueryi | Returns one of `os_version`, `applications`, `listening_ports` |
| `scan_malware(root_alias, relative_path=".")` | `malware <root_alias> [relative_path]` | clamscan | Scans an authorized folder, or a path inside it |
| `get_vulnerabilities(cursor="")` | `vulnerabilities [--cursor C]` | Wazuh indexer | Returns vulnerabilities for the one configured device, most severe first |
| `collect_android(device_alias, query_id)` | `android <device_alias> <query_id>` | adb | Returns one of `device` (version, security patch), `apps` (installed apps and their recorded install source), `privileged_access` (accessibility, notification access, device admin) for a registered Android device |
| `check_android_monitoring_apps(device_alias)` | `android-check <device_alias>` | adb | Matches every package against known monitoring apps and lists apps worth reviewing |
| — | `history [--limit N] [--json]` | — | Shows the scan summaries recorded on this PC (see [Scan history](#scan-history)). The AI cannot read them |
| — | `dashboard [--limit N] [--no-open]` | — | Writes the scan history, with any kept details, to an HTML page on this PC and opens it (see [Dashboard](#dashboard)). The AI cannot read it |
| — | `serve` | — | Starts the MCP server |

`listening_ports` also returns the listening address (`0.0.0.0` means exposed on all interfaces, `127.0.0.1` means this PC only) and the process name.

The valid `query_id` values and the authorized folder aliases are part of the tool definitions, so the AI client knows which values it can use.

## Requirements

- **Python 3.11 or later**
- **The scan engines you want to use** (all optional)
  - [osquery](https://osquery.io/downloads/): for inventory
  - [ClamAV](https://docs.clamav.net/manual/Installing.html): for malware scans. You keep the signatures up to date yourself with `freshclam`
  - Wazuh: for vulnerabilities. **Installing the Wazuh agent on the PC is not enough.**
    You also need a Wazuh server / indexer (for example on Linux), the PC's agent registered to it, and vulnerability detection enabled
- **For MCP**: the MCP Python SDK v1 (installed with the `agent` extra below)
- **To start it with `npx` instead**: Node.js 22 or later, in addition to Python (see [Using npx](#using-npx-npm))
- **For Android**: [Android SDK Platform-Tools](https://developer.android.com/tools/releases/platform-tools) (adb; 37.0.1 or
  later is known to work) and Android 10 or later (see [Using an Android device](#using-an-android-device))

## Setup

### 1. Install the scan engines

Install the engines you want from their official sources. After installing ClamAV, run `freshclam` once to download the signatures.

Find where they are installed (you will put these paths in the configuration file):

```sh
# macOS / Linux
which osqueryi clamscan
```

```powershell
# Windows
where.exe osqueryi clamscan
```

Typical locations (they depend on how you installed them):

| OS | osqueryi | clamscan |
|---|---|---|
| Windows | `C:\Program Files\osquery\osqueryi.exe` | `C:\Program Files\ClamAV\clamscan.exe` |
| macOS | `/usr/local/bin/osqueryi` | `/opt/homebrew/bin/clamscan` (Homebrew, Apple silicon) |
| Linux | `/usr/bin/osqueryi` | `/usr/bin/clamscan` |

### 2. Install this project

macOS / Linux:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install '.[agent]'
```

Windows (PowerShell):

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install ".[agent]"
```

If you only need the CLI, you can omit `[agent]`. You can also run `python -m pc_scanner.cli` directly from the project folder without installing.

### 3. Create the configuration file

Copy `scanner.example.toml` to `scanner.toml`, then set the absolute engine paths and the folders you allow to be scanned.

```toml
[local]
osquery_binary = '/usr/local/bin/osqueryi'
clamav_binary = '/opt/homebrew/bin/clamscan'

[scan_roots]
# "alias = absolute path". The AI can only refer to folders by alias
downloads = '/Users/you/Downloads'
```

- Use **single quotes** for paths. Windows backslashes then work as is (for example `'C:\Users\you\Downloads'`).
- Leaving an engine path empty disables that engine.
- Only the owner should edit this file. Do not let the AI edit it.
- Unknown settings, such as a misspelt `[scan_root]`, are ignored but reported in `warnings` of every result
  (and on the MCP server's log at startup), with a suggestion such as "did you mean 'scan_roots'?".

### 4. Check that it works

```sh
.venv/bin/python -m pc_scanner.cli --config scanner.toml status
.venv/bin/python -m pc_scanner.cli --config scanner.toml inventory os_version
.venv/bin/python -m pc_scanner.cli --config scanner.toml malware downloads
```

On Windows, replace `.venv/bin/python` with `.venv\Scripts\python.exe`.
Results are printed as JSON (see [Reading the results](#reading-the-results)).

### 5. Register it with your AI client

Add the equivalent of the following to your MCP (stdio) client's configuration. Check your client's documentation for the exact format.

```json
{
  "mcpServers": {
    "personal-device-scanner": {
      "command": "/absolute/path/to/project/.venv/bin/python",
      "args": ["-m", "pc_scanner.cli", "--config", "/absolute/path/to/project/scanner.toml", "serve"]
    }
  }
}
```

- On Windows, set `command` to something like `C:\\path\\to\\project\\.venv\\Scripts\\python.exe` (backslashes are written as `\\` in JSON).
- Because the package was installed in step 2, you do not need to set a working directory (`cwd`).
- This project itself does not need an API key for any AI service.

### Using npx (npm)

Instead of steps 2 and 5, you can start the server with `npx`. Python 3.11 or later is still needed:
the npm package holds a small launcher, this project's Python code and the lock files, and no third-party code.

```json
{
  "mcpServers": {
    "personal-device-scanner": {
      "command": "npx",
      "args": ["-y", "personal-device-scanner-mcp@0.4.0", "--config", "/absolute/path/to/scanner.toml", "serve"]
    }
  }
}
```

- On first use, the launcher creates its own virtual environment in your cache folder and installs the Python packages there
  (macOS: `~/Library/Caches/personal-device-scanner-mcp`, Linux: `~/.cache/personal-device-scanner-mcp`,
  Windows: `%LOCALAPPDATA%\personal-device-scanner-mcp`). This can take longer than some clients wait for a server to start,
  so run `npx -y personal-device-scanner-mcp@0.4.0 setup` once beforehand.
- With CPython 3.14 on Windows x64, macOS (Intel or Apple silicon) or Linux x86_64, packages are installed with the hashes
  in the bundled lock files (`pip --require-hashes`). Other Python versions and CPUs get the same versions without hash
  checks, and the launcher says so on stderr. Its own messages and pip's output go to stderr, never to the MCP channel.
- It looks for `python3.14`, `python3.13` … `python3` (Windows: `py -3.14`, `py -3`, `python`) in the absolute folders on
  `PATH` only. It never looks in the current folder (which Windows would otherwise search first) or in relative `PATH`
  entries such as `.`, so a program named like Python in a downloads folder is not run. To choose one, set
  `PC_SCANNER_PYTHON` to its absolute path; `PC_SCANNER_CACHE_DIR` (absolute) moves the cache.
- Keep the version pinned (`@0.4.0`) so that updating is your decision. Each version and Python gets its own environment;
  old ones in the cache folder can be deleted.
- The CLI works the same way, for example `npx -y personal-device-scanner-mcp@0.4.0 --config scanner.toml status`.
- If a Windows client cannot start `npx` directly, use `"command": "cmd"` with `"args": ["/c", "npx", ...]`.

### Using Wazuh

Set the following in the `[wazuh]` section of `scanner.toml`:

```toml
[wazuh]
url = 'https://indexer.example:9200'   # HTTPS address of the indexer (not the manager API on port 55000)
agent_id = '001'                        # Device ID in Wazuh; '1' is treated as '001'
ca_file = '/path/to/root-ca.pem'        # CA certificate of the indexer
agent_name = ''                         # Optional: the agent's name in Wazuh, if it differs from this PC's host name
```

Pass the user name and password as environment variables, **never in the configuration file**:

```sh
export PC_SCANNER_WAZUH_USER='reader'
export PC_SCANNER_WAZUH_PASSWORD='...'
```

For MCP, provide them through your client's secret management or the environment that launches it.
Give the indexer account **read access only** to the target device's vulnerability index. Do not use an administrator account.

### Using an Android device

This inspects **your own** Android phone or tablet, connected to this computer with a USB cable. It only reads;
it never installs, removes or changes anything on the device. The design is in [docs/android-design.md](docs/android-design.md).

1. Install [Android SDK Platform-Tools](https://developer.android.com/tools/releases/platform-tools) from Google.
2. On the device, turn on Developer options and **USB debugging**, connect the cable, and approve this computer on the device.
3. Find the device's serial with `adb devices -l`.
4. Download the monitoring-app indicators (Echap [stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators),
   CC-BY 4.0). Update them regularly, as you do with ClamAV signatures; this tool never downloads them itself.

   ```sh
   curl -fsSL -o /absolute/path/to/stalkerware.stix2 https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/stalkerware.stix2
   ```

   On Windows, use `curl.exe` with the same arguments.
5. Add the settings:

   ```toml
   [android]
   adb_binary = '/absolute/path/to/platform-tools/adb'
   indicators_file = '/absolute/path/to/stalkerware.stix2'

   [android_devices]
   # "alias = serial". The AI can only refer to devices by alias
   my-phone = 'SERIAL'
   ```

6. Check: `.venv/bin/python -m pc_scanner.cli --config scanner.toml android-check my-phone`
7. **When you are done, turn USB debugging off** and use "Revoke USB debugging authorizations" in Developer options.
   USB debugging widens the device's attack surface.

- Only USB connections are inspected. The connection type is read from adb (`adb track-devices --proto-text`), not guessed
  from the serial, so wireless debugging and emulators are refused.
- adb starts its server (localhost:5037) on first use and leaves it running; it is shared with tools such as Android Studio,
  so this tool does not stop it. Stop it with `adb kill-server` if you want.

### Troubleshooting

- **`cryptography` fails to build**: install prebuilt packages only. This happens on Intel Macs (x86_64),
  where the latest `cryptography` has no prebuilt package and pip falls back to building from source.

  ```sh
  .venv/bin/python -m pip install --only-binary=cryptography '.[agent]'
  ```

- **You want pinned dependency versions**: `requirements-agent.lock` pins the dependencies with hashes.
  It is **for macOS x86_64 / CPython 3.14.7 only** and does not work on other environments.

  ```sh
  .venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements-agent.lock
  .venv/bin/python -m pip install --no-deps .
  ```

## Configuration reference

| Setting | Description | Default |
|---|---|---|
| `local.osquery_binary` | Absolute path to osqueryi. Empty disables it | empty |
| `local.clamav_binary` | Absolute path to clamscan. Empty disables it. `.bat` / `.cmd` files are rejected | empty |
| `local.timeout_seconds` | Time limit per operation (1–3600 seconds). For ClamAV it covers the folder check and the scan together; Wazuh uses at most 30 seconds | `600` |
| `local.max_output_bytes` | Maximum engine output (1024–8388608 bytes) | `1048576` |
| `local.max_signature_age_days` | ClamAV signatures older than this many days (1–365) make the scan `partial` | `7` |
| `scan_roots.<alias>` | A folder allowed to be scanned (absolute path). Aliases use letters, digits, `_` and `-`, up to 64 characters | none |
| `wazuh.url` | HTTPS address of the Wazuh indexer. Empty disables it | empty |
| `wazuh.agent_id` | Numeric ID of the target device | empty |
| `wazuh.ca_file` | Absolute path to the indexer's CA certificate (PEM). Empty uses the system certificates. A missing file is warned about at load; an unreadable or non-PEM file fails the Wazuh request before connecting | empty |
| `wazuh.agent_name` | The agent name expected in Wazuh (exact, ignoring case). Empty compares with this PC's host name, ignoring the domain | empty |
| Environment variables `PC_SCANNER_WAZUH_USER` / `PC_SCANNER_WAZUH_PASSWORD` | Wazuh credentials | — |
| `android.adb_binary` | Absolute path to adb (Android SDK Platform-Tools). Empty disables Android | empty |
| `android.indicators_file` | Absolute path to the monitoring-app indicators (STIX2). Empty: no matching, and the check is `partial` | empty |
| `android.max_indicator_age_days` | Indicators older than this many days (1–365), by the provider's generation time, make the check `partial` | `30` |
| `android.max_patch_age_days` | A security patch older than this many days (1–3650) is reported as `outdated_patch` | `90` |
| `android_devices.<alias>` | An Android device allowed to be inspected: its adb serial. Aliases as for `scan_roots` | none |
| `history.enabled` | Record a summary of each scan on this PC. `false` turns it off | `true` |
| `history.file` | Absolute path to the history file. Empty uses the per-user folder (see [Scan history](#scan-history)) | empty |
| `history.details` | Also keep the full result of each scan (findings, warnings, data) for the dashboard. Think first: see [Dashboard](#dashboard) | `false` |
| `history.details_max_mb` | Size limit for kept results (1–1024 MiB); the oldest are removed first | `50` |

## Reading the results

Every operation returns JSON with the same shape:

```json
{
  "schema_version": 1,
  "source": "clamav",
  "status": "partial",
  "observed_at": "2026-10-12T05:00:00+00:00",
  "findings": [{"kind": "malware", "severity": "high", "path": "sub/file.exe", "signature": "..."}],
  "warnings": ["Signature-based detection only; no detection does not prove safety"],
  "data": {"root_alias": "downloads", "unreadable_directories": ["locked"]}
}
```

`observed_at` is the time the result was collected (UTC).

### status

| status | Meaning | How to treat it |
|---|---|---|
| `completed` | The operation ran to the end | **This does not mean the PC is safe** |
| `partial` | Only part could be checked (unreadable folders, limits reached, outdated signatures, zero records, a single page, etc.) | Read `warnings`. Coverage is incomplete |
| `error` | The operation could not run (not configured, permission denied, timeout, connection failure, etc.) | Treat it as not checked |

### CLI exit codes

| Exit code | Meaning |
|---|---|
| `0` | Completed with no findings |
| `1` | Completed with findings (malware, vulnerabilities, etc.) |
| `2` | `partial` or `error` (unexpected internal errors too, still printed as JSON). **A `partial` result returns 2 even when it has findings** |

### Large results (paging)

Inventory and Wazuh results come in pages of 500. A single page, and any page after the first, is reported as `partial`.

- **Inventory**: when more rows remain, `data.next_offset` holds a number; pass it as `offset` (`--offset` in the CLI).
  The maximum `offset` is 9500.
- **Wazuh**: when more results remain, `data.next_cursor` holds a string; pass it unchanged as `cursor`
  (`--cursor` in the CLI). There is no upper limit, so more than 10,000 results can be read.
  Each page continues after the last record of the previous one, ordered by severity and then by the CVE and
  the fields Wazuh uses to identify a package, so no record is skipped or repeated at page boundaries.
  If Wazuh updates its data while you are paging, records may shift between pages. Cursors now carry the page number,
  so a cursor from 0.3.0 is refused; start again from the first page.

### Scan history

Each scan run from the CLI, or by the AI over MCP, is recorded on this PC as one summary line. `status` and
`history` are not recorded.

```sh
.venv/bin/python -m pc_scanner.cli --config scanner.toml history
```

```text
TIME                 VIA  OPERATION      STATUS     FINDINGS    SECONDS  TARGET
2026-10-15 09:12:04  mcp  malware        completed  0              41.8  downloads
2026-10-15 09:13:30  cli  android_check  partial    1 (high 1)      6.2  phone
2026-10-15 09:20:11  mcp  inventory      error      -               0.0  applications
                     error: osquery_binary is not configured or not installed
```

- **What is kept**: the start time, `cli` or `mcp`, the operation and its target (folder alias and relative path,
  `query_id`, device alias; for Wazuh only the page number, never the cursor), `status`, the number of findings per severity,
  the number of warnings, how long it took, the error message, and for paged results whether another page follows. **The findings themselves (file names, signature
  names, app and package names, CVEs) are not kept** unless you turn on `history.details` (see [Dashboard](#dashboard)).
  A paged result is one line per page, with that page's findings.
- **The AI cannot read it**: there is no MCP tool for it; only you read it with this command. `--limit N` (1–1000,
  default 20) sets how many of the latest scans are shown, and `--json` prints JSON instead of a table.
- **Where**: macOS `~/Library/Application Support/personal-device-scanner-mcp/history.jsonl`, Linux
  `~/.local/state/personal-device-scanner-mcp/history.jsonl` (or under `$XDG_STATE_HOME`), Windows
  `%LOCALAPPDATA%\personal-device-scanner-mcp\history.jsonl`. `history.file` changes it. On macOS / Linux both history
  files, `.1` included, are kept readable only by you (0600, also when one already existed with wider permissions), and a
  link in place of the file is refused.
- **Size**: when the file reaches 1 MiB it becomes `history.jsonl.1`, replacing the previous one, so roughly the latest
  several thousand scans are kept. Delete `history.jsonl` and `history.jsonl.1` to clear the history. The empty
  `history.jsonl.lock` next to them makes a CLI and MCP servers running at the same time take turns, so none of them
  rotates over another's history.
- **Turning it off**: `history.enabled = false`. The `history` command still shows what was recorded before.
- If the history cannot be written, the scan is unaffected and its result gets a warning.

### Dashboard

```sh
.venv/bin/python -m pc_scanner.cli --config scanner.toml dashboard
```

This writes `history.html` next to the history file and opens it in your browser (`--no-open` only writes it;
`--limit N`, 1–1000, default 100, sets how many of the latest scans it includes). The page lists the latest result for
each target, then every scan, newest first. Open a scan to see its warnings, findings and data.

- **Pages count together**: for inventory and Wazuh, the latest result of a target is its newest first page plus the
  later pages fetched after it. It shows the findings of all those pages, the worst `status` among them, the number of
  pages, and whether more pages remain (as the furthest page said). A page fetched again replaces the earlier fetch:
  inventory pages are told apart by offset, Wazuh pages by the page number in the cursor. History lines from 0.3.0
  have no Wazuh page number; for them, a page fetched right after a failed later page is taken as that page again,
  since a failed page gives no cursor.

- **Details are off by default.** Without them, the page shows the same summaries as `history`. To see findings, set
  `history.details = true`. From then on, the full result of each scan (as the AI received it) is kept in
  `history.jsonl.details/`, one file per scan.
- **Think before turning details on.** They hold file names, app and package names, and CVEs. In particular, if you are
  checking a phone for monitoring apps, a kept result that shows one can be seen by anyone who can use this PC,
  including whoever installed it.
- **Size**: when the kept results exceed `history.details_max_mb` (default 50 MiB), the oldest are removed first; the
  newest is always kept. The page says when a scan's details were not kept or have been removed.
- **Safe to open**: the page is one file that loads nothing and runs no scripts (its Content Security Policy allows only
  its own style sheet), and every file, app and package name is shown as text. On macOS / Linux the page and the kept
  results are readable only by you (0600, folder 0700), and links in their place are refused.
- **Not live**: run `dashboard` again after new scans. To remove the details, delete `history.html` and
  `history.jsonl.details/`.
- The AI cannot read the page or the kept results: there is no MCP tool for them.

## Limitations

### Coverage

- The application list comes only from the OS's standard sources. Portable apps, language packages, and browser extensions are not included.
- When run as a standard user, the listening ports list may miss sockets owned by other users or the system.
- Listening entries on port 0 (such as UNIX sockets) are excluded.

### ClamAV limits

| Limit | Value |
|---|---|
| File size | 100 MB |
| Total extracted size of an archive | 200 MB |
| Nested archives | 16 levels |
| Folder depth | 16 levels, counting the scanned folder itself as level 1 |

- Files over a limit are reported as `scan_limit` findings, separate from malware.
- If some folders exceed the depth limit, findings already made are kept and the result is `partial`.
- Symbolic links are not followed. Windows junctions are excluded from the folder depth check,
  but whether clamscan itself follows junctions must be verified on each environment.
- Unmaterialized iCloud/OneDrive files and directories are identified from macOS dataless flags or Windows offline/recall attributes and excluded without opening their contents.
  Exclusions produce `partial` and a warning, with `data.cloud_excluded_count` and `data.cloud_excluded_paths` (up to 20 entries).
  Downloaded files remain eligible. If exclusion arguments are too large or cannot be passed safely, no scan starts and the result is `partial`.
  ClamAV compares exclusions with only the first 512 bytes (UTF-8) of a path, so a placeholder with a longer path
  also stops the scan before it starts (`partial`), rather than letting ClamAV read and download it.
  Detection reflects metadata at preflight time; concurrent sync-state changes and providers that do not expose these attributes are outside this guarantee.
- Unreadable folders do not stop the scan. They are listed in `data.unreadable_directories` (up to 20) and the result is `partial`.
- Detections are checked against ClamAV's own summary. If its count of infected files or of errors does not match
  what was read, or a detection does not name an existing file inside the authorized folder, the result is `partial`
  and that finding has no `path`. ClamAV's counts are in `data.engine_counts`.
- A line break in a file name can make one detection read as another file's. If any name contains one, no finding
  gets a `path`, the result is `partial`, and the names are listed (escaped) in `data.line_break_names`.
- Before each scan, the signature date is read from `clamscan --version`. If the signatures are older than
  `max_signature_age_days` (7 days by default, the same point at which ClamAV itself warns) or their date is unknown,
  the scan still runs but the result is `partial` with a warning to run `freshclam`.
  The engine version, signature version, build time, and age (rounded up to 0.1 day) are in `data.signatures`.
- Unsupported formats, encrypted files, or outdated signatures may prevent detection.
- clamscan loads its signatures on every run, so a short time limit makes timeouts more likely.

### Wazuh

- It reads data **already stored** in Wazuh. The index records no scan time, so freshness cannot be verified
  (`data.freshness` stays `unverified`), and it does not tell whether the PC is currently online.
- A Wazuh request is limited to about 30 seconds in total, runs one at a time, and can be cancelled.
  An answer that trickles in or stalls is cut off within about 0.1 seconds of the limit or a cancel.
- To catch results that belong to another device, the agent name in the index is compared with this PC's host name
  (or `wazuh.agent_name`). If they differ, or the name is missing, the result is `partial` with a warning.
  The names, the expected name, and the OS recorded by Wazuh are in `data.device`.
- When the device has zero records, the result is `partial`, because a wrong device ID, an unregistered device, and a never-scanned device look the same.
  Check the device ID, name, registration, and collection time in Wazuh.

### Android

- Only USB-connected devices with Android 10 or later (tested on Android 10 and 16 emulators). Emulators and wireless
  debugging are refused because they are not USB connections.
- Matching covers only the monitoring apps in the indicator file, by package name; an app renamed or not yet listed is
  not detected. Certificate matching and MVT-style forensic checks are not done.
- `review` findings (an app from outside Google Play, or with an unknown install source, holding accessibility,
  notification access or device admin) are prompts to check, not verdicts. Device management, assistive and work apps can
  appear there. Watchware matches may be apps you or your family installed knowingly.
- Install sources are what the device recorded: `unknown` does not mean sideloaded. "No launcher activity" does not mean an
  app hides its icon.
- Everything is read per user, including work profiles. A work profile shares accessibility with its parent user, so it is
  matched with the parent's apps.
- Anything that could not be read is listed in `data.unavailable` and makes the result `partial`; it is never treated as absent.
  This includes output in an unexpected format, even when the command succeeded. If nothing at all can be read from the
  device, the result is `error`. A malformed indicator file does not stop the device check; it makes it `partial`.
- The format of `dumpsys device_policy` with an enabled device admin is taken from the AOSP source; it could not be
  reproduced on the emulators, and manufacturers may differ.
- Returned: Android version, security patch, model, package names and versions, user IDs. Not returned: the serial,
  user names, accounts, phone numbers, or any app data.
- adb trusts whatever answers on its server port (localhost:5037) on this computer. On a computer other people also
  sign in to, someone who starts a fake ADB server first could feed false results. Use it on your own computer, or run
  `adb kill-server` and then `adb start-server` yourself before the check.

### Privacy

- Passing results to a cloud AI may send application names, process IDs, file names, host names, and similar data. The PC owner decides where results go and how much is shared.
- To reduce what is sent, file paths are returned relative to the authorized folder, and absolute paths in engine output are replaced with `<alias>`.
- Text from the PC or the index (file, application and package names, engine output) is cleaned before it is returned:
  control, bidi and zero-width characters are shown as `\uXXXX`, bytes that are not UTF-8 as `\xNN`, and names are
  capped at 256 characters (paths at 1,024). osquery rows keep only the expected columns; Wazuh fields are type-checked.
- Engine output is shortened to its first and last 60 lines in total, and lines over 500 characters keep both ends (`data.engine_text_truncated` is true when anything was shortened). Findings are capped at 500, with malware listed first.

### Operating assumptions

- Run as a **standard user**, not an administrator. The tool never elevates privileges.
- The folder restriction is not an OS sandbox. It does not protect against a malicious local user swapping files.
- On a time limit, output limit, or cancellation, the engine is stopped together with every process it started
  (a process group on macOS / Linux, a job object on Windows). Processes the engine leaves behind after a normal exit are stopped too.
  A process that deliberately leaves the group (for example by starting a new session on macOS / Linux) is not stopped;
  if it keeps the engine's output open, the result is an error.
- On macOS / Linux, a SIGTERM sent to the scanner also stops the engines it is running. SIGKILL cannot be intercepted.

## Safety design

- **Fixed operations only**: the AI cannot specify SQL, paths, executables, connection targets, or device IDs.
- **Read-only**: options that delete or quarantine files are never used. All tools carry the read-only annotation (`readOnlyHint`).
  Some clients use this annotation to run tools without asking, so configure your client if you want to approve every call.
- **No shell**: engines are started directly, without a shell. Windows `.bat` / `.cmd` files are never run.
  On Windows, the scan target's path must be exactly representable in the system code page; otherwise the scan is refused
  before the engine starts, because best-fit conversion could turn a character such as U+FF02 into a quote and add options.
- **No credentials passed on**: engines receive only path-related environment variables (including Windows `USERPROFILE`, `PROGRAMDATA`, etc.).
- **Restricted network access**: Wazuh is reached over HTTPS only, and certificate verification cannot be turned off. Proxies and redirects are not used.
- **AI-facing text is untrusted**: the AI is instructed to treat file and application names in results as untrusted strings, never as instructions.
- **Android, read-only and pinned**: only fixed adb commands run, on the transport confirmed to be USB (`adb -t`). Strings
  read from the device are never put into a device command; only user and transport IDs checked to be numbers are.
- **Responsive during long scans**: scans run in a worker thread, and engines run one at a time.
  Progress is reported every 10 seconds, so clients that extend their timeout on progress can wait for long scans.
- **Stops on cancel**: when the AI client cancels a request, the running engine and the processes it started are stopped within about 0.1 seconds,
  and a scan still waiting for its turn never starts.
- **History stays on this PC**: the scan history keeps no findings unless you turn on `history.details`, and neither it nor the
  dashboard has an MCP tool, so the AI never reads them. The dashboard page runs no scripts and loads nothing.
- **Character encoding**: on Windows, engine output that is not UTF-8 is decoded with the system's default code page (cp932 on Japanese Windows).

## Testing

Run the tests with the virtual environment's Python from [step 2](#2-install-this-project).

macOS / Linux:

```sh
.venv/bin/python -m unittest discover -s tests -v
```

Windows (PowerShell):

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

- Tests use simulated engine output and Wazuh responses to check boundaries and failure handling.
- The 4 MCP tests need the `agent` extra. With a Python that does not have it, such as the system `python3`, they are skipped.
  They start a real server to check connection, tool listing, and calls, and use an in-memory connection to check responsiveness during long scans, queuing, and progress notifications.
- GitHub Actions runs the tests on Windows / macOS / Linux with Python 3.11 and 3.14 for every push to `main` and every pull request,
  installing the `agent` extra so MCP tests are never skipped. It also builds the wheel and sdist and checks that
  the third-party notices and SBOM files are included. On Windows, real junctions and ACL-denied folders
  (including a junction like `Documents\My Music`) are created to verify how scans handle them.
- Android tests (`tests/test_android.py`) use output recorded from Android 10 and 16 emulators (with synthetic names):
  the USB check against a real streaming process, the parsers, indicator freshness, work profiles, and items that could
  not be read. The same code was also run against the emulators ([record](docs/acceptance/android-emulator-2026-10-14.json)).
- The npm launcher has its own tests (Node.js 22 or later): `node --test npm/test/launcher.test.js npm/test/roundtrip.test.js`.
  With `PC_SCANNER_NPM_E2E=1` (it installs packages from PyPI), the package is packed and installed as a user gets it,
  sets itself up on the first `serve` and answers MCP; the test also checks that stdout carries only MCP messages,
  that a wrong hash in the lock stops the setup, that modules planted in the current folder are not imported,
  and (macOS / Linux) that SIGTERM to the launcher stops the server. CI runs this on every OS with Python 3.11 and 3.14.
- Detection accuracy with real engines and behavior on each OS are not guaranteed. Acceptance testing on real machines for each OS is required before distribution.

## Related documents and license

These documents are in Japanese.

- [docs/backlog.md](docs/backlog.md): open issues and items to verify on real machines
- [docs/licensing.md](docs/licensing.md): license policy and pre-distribution checks
- [docs/compliance.md](docs/compliance.md): scope of the SBOM and third-party notices, and how to regenerate them
- [docs/releasing.md](docs/releasing.md): how the npm package is released (staged publishing from GitHub Actions, in Japanese)
- [profiles/](profiles/): the lock, SBOM and notices for Windows, Linux and macOS arm64 (the root holds the macOS x86_64 reference)
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and the [CycloneDX SBOM](sbom/python-agent.cdx.json): notices for the Python dependencies used for MCP

This project's own code is licensed under the [MIT License](LICENSE) (Copyright (c) 2026 tedorigawa001);
the reasoning is in [docs/license-recommendation.md](docs/license-recommendation.md). Third-party components keep their own licenses.
This repository does not contain any Wazuh, osquery, or ClamAV code, binaries, rules, or signatures.
