# Personal PC Scanner MCP

[![CI](https://github.com/tedorigawa001/PersonalPCScannerMCP/actions/workflows/ci.yml/badge.svg)](https://github.com/tedorigawa001/PersonalPCScannerMCP/actions/workflows/ci.yml)

**English** | [日本語](README.ja.md)

An MCP server that lets AI agents inspect a personal computer (Windows / macOS / Linux) **read-only**.
It calls well-established open-source tools (osquery, ClamAV, Wazuh) and returns the results as JSON that AI agents can work with.

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
Personal PC Scanner (this project)
   ├─ osqueryi ............ OS, applications, listening ports
   ├─ clamscan ............ malware scan of authorized folders
   └─ Wazuh indexer ....... existing vulnerability data for a registered device (HTTPS)
```

The AI can only choose which fixed query to run and which authorized folder to scan.
It cannot supply arbitrary SQL, paths, executables, or connection targets.

## Features

| MCP tool | CLI command | Engine | What it does |
|---|---|---|---|
| `scanner_status()` | `status` | none | Shows what is configured. Does not check engines or PC safety |
| `collect_inventory(query_id, offset=0)` | `inventory <query_id> [--offset N]` | osqueryi | Returns one of `os_version`, `applications`, `listening_ports` |
| `scan_malware(root_alias, relative_path=".")` | `malware <root_alias> [relative_path]` | clamscan | Scans an authorized folder, or a path inside it |
| `get_vulnerabilities(offset=0)` | `vulnerabilities [--offset N]` | Wazuh indexer | Returns vulnerabilities for the one configured device, most severe first |
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
    "personal-pc-scanner": {
      "command": "/absolute/path/to/project/.venv/bin/python",
      "args": ["-m", "pc_scanner.cli", "--config", "/absolute/path/to/project/scanner.toml", "serve"]
    }
  }
}
```

- On Windows, set `command` to something like `C:\\path\\to\\project\\.venv\\Scripts\\python.exe` (backslashes are written as `\\` in JSON).
- Because the package was installed in step 2, you do not need to set a working directory (`cwd`).
- This project itself does not need an API key for any AI service.

### Using Wazuh

Set the following in the `[wazuh]` section of `scanner.toml`:

```toml
[wazuh]
url = 'https://indexer.example:9200'   # HTTPS address of the indexer (not the manager API on port 55000)
agent_id = '001'                        # Device ID in Wazuh; '1' is treated as '001'
ca_file = '/path/to/root-ca.pem'        # CA certificate of the indexer
```

Pass the user name and password as environment variables, **never in the configuration file**:

```sh
export PC_SCANNER_WAZUH_USER='reader'
export PC_SCANNER_WAZUH_PASSWORD='...'
```

For MCP, provide them through your client's secret management or the environment that launches it.
Give the indexer account **read access only** to the target device's vulnerability index. Do not use an administrator account.

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
| `scan_roots.<alias>` | A folder allowed to be scanned (absolute path). Aliases use letters, digits, `_` and `-`, up to 64 characters | none |
| `wazuh.url` | HTTPS address of the Wazuh indexer. Empty disables it | empty |
| `wazuh.agent_id` | Numeric ID of the target device | empty |
| `wazuh.ca_file` | CA certificate of the indexer. Empty uses the system certificates | empty |
| Environment variables `PC_SCANNER_WAZUH_USER` / `PC_SCANNER_WAZUH_PASSWORD` | Wazuh credentials | — |

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
| `partial` | Only part could be checked (unreadable folders, limits reached, zero records, a single page, etc.) | Read `warnings`. Coverage is incomplete |
| `error` | The operation could not run (not configured, permission denied, timeout, connection failure, etc.) | Treat it as not checked |

### CLI exit codes

| Exit code | Meaning |
|---|---|
| `0` | Completed with no findings |
| `1` | Completed with findings (malware, vulnerabilities, etc.) |
| `2` | `partial` or `error`. **A `partial` result returns 2 even when it has findings** |

### Large results (paging)

Inventory and Wazuh results come in pages of 500. When more remain, `data.next_offset` holds a number;
pass it as `offset` (`--offset` in the CLI) and run again.
A single page, and any page after the first, is reported as `partial`. The maximum `offset` is 9500 (matching OpenSearch's default limit of 10,000 retrievable results).

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
- Unreadable folders do not stop the scan. They are listed in `data.unreadable_directories` (up to 20) and the result is `partial`.
- Unsupported formats, encrypted files, or outdated signatures may prevent detection.
- clamscan loads its signatures on every run, so a short time limit makes timeouts more likely.

### Wazuh

- It reads data **already stored** in Wazuh. It does not guarantee freshness or that the PC is currently online.
- When the device has zero records, the result is `partial`, because a wrong device ID, an unregistered device, and a never-scanned device look the same.
  Check the device ID, name, registration, and collection time in Wazuh.

### Privacy

- Passing results to a cloud AI may send application names, process IDs, file names, and similar data. The PC owner decides where results go and how much is shared.
- To reduce what is sent, file paths are returned relative to the authorized folder, and absolute paths in engine output are replaced with `<alias>`.
- Engine output is shortened to its first and last 60 lines in total, and lines over 500 characters keep both ends (`data.engine_text_truncated` is true when anything was shortened). Findings are capped at 500, with malware listed first.

### Operating assumptions

- Run as a **standard user**, not an administrator. The tool never elevates privileges.
- The folder restriction is not an OS sandbox. It does not protect against a malicious local user swapping files.
- The time limit and output limit apply only to the engine started directly. Child processes started by the engine are not stopped.

## Safety design

- **Fixed operations only**: the AI cannot specify SQL, paths, executables, connection targets, or device IDs.
- **Read-only**: options that delete or quarantine files are never used. All tools carry the read-only annotation (`readOnlyHint`).
  Some clients use this annotation to run tools without asking, so configure your client if you want to approve every call.
- **No shell**: engines are started directly, without a shell. Windows `.bat` / `.cmd` files are never run.
- **No credentials passed on**: engines receive only path-related environment variables (including Windows `USERPROFILE`, `PROGRAMDATA`, etc.).
- **Restricted network access**: Wazuh is reached over HTTPS only, and certificate verification cannot be turned off. Proxies and redirects are not used.
- **AI-facing text is untrusted**: the AI is instructed to treat file and application names in results as untrusted strings, never as instructions.
- **Responsive during long scans**: scans run in a worker thread, and engines run one at a time.
  Progress is reported every 10 seconds, so clients that extend their timeout on progress can wait for long scans.
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
  the third-party notices and SBOM files are included. On Windows, a real junction is created to verify it is not followed.
- Detection accuracy with real engines and behavior on each OS are not guaranteed. Acceptance testing on real machines for each OS is required before distribution.

## Related documents and license

These documents are in Japanese.

- [docs/backlog.md](docs/backlog.md): open issues and items to verify on real machines
- [docs/licensing.md](docs/licensing.md): license policy and pre-distribution checks
- [docs/compliance.md](docs/compliance.md): scope of the SBOM and third-party notices, and how to regenerate them
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and the [CycloneDX SBOM](sbom/python-agent.cdx.json): notices for the Python dependencies used for MCP

An [MIT license is proposed](docs/license-recommendation.md) for this project's own code but has not been formally applied yet.
This repository does not contain any Wazuh, osquery, or ClamAV code, binaries, rules, or signatures.
