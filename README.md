# PortSweep

PortSweep discovers open TCP ports with masscan, enriches those exact host/port
pairs with Nmap service detection and default scripts, and builds searchable,
self-contained HTML reports plus JSON and CSV exports.

## Requirements

- Linux or macOS and Python 3.10 or newer.
- `masscan` and `nmap` on `PATH` for scanning. No Python packages are required.
- Root privileges for masscan. When started as a regular user, PortSweep runs
  `sudo -v` in the foreground and elevates only masscan. Nmap uses TCP connect
  scanning (`-sT`), and parsing/reporting run as the invoking user.

No Bash launcher, XML utilities, or Python packages are required.
Help, version information, comparisons, and report generation do not require
scanner installations or elevated privileges. If you launch the entire command
with `sudo`, its private run directory belongs to root; use the same owner for
subsequent commands.

## Installation

Keep these files together in your installation directory:

```text
portsweep.py
data/ports.json
README.md
LICENSE
```

Install Python 3.10 or newer, masscan, and Nmap using your operating system's
package manager. Check the entry point before scanning:

```sh
python3 portsweep.py --help
python3 portsweep.py --version
```

You can also invoke `./portsweep.py` directly when its executable permission is
preserved. Run it from the directory where you want scan results written. The
port presets are resolved relative to the program, independent of that directory.
The former `portsweep.sh` launcher has been removed; update existing callers to
use `python3 /path/to/portsweep.py` with the same arguments.

## Scan

Run the Python entry point with ports, packet rate, and a target file:

```sh
python3 portsweep.py 21,22,23,80,443 1000 ips.txt
python3 portsweep.py top-1000 1000 'targets with spaces.txt'
```

An explicit `scan` command is equivalent:

```sh
python3 portsweep.py scan all 1000 ips.txt
python3 portsweep.py --help
python3 portsweep.py --version
```

Ports may be `all` (1–65535), `top-100`, `top-1000`, or a comma-separated list of
TCP ports and inclusive ranges. The top-port presets preserve the original
project's lists in `data/ports.json`; they do not track changes to Nmap's database.
Rate is a positive integer in packets per second. Target files contain one IPv4
address or CIDR per line; comments beginning with `#` and blank lines are allowed.
IPv6 and UDP discovery are not supported by this workflow.

A unique `portsweep-<timestamp>-<suffix>/` directory is created in the current
working directory. The normalized target list is copied there, so resuming does
not depend on the original input file. Hosts with identical discovered port sets
share an Nmap invocation. Groups run sequentially; a host is never given another
host's additional discovered ports. Follow-up options remain `-Pn -n -v -sV -sT
--version-intensity 9 -sC` and are recorded in the manifest. Nmap confirmation
retains closed and filtered states rather than hiding them with `--open`.

Progress messages show the current stage/group and scanner log paths. Tail the
named log to see scanner-specific progress during a long stage.

## Resume and regenerate

```sh
python3 portsweep.py resume portsweep-2026-10-31_120000-example/
python3 portsweep.py report portsweep-2026-10-31_120000-example/
```

Ctrl-C and SIGTERM stop the active scanner and save interrupted status. Discovery
uses masscan's `paused.conf` when available and its preceding output is valid.
Each discovery attempt writes a separate XML file; results are combined and
deduplicated, avoiding concatenated XML documents. If a usable checkpoint or
valid partial output is unavailable (for example, after a hard kill), discovery
restarts while retaining earlier artifacts. A hard kill cannot guarantee a
checkpoint.

Once discovery is complete, resume skips it and reruns only unfinished Nmap
groups. A failed or interrupted group restarts from its beginning; completed
groups are retained. Missing or malformed XML from a previously completed group
is retried on resume. A completed run can be resumed without scanning again.

`report` rebuilds exports from the retained XML without scanning. It requires
completed discovery and enrichment and refuses incomplete runs. Failed commands,
missing output, malformed XML, and unsuccessful Nmap completion markers produce
errors instead of empty success reports. A successful masscan run with zero
findings produces an empty report and skips Nmap, retaining all artifacts.
Masscan can legitimately leave a zero-byte output file in this case.

## Output

| Artifact | Contents |
| --- | --- |
| `manifest.json` | Run status, scope, options, tool versions, commands, timestamps, stages, attempts, and errors |
| `targets.txt` | Normalized discovery target snapshot |
| `ip_port.txt` | Deduplicated discovered `IP:PORT` pairs |
| `liveips.txt` | Addresses with at least one discovered open port |
| `discovery/` | Per-attempt masscan XML/logs and saved checkpoints |
| `nmap/` | Group target lists and per-attempt raw `.xml`, `.nmap`, `.gnmap`, and logs |
| `results.json` | Versioned structured export with service attributes, CPEs, port scripts, and host scripts |
| `results.csv` | Flat service/version and script findings for spreadsheets |
| `report.html` | Offline report with text filtering and links to exports |

Report rows represent discovery findings. `state` reflects Nmap confirmation;
`unconfirmed` means the follow-up provided no conclusive state for that endpoint.
The separate JSON `discovery_state` remains `open`. Structured NSE XML is retained
in JSON alongside each script's ID and output. HTML escapes scanner-supplied
content, and CSV prefixes potential spreadsheet formulas with an apostrophe;
JSON preserves the original values.

Directories use private permissions, updates to manifests/exports use atomic
replacement, and an advisory lock prevents concurrent resume/report operations
on the same run. Scanner stdout/stderr and every attempt's raw output are kept.
Export filenames and the per-group Nmap layout replace the old single timestamped
Nmap/HTML output names. Existing legacy scan directories have no manifest and
cannot be resumed or imported by this version.

## Compare scans

```sh
python3 portsweep.py compare path/to/earlier-run path/to/later-run > changes.json
```

Both runs must be complete and have identical normalized target lists and
resolved port specifications. The JSON comparison includes `newly_open`,
`closed`, `no_longer_observed_open`, and `service_changed` entries. Only an explicit
Nmap closed state is called closed. A port absent from later discovery, filtered,
or unconfirmed is reported as no longer observed open. Silence during discovery
does not prove closure. These are observations from the requested scopes, not a
guarantee that either discovery scan found every open port. Different spellings
of equivalent port sets or target ranges can conservatively fail the scope check.
