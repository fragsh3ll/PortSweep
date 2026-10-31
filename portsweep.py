#!/usr/bin/env python3
"""Masscan discovery, host-specific Nmap enrichment, and offline reports."""

import argparse
from collections import defaultdict
from contextlib import contextmanager
import csv
from datetime import datetime, timezone
import fcntl
import html
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

VERSION = "2.0.0"
NMAP_OPTIONS = ["-Pn", "-n", "-v", "-sV", "-sT", "--version-intensity", "9", "-sC"]


class ScanError(Exception):
    """An actionable scan, data, or dependency error."""


class ScanProgress:
    """Render scanner-reported progress without changing the raw log stream."""

    def __init__(self, label, scanner):
        self.label = label
        self.scanner = scanner
        self.enabled = sys.stderr.isatty() and os.environ.get("TERM") != "dumb"
        self.phase = "Starting"
        self.percent = None
        self.detail = ""
        self.pending = b""
        self.started = time.monotonic()
        self.width = 0
        self.open_ports = 0
        self.open_endpoints = set()

    def update(self, line):
        finding = re.match(r"Discovered open port (\d+)/tcp on (\S+)", line.strip())
        if finding:
            try:
                host = str(ipaddress.ip_address(finding[2]))
                port = int(finding[1])
                if 1 <= port <= 65535:
                    self.open_endpoints.add((host, port))
                    self.open_ports = max(self.open_ports, len(self.open_endpoints))
            except ValueError:
                pass
        if self.scanner == "masscan":
            found = re.search(r"\bfound=(\d+)\b", line)
            if found and line.lstrip().startswith("rate:"):
                self.open_ports = max(self.open_ports, int(found[1]))
            match = re.search(r"rate:\s*[\d.]+-kpps,\s*(\d+(?:\.\d+)?)% done", line)
            if not match:
                return
            self.percent = min(100.0, max(0.0, float(match[1])))
            waiting = re.search(r"waiting (\d+)-secs", line)
            remaining = re.search(r"(\d+:\d{2}:\d{2}) remaining", line)
            self.phase = "Receiving replies" if waiting else "Sending probes"
            self.detail = f"{waiting[1]}s wait" if waiting else (
                f"ETA {remaining[1]}" if remaining else "")
        else:
            match = re.search(r"([A-Za-z][A-Za-z -]{0,50}) Timing: About (\d+(?:\.\d+)?)% done", line)
            if match:
                self.phase = match[1].strip()
                self.percent = min(100.0, max(0.0, float(match[2])))
                self.detail = "phase progress"
            else:
                match = re.match(r"(?:NSE: )?Initiating ([A-Za-z][A-Za-z -]{0,50}) at \d", line)
                if match:
                    self.phase = match[1].strip()
                    self.percent = None
                    self.detail = ""

    def follow(self, stream, final=False):
        # Never skip finding events: each distinct host/port must be counted.
        # Bound work while the process runs so display and signals stay responsive.
        chunks = 0
        while final or chunks < 16:
            data = stream.read(65536)
            if not data:
                break
            chunks += 1
            lines = re.split(rb"[\r\n]", self.pending + data)
            self.pending = lines.pop()[-4096:]
            for line in lines:
                self.update(line.decode("ascii", errors="replace"))
        if final and self.pending:
            self.update(self.pending.decode("ascii", errors="replace"))
            self.pending = b""

    def render(self, status=None):
        if not self.enabled:
            return
        elapsed = int(time.monotonic() - self.started)
        size = 20
        if self.percent is None:
            position = int((time.monotonic() - self.started) * 5) % size
            bar = " " * position + "=" + " " * (size - position - 1)
            amount = " --.-%"
        else:
            filled = int(size * self.percent / 100)
            bar = "=" * filled + " " * (size - filled)
            amount = f"{self.percent:5.1f}%"
        suffix = status or f"{self.phase} {self.detail}".strip()
        count_label = "open" if self.scanner == "masscan" else "confirmed"
        line = (f"{self.label} {count_label}: {self.open_ports} [{bar}] {amount} "
                f"{elapsed // 60:02d}:{elapsed % 60:02d} {suffix}")
        columns = shutil.get_terminal_size((100, 24)).columns
        line = line[:max(1, columns - 1)]
        # Use padding instead of escape sequences, and never print scanner banners.
        self.write("\r" + line + " " * max(0, min(self.width, columns - 1) - len(line)))
        self.width = len(line)

    def write(self, text):
        try:
            sys.stderr.write(text)
            sys.stderr.flush()
        except OSError:
            # Losing a terminal must not stop a scan or prevent saving its state.
            self.enabled = False

    def finish(self, status):
        if status == "complete":
            self.percent = 100.0
        self.render(status)
        if self.enabled and self.width:
            self.write("\n")


def now():
    return datetime.now(timezone.utc).isoformat()


def atomic_write(path, text):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path, value):
    atomic_write(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


@contextmanager
def run_lock(directory):
    with (directory / ".lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ScanError(f"Another process is using {directory}") from error
        yield


def load_manifest(directory):
    manifest = json.loads((directory / "manifest.json").read_text())
    if manifest.get("schema_version") != 1:
        raise ScanError("Unsupported manifest version")
    return manifest


def save_manifest(directory, manifest):
    manifest["updated_at"] = now()
    write_json(directory / "manifest.json", manifest)


def parse_ports(value):
    presets = json.loads((Path(__file__).parent / "data/ports.json").read_text())
    value = presets.get(value, "1-65535" if value == "all" else value)
    if not re.fullmatch(r"[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*", value):
        raise ScanError("Ports must be all, top-100, top-1000, or TCP ports/ranges")
    for part in value.split(","):
        bounds = list(map(int, part.split("-")))
        if not 1 <= bounds[0] <= bounds[-1] <= 65535:
            raise ScanError(f"Invalid port range: {part}")
    return value


def normalize_targets(path):
    targets = set()
    for number, line in enumerate(path.read_text().splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError as error:
            raise ScanError(f"Invalid IP/CIDR at {path}:{number}: {line}") from error
        if network.version != 4:
            raise ScanError("Discovery currently supports IPv4 targets only")
        targets.add(str(network))
    if not targets:
        raise ScanError("Target file contains no IP addresses or CIDRs")
    return sorted(targets, key=lambda value: (int(ipaddress.ip_network(value).network_address), value))


def xml_root(path, scanner, allow_empty=False):
    # Masscan creates its output lazily: successful zero-findings scans can be empty.
    if allow_empty and path.is_file() and path.stat().st_size == 0:
        return ET.Element("nmaprun", scanner=scanner)
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as error:
        raise ScanError(f"Invalid or missing XML: {path}: {error}") from error
    if root.tag != "nmaprun" or root.get("scanner") != scanner:
        raise ScanError(f"Expected {scanner} XML in {path}")
    if scanner == "nmap":
        finished = root.find("runstats/finished")
        if finished is None or finished.get("exit") != "success":
            raise ScanError(f"Nmap XML does not describe a successful completed scan: {path}")
    return root


def address(host):
    for item in host.findall("address"):
        if item.get("addrtype") in ("ipv4", "ipv6"):
            try:
                return str(ipaddress.ip_address(item.get("addr", "")))
            except ValueError as error:
                raise ScanError("Invalid address in scanner XML") from error
    raise ScanError("Host has no IP address in scanner XML")


def port_number(port):
    try:
        value = int(port.get("portid", ""))
        if not 1 <= value <= 65535 or port.get("protocol") != "tcp":
            raise ValueError
        return value
    except ValueError as error:
        raise ScanError("Invalid TCP port in scanner XML") from error


def discoveries(directory, manifest):
    hosts = defaultdict(set)
    networks = [ipaddress.ip_network(t) for t in manifest["targets"]]
    for attempt in manifest["discovery"]["attempts"]:
        if not attempt.get("contributes"):
            continue
        root = xml_root(directory / attempt["xml"], "masscan", allow_empty=True)
        for host in root.findall("host"):
            ip = address(host)
            if not any(ipaddress.ip_address(ip) in network for network in networks):
                raise ScanError(f"Discovery returned an out-of-scope host: {ip}")
            for port in host.findall("ports/port"):
                if port.find("state") is not None and port.find("state").get("state") == "open":
                    hosts[ip].add(port_number(port))
    return dict(sorted(hosts.items(), key=lambda item: int(ipaddress.ip_address(item[0]))))


def executable(name, manifest):
    path = shutil.which(name)
    if not path:
        raise ScanError(f"Missing dependency: {name}; install it and resume this run")
    path = str(Path(path).resolve())
    if name not in manifest["tools"]:
        try:
            version = subprocess.run([path, "--version"], capture_output=True, text=True,
                                     timeout=10, check=False)
            details = (version.stdout + version.stderr).strip()
        except (OSError, subprocess.TimeoutExpired) as error:
            details = f"Version unavailable: {error}"
        manifest["tools"][name] = {"path": path, "version": details}
    return path


def command_run(directory, manifest, stage, command, logfile, label, scanner):
    attempt = {"command": command, "started_at": now(), "log": logfile,
               "status": "running"}
    stage.setdefault("commands", []).append(attempt)
    stage["status"] = "running"
    save_manifest(directory, manifest)
    print(f"[*] Running {Path(command[0]).name}; log: {directory / logfile}", flush=True)
    progress = ScanProgress(label, scanner)
    try:
        with (directory / logfile).open("w") as log, (directory / logfile).open("rb") as tail:
            # Keep the controlling terminal (and sudo's terminal-bound credentials),
            # but isolate the child group so parent-only signals can be forwarded.
            # This CLI is single-threaded, so setpgrp in preexec_fn is safe here.
            process = subprocess.Popen(command, cwd=directory, stdout=log,
                                       stderr=subprocess.STDOUT, preexec_fn=os.setpgrp)
            try:
                if progress.enabled:
                    while True:
                        progress.follow(tail)
                        progress.render()
                        try:
                            code = process.wait(timeout=0.2)
                            break
                        except subprocess.TimeoutExpired:
                            continue
                    progress.follow(tail, final=True)
                else:
                    code = process.wait()
            except KeyboardInterrupt:
                progress.phase, progress.detail, progress.percent = "Stopping scanner", "", None
                progress.render()
                # Give masscan time to write paused.conf and close its XML output.
                for sig, timeout in ((signal.SIGINT, 15), (signal.SIGTERM, 5), (signal.SIGKILL, 5)):
                    try:
                        os.killpg(process.pid, sig)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=timeout)
                        break
                    except subprocess.TimeoutExpired:
                        continue
                raise
        attempt["returncode"] = code
        if code:
            raise ScanError(f"Command exited {code}; see {directory / logfile}")
        attempt["status"] = "complete"
    except KeyboardInterrupt:
        attempt["status"] = stage["status"] = "interrupted"
        raise
    except (OSError, ScanError):
        attempt["status"] = stage["status"] = "failed"
        raise
    finally:
        progress.finish(attempt["status"])
        attempt["finished_at"] = now()
        save_manifest(directory, manifest)


def discover(directory, manifest):
    stage = manifest["discovery"]
    if stage["status"] == "complete":
        return discoveries(directory, manifest)
    masscan = executable("masscan", manifest)
    command = [masscan]
    if os.geteuid() != 0:
        sudo = shutil.which("sudo")
        if not sudo:
            raise ScanError("Masscan requires root; install sudo or run discovery as root")
        # Authenticate in the foreground, before redirecting scanner output. Never
        # leave a password prompt hidden inside a log or a background process group.
        if subprocess.run([sudo, "-v"], check=False).returncode:
            raise ScanError("Could not obtain sudo credentials for masscan")
        command = [str(Path(sudo).resolve()), "-n", "--", masscan]
    paused = directory / "paused.conf"
    can_resume = False
    if paused.is_file() and stage["attempts"]:
        try:
            xml_root(directory / stage["attempts"][-1]["xml"], "masscan", allow_empty=True)
            can_resume = True
        except ScanError:
            print("[*] Partial XML is invalid; restarting discovery and preserving prior artifacts")
    number = len(stage["attempts"]) + 1
    if can_resume:
        checkpoint = f"discovery/paused-{number:04d}.conf"
        # Copy first: a crash before the new command starts must not destroy the
        # only resumable checkpoint. Masscan replaces paused.conf on the next pause.
        shutil.copyfile(paused, directory / checkpoint)
        command += ["--resume", checkpoint]
    else:
        for previous in stage["attempts"]:
            previous["contributes"] = False
        if paused.exists():
            paused.rename(directory / f"discovery/unused-paused-{number:04d}.conf")
        command += ["-Pn", "-p", manifest["options"]["ports"], "--rate",
                    str(manifest["options"]["rate"]), "-iL", "targets.txt"]
    xml = f"discovery/masscan-{number:04d}.xml"
    # Each resume writes a new XML document; never append documents to the same file.
    command += ["-oX", xml]
    stage["attempts"].append({"xml": xml, "contributes": True, "resumed": can_resume})
    command_run(directory, manifest, stage, command, f"discovery/masscan-{number:04d}.log",
                "Discovery", "masscan")
    hosts = discoveries(directory, manifest)
    stage.update(status="complete", finished_at=now(), hosts=len(hosts),
                 open_ports=sum(map(len, hosts.values())))
    save_manifest(directory, manifest)
    print(f"[*] Discovery complete: {stage['open_ports']} open ports on {len(hosts)} hosts")
    return hosts


def prepare_groups(directory, manifest, hosts):
    atomic_write(directory / "liveips.txt", "".join(f"{ip}\n" for ip in hosts))
    atomic_write(directory / "ip_port.txt", "".join(
        f"{ip}:{port}\n" for ip, ports in hosts.items() for port in sorted(ports)))
    if manifest["enrichment"]["groups"]:
        return
    grouped = defaultdict(list)
    for ip, ports in hosts.items():
        grouped[tuple(sorted(ports))].append(ip)
    groups = []
    for number, (ports, ips) in enumerate(grouped.items(), 1):
        prefix = f"nmap/group-{number:04d}"
        atomic_write(directory / f"{prefix}-targets.txt", "".join(f"{ip}\n" for ip in ips))
        groups.append({
            "ports": list(ports), "hosts": ips, "prefix": prefix, "status": "pending"})
    # Publish the complete plan together; interruption must not persist half a plan.
    manifest["enrichment"]["groups"] = groups
    save_manifest(directory, manifest)


def enrich(directory, manifest):
    stage = manifest["enrichment"]
    for group in stage["groups"]:
        if group["status"] == "complete":
            try:
                xml_root(directory / group["xml"], "nmap")
            except ScanError:
                group["status"] = "failed"
                print(f"[*] Missing or invalid completed XML; retrying {group['prefix']}")
    pending = [group for group in stage["groups"] if group["status"] != "complete"]
    if pending:
        nmap = executable("nmap", manifest)
    stage["status"] = "running"
    for index, group in enumerate(stage["groups"], 1):
        if group["status"] == "complete":
            xml_root(directory / group["xml"], "nmap")
            continue
        print(f"[*] Enrichment group {index}/{len(stage['groups'])}: "
              f"{len(group['hosts'])} hosts, {len(group['ports'])} ports")
        attempt = len(group.get("commands", [])) + 1
        prefix = f"{group['prefix']}-attempt-{attempt:04d}"
        group["xml"] = f"{prefix}.xml"
        options = list(manifest["options"]["nmap_options"])
        # Also enable periodic statistics when resuming manifests from older runs.
        if "--stats-every" not in options:
            options += ["--stats-every", "1s"]
        command = [nmap, *options, "-p", ",".join(map(str, group["ports"])),
                   "-iL", f"{group['prefix']}-targets.txt", "-oA", prefix]
        command_run(directory, manifest, group, command, f"{prefix}.log",
                    f"Nmap {index}/{len(stage['groups'])}", "nmap")
        try:
            xml_root(directory / group["xml"], "nmap")
        except ScanError:
            group["status"] = "failed"
            save_manifest(directory, manifest)
            raise
        group.update(status="complete", finished_at=now())
        save_manifest(directory, manifest)
    stage.update(status="complete", finished_at=now())
    save_manifest(directory, manifest)


def scripts(parent):
    return [{"id": script.get("id", ""), "output": script.get("output", ""),
             "xml": ET.tostring(script, encoding="unicode")} for script in parent.findall("script")]


def collect_results(directory, manifest):
    hosts = discoveries(directory, manifest)
    rows = {(ip, port): {"host": ip, "port": port, "protocol": "tcp",
                        "discovery_state": "open", "state": "unconfirmed",
                        "service": {}, "scripts": [], "host_scripts": []}
            for ip, ports in hosts.items() for port in sorted(ports)}
    for group in manifest["enrichment"]["groups"]:
        root = xml_root(directory / group["xml"], "nmap")
        for host in root.findall("host"):
            ip = address(host)
            if ip not in group["hosts"]:
                raise ScanError(f"Unexpected host in Nmap results: {ip}")
            host_scripts = scripts(host.find("hostscript")) if host.find("hostscript") is not None else []
            for port in host.findall("ports/port"):
                number = port_number(port)
                if number not in group["ports"]:
                    raise ScanError(f"Unexpected port in Nmap results: {number}")
                row = rows[(ip, number)]
                state = port.find("state")
                if state is None or not state.get("state"):
                    raise ScanError("Nmap port has no state")
                service = port.find("service")
                row.update(state=state.get("state"), scripts=scripts(port), host_scripts=host_scripts)
                if service is not None:
                    row["service"] = {**service.attrib, "cpe": [c.text for c in service.findall("cpe")]}
            # Infer summarized states only when every omitted port has one state.
            missing = [p for p in group["ports"] if rows[(ip, p)]["state"] == "unconfirmed"]
            extra = host.findall("ports/extraports")
            if len(extra) == 1 and extra[0].get("count") == str(len(missing)):
                state = extra[0].get("state")
                if state in ("closed", "filtered"):
                    for number in missing:
                        rows[(ip, number)]["state"] = state
            for number in group["ports"]:
                rows[(ip, number)]["host_scripts"] = host_scripts
    return list(rows.values())


def findings(items):
    return "\n".join(f"{s['id']}: {s['output']}" for s in items)


def generate_report(directory, manifest):
    if any(manifest[stage]["status"] != "complete" for stage in ("discovery", "enrichment")):
        raise ScanError("Discovery and enrichment must finish before reporting; use resume")
    rows = collect_results(directory, manifest)
    result = {"schema_version": 1, "run_id": manifest["run_id"], "generated_at": now(),
              "scope": {"targets": manifest["targets"], "ports": manifest["options"]["ports"]},
              "results": rows}
    write_json(directory / "results.json", result)
    output = io.StringIO(newline="")
    fields = ["host", "port", "protocol", "state", "service", "product", "version", "extrainfo", "scripts", "host_scripts"]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    table_rows = []
    for row in rows:
        service = row["service"]
        flattened = {**{k: row[k] for k in fields[:4]},
                     "service": service.get("name", ""),
                     **{k: service.get(k, "") for k in ("product", "version", "extrainfo")},
                     "scripts": findings(row["scripts"]), "host_scripts": findings(row["host_scripts"])}
        # Scanner banners are untrusted. Avoid spreadsheet formula execution.
        writer.writerow({k: "'" + str(v) if str(v).startswith(("=", "+", "-", "@", "\t", "\r")) else v
                         for k, v in flattened.items()})
        table_rows.append("<tr>" + "".join(f"<td>{html.escape(str(flattened[k]))}</td>" for k in fields) + "</tr>")
    atomic_write(directory / "results.csv", output.getvalue())
    page = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PortSweep results</title><style>
body{font:15px system-ui,sans-serif;margin:2rem;color:#172033;background:#f4f6fa}
input{font:inherit;padding:.7rem;width:min(28rem,90%);margin-bottom:1rem}
.table{overflow:auto}table{border-collapse:collapse;background:white;width:100%}
th,td{text-align:left;padding:.7rem;border-bottom:1px solid #dce2ec;vertical-align:top}
th{background:#172033;color:white}td{white-space:pre-wrap;overflow-wrap:anywhere;max-width:35rem}
</style><h1>PortSweep results</h1>"""
    page += f"<p>Run {html.escape(manifest['run_id'])} · {len(rows)} discovered endpoints. "
    page += "States reflect Nmap confirmation; unconfirmed means no conclusive follow-up result.</p>"
    page += '<label for="search">Filter hosts, services, versions, and findings</label><br><input id="search" type="search" placeholder="Search results…">'
    page += '<p><a href="results.json">JSON</a> · <a href="results.csv">CSV</a></p><div class="table"><table><thead><tr>'
    page += "".join(f"<th scope='col'>{html.escape(k.replace('_', ' ').title())}</th>" for k in fields)
    page += "</tr></thead><tbody>" + "".join(table_rows) + "</tbody></table></div>"
    if not rows:
        page += "<p>No open ports were discovered. The discovery scan completed successfully.</p>"
    page += """<script>document.getElementById('search').addEventListener('input',function(){
const query=this.value.toLowerCase();document.querySelectorAll('tbody tr').forEach(row=>{
row.hidden=!row.textContent.toLowerCase().includes(query);});});</script></html>"""
    atomic_write(directory / "report.html", page)
    manifest["report"] = {"status": "complete", "finished_at": now(), "endpoints": len(rows)}
    save_manifest(directory, manifest)
    print(f"[*] Reports: {directory / 'report.html'} (also results.json and results.csv)")


def continue_run(directory, manifest):
    manifest.update(status="running", error=None)
    save_manifest(directory, manifest)
    try:
        hosts = discover(directory, manifest)
        prepare_groups(directory, manifest, hosts)
        enrich(directory, manifest)
        generate_report(directory, manifest)
    except (ScanError, OSError, ValueError) as error:
        manifest.update(status="failed", error=str(error))
        for stage in ("discovery", "enrichment"):
            if manifest[stage]["status"] == "running":
                manifest[stage]["status"] = "failed"
        save_manifest(directory, manifest)
        raise
    except KeyboardInterrupt:
        manifest.update(status="interrupted", error="Interrupted; resume this run to continue")
        for stage in ("discovery", "enrichment"):
            if manifest[stage]["status"] == "running":
                manifest[stage]["status"] = "interrupted"
        save_manifest(directory, manifest)
        raise
    manifest.update(status="complete", finished_at=now())
    save_manifest(directory, manifest)


def start_scan(args):
    ports = parse_ports(args.ports)
    if args.rate <= 0:
        raise ScanError("Rate must be a positive integer")
    targets = normalize_targets(Path(args.targets))
    directory = Path(tempfile.mkdtemp(prefix=datetime.now().strftime("portsweep-%Y-%m-%d_%H%M%S-"),
                                      dir=Path.cwd())).resolve()
    for name in ("discovery", "nmap"):
        (directory / name).mkdir()
    atomic_write(directory / "targets.txt", "\n".join(targets) + "\n")
    manifest = {"schema_version": 1, "portsweep_version": VERSION, "run_id": directory.name,
                "created_at": now(), "status": "pending", "targets": targets,
                "options": {"ports": ports, "requested_ports": args.ports, "rate": args.rate,
                            "nmap_options": NMAP_OPTIONS}, "tools": {},
                "discovery": {"status": "pending", "attempts": []},
                "enrichment": {"status": "pending", "groups": []},
                "report": {"status": "pending"}}
    print(f"[*] Run directory: {directory}", flush=True)
    with run_lock(directory):
        continue_run(directory, manifest)


def compare_runs(before, after):
    def read(directory):
        manifest = load_manifest(directory)
        if manifest["status"] != "complete":
            raise ScanError(f"Cannot compare an incomplete run: {directory}")
        return json.loads((directory / "results.json").read_text())
    old, new = read(before), read(after)
    if old["scope"] != new["scope"]:
        raise ScanError("Cannot compare different target/port scopes")
    def key(row):
        return row["host"], row["protocol"], row["port"]
    left, right = ({key(r): r for r in data["results"]} for data in (old, new))
    changes = {"newly_open": [], "closed": [], "no_longer_observed_open": [], "service_changed": []}
    for endpoint in sorted(left.keys() | right.keys()):
        previous, current = left.get(endpoint), right.get(endpoint)
        if current and current["state"] == "open":
            if not previous or previous["state"] != "open":
                changes["newly_open"].append(current)
            elif previous["service"] != current["service"]:
                changes["service_changed"].append({"before": previous, "after": current})
        elif previous and previous["state"] == "open":
            if current and current["state"] == "closed":
                changes["closed"].append(current)
            else:
                changes["no_longer_observed_open"].append({"before": previous, "after": current})
    print(json.dumps(changes, indent=2, sort_keys=True))


def interrupt_handler(_signum, _frame):
    raise KeyboardInterrupt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    sub = parser.add_subparsers(dest="action", required=True)
    scan = sub.add_parser("scan", help="Run discovery and enrichment")
    scan.add_argument("ports", help="all, top-100, top-1000, or TCP ports/ranges")
    scan.add_argument("rate", type=int, help="Masscan packets per second")
    scan.add_argument("targets", help="File of IPv4 addresses/CIDRs")
    for name, description in (("resume", "Continue an interrupted or failed run"),
                              ("report", "Regenerate reports without scanning")):
        command = sub.add_parser(name, help=description)
        command.add_argument("directory", type=Path)
    compare = sub.add_parser("compare", help="Compare completed runs of the same scope")
    compare.add_argument("before", type=Path)
    compare.add_argument("after", type=Path)
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] not in ("scan", "resume", "report", "compare", "-h", "--help", "--version"):
        args.insert(0, "scan")
    options = parser.parse_args(args)
    signal.signal(signal.SIGTERM, interrupt_handler)
    try:
        if options.action == "scan":
            start_scan(options)
        elif options.action == "compare":
            compare_runs(options.before.resolve(), options.after.resolve())
        else:
            directory = options.directory.resolve()
            with run_lock(directory):
                manifest = load_manifest(directory)
                if options.action == "resume":
                    continue_run(directory, manifest)
                else:
                    generate_report(directory, manifest)
                    manifest.update(status="complete", finished_at=now(), error=None)
                    save_manifest(directory, manifest)
        return 0
    except KeyboardInterrupt:
        print("[!] Interrupted. Artifacts retained; use python3 portsweep.py resume RUN_DIRECTORY.", file=sys.stderr)
        return 130
    except (ScanError, OSError, ValueError) as error:
        print(f"[!] {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
