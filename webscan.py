#!/usr/bin/env python3
"""Single-host web assessment runner. Python 3.10+, Linux/Kali/WSL.

External scanners stay external: this script schedules them and records evidence.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import datetime as dt
import html
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from findings import collect
from crawler import crawl, select_candidates, origin
from scope import parse_target, prepare_target, normalize_url, authority
from checks import run_checks
from findings import finding_groups, sqlmap_outcome

VERSION = "1.3.0"
ENUM_TOOLS = ("ffuf", "gobuster", "feroxbuster", "dirsearch")
ALL_TOOLS = ("nmap", "httpx", "whatweb", *ENUM_TOOLS, "nikto", "nuclei", "sqlmap")
COMMON_WEB_PORTS = {80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000}
PRINT_LOCK = threading.Lock()


def say(message):
    with PRINT_LOCK:
        print(message, flush=True)


def ipv4(value):
    try:
        return str(ipaddress.IPv4Address(value.strip()))
    except ipaddress.AddressValueError as exc:
        raise argparse.ArgumentTypeError("Enter one IPv4 address, e.g. 192.168.56.101; no URL or range.") from exc


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("Must be at least 1.")
    return number


def ports(value):
    if not re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", value):
        raise argparse.ArgumentTypeError("Use 80,443,8080 or 1-65535.")
    for part in value.split(","):
        bounds = [int(x) for x in part.split("-")]
        if any(x < 1 or x > 65535 for x in bounds) or bounds[0] > bounds[-1]:
            raise argparse.ArgumentTypeError("Ports must be in ascending ranges between 1 and 65535.")
    return value


def listed_ports(value):
    result = set()
    for item in value.split(","):
        bounds = [int(x) for x in item.split("-")]
        result.update(range(bounds[0], bounds[-1] + 1))
    return result


def scoped_url(value, target):
    u = urllib.parse.urlsplit(value)
    if u.fragment:
        raise ValueError('Use a URL without a fragment')
    return normalize_url(value, target)


def target_input(value):
    try:
        target = parse_target(value)
        return target.url or target.host
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def parse_nmap(path, target):
    """Only accept ports attached to our IP; closed and filtered ports are excluded."""
    found = []
    for host in ET.parse(path).getroot().findall("host"):
        def matches(address):
            try:
                return ipaddress.ip_address(address.get('addr', '')) == ipaddress.ip_address(target)
            except ValueError:
                return False
        if not any(matches(a) for a in host.findall("address")):
            continue
        for p in host.findall("ports/port"):
            state = p.find("state")
            if p.get("protocol") != "tcp" or state is None or state.get("state") != "open":
                continue
            service = p.find("service")
            info = dict(service.attrib) if service is not None else {}
            port = int(p.get("portid", "0"))
            if 1 <= port <= 65535:
                found.append({"port": port, "service": info.get("name", "unknown"),
                              "product": info.get("product", ""), "version": info.get("version", ""),
                              "tunnel": info.get("tunnel", "")})
    return sorted(found, key=lambda row: row["port"])


def candidates(target, services):
    urls = []
    for entry in services:
        port = entry["port"]
        if "http" not in entry["service"].lower() and port not in COMMON_WEB_PORTS:
            continue
        tls = entry.get("tunnel") == "ssl" or "https" in entry["service"].lower() or port in (443, 8443)
        schemes = ("https", "http") if tls else ("http", "https")
        urls.extend(f"{scheme}://{authority(target, port)}/" for scheme in schemes)
    return list(dict.fromkeys(urls))


def probe(url, insecure=False, timeout=5):
    """One GET, bounded response, no redirects, no environment proxies or DNS."""
    u = urllib.parse.urlsplit(url)
    conn = None
    try:
        if u.scheme == "https":
            context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
            conn = http.client.HTTPSConnection(u.hostname, u.port, timeout=timeout, context=context)
        else:
            conn = http.client.HTTPConnection(u.hostname, u.port, timeout=timeout)
        conn.request("GET", urllib.parse.urlunsplit(('', '', u.path or '/', u.query, '')),
                     headers={"User-Agent": "Abdulla-WebScan/" + VERSION})
        response = conn.getresponse()
        body = response.read(65536).decode("utf-8", "replace")
        title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        return {"url": url, "status": response.status, "server": response.getheader("Server", ""),
                "title": html.unescape(re.sub(r"\s+", " ", title.group(1))).strip() if title else "",
                "location": response.getheader("Location", ""), "tls_verified": u.scheme == "https" and not insecure}
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
        return {"url": url, "error": str(exc)[:500]}
    finally:
        if conn:
            conn.close()


@dataclasses.dataclass
class Job:
    name: str
    tool: str
    argv: list[str]
    folder: Path
    timeout: int
    outputs: list[str] = dataclasses.field(default_factory=list)
    skip_reason: str = ""


class Runner:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.active = set()

    @staticmethod
    def kill(proc):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()

    def cancel(self):
        self.stop.set()
        with self.lock:
            for proc in list(self.active):
                self.kill(proc)

    def execute(self, job):
        job.folder.mkdir(parents=True, exist_ok=True)
        record = {"name": job.name, "tool": job.tool, "command": shlex.join(job.argv),
                  "argv": job.argv, "folder": str(job.folder), "status": "planned", "elapsed": 0,
                  "exit_code": None, "outputs": job.outputs, "note": ""}
        (job.folder / "command.txt").write_text(record["command"] + "\n", encoding="utf-8")
        if self.dry_run:
            say("[PLAN] " + record["command"])
            return record
        if self.stop.is_set():
            record.update(status="cancelled", note="Run interrupted before starting.")
            return record
        binary = shutil.which(job.argv[0])
        if job.skip_reason or not binary:
            record.update(status="skipped", note=job.skip_reason or f"{job.argv[0]} is not installed/on PATH.")
            say(f"[SKIP] {job.name}: {record['note']}")
            return record
        start = time.monotonic()
        say(f"[START] {job.name}")
        proc = None
        try:
            with (job.folder / "console.log").open("wb") as log:
                with self.lock:
                    if self.stop.is_set():
                        record.update(status="cancelled", note="Run interrupted before starting.")
                        return record
                    # Argument arrays only; shell expansion never executes user input.
                    proc = subprocess.Popen([binary, *job.argv[1:]], stdout=log, stderr=subprocess.STDOUT,
                                            stdin=subprocess.DEVNULL, start_new_session=True)
                    self.active.add(proc)
                deadline = start + job.timeout
                while proc.poll() is None:
                    if self.stop.wait(0.2):
                        self.kill(proc)
                        record.update(status="cancelled", note="Run interrupted.")
                        break
                    if time.monotonic() >= deadline:
                        self.kill(proc)
                        record.update(status="timeout", note="Time limit reached; output may be incomplete.")
                        break
                record["exit_code"] = proc.returncode
                if record["status"] == "planned":
                    record["status"] = "completed" if proc.returncode == 0 else "failed"
                    if proc.returncode != 0:
                        record["note"] = "See console.log for scanner errors/version incompatibilities."
        except OSError as exc:
            record.update(status="failed", note=str(exc))
        except KeyboardInterrupt:
            self.cancel()
            record.update(status="cancelled", note="Run interrupted.")
        finally:
            if proc:
                with self.lock:
                    self.active.discard(proc)
            record["elapsed"] = round(time.monotonic() - start, 2)
        say(f"[{record['status'].upper()}] {job.name} ({record['elapsed']}s)")
        return record


def tool_paths(dry_run=False):
    found = {name: shutil.which(name) for name in ALL_TOOLS}
    # Kali names ProjectDiscovery's executable httpx-toolkit, to avoid Python HTTPX.
    found["httpx"] = shutil.which("httpx-toolkit") or found["httpx"]
    if found["httpx"] and not dry_run:
        try:
            check = subprocess.run([found["httpx"], "-h"], capture_output=True, timeout=10, text=True)
            help_text = check.stdout + check.stderr
            if "-no-fallback-scheme" not in help_text or "-json" not in help_text:
                found["httpx"] = None
        except (OSError, subprocess.TimeoutExpired):
            found["httpx"] = None
    return found


def template_path(args):
    """An explicit path wins; otherwise discover legacy, XDG and Kali locations."""
    if args.templates is not None:
        return args.templates.expanduser().resolve()
    home = Path.home()
    locations = [Path(os.environ['NUCLEI_TEMPLATES_DIR'])] if os.environ.get('NUCLEI_TEMPLATES_DIR') else []
    locations += [home / 'nuclei-templates',
                  Path(os.environ.get('XDG_DATA_HOME', str(home / '.local/share'))) / 'nuclei/nuclei-templates']
    locations += [Path(p) / 'nuclei/nuclei-templates' for p in os.environ.get('XDG_DATA_DIRS', '/usr/local/share:/usr/share').split(os.pathsep)]
    locations += [Path('/usr/share/nuclei-templates')]
    return next((p.resolve() for p in locations if p.is_dir() and next(p.rglob('*.yaml'), None)),
                (home / 'nuclei-templates').resolve())


def apply_profile(args, argv):
    if args.profile != 'lab':
        return
    defaults = {'crawl_pages': 300, 'crawl_depth': 5, 'crawl_timeout': 600,
                'max_sqli_jobs': 20, 'sqli_timeout': 180, 'sqli_techniques': 'BEUT',
                'checks_timeout': 180}
    for name, value in defaults.items():
        flag = '--' + name.replace('_', '-')
        if not any(v == flag or v.startswith(flag + '=') for v in argv):
            setattr(args, name, value)
    args.active_checks = not args.no_active_checks


def build_jobs(args, root, urls, binaries):
    jobs = []
    wordlist = str(args.wordlist.resolve())
    timeout = args.tool_timeout
    rate = str(args.rate)
    enum_names = list(ENUM_TOOLS) if args.enum == "all" else [args.enum]
    if args.enum == "auto":
        enum_names = [next((name for name in ENUM_TOOLS if binaries.get(name)), "ffuf")]
    if args.enum == "none":
        enum_names = []
    for index, url in enumerate(urls, 1):
        prefix = root / f"web-{index:02d}"
        parsed = urllib.parse.urlsplit(url)
        enum_path = parsed.path if parsed.path.endswith('/') else parsed.path.rsplit('/', 1)[0] + '/'
        enum_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, enum_path, '', ''))

        def add(tool, parameters, outputs=(), reason=""):
            folder = prefix / tool
            jobs.append(Job(f"{tool} @ {url}", tool,
                            [binaries.get(tool) or ("httpx-toolkit" if tool == "httpx" else tool),
                             *parameters(folder)], folder, timeout, list(outputs), reason))

        if "httpx" not in args.skip:
            add("httpx", lambda f: ["-u", url, "-nfs", "-sc", "-title", "-server", "-td",
                                   "-json", "-silent", "-duc", "-t", "1", "-rl", rate,
                                   "-timeout", "5", "-o", str(f / "results.jsonl")], ["results.jsonl"],
                "ProjectDiscovery httpx/httpx-toolkit not found; Python HTTPX is a different tool."
                if not binaries.get("httpx") and not args.dry_run else "")
        if "whatweb" not in args.skip:
            add("whatweb", lambda f: ["-a", "1", "--max-redirects=0", "--color=never",
                                     "--log-json=" + str(f / "results.json"), url], ["results.json"])
        for tool in enum_names:
            if tool in args.skip:
                continue
            if tool == "ffuf":
                add(tool, lambda f: ["-u", enum_url + "FUZZ", "-w", wordlist, "-t", "2", "-rate", rate,
                                     "-timeout", "5", "-maxtime", str(timeout), "-ac", "-s",
                                     "-of", "json", "-o", str(f / "results.json")]
                    + (["-k"] if args.insecure else []), ["results.json"])
            elif tool == "gobuster":
                # A single worker and delay approximate the requested per-tool cap.
                add(tool, lambda f: ["dir", "-u", enum_url, "-w", wordlist, "-t", "1", "--delay",
                                     f"{max(1, int(1000 / args.rate))}ms", "--timeout", "5s",
                                     "--no-progress", "-o", str(f / "results.txt")]
                    + (["-k"] if args.insecure else []), ["results.txt"])
            elif tool == "feroxbuster":
                add(tool, lambda f: ["-u", enum_url, "-w", wordlist, "-t", "2", "--rate-limit", rate,
                                     "--no-recursion", "--dont-extract-links", "--no-state",
                                     "--time-limit", f"{timeout}s", "--timeout", "5", "--json",
                                     "--silent", "-o", str(f / "results.jsonl")]
                    + (["-k"] if args.insecure else []), ["results.jsonl"])
            elif tool == "dirsearch":
                add(tool, lambda f: ["-u", enum_url, "-w", wordlist, "-t", "2", "--max-rate", rate,
                                     "--timeout", "5", "--retries", "0", "--format", "json",
                                     "--no-color", "-q", "-o", str(f / "results.json")], ["results.json"])
        if "nikto" not in args.skip:
            add("nikto", lambda f: ["-h", url, "-Tuning", "123b", "-Pause", str(1 / args.rate),
                                   "-timeout", "5", "-maxtime", f"{timeout}s",
                                   "-nocheck", "-nointeractive", "-Format", "json",
                                   "-output", str(f / "results.json")], ["results.json"])
        if "nuclei" not in args.skip:
            templates = template_path(args)
            add("nuclei", lambda f: ["-u", url, "-t", str(templates), "-type", "http",
                                    "-tags", "tech,misconfig,exposure,cve", "-etags",
                                    "dos,fuzz,bruteforce,intrusive,headless,code",
                                    "-dr", "-ni", "-duc", "-rl", rate, "-c", "2", "-bs", "1",
                                    "-timeout", "5", "-retries", "0", "-jsonl", "-silent",
                                    "-o", str(f / "results.jsonl")], ["results.jsonl"],
                f'No YAML templates at {templates}; run nuclei -ut -ud "{templates}" first, or use --templates.'
                if (not templates.is_dir() or next(templates.rglob('*.yaml'), None) is None) and not args.dry_run else "")
    return jobs


def sqlmap_job(args, root, url, parameter, name, automatic=False):
    cmd = ['sqlmap', '-u', url, '-p', parameter, '--batch', '--level=1',
           '--risk=1', '--threads=1', '--technique=' + args.sqli_techniques, '--ignore-redirects', '--ignore-proxy',
           '--delay=' + str(1 / args.rate), '--timeout=10', '--retries=1',
           '-t', str(root / 'traffic.log'),
           '--output-dir=' + str(root / 'session')]
    return Job(name, 'sqlmap', cmd, root,
               min(args.tool_timeout, args.sqli_timeout) if automatic else args.tool_timeout, ['traffic.log'])


def run_discovered(args, root, live, summary, runner, binaries):
    """Discovery and checks are separate stages; only in-scope URLs become inputs."""
    summary['crawl'] = {'status': 'disabled' if args.no_crawl else 'planned',
                        'pages': [], 'discovered': [], 'forms': [], 'limits': []}
    summary['injection'] = {'status': 'disabled' if args.no_auto_sqli else 'pending',
                            'selected': [], 'excluded': []}
    if args.no_crawl or args.dry_run or runner.stop.is_set() or not live:
        if args.dry_run:
            summary['injection']['status'] = 'planned_after_discovery' if not args.no_auto_sqli else 'disabled'
        elif not args.no_auto_sqli:
            summary['injection']['status'] = 'not_run'
        return
    observed, _ = collect(root, summary)
    allowed = {origin(url) for url in live}
    seeds = live + [f['url'] for f in observed if f['category'] == 'endpoint'
                    and f['check'].isdigit() and 200 <= int(f['check']) < 300 and origin(f['url']) in allowed]
    folder = root / 'crawl'
    say('[CRAWL] Discovering same-host pages and GET parameters')
    started = time.monotonic()
    try:
        crawl(seeds, args.target, folder, runner.stop, args.crawl_pages, args.crawl_depth,
              args.rate, args.crawl_timeout, args.insecure, summary['crawl'])
    except KeyboardInterrupt:
        summary['crawl']['status'] = 'cancelled'
        raise
    finally:
        (folder / 'crawl.json').write_text(json.dumps(summary['crawl'], indent=2), encoding='utf-8')
        summary['jobs'].append({'name': 'HTML crawling and passive checks', 'tool': 'crawler',
            'argv': [], 'command': 'Built-in bounded HTTP GET crawler', 'folder': str(folder),
            'outputs': ['crawl.json'], 'status': summary['crawl']['status'],
            'elapsed': round(time.monotonic() - started, 2), 'exit_code': None,
            'note': ', '.join(summary['crawl']['limits'])})
    urls = summary['crawl']['discovered']
    (folder / 'urls.txt').write_text('\n'.join(urls) + ('\n' if urls else ''), encoding='utf-8')
    selected, excluded = select_candidates(urls, args.max_sqli_jobs)
    summary['injection'].update(selected=selected, excluded=excluded)
    if runner.stop.is_set():
        summary['injection']['status'] = 'cancelled'
        return
    if args.active_checks and not args.no_active_checks:
        checks_folder = root / 'checks'
        started = time.monotonic()
        say('[CHECKS] Comparing GET controls with inert reflection and redirect probes')
        try:
            summary['active_checks'] = run_checks(selected, args.target, checks_folder, runner.stop,
                args.rate, args.checks_timeout, args.insecure)
        finally:
            state_file = checks_folder / 'checks.json'
            if state_file.exists():
                state = json.loads(state_file.read_text(encoding='utf-8'))
                summary['active_checks'] = state
                summary['jobs'].append(dict(name='GET differential checks', tool='checks', argv=[],
                    command='Built-in control/probe GET checks; no redirects followed', folder=str(checks_folder),
                    outputs=['checks.json'], status=state['status'], elapsed=round(time.monotonic() - started, 2),
                    exit_code=None, note='No-match is limited to these probes; candidates need validation.'))
    if urls and 'nuclei' not in args.skip:
        job = next(j for j in build_jobs(args, root / 'discovered', [live[0]], binaries) if j.tool == 'nuclei')
        index = job.argv.index('-u')
        job.argv[index:index + 2] = ['-l', str(folder / 'urls.txt')]
        job.name = 'Nuclei discovered URLs'
        summary['jobs'].append(runner.execute(job))
    if args.no_auto_sqli or 'sqlmap' in args.skip:
        summary['injection']['status'] = 'disabled'
        return
    summary['injection']['status'] = 'completed' if selected else 'no_candidates'
    # Automatic injection jobs run sequentially, independent of scanner parallelism.
    for index, candidate in enumerate(selected, 1):
        job = sqlmap_job(args, root / 'auto-sqli' / f'{index:03d}', candidate['url'],
                         candidate['parameter'], f'SQLmap discovered GET {index}: {candidate["parameter"]}', True)
        result = runner.execute(job)
        summary['jobs'].append(result)
        candidate['job'] = result['name']
        candidate['job_status'] = result['status']
        candidate['detection_outcome'] = sqlmap_outcome(result)
        if result['status'] != 'completed':
            summary['injection']['status'] = 'incomplete'
        if runner.stop.is_set():
            summary['injection']['status'] = 'cancelled'
            break


def run_batch(runner, jobs, mode, workers):
    if mode == "sequential":
        return [runner.execute(job) for job in jobs]
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    futures = [pool.submit(runner.execute, job) for job in jobs]
    try:
        # Results retain input order even if execution finishes in a different order.
        return [future.result() for future in futures]
    except KeyboardInterrupt:
        runner.cancel()
        return [future.result() for future in futures]
    finally:
        pool.shutdown(wait=True)


def write_reports(root, summary):
    summary['findings'], summary['parse_issues'] = collect(root, summary)
    ranks = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
    summary['findings'].sort(key=lambda f: (ranks.get(str(f['severity']).lower(), 5), f['url'], f['check']))
    summary['finding_groups'] = finding_groups(summary['findings'])
    severity_counts = {s: 0 for s in ranks}
    for f in summary['finding_groups']:
        if f['category'] in ('scanner_match', 'configuration'):
            s = str(f['severity']).lower()
            severity_counts[s if s in ranks else 'unknown'] += 1
    instance_counts = {s: 0 for s in ranks}
    for f in summary['findings']:
        if f['category'] in ('scanner_match', 'configuration'):
            s = str(f['severity']).lower()
            instance_counts[s if s in ranks else 'unknown'] += 1
    summary['coverage'] = {'severity_counts': severity_counts,
        'severity_instance_counts': instance_counts,
        'observations': len(summary['findings']),
        'parsing_gaps': sum(i.get('kind') != 'manual_review' for i in summary['parse_issues']),
        'adapter_review_notes': sum(i.get('kind') == 'manual_review' for i in summary['parse_issues']),
        'job_gaps': sum(j['status'] in ('skipped', 'failed', 'timeout', 'limited', 'cancelled', 'incomplete') for j in summary['jobs']),
        'crawl_status': summary.get('crawl', {}).get('status', 'not_run'),
        'crawl_requests': summary.get('crawl', {}).get('requests', 0),
        'discovered_urls': len(summary.get('crawl', {}).get('discovered', [])),
        'crawl_errors': sum('error' in p for p in summary.get('crawl', {}).get('pages', [])),
        'truncated_pages': sum(bool(p.get('truncated')) for p in summary.get('crawl', {}).get('pages', [])),
        'forms_for_manual_review': sum(bool(f.get('reason')) for f in summary.get('crawl', {}).get('forms', [])),
        'crawl_limits': summary.get('crawl', {}).get('limits', []),
        'sqli_status': summary.get('injection', {}).get('status', 'not_run'),
        'sqli_selected': len(summary.get('injection', {}).get('selected', [])),
        'sqli_excluded': len(summary.get('injection', {}).get('excluded', [])),
        'sqli_inconclusive': sum(c.get('detection_outcome') in ('inconclusive', 'incomplete')
            for c in summary.get('injection', {}).get('selected', [])),
        'active_checks_status': summary.get('active_checks', {}).get('status', 'not_run'),
        'active_checks_requests': summary.get('active_checks', {}).get('requests', 0)}
    summary['report_schema_version'] = 3
    (root / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    esc = lambda value: html.escape(str(value), quote=True)
    port_rows = "".join("<tr>" + "".join(f"<td>{esc(p.get(k, ''))}</td>" for k in
                                     ("port", "service", "product", "version")) + "</tr>"
                        for p in summary["ports"])
    url_rows = "".join("<tr>" + "".join(f"<td>{esc(p.get(k, ''))}</td>" for k in
                                    ("url", "status", "title", "server", "location", "error")) + "</tr>"
                       for p in summary["probes"])
    job_rows = []
    for job in summary["jobs"]:
        folder = Path(job["folder"])
        links = []
        for filename in ["command.txt", "console.log", *job["outputs"]]:
            path = folder / filename
            if path.is_file():
                rel = urllib.parse.quote(path.relative_to(root).as_posix())
                links.append(f'<a href="{esc(rel)}">{esc(filename)}</a>')
        job_rows.append(f"<tr><td>{esc(job['name'])}</td><td>{esc(job['status'])}</td>"
                        f"<td>{esc(job['elapsed'])}</td><td>{esc(job['note'])}</td>"
                        f"<td>{' · '.join(links)}</td></tr>")
    finding_rows = []
    for finding in summary['findings']:
        links = ' · '.join(f'<a href="{esc(urllib.parse.quote(e["file"]))}">{esc(e["tool"])} record {e["record"]}</a>'
                           for e in finding['evidence'])
        finding_rows.append(f'<tr><td>{esc(finding["title"])}<br><small>{esc(finding["category"])}</small></td><td>{esc(finding["url"])}</td>'
                            f'<td>{esc(finding["severity"])}</td><td>needs_validation</td><td>{links}</td>'
                            f'<td>{esc(finding.get("recommendation", ""))}</td></tr>')
    issues = ''.join(f'<li>{esc(json.dumps(issue, ensure_ascii=False))}</li>' for issue in summary['parse_issues'])
    coverage_rows = ''.join(f'<tr><th>{esc(k)}</th><td>{esc(json.dumps(v) if isinstance(v, (dict, list)) else v)}</td></tr>'
                            for k, v in summary['coverage'].items())
    injection_rows = ''.join('<tr>' + ''.join(f'<td>{esc(c.get(k, ""))}</td>' for k in ('url', 'parameter', 'job_status', 'detection_outcome', 'reason')) + '</tr>'
                              for c in summary.get('injection', {}).get('selected', []) + summary.get('injection', {}).get('excluded', []))
    grouped_rows = ''.join('<tr><td>' + esc(g['title']) + '</td><td>' + esc(g['severity']) +
        '</td><td>needs_validation</td><td><details><summary>' + str(len(g['urls'])) +
        ' affected URL(s)</summary>' + '<br>'.join(esc(u) for u in g['urls']) + '</details></td></tr>'
        for g in summary['finding_groups'] if g['category'] in ('scanner_match', 'configuration'))
    forms_rows = ''.join('<tr>' + ''.join(f'<td>{esc(f.get(k, ""))}</td>'
        for k in ('source', 'method', 'action', 'reason')) + '</tr>'
        for f in summary.get('crawl', {}).get('forms', []) if f.get('reason'))
    report = f"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Abdulla WebScan — {esc(summary['target'])}</title>
<style>body{{background:#101827;color:#e6edf7;font:15px system-ui;margin:0;padding:32px}}
main{{max-width:1400px;margin:auto}}h1{{color:#85ddce}}h2{{margin-top:32px}}a{{color:#85ddce}}
table{{width:100%;border-collapse:collapse;background:#172235}}td,th{{text-align:left;padding:12px;
border-bottom:1px solid #2e3e55;vertical-align:top;overflow-wrap:anywhere}}th{{color:#a3b8cf}}
.scroll{{overflow:auto}}.note{{background:#203149;padding:16px;border-radius:8px;line-height:1.6}}
</style><main><h1>Abdulla WebScan</h1><p>Target: {esc(summary['target'])} ·
{esc(summary['created'])} · Mode: {esc(summary['mode'])}</p>
<div class="note">{esc(summary['outcome'])}<br>Scanner matches require manual validation.
Completed means the process exited successfully; it does not certify the site is secure.
Skipped, failed, timeout and cancelled jobs leave gaps in coverage. This is an evidence index,
not a validated penetration testing report. Each active web job uses its own rate cap;
parallel mode adds those rates. HTTP errors and redirects are recorded as responses.
Redirect destinations are displayed for review.</div>
<h2>Assessment coverage</h2><p>Unauthenticated web assessment of one host. Nmap target: {esc(summary.get('scan_ip', summary['target']))}.
HTTP uses the target hostname for Host headers, TLS SNI and certificate verification. Severity counts group repeated header checks per origin; instance counts retain affected responses. All counts describe unvalidated scanner/configuration matches;
endpoint and technology observations are excluded from these counts. Coverage limits and gaps do not mean the target is secure.</p>
<div class="scroll"><table>{coverage_rows}</table></div>
<h2>Grouped assessment findings</h2><p>Repeated header notes are grouped; individual URLs and raw evidence remain below.</p>
<div class="scroll"><table><tr><th>Observation</th><th>Severity</th><th>Validation</th><th>Affected URLs</th></tr>{grouped_rows}</table></div>
<h2>Discovered GET parameter checks</h2><p>Candidates are not proof of injection. Checks use SQLmap detection only.
POST forms, JavaScript execution and authenticated workflows require separate review.</p>
<div class="scroll"><table><tr><th>URL</th><th>Parameter</th><th>Job status</th><th>Detection outcome</th><th>Selection/review reason</th></tr>{injection_rows}</table></div>
<h2>Deferred forms</h2><div class="scroll"><table><tr><th>Source</th><th>Method</th><th>Action</th><th>Review reason</th></tr>{forms_rows}</table></div>
<h2>Unified findings ({len(summary['findings'])})</h2><p>Severity is scanner-reported; every observation needs validation.
Distinct checks, queries, schemes, ports and HTTP statuses remain separate.</p>
<div class="scroll"><table><tr><th>Observation</th><th>URL</th><th>Scanner severity</th><th>Validation</th><th>Evidence</th><th>Recommended review/remediation</th></tr>
{''.join(finding_rows)}</table></div><h2>Parsing and manual review gaps</h2><ul>{issues}</ul>
<h2>Open TCP ports</h2><div class="scroll"><table><tr><th>Port</th><th>Service</th>
<th>Product</th><th>Version</th></tr>{port_rows}</table></div>
<h2>HTTP discovery</h2><div class="scroll"><table><tr><th>URL</th><th>Status</th><th>Title</th>
<th>Server</th><th>Redirect location</th><th>Probe error</th></tr>{url_rows}</table></div>
<h2>Tasks and raw evidence</h2><div class="scroll"><table><tr><th>Task</th><th>Status</th>
<th>Seconds</th><th>Notes</th><th>Files</th></tr>{''.join(job_rows)}</table></div>
<h2>Manual follow-up</h2><p>Use Burp Suite to inspect authentication, authorization, IDOR,
business logic, POST forms and XSS. Crawled GET parameters are selected for bounded SQLmap
checks; unlinked routes, JavaScript-only pages and authenticated endpoints may remain undiscovered.
</p><p><a href="summary.json">summary.json</a></p></main></html>"""
    (root / "report.html").write_text(report, encoding="utf-8")


def parser():
    p = argparse.ArgumentParser(description="Abdulla WebScan: one-host web assessment pipeline for authorized labs.")
    p.add_argument("target", nargs="?", type=target_input, help="One IPv4/IPv6, hostname, or HTTP(S) URL; prompted if omitted.")
    p.add_argument("--mode", choices=("sequential", "parallel"), default="sequential")
    p.add_argument('--profile', choices=('standard', 'lab'), default='standard',
                   help='lab: larger crawl budgets, BEUT SQLi detection and bounded differential GET checks.')
    p.add_argument('--report-only', type=Path, help='Rebuild reports from an existing run directory; no network/scanners.')
    p.add_argument("--workers", type=positive, default=2, help="Concurrent web tools, default 2.")
    p.add_argument("--enum", choices=("auto", *ENUM_TOOLS, "all", "none"), default="auto")
    p.add_argument("--ports", type=ports, help="TCP ports/ranges; default Nmap's top 1000.")
    p.add_argument("--all-ports", action="store_true", help="TCP 1-65535; slower.")
    p.add_argument("--url", action="append", default=[], help="Additional same-host HTTP(S) base URL, useful for unusual ports.")
    p.add_argument("--wordlist", type=Path, default=Path(__file__).resolve().parent / "wordlist.txt")
    p.add_argument("--templates", type=Path, help='Local Nuclei YAML root; auto-detect legacy, XDG or Kali directories.')
    p.add_argument("--rate", type=positive, default=5, help="Approximate web requests/sec per tool, not global.")
    p.add_argument("--tool-timeout", type=positive, default=600, help="Seconds per external web job.")
    p.add_argument("--nmap-timeout", type=positive, default=900, help="Seconds for Nmap.")
    p.add_argument("--insecure", action="store_true", help="Accept self-signed lab TLS during discovery and supported tools.")
    p.add_argument("--skip", nargs="*", choices=ALL_TOOLS, default=[])
    p.add_argument("--dry-run", action="store_true", help="Write and print a plan without subprocesses or network requests.")
    p.add_argument("--check", action="store_true", help="List installed tool paths and exit; no target needed.")
    p.add_argument("--sqlmap-url", help="Optional specific same-host GET URL for a separate SQLi detection job.")
    p.add_argument("--sqlmap-param", help="Existing GET parameter name to test, e.g. id.")
    p.add_argument('--no-crawl', action='store_true', help='Disable automatic HTML discovery and checks derived from it.')
    p.add_argument('--crawl-pages', type=positive, default=100, help='Maximum crawler GET requests, default 100.')
    p.add_argument('--crawl-depth', type=positive, default=3, help='Maximum link depth, default 3.')
    p.add_argument('--crawl-timeout', type=positive, default=120, help='Crawler time budget in seconds, default 120.')
    p.add_argument('--no-auto-sqli', action='store_true', help='Inventory GET parameters without automatic SQLmap checks.')
    p.add_argument('--max-sqli-jobs', type=positive, default=10, help='Maximum discovered URL/parameter checks, default 10.')
    p.add_argument('--sqli-timeout', type=positive, default=120, help='Seconds per automatic SQLmap job, default 120.')
    p.add_argument('--sqli-techniques', choices=('BEU', 'BEUT'), default='BEU', help='BEUT also includes time-based blind detection.')
    p.add_argument('--active-checks', action='store_true', help='Bounded inert HTML reflection and external redirect GET probes.')
    p.add_argument('--no-active-checks', action='store_true', help='Disable differential checks, including in lab profile.')
    p.add_argument('--checks-timeout', type=positive, default=120, help='Time budget for differential checks.')
    p.add_argument("--output", type=Path, default=Path("results"), help="Parent folder; every run gets a new directory.")
    p.add_argument("--version", action="version", version=VERSION)
    return p


def main(argv=None):
    p = parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    args = p.parse_args(argv)
    apply_profile(args, argv)
    if args.report_only:
        root = args.report_only.expanduser().resolve()
        try:
            summary = json.loads((root / 'summary.json').read_text(encoding='utf-8'))
            for candidate in summary.get('injection', {}).get('selected', []):
                job = next((j for j in summary['jobs'] if j['name'] == candidate.get('job')), None)
                if job:
                    candidate['detection_outcome'] = sqlmap_outcome(job)
            summary['report_generator_version'] = VERSION
            write_reports(root, summary)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            p.error(f'Cannot rebuild this run: {exc}')
        say(f'Rebuilt report: {root / "report.html"}')
        return 0
    if os.name != "posix":
        p.error("Run under Kali/Linux or WSL; native Windows is not supported.")
    if args.check:
        for name, path in tool_paths(args.dry_run).items():
            say(f"{name:12} {path or 'MISSING'}")
        templates = template_path(args)
        available = templates.is_dir() and next(templates.rglob('*.yaml'), None) is not None
        say(f'Nuclei YAML: {templates} ({"found" if available else "MISSING"})')
        return 0
    if not args.target:
        try:
            args.target = target_input(input("Lab target IP, hostname or URL: "))
        except (argparse.ArgumentTypeError, EOFError) as exc:
            p.error(str(exc))
    if args.ports and args.all_ports:
        p.error("Use either --ports or --all-ports.")
    if args.workers > 8 or args.rate > 50:
        p.error("Use workers <= 8 and rate <= 50 for this lab runner.")
    if args.crawl_pages > 1000 or args.crawl_depth > 10 or args.max_sqli_jobs > 50:
        p.error('Use crawl-pages <= 1000, crawl-depth <= 10 and max-sqli-jobs <= 50.')
    if bool(args.sqlmap_url) != bool(args.sqlmap_param):
        p.error("Use --sqlmap-url and --sqlmap-param together.")
    try:
        prepare_target(args)
        if args.input_url:
            u = urllib.parse.urlsplit(args.input_url)
            if args.ports and (u.port or (443 if u.scheme == 'https' else 80)) not in listed_ports(args.ports):
                raise ValueError('The target URL port is outside --ports.')
        for index, url in enumerate(args.url):
            args.url[index] = scoped_url(url, args.target)
            u = urllib.parse.urlsplit(url)
            if u.query:
                raise ValueError("--url is a base URL without query parameters; use --sqlmap-url for SQLmap.")
            if args.ports and (u.port or (443 if u.scheme == "https" else 80)) not in listed_ports(args.ports):
                raise ValueError("An explicit URL port is outside --ports.")
        if args.sqlmap_url:
            args.sqlmap_url = scoped_url(args.sqlmap_url, args.target)
            sql_url = urllib.parse.urlsplit(args.sqlmap_url)
            if args.ports and (sql_url.port or (443 if sql_url.scheme == "https" else 80)) not in listed_ports(args.ports):
                raise ValueError("The SQLmap URL port is outside --ports.")
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.sqlmap_param):
                raise ValueError("Use one plain GET parameter name for --sqlmap-param.")
            if args.sqlmap_param not in urllib.parse.parse_qs(urllib.parse.urlsplit(args.sqlmap_url).query,
                                                             keep_blank_values=True):
                raise ValueError("The SQLmap parameter must exist in the URL query string.")
    except (ValueError, OSError, argparse.ArgumentTypeError) as exc:
        p.error(str(exc))
    args.wordlist = args.wordlist.expanduser()
    if args.enum != "none" and not args.wordlist.is_file():
        p.error(f"Wordlist not found: {args.wordlist}")
    root = args.output.expanduser().resolve() / (
        re.sub(r'[^A-Za-z0-9_.-]', '_', args.target) + "_" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6])
    root.mkdir(parents=True)
    runner = Runner(args.dry_run)
    summary = {"version": VERSION, "target": args.target, "input_target": args.input_target,
               "input_url": args.input_url, "scan_ip": args.scan_ip,
               "created": dt.datetime.now(dt.timezone.utc).isoformat(),
               "mode": args.mode, "profile": args.profile, "sqli_techniques": args.sqli_techniques,
               "dry_run": args.dry_run, "ports": [], "probes": [], "jobs": [],
               "outcome": "Discovery started."}
    say(f"Abdulla WebScan {VERSION} | target {args.target} | {args.mode}\nResults: {root}")
    try:
        if "nmap" not in args.skip:
            folder = root / "nmap"
            cmd = ["nmap", "-sT", "-sV", "--version-light", "-Pn", "-n", "-T3", "--max-rate", "100",
                   "--max-retries", "1", "--host-timeout", f"{args.nmap_timeout}s"]
            if ':' in args.scan_ip:
                cmd.append('-6')
            cmd += ["-p", "1-65535"] if args.all_ports else (["-p", args.ports] if args.ports else ["--top-ports", "1000"])
            cmd += ["-oX", str(folder / "services.xml"), args.scan_ip]
            result = runner.execute(Job("Nmap TCP/services", "nmap", cmd, folder,
                                        args.nmap_timeout + 10, ["services.xml"]))
            summary["jobs"].append(result)
            if not args.dry_run and (folder / "services.xml").exists():
                try:
                    summary["ports"] = parse_nmap(folder / "services.xml", args.scan_ip)
                except (ET.ParseError, ValueError, OSError) as exc:
                    summary["outcome"] = "Nmap XML incomplete/unreadable: " + str(exc)
        # If Nmap is absent/failed, only try common ports within a requested port scope.
        fallback = sorted(COMMON_WEB_PORTS & listed_ports(args.ports)) if args.ports else sorted(COMMON_WEB_PORTS)
        services = summary["ports"] or [{"port": port, "service": "unknown"} for port in fallback]
        base_urls = [url.rstrip('/') + '/' for url in args.url]
        if args.input_url:
            base_urls.insert(0, args.input_url)
        candidate_urls = list(dict.fromkeys(base_urls + ([] if args.url_only else candidates(args.target, services))))
        if args.dry_run:
            live = candidate_urls
            summary["outcome"] = "Dry run: planned commands only; HTTP discovery and scanners were not executed."
        else:
            live = []
            for url in candidate_urls:
                if runner.stop.is_set():
                    break
                result = probe(url, args.insecure)
                summary["probes"].append(result)
                if "status" in result:
                    live.append(url)
                    say(f"[HTTP] {result['status']} {url} {result['title'][:80]}")
                write_reports(root, summary)
            summary["outcome"] = f"{len(live)} responding HTTP(S) base URLs."
            if not live:
                summary["outcome"] += " No web tool jobs started; check the IP, ports, TLS or use --url."
        (root / "urls.txt").write_text("\n".join(live) + ("\n" if live else ""), encoding="utf-8")
        binaries = tool_paths(args.dry_run) if not runner.stop.is_set() else {}
        jobs = build_jobs(args, root, live, binaries)
        summary["jobs"].extend(run_batch(runner, jobs, args.mode, args.workers))
        run_discovered(args, root, live, summary, runner, binaries)
        if args.sqlmap_url and "sqlmap" not in args.skip:
            folder = root / "sqlmap"
            summary["jobs"].append(runner.execute(sqlmap_job(args, folder, args.sqlmap_url,
                                    args.sqlmap_param, 'SQLmap selected GET parameter')))
    except KeyboardInterrupt:
        runner.cancel()
        summary["outcome"] = "Run interrupted; reports contain only available evidence."
    finally:
        if runner.stop.is_set():
            summary["outcome"] = "Run interrupted; results are incomplete."
        write_reports(root, summary)
        say(f"\nReport: {root / 'report.html'}")
    if runner.stop.is_set():
        return 130
    if args.dry_run:
        return 0
    # Report incomplete coverage even if other scanners succeeded.
    if not any("status" in row for row in summary["probes"]) and not args.sqlmap_url:
        return 2
    return 2 if (any(j["status"] in ("skipped", "failed", "timeout", "limited", "incomplete") for j in summary["jobs"])
                 or summary.get('injection', {}).get('excluded')
                 or summary['coverage']['parsing_gaps'] or summary['coverage']['sqli_inconclusive']
                 or any('error' in page or page.get('truncated') for page in summary.get('crawl', {}).get('pages', []))) else 0


if __name__ == "__main__":
    raise SystemExit(main())
