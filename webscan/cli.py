#!/usr/bin/env python3
"""The World Is Yours single-host assessment runner. Python 3.10+, Linux/Kali/WSL.

External scanners stay external: this script schedules them and records evidence.
"""
from __future__ import annotations
from .paths import PROJECT_ROOT

import argparse
from . import web_review
from . import reporting
from . import scan_modes
from . import run_history
import base64
import concurrent.futures
import dataclasses
import datetime as dt
import html
import hashlib
import http.client
import ipaddress
import json
import math
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
from .findings import collect
from .crawler import crawl, select_candidates, origin
from .scope import parse_target, prepare_target, normalize_url, authority
from .checks import run_checks, run_sensitive_files, run_cors
from .scope import RequestGate
from .terminal import TerminalUI, BANNER
from .findings import finding_groups, sqlmap_outcome
from . import nmap_scan
from . import evidence
from . import assessment
from . import advanced
from . import reliability
from . import technology
from . import scan_diagnostics
from . import web_engine
from . import whatweb_snapshot
from . import tool_coverage
from .transport import connection

from .brand import VERSION
UI = TerminalUI('plain')
ENUM_TOOLS = ("ffuf", "gobuster", "feroxbuster", "dirsearch")
ALL_TOOLS = ("nmap", "httpx", "whatweb", *ENUM_TOOLS, "nikto", "nuclei", "sqlmap", "wpscan", *web_engine.TOOLS)
COMMON_WEB_PORTS = {80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000}
PRINT_LOCK = threading.Lock()
REPORT_SCRIPT = (PROJECT_ROOT / 'assets' / 'report.js').read_text(encoding='utf-8')


def say(message):
    with PRINT_LOCK:
        UI.message(message)


def nonnegative(value):
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise argparse.ArgumentTypeError('Must be a finite nonnegative number.')
    return number


def with_progress(name, function, *positional, **options):
    with UI.stage(name) as progress:
        if progress:
            options['progress'] = progress
        return function(*positional, **options)


from .reporting import export_reports


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
    try:
        return scan_modes.parse_ports(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


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
    """Compatible strict parser for observed open TCP services on one target IP."""
    return nmap_scan.read_xml(path, target)[0]


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


def probe(url, insecure=False, timeout=5, scan_ip=None):
    """One GET, bounded response, no redirects, no environment proxies or DNS."""
    u = urllib.parse.urlsplit(url)
    conn = None
    try:
        conn = connection(url, insecure, timeout, scan_ip)
        conn.request("GET", urllib.parse.urlunsplit(('', '', u.path or '/', u.query, '')),
                     headers={"User-Agent": "The World Is Yours/" + VERSION})
        request = evidence.request_details(conn)
        response = conn.getresponse()
        body_error = ''
        try:
            body = response.read(65536).decode("utf-8", "replace")
        except (OSError, http.client.HTTPException) as exc:
            # A slow/broken body does not erase an already observed HTTP response.
            body, body_error = '', 'Response headers received; body read failed: ' + str(exc)[:400]
        hints = technology.detect(url, response.getheaders(), body)
        title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        result = {"url": url, "status": response.status, "technologies": hints, 'request': request, 'headers': [list(p) for p in response.getheaders()], "server": response.getheader("Server", ""),
                "title": html.unescape(re.sub(r"\s+", " ", title.group(1))).strip() if title else "",
                "location": response.getheader("Location", ""), "retry_after": response.getheader("Retry-After", ""), "tls_verified": u.scheme == "https" and not insecure}
        if body_error:
            result['error'] = body_error
        return result
    except Exception as exc:
        reliability.record('http_discovery', exc)
        return {"url": url, "error": str(exc)[:500], 'error_kind': scan_diagnostics.error_kind(exc)}
    finally:
        if conn:
            conn.close()


from .process_runner import Job, ProcessRunner


class Runner(ProcessRunner):
    """Bind the process runner to the active terminal UI."""
    def __init__(self, dry_run=False):
        super().__init__(dry_run, notify=say)


def tool_paths(dry_run=False, selected=None):
    found = {name: shutil.which(name) for name in ALL_TOOLS if selected is None or name in selected}
    # Kali names ProjectDiscovery's executable httpx-toolkit, to avoid Python HTTPX.
    if "httpx" in found:
        found["httpx"] = shutil.which("httpx-toolkit") or found["httpx"]
    if found.get("httpx") and not dry_run:
        try:
            check = subprocess.run([found["httpx"], "-h"], capture_output=True, timeout=10, text=True)
            help_text = check.stdout + check.stderr
            if "-no-fallback-scheme" not in help_text or "-json" not in help_text:
                found["httpx"] = None
        except (OSError, subprocess.TimeoutExpired):
            found["httpx"] = None
    if "testssl" in found:
        found["testssl"] = shutil.which("testssl.sh") or found["testssl"]
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
    if args.profile == 'web':
        args.active_checks = not args.no_active_checks
        args.builtin_sqli = not args.no_active_checks
        args.sensitive_files = True
        args.api_discovery = True
        return
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

        def add(tool, parameters, outputs=(), reason="", snapshot=None):
            folder = prefix / tool
            jobs.append(Job(f"{tool} @ {url}", tool,
                            [binaries.get(tool) or ("httpx-toolkit" if tool == "httpx" else tool),
                             *parameters(folder)], folder, timeout, list(outputs), reason, snapshot))

        if "httpx" not in args.skip:
            add("httpx", lambda f: ["-u", url, "-nfs", "-sc", "-title", "-server", "-td",
                                   "-json", "-silent", "-duc", "-t", "1", "-rl", rate,
                                   "-timeout", "5", "-o", str(f / "results.jsonl")], ["results.jsonl"],
                "ProjectDiscovery httpx/httpx-toolkit not found; Python HTTPX is a different tool."
                if not binaries.get("httpx") and not args.dry_run else "")
        if "whatweb" not in args.skip:
            try:
                ipaddress.ip_address(parsed.hostname)
                snapshot = None
            except ValueError:
                snapshot = dict(url=url, scan_ip=getattr(args, 'scan_ip', None), insecure=args.insecure,
                                timeout=args.http_timeout)
            add("whatweb", lambda f: ["-a", "1", "--follow-redirect=never", "--color=never",
                                     "--max-threads=1", "--open-timeout=" + str(args.http_timeout),
                                     "--read-timeout=" + str(args.http_timeout),
                                     "--log-json=" + str(f / "results.json"),
                                     str(f / 'response.http') if snapshot else url], ["results.json"], snapshot=snapshot)
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


def run_web_engines(args, root, live, summary, runner, binaries, selected=None):
    """Discovery precedes crawling; Dalfox runs independently of SQLmap opt-out."""
    phase = 'parameters' if selected is not None else 'discovery'
    state = summary.setdefault('web_engines', {})
    state.setdefault(phase, [])
    if not args.external_tools or getattr(args, 'session', None):
        state[phase + '_status'] = 'disabled' if not args.external_tools else 'authenticated_session_deferred'
        return
    compatibility = state.setdefault('compatibility', {})
    tools = ('dalfox',) if selected is not None else ('katana', 'testssl')
    for tool in tools:
        if tool in args.skip or runner.stop.is_set():
            continue
        if tool == 'katana' and args.no_crawl and tool not in (args.only or []):
            continue
        if tool not in compatibility and not args.dry_run:
            compatibility[tool] = web_engine.compatibility(tool, binaries.get(tool))
        targets = [(entry['url'], entry['parameter']) for entry in selected] if selected is not None else [(url, None) for url in live]
        if not targets:
            state[phase].append(dict(tool=tool, status='no_candidates'))
        for index, (url, parameter) in enumerate(targets, 1):
            if tool == 'testssl' and not url.startswith('https://'):
                continue
            folder = root / 'web-engines' / tool / f'{index:03d}'
            web_engine.prepare(tool, folder)
            argv, output, reason = web_engine.command(tool, binaries.get(tool), url, folder, args, parameter)
            result = runner.execute(Job(f'{tool} @ {url}', tool, argv, folder,
                args.tool_timeout if tool != 'katana' else args.crawl_timeout,
                [output], reason or compatibility.get(tool, '')))
            summary['jobs'].append(result)
            state[phase].append(dict(tool=tool, url=url, status=result['status'], reason=result.get('note', '')))
            if runner.stop.is_set():
                break


def run_technology_plan(args, root, live, summary, runner, binaries):
    """Fingerprint first; specialized adapters run after bounded route discovery."""
    observed, _ = collect(root, summary)
    view = dict(summary, findings=observed)
    summary['technology_plan'] = technology.plan(live, view)
    (root / 'technology-plan.json').write_text(evidence.dumps(summary['technology_plan']), encoding='utf-8')
    for index, row in enumerate(summary['technology_plan'], 1):
        if 'wpscan' in args.skip:
            row.update(wpscan='disabled', reason='WPScan disabled by tool selection or external-scanner policy.')
            continue
        explicit = 'wpscan' in (args.only or [])
        if row['wpscan'] != 'eligible' and not explicit:
            continue
        reason = ''
        folder = root / f'web-{index:02d}' / 'wpscan'
        argv = [binaries.get('wpscan') or 'wpscan', '--url', row['url'],
                '--format', 'json', '--output', str(folder / 'results.json'),
                '--no-update', '--ignore-main-redirect', '--enumerate', 'vp,vt', '--detection-mode', 'passive',
                '--plugins-detection', 'passive', '--plugins-version-detection', 'passive',
                '--max-threads', '1', '--throttle', str(max(1, int(1000 / args.rate))),
                '--request-timeout', str(args.http_timeout), '--connect-timeout', str(args.http_timeout)]
        if args.insecure:
            argv.append('--disable-tls-checks')
        job = runner.execute(Job('wpscan @ ' + row['url'], 'wpscan', argv, folder,
                                 args.tool_timeout, ['results.json'], reason))
        summary['jobs'].append(job)
        row['wpscan'] = job['status']
        row['reason'] = job['note'] or ('Explicit tool selection.' if explicit else row['reason'])
        row['coverage_note'] = 'Passive inventory only; vulnerability metadata requires a configured WPScan API token or database. Empty results do not establish safety.'
    (root / 'technology-plan.json').write_text(evidence.dumps(summary['technology_plan']), encoding='utf-8')


def sqlmap_job(args, root, url, parameter, name, automatic=False):
    cmd = ['sqlmap', '-u', url, '-p', parameter, '--batch', '--level=1',
           '--risk=1', '--threads=1', '--technique=' + args.sqli_techniques, '--ignore-redirects', '--ignore-proxy',
           '--delay=' + str(1 / args.rate), '--timeout=10', '--retries=1',
           '-t', str(root / 'traffic.log'),
           '--output-dir=' + str(root / 'session')]
    return Job(name, 'sqlmap', cmd, root,
               min(args.tool_timeout, args.sqli_timeout) if automatic else args.tool_timeout, ['traffic.log'])


def stage_snapshot(path, fallback):
    """A corrupt/missing checkpoint must not abort unrelated web stages."""
    try:
        state = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(state, dict) or 'status' not in state:
            raise ValueError('Invalid stage checkpoint')
        return state
    except FileNotFoundError:
        return fallback
    except Exception as exc:
        state = dict(fallback, status='incomplete', error=reliability.record('stage_checkpoint', exc))
        return state


def stage_failure(summary, root, name, tool, exc):
    error = reliability.record(name, exc)
    say(f'[INCOMPLETE] {name}: {error}; continuing with remaining stages.')
    summary['jobs'].append(dict(name=name, tool=tool, argv=[], command='', folder=str(root),
        outputs=['checks.json'] if tool == 'checks' and (root / 'checks.json').is_file() else [],
        status='incomplete', elapsed=0, exit_code=None, note=error))
    return error


def run_file_stage(args, root, live, summary, runner):
    files_folder = root / 'sensitive-files'
    started = time.monotonic()
    try:
        summary['sensitive_files'] = with_progress('Checking sensitive files', run_sensitive_files,
            live, args.target, args.wordlist, files_folder, runner.stop, rate=args.rate,
            timeout=args.checks_timeout, request_timeout=args.http_timeout, insecure=args.insecure, session=getattr(args, 'session', None),
            workers=args.http_workers, delay=args.delay, gate=getattr(args, 'request_gate', None), limit=args.file_limit, scan_ip=getattr(args, 'scan_ip', None), retain_raw=getattr(args, 'retain_raw_evidence', False))
    finally:
        state_file = files_folder / 'checks.json'
        if state_file.exists():
            state = stage_snapshot(state_file, {'status': 'incomplete'})
            summary['sensitive_files'] = state
            summary['jobs'].append(dict(name='Sensitive file content checks', tool='checks', argv=[],
                command='Built-in scoped GET probes with soft-404 control', folder=str(files_folder),
                outputs=['checks.json'], status=state['status'], elapsed=round(time.monotonic() - started, 2),
                exit_code=None, note='Content signatures are candidates needing validation.'))


def run_discovered(args, root, live, summary, runner, binaries):
    """Discovery and checks are separate stages; only in-scope URLs become inputs."""
    summary['crawl'] = {'status': 'disabled' if args.no_crawl else 'planned',
                        'pages': [], 'discovered': [], 'forms': [], 'limits': []}
    summary['injection'] = {'status': 'disabled' if args.no_auto_sqli else 'pending',
                            'selected': [], 'excluded': []}
    if args.sensitive_files and not args.dry_run and not runner.stop.is_set() and live:
        try:
            run_file_stage(args, root, live, summary, runner)
        except Exception as exc:
            summary['sensitive_files'] = dict(status='incomplete', error=stage_failure(
                summary, root, 'Sensitive file stage', 'checks', exc))
    if (args.profile == 'web' or getattr(args, 'cors_checks', False)) and not args.no_active_checks and not args.dry_run and not runner.stop.is_set() and live:
        cors_folder = root / 'cors'
        started = time.monotonic()
        try:
            summary['cors'] = with_progress('Checking CORS origins', run_cors, live, args.target, cors_folder, runner.stop,
                gate=getattr(args, 'request_gate', None), timeout=args.checks_timeout, request_timeout=args.http_timeout,
                scan_ip=getattr(args, 'scan_ip', None), session=getattr(args, 'session', None),
                insecure=args.insecure, retain_raw=args.retain_raw_evidence)
            summary['jobs'].append(dict(name='CORS origin comparisons', tool='checks', argv=[],
                command='GET control and two inert Origin headers', folder=str(cors_folder), outputs=['checks.json'],
                status=summary['cors']['status'], elapsed=round(time.monotonic() - started, 2), note='Browser impact requires validation.'))
        except Exception as exc:
            summary['cors'] = dict(status='incomplete', error=stage_failure(
                summary, cors_folder, 'CORS stage', 'checks', exc))
    if args.no_crawl or args.dry_run or runner.stop.is_set() or not live:
        if args.dry_run:
            summary['injection']['status'] = 'planned_after_discovery' if not args.no_auto_sqli else 'disabled'
        elif not args.no_auto_sqli:
            summary['injection']['status'] = 'not_run'
        return
    observed, _ = collect(root, summary)
    allowed = {origin(url) for url in live}
    engine_urls, engine_rejected = web_engine.discovered_urls(summary['jobs'], live, args.target, args.crawl_pages)
    summary.setdefault('web_engines', {}).update(discovered=len(engine_urls), rejected=engine_rejected)
    seeds = live + engine_urls + [f['url'] for f in observed if f['category'] == 'endpoint'
                    and not any(e.get('tool') == 'katana' for e in f['evidence'])
                    and f['check'].isdigit() and 200 <= int(f['check']) < 400 and origin(f['url']) in allowed]
    folder = root / 'crawl'
    folder.mkdir(parents=True, exist_ok=True)
    say('[CRAWL] Discovering same-host pages and GET parameters')
    started = time.monotonic()
    try:
        options = {'workers': args.http_workers, 'delay': args.delay,
                   'gate': getattr(args, 'request_gate', None), 'scan_ip': getattr(args, 'scan_ip', None),
                   'retain_raw': getattr(args, 'retain_raw_evidence', False), 'api_paths': True,
                   'request_timeout': args.http_timeout, 'metadata_paths': not getattr(args, 'no_web_metadata', False)}
        if args.crawl_redirects:
            options['follow_redirects'] = True
        if getattr(args, 'session', None):
            options['session'] = args.session
        with_progress('Discovering routes', crawl, seeds, args.target, folder, runner.stop, args.crawl_pages, args.crawl_depth,
              args.rate, args.crawl_timeout, args.insecure, summary['crawl'], **options)
    except KeyboardInterrupt:
        summary['crawl']['status'] = 'cancelled'
        raise
    except Exception as exc:
        summary['crawl'].update(status='incomplete', error=stage_failure(
            summary, root, 'Crawl stage', 'crawler', exc))
    finally:
        (folder / 'crawl.json').write_text(evidence.dumps(summary['crawl']), encoding='utf-8')
        summary['jobs'].append({'name': 'HTML crawling and passive checks', 'tool': 'crawler',
            'argv': [], 'command': 'Built-in bounded HTTP GET crawler', 'folder': str(folder),
            'outputs': ['crawl.json'], 'status': summary['crawl']['status'],
            'elapsed': round(time.monotonic() - started, 2), 'exit_code': None,
            'note': ', '.join(summary['crawl']['limits'])})
    urls = [url for url in dict.fromkeys(summary['crawl']['discovered'] + engine_urls)
            if not urllib.parse.urlsplit(url).path.lower().endswith('.js')]
    (folder / 'urls.txt').write_text('\n'.join(evidence.url(u) for u in urls) + ('\n' if urls else ''), encoding='utf-8')
    selected, excluded = select_candidates(urls, args.max_sqli_jobs)
    summary['injection'].update(selected=selected, excluded=excluded)
    say(f'[POST-CRAWL] {len(urls)} routes; {len(selected)} eligible GET parameters; {len(excluded)} excluded. Continuing web checks.')
    if runner.stop.is_set():
        summary['injection']['status'] = 'cancelled'
        return
    if (args.active_checks or args.builtin_sqli or args.time_sqli or args.template_checks) and not args.no_active_checks:
        checks_folder = root / 'checks'
        started = time.monotonic()
        say('[CHECKS] Comparing GET controls with inert reflection and redirect probes')
        try:
            options = {'scan_ip': getattr(args, 'scan_ip', None), 'retain_raw': getattr(args, 'retain_raw_evidence', False),
                       'request_timeout': args.http_timeout}
            if getattr(args, 'session', None):
                options['session'] = args.session
            summary['active_checks'] = with_progress('Checking GET parameters', run_checks,
                selected, args.target, checks_folder, runner.stop,
                args.rate, args.checks_timeout, args.insecure, workers=args.http_workers, delay=args.delay,
                gate=getattr(args, 'request_gate', None), sqli=args.builtin_sqli, time_sqli=args.time_sqli, template_checks=args.template_checks, **options)
        except Exception as exc:
            summary['active_checks'] = dict(status='incomplete', error=stage_failure(
                summary, root, 'GET parameter stage', 'checks', exc))
        finally:
            state_file = checks_folder / 'checks.json'
            if state_file.exists():
                state = stage_snapshot(state_file, summary.get('active_checks', {'status': 'incomplete'}))
                if summary.get('active_checks', {}).get('error'):
                    state.update(status='incomplete', error=summary['active_checks']['error'])
                summary['active_checks'] = state
                summary['jobs'].append(dict(name='GET differential checks', tool='checks', argv=[],
                    command='Built-in control/probe GET checks; no redirects followed', folder=str(checks_folder),
                    outputs=['checks.json'], status=state['status'], elapsed=round(time.monotonic() - started, 2),
                    exit_code=None, note='No-match is limited to these probes; candidates need validation.'))
        say('[GET CHECKS] ' + summary.get('active_checks', {}).get('status', 'incomplete'))
    else:
        summary['active_checks'] = dict(status='disabled', reason='Use --profile web or --active-checks; --no-active-checks disables parameter probes.')
        say('[GET CHECKS] Disabled by the selected profile/options.')
    additional_urls = [url for url in urls if url not in live]
    (folder / 'scanner-urls.txt').write_text('\n'.join(additional_urls), encoding='utf-8')
    if additional_urls and 'nuclei' not in args.skip and not getattr(args, 'session', None):
        try:
            job = next(j for j in build_jobs(args, root / 'discovered', [live[0]], binaries) if j.tool == 'nuclei')
            index = job.argv.index('-u')
            job.argv[index:index + 2] = ['-l', str(folder / 'scanner-urls.txt')]
            job.name = 'Nuclei discovered URLs'
            summary['jobs'].append(runner.execute(job))
        except Exception as exc:
            stage_failure(summary, root, 'Discovered Nuclei stage', 'nuclei', exc)
    else:
        say('[NUCLEI] Discovered URL scan not run: disabled/skipped, authenticated session, or no additional routes.')
    try:
        run_web_engines(args, root, live, summary, runner, binaries, selected)
    except Exception as exc:
        stage_failure(summary, root, 'Dalfox parameter stage', 'dalfox', exc)
    if args.no_auto_sqli or 'sqlmap' in args.skip:
        summary['injection'].update(status='disabled', reason='SQLmap opt-out or external scanners disabled/skipped; built-in GET checks run independently.')
        say('[SQLMAP] ' + summary['injection']['reason'])
        return
    if getattr(args, 'session', None):
        summary['injection']['status'] = 'requires_authenticated_scanner'
        return
    summary['injection']['status'] = 'completed' if selected else 'no_candidates'
    if not selected:
        say('[SQLMAP] No eligible GET parameters; API and other web stages continue independently.')
        return
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


from .scheduler import run_batch


def write_reports(root, summary):
    """Compatibility boundary; presentation is independent of CLI orchestration."""
    summary.setdefault('performance', {}).setdefault('full_report_renders', 0)
    summary['performance']['full_report_renders'] += 1
    return reporting.write_reports(root, summary, tools=ALL_TOOLS,
        report_script=REPORT_SCRIPT, collector=collect)


def parser():
    p = argparse.ArgumentParser(description="The World Is Yours: one-host web assessment pipeline for authorized labs.")
    p.add_argument("target", nargs="?", type=target_input, help="One IPv4/IPv6, hostname, or HTTP(S) URL; prompted if omitted.")
    p.add_argument('--scan', choices=('full', 'web', 'quick', 'port', 'all-ports', 'ctf', 'deep', 'server', 'estate'), default='full', help='server inventories all TCP ports plus network/web checks; estate discovers a domain and its subdomains.')
    p.add_argument('--subdomain-file', type=Path, help='Additional newline-separated subdomain names for estate discovery.')
    p.add_argument('--no-passive', action='store_true', help='Do not query passive Subfinder sources during estate discovery.')
    p.add_argument('--discover-only', action='store_true', help='Estate DNS inventory only, without port scans or HTTP requests.')
    p.add_argument('--max-hosts', type=positive, default=25, help='Estate host cap including apex, maximum 500; omitted names are recorded.')
    p.add_argument('--host-workers', type=positive, default=2, help='Concurrent estate child scans, maximum 4.')
    p.add_argument('--discovery-timeout', type=positive, default=120, help='Subfinder process timeout in seconds.')
    p.add_argument('--host-timeout', type=positive, default=7200, help='Whole child scan timeout in seconds; partial reports retained.')
    p.add_argument('--connect-ip', type=ipaddress.ip_address, help='Pin this single-host scan to an explicitly selected IP (Host/SNI retain the target name).')
    p.add_argument('--reuse-services', type=Path, help='Reuse a completed same-IP summary service inventory instead of repeating Nmap.')
    p.add_argument('--only', nargs='+', choices=scan_modes.TOOLS, help='Run only selected tools; checks/SQLmap use crawl for GET discovery. External tools require --retain-raw-evidence.')
    menu = p.add_mutually_exclusive_group()
    menu.add_argument('--menu', action='store_true', help='Show scan choices after the target.')
    menu.add_argument('--no-menu', action='store_true', help='Use command-line options without an interactive scan menu.')
    p.add_argument('--compare', type=Path, help='Previous summary.json or run directory for a same-target offline comparison.')
    p.add_argument('--target', dest='target_option', type=target_input, help='Alternative to the positional target.')
    p.add_argument("--mode", choices=("sequential", "parallel"), default="sequential")
    p.add_argument('--profile', choices=('standard', 'lab', 'web'), default='web',
                   help='web (default): sensitive files, CORS, API and GET error/reflection/redirect checks; lab: larger budgets and BEUT SQLi.')
    p.add_argument('--assessment', choices=('full', 'web', 'network'), default='web',
                   help='full: network configuration, TLS and web; network: inventory/TLS without HTTP crawling; web (default): discover HTTP services and assess web vulnerabilities.')
    p.add_argument('--network-timeout', type=positive, default=60, help='Budget for bounded network/TLS assessment in seconds.')
    p.add_argument('--service-checks', action='store_true', help='Opt in to allowlisted Nmap SSH algorithm and SMB2 signing negotiation; no arbitrary/vuln scripts.')
    p.add_argument('--http-timeout', type=positive, default=10, help='Per-request timeout for built-in discovery, crawl, checks and TLS; default 10 seconds.')
    p.add_argument('--report-only', type=Path, help='Rebuild reports from an existing run directory; no network/scanners.')
    p.add_argument("--workers", type=positive, default=2, help="Concurrent web tools, default 2.")
    p.add_argument('--http-workers', type=positive, default=4, help='Built-in HTTP workers, 1..8; timing checks use one.')
    p.add_argument('--delay', type=nonnegative, default=0, help='Minimum seconds between built-in HTTP starts, shared across workers; external tools use --rate.')
    p.add_argument('--ui', choices=('auto', 'rich', 'plain'), default='auto')
    p.add_argument('--theme', choices=('scarface', 'plain'), default='scarface', help='ASCII globe/palms identity, or compact text-only startup.')
    p.add_argument('--no-banner', action='store_true')
    p.add_argument("--enum", choices=("auto", *ENUM_TOOLS, "all", "none"), default="auto")
    port_scope = p.add_mutually_exclusive_group()
    port_scope.add_argument("--ports", type=ports, help="TCP ports/ranges; default Nmap's top 1000.")
    port_scope.add_argument("--all-ports", action="store_true", help="TCP 1-65535; slower.")
    port_scope.add_argument('--top-ports', type=positive, help='Scan N most common TCP ports (1..65535), including for URL targets; default 1000 for URLs and bare hosts.')
    port_scope.add_argument('--url-port-only', action='store_true', help='Opt in to scanning only the target URL port.')
    p.add_argument('--nmap-scan', choices=('connect', 'syn'), default='connect', help='connect uses -sT; syn uses -sS and requires raw-socket privileges.')
    p.add_argument('--version-intensity', type=int, choices=range(10), default=7,
                   help='Nmap service probe intensity 0..9; default 7, light=2, exhaustive=9. Higher takes longer.')
    p.add_argument('--nmap-rate', type=positive, default=100, help='Nmap maximum packet rate, <=1000; independent of web --rate.')
    p.add_argument("--url", action="append", default=[], help="Additional same-host HTTP(S) base URL, useful for unusual ports.")
    p.add_argument("--wordlist", type=Path, default=PROJECT_ROOT / "wordlists" / "default.txt")
    p.add_argument("--templates", type=Path, help='Local Nuclei YAML root; auto-detect legacy, XDG or Kali directories.')
    p.add_argument('--retain-raw-evidence', action='store_true', help='Retain sensitive response bodies and external scanner files; protect the run directory.')
    p.add_argument('--external-tools', action='store_true', help='Enable external web scanners for numeric IP targets; per-tool rates, independent of built-in gate. Requires --retain-raw-evidence.')
    p.add_argument('--all-tools', action='store_true', help='Enable all applicable external adapters and all directory engines; retains raw scanner evidence. Explicit --skip and --enum still apply.')
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
    p.add_argument('--no-web-metadata', action='store_true', help='Do not seed robots.txt/sitemap.xml during crawling.')
    redirects = p.add_mutually_exclusive_group()
    redirects.add_argument('--crawl-redirects', dest='crawl_redirects', action='store_true', default=True,
                           help='Follow same-origin, non-action redirects within crawl budgets (default).')
    redirects.add_argument('--no-crawl-redirects', dest='crawl_redirects', action='store_false',
                           help='Inventory redirects without following them during crawling.')
    p.add_argument('--cookie-file', type=Path, help='One Cookie header value; built-in crawler/checks only, target URL origin required.')
    p.add_argument('--no-auto-sqli', action='store_true', help='Inventory GET parameters without automatic SQLmap checks.')
    p.add_argument('--max-sqli-jobs', type=positive, default=10, help='Maximum discovered URL/parameter checks, default 10.')
    p.add_argument('--sqli-timeout', type=positive, default=120, help='Seconds per automatic SQLmap job, default 120.')
    p.add_argument('--sqli-techniques', choices=('BEU', 'BEUT'), default='BEU', help='BEUT also includes time-based blind detection.')
    p.add_argument('--active-checks', action='store_true', help='Bounded inert HTML reflection and external redirect GET probes.')
    p.add_argument('--no-active-checks', action='store_true', help='Disable differential checks, including in lab profile.')
    p.add_argument('--checks-timeout', type=positive, default=120, help='Time budget for differential checks.')
    p.add_argument('--builtin-sqli', action='store_true', help='Preliminary quote/error signature checks with a control response.')
    p.add_argument('--template-checks', action='store_true', help='Compare two arithmetic-only template expressions per syntax with control requests (CTF preset enables this).')
    p.add_argument('--time-sqli', action='store_true', help='Opt-in repeated one-second MySQL delay anomaly probes, serialized; not proof of SQLi.')
    p.add_argument('--sensitive-files', action='store_true', help='Bounded wordlist GETs with baseline and content signatures.')
    p.add_argument('--file-limit', type=positive, default=100, help='Maximum sensitive-file URLs across all origins, <=1000.')
    p.add_argument('--api-discovery', action='store_true', help='Bounded OpenAPI/Swagger JSON inventory; no automatic administrative actions.')
    p.add_argument('--contexts', type=Path, help='JSON account contexts and explicit per-resource access policies; GET-only comparisons.')
    p.add_argument('--idor', action='store_true', help='Bounded adjacent ID inventory; owner policy is required for access-control findings.')
    p.add_argument('--idor-value', action='append', default=[], help='Explicit alternative object identifier, max four.')
    p.add_argument('--ssrf-canary', help='Owned HTTP(S) canary URL submitted to existing URL-like GET parameters; inspect canary logs.')
    p.add_argument('--ssrf-metadata', action='store_true', help='Opt-in lab metadata ROOT probe through target inputs; no credential endpoints.')
    p.add_argument('--advanced-timeout', type=positive, default=120, help='Shared advanced-stage budget; maximum 120 HTTP starts.')
    p.add_argument('--show-helpers', action='store_true', help='Print redacted GET cURL reproductions for advanced candidates.')
    p.add_argument('--log-file', type=Path, default=Path('ws-r.log'), help='Quiet, rotating diagnostics without credentials or exception messages.')
    p.add_argument("--output", type=Path, default=Path("results"), help="Run parent directory, or report.json/report.html with a separate evidence directory.")
    p.add_argument("--version", action="version", version=VERSION)
    return p


def _main(argv=None):
    global UI
    p = parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    args = p.parse_args(argv)
    reliability.configure(args.log_file)
    if args.target and args.target_option:
        p.error('Use either positional target or --target, not both.')
    args.target = args.target or args.target_option
    UI = TerminalUI(args.ui, theme=args.theme)
    apply_profile(args, argv)
    if args.assessment == 'network' and args.sqlmap_url:
        p.error('--sqlmap-url requires --assessment web or full.')
    if args.assessment == 'web' and args.service_checks and args.scan not in ('server', 'estate'):
        p.error('--service-checks requires --assessment network or full.')
    if args.report_only:
        root = args.report_only.expanduser().resolve()
        try:
            summary = json.loads((root / 'summary.json').read_text(encoding='utf-8'))
            run_history.relocate(summary, root)
            for candidate in summary.get('injection', {}).get('selected', []):
                job = next((j for j in summary['jobs'] if j['name'] == candidate.get('job')), None)
                if job:
                    candidate['detection_outcome'] = sqlmap_outcome(job)
            if args.compare:
                previous = run_history.load(args.compare)
                if previous['target'] != summary['target']:
                    raise ValueError('Baseline target differs from this run')
                summary['comparison_base'] = run_history.snapshot(root, previous)
            summary['report_generator_version'] = VERSION
            write_reports(root, summary)
            if args.output.suffix.lower() in ('.json', '.html'):
                export_reports(root, args.output)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            p.error(f'Cannot rebuild this run: {exc}')
        say(f'Rebuilt report: {root / "report.html"}')
        incomplete = summary.get('comparison', {}).get('status') == 'incomplete'
        parsing_gaps = any(issue.get('kind') != 'manual_review' for issue in summary.get('parse_issues', []))
        return 2 if incomplete or parsing_gaps else 0
    if not sys.platform.startswith('linux'):
        p.error('The World Is Yours requires Linux (Kali/Ubuntu or a Linux WSL environment).')
    if args.check:
        for name, path in tool_paths(args.dry_run).items():
            say(f"{name:12} {path or 'MISSING'}")
        templates = template_path(args)
        available = templates.is_dir() and next(templates.rglob('*.yaml'), None) is not None
        say(f'Nuclei YAML: {templates} ({"found" if available else "MISSING"})')
        return 0
    if not args.no_banner:
        UI.startup(VERSION)
    if not args.target:
        try:
            entered = UI.prompt_target().strip()
            # Preserve bare hosts so selected web tools can discover ports 80/443.
            parsed = parse_target(entered)
            args.target = parsed.url or parsed.host
        except (ValueError, argparse.ArgumentTypeError, EOFError) as exc:
            p.error(str(exc))
    try:
        interactive = sys.stdin.isatty() and sys.stdout.isatty()
        if args.menu or (interactive and not args.no_menu and not args.dry_run and not args.only
                        and not any(v == '--scan' or v.startswith('--scan=') for v in argv)):
            if args.only:
                raise ValueError('Use --menu or --only, not both')
            selection = UI.prompt_scan()
            if selection.get('ports') is not None:
                selection['ports'] = ports(selection['ports'])
            for key, value in selection.items():
                setattr(args, key, value)
        scan_modes.apply(args, argv)
    except (ValueError, EOFError, argparse.ArgumentTypeError) as exc:
        p.error(str(exc))
    if sum(bool(v) for v in (args.ports, args.all_ports, args.top_ports)) > 1:
        p.error('Use only one of --ports, --all-ports or --top-ports.')
    if args.top_ports and args.top_ports > 65535 or args.nmap_rate > 1000:
        p.error('Use top-ports <= 65535 and nmap-rate <= 1000.')
    if args.workers > 8 or args.http_workers > 8 or args.file_limit > 1000 or args.rate > 50:
        p.error("Use workers/http-workers <= 8, file-limit <= 1000 and rate <= 50.")
    if args.crawl_pages > 1000 or args.crawl_depth > 10 or args.max_sqli_jobs > 50:
        p.error('Use crawl-pages <= 1000, crawl-depth <= 10 and max-sqli-jobs <= 50.')
    if args.scan == 'estate':
        from . import estate
        try:
            return estate.run(args)
        except (ValueError, OSError) as exc:
            p.error(str(exc))
    if args.subdomain_file or args.no_passive or args.discover_only:
        p.error('Subdomain discovery options require --scan estate.')
    if bool(args.sqlmap_url) != bool(args.sqlmap_param):
        p.error("Use --sqlmap-url and --sqlmap-param together.")
    try:
        prepare_target(args)
        if args.connect_ip:
            try:
                numeric_target = ipaddress.ip_address(args.target)
            except ValueError:
                numeric_target = None
            if numeric_target is not None and numeric_target != args.connect_ip:
                raise ValueError('--connect-ip must match a numeric target')
            args.scan_ip = str(args.connect_ip)
        if args.reuse_services and 'nmap' in args.skip:
            raise ValueError('--reuse-services conflicts with --skip nmap')
        if args.input_url and args.ports and origin(args.input_url)[2] not in listed_ports(args.ports):
            if args.cookie_file or args.contexts:
                raise ValueError('Selected ports exclude the authenticated URL. Use a matching URL to preserve credential origin scope.')
            say('[WEB SCOPE] Target URL port is outside selected ports; using the same host on your selected ports. URL path/query are not carried across origins.')
            args.input_url = ''
        args.session = None
        args.context_objects, args.context_policies = [], []
        if args.contexts:
            if not args.input_url:
                raise ValueError('--contexts requires a target URL to bind account credentials')
            args.context_objects, args.context_policies = advanced.load_contexts(args.contexts, args.input_url)
        if len(args.idor_value) > 4 or any(len(v) > 128 for v in args.idor_value):
            raise ValueError('Use at most four IDOR values of up to 128 characters')
        if args.ssrf_canary:
            args.ssrf_canary = normalize_url(args.ssrf_canary, urllib.parse.urlsplit(args.ssrf_canary).hostname)
        if args.cookie_file:
            if not args.input_url:
                raise ValueError('--cookie-file requires a target HTTP(S) URL to bind the session to one origin')
            from .session import Session
            args.session = Session(args.input_url, args.cookie_file.expanduser())
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
    if args.only and args.external_tools and args.session:
        p.error('Selected external tools do not inherit account credentials; use built-in tools for cookie-scoped scans.')
    if args.external_tools and not args.retain_raw_evidence and not args.dry_run:
        p.error('--external-tools requires --retain-raw-evidence because scanners write raw responses.')
    if not args.external_tools and not args.dry_run:
        args.skip = list(dict.fromkeys(args.skip + [t for t in ALL_TOOLS if t != 'nmap']))
    args.wordlist = args.wordlist.expanduser()
    if (args.enum != "none" or args.sensitive_files) and not args.wordlist.is_file():
        p.error(f"Wordlist not found: {args.wordlist}")
    export_path = args.output if args.output.suffix.lower() in ('.json', '.html') else None
    output_parent = (args.output.parent / (args.output.stem + '.evidence')) if export_path else args.output
    root = output_parent.expanduser().resolve() / (
        re.sub(r'[^A-Za-z0-9_.-]', '_', args.target) + "_" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6])
    root.mkdir(parents=True, mode=0o700)
    runner = Runner(args.dry_run)
    try:
        ipaddress.ip_address(args.target)
    except ValueError:
        runner.web_skip_reason = 'External scanner deferred: cannot guarantee DNS pinning for this hostname; built-in checks remain available.'
    if not args.external_tools and not args.dry_run:
        runner.web_skip_reason = 'External scanners disabled by default; use --external-tools with --retain-raw-evidence for numeric IP targets.'
    args.request_gate = RequestGate(args.rate, args.delay)
    runner.request_gate = args.request_gate
    summary = {"version": VERSION, "target": args.target, "input_target": args.input_target,
               "input_url": args.input_url, "scan_ip": args.scan_ip,
               "created": dt.datetime.now(dt.timezone.utc).isoformat(),
               "mode": args.mode, "profile": args.profile, "sqli_techniques": args.sqli_techniques,
               "dry_run": args.dry_run, "retain_raw_evidence": args.retain_raw_evidence, "ports": [], "probes": [], "jobs": [],
               "outcome": "Discovery started."}
    summary['built_in_http'] = {'workers': args.http_workers, 'delay': args.delay, 'rate': args.rate,
                               'time_checks_workers': 1 if args.time_sqli else None}
    summary['external_scanners'] = {'enabled': args.external_tools,
        'policy': 'Numeric IP targets for remote adapters; WhatWeb hostname snapshots are pinned; explicit raw-evidence opt-in; mode=' + args.mode}
    summary['scan_plan'] = scan_modes.plan(args)
    summary['tool_selection'] = dict(skipped=list(args.skip), enum=args.enum,
        no_auto_sqli=args.no_auto_sqli, no_active_checks=args.no_active_checks,
        no_crawl=args.no_crawl, session=bool(args.session))
    summary['tool_inventory'] = (tool_paths(args.dry_run, args.only)
        if args.assessment != 'network' else {})
    if args.external_tools:
        for tool, binary in summary['tool_inventory'].items():
            if tool not in args.skip:
                say('[TOOLS] ' + tool + ': ' + ('available' if binary else 'MISSING / incompatible executable; install and rerun --check'))
    if args.compare:
        try:
            previous = run_history.load(args.compare)
            if previous['target'] != args.target:
                raise ValueError('Baseline target differs from the selected target')
            summary['comparison_base'] = run_history.snapshot(root, previous)
        except (OSError, ValueError) as exc:
            p.error(str(exc))
    summary['assessment_mode'] = args.assessment
    summary['service_checks_requested'] = args.service_checks
    summary['built_in_http']['request_timeout'] = args.http_timeout
    summary['session_scope'] = ('Built-in crawler and GET checks only; external scanners are unauthenticated; '
        'automatic SQLmap and discovered Nuclei deferred' if args.session else 'unauthenticated')
    say(f"Target: {args.target} | Assessment: {args.assessment} | {args.mode}\nResults: {root}")
    if args.only == ['whatweb'] and not args.dry_run:
        say('[WHATWEB] Selected: fingerprinting only. Results will appear under WHATWEB RESULTS.')
        if not shutil.which('whatweb'):
            say('[WHATWEB] Missing executable. Install on Kali/Ubuntu/WSL: sudo apt install whatweb')
    summary['nmap'] = dict(status='skipped', selection=nmap_scan.selection(args),
                           note='Nmap was excluded with --skip; no observed port inventory.')
    if args.dry_run:
        say('[PLAN ONLY] No network requests will run. Open ports and versions will be empty.')
    try:
        if args.reuse_services:
            from . import estate
            summary['ports'], summary['nmap'] = estate.reuse_services(args.reuse_services, args.scan_ip, nmap_scan.selection(args))
            summary['nmap']['selection'] = nmap_scan.selection(args)
            # Copy the source evidence into this run so the report remains portable.
            folder = root / 'nmap'
            folder.mkdir(exist_ok=True)
            shutil.copyfile(args.reuse_services.parent / 'nmap' / 'services.xml', folder / 'services.xml')
            summary['jobs'].append(dict(name='Reused same-IP service inventory', tool='nmap', argv=[],
                command='Verified local Nmap XML reuse', folder=str(folder), outputs=['services.xml'],
                status='completed', elapsed=0, note=summary['nmap']['note']))
            UI.services_table(summary['ports'], summary['nmap']['note'])
        elif "nmap" not in args.skip:
            folder = root / "nmap"
            cmd = nmap_scan.command(args, folder)
            say(f'[NMAP SCOPE] {nmap_scan.selection(args)}; version intensity {args.version_intensity}; target {args.scan_ip}')
            result = runner.execute(Job("Nmap TCP/services", "nmap", cmd, folder,
                                        args.nmap_timeout + 10, ["services.xml"]))
            summary["jobs"].append(result)
            try:
                summary['ports'], details = nmap_scan.inventory(folder / 'services.xml', args.scan_ip, result['status'])
                summary['nmap'].update(details, selection=nmap_scan.selection(args), version_intensity=args.version_intensity)
            except (ValueError, OSError) as exc:
                summary['nmap'].update(status='inconclusive', note='Nmap XML unreadable: ' + str(exc))
            UI.services_table(summary['ports'], summary['nmap']['note'])
        # If Nmap is absent/failed, only try common ports within a requested port scope.
        requested = sorted(listed_ports(args.ports)) if args.ports else []
        if len(requested) > 64 and summary['nmap'].get('status') not in ('completed', 'completed_no_open_ports'):
            say('[WEB SCOPE] More than 64 selected ports require successful Nmap discovery; direct fallback probes are limited to 64 ports.')
        fallback = requested[:64] if args.ports else sorted(COMMON_WEB_PORTS)
        if args.only and not args.ports and not args.input_url and not summary['ports']:
            fallback = [80, 443]
        services = summary["ports"] if args.scan == 'all-ports' or summary['nmap'].get('status') == 'completed_no_open_ports' else (summary["ports"] or [{"port": port, "service": "http-candidate"} for port in fallback])
        base_urls = [url.rstrip('/') + '/' for url in args.url]
        if args.input_url:
            base_urls.insert(0, args.input_url)
        # Without an observed port inventory, retain an explicit URL rather than
        # guessing many unrelated ports after skipped/failed Nmap.
        derived_urls = candidates(args.target, services) if (summary['ports'] or not args.input_url) and not args.url_only else []
        candidate_urls = list(dict.fromkeys(base_urls + derived_urls))
        if args.assessment != 'web' and (not args.only or 'tls' in args.only) and not args.dry_run and not runner.stop.is_set():
            say('[NETWORK] Reviewing service exposure and verified TLS; no login or exploit probes')
            started = time.monotonic()
            folder = root / 'network'
            tls_urls = list(base_urls)
            if args.only and 'tls' in args.only and 'nmap' not in args.only:
                requested_ports = sorted(listed_ports(args.ports)) if args.ports else ([origin(args.input_url)[2]] if args.input_url else [443])
                tls_urls += ['https://' + authority(args.target, port) + '/' for port in requested_ports[:33]]
                summary['tls_candidates'] = tls_urls
            try:
                summary['network_assessment'] = with_progress('Network configuration and TLS', assessment.run,
                    args.target, args.scan_ip, summary['ports'], tls_urls, folder, runner.stop, args.request_gate,
                    timeout=args.network_timeout, request_timeout=args.http_timeout)
                summary['jobs'].append(dict(name='Network configuration and TLS', tool='network', argv=[],
                    command='Pinned TLS handshakes and Nmap exposure review', folder=str(folder), outputs=['assessment.json'],
                    status=summary['network_assessment']['status'], elapsed=round(time.monotonic() - started, 2), note=''))
            except Exception as exc:
                error = stage_failure(summary, folder, 'Network configuration and TLS', 'network', exc)
                state = stage_snapshot(folder / 'assessment.json', {'checks': [], 'tls': []})
                state.update(status='incomplete', error=error)
                summary['network_assessment'] = state
            write_reports(root, summary)
        if args.assessment == 'network' or args.only == ['sqlmap'] and args.sqlmap_url:
            candidate_urls = []
            args.no_crawl = True
        if args.dry_run:
            live = candidate_urls
            summary["outcome"] = "Dry run: planned commands only; HTTP discovery and scanners were not executed."
        else:
            live = []
            for url in candidate_urls:
                if scan_diagnostics.redundant_alternative(url, base_urls, summary['probes']):
                    summary.setdefault('probe_skips', []).append(dict(url=url, reason='Opposite protocol already identified on this host/port.'))
                    say('[HTTP SKIP] ' + evidence.url(url) + ': opposite protocol already identified on this port.')
                    continue
                if runner.stop.is_set():
                    break
                try:
                    args.request_gate.wait(runner.stop, time.monotonic() + args.http_timeout + 1 + args.delay)
                    say(f'[HTTP PROBE] {evidence.url(url)} (timeout {args.http_timeout}s)')
                    result = probe(url, args.insecure, timeout=args.http_timeout, scan_ip=args.scan_ip)
                except TimeoutError as exc:
                    result = {'url': url, 'error': str(exc)}
                result["fallback_candidate"] = url not in base_urls
                args.request_gate.observe(result)
                if not args.retain_raw_evidence:
                    result["title"] = ""
                summary["probes"].append(result)
                if "status" in result:
                    live.append(url)
                    say(f"[HTTP] {result['status']} {evidence.url(url)}")
                    if result.get('error'):
                        say(f"[HTTP WARNING] {evidence.url(url)}: {result['error']}")
                else:
                    say(f"[HTTP ERROR] {evidence.url(url)}: {result.get('error', 'No response')}")
                    if scan_diagnostics.certificate_blocked(result):
                        say('[TLS] Certificate verification failed. Trust the lab CA, or explicitly use --insecure for a self-signed authorized lab.')
                reporting.write_checkpoint(root, summary)
            summary["outcome"] = f"{len(live)} responding HTTP(S) base URLs."
            if args.assessment == 'network':
                summary['outcome'] = 'Network assessment selected; HTTP discovery and crawling were not requested.'
            elif args.only == ['sqlmap'] and args.sqlmap_url:
                summary['outcome'] = 'Explicit SQLmap GET target selected; HTTP discovery and crawling were not requested.'
            elif not live:
                summary["outcome"] += " No web tool jobs started; check the IP, ports, TLS or use --url."
        if not args.dry_run:
            say('[DISCOVERY] ' + summary['outcome'])
            if not args.external_tools:
                say('[WEB] Built-in discovery/checks enabled; external web scanners are opt-in (--external-tools --retain-raw-evidence) for numeric IP targets.')
        (root / "urls.txt").write_text("\n".join(evidence.url(u) for u in live) + ("\n" if live else ""), encoding="utf-8")
        binaries = summary['tool_inventory'] if not runner.stop.is_set() and args.assessment != 'network' else {}
        jobs = build_jobs(args, root, live, binaries)
        summary["jobs"].extend(run_batch(runner, jobs, args.mode, args.workers))
        try:
            run_web_engines(args, root, live, summary, runner, binaries)
        except Exception as exc:
            stage_failure(summary, root, 'Complementary engine stage', 'katana', exc)
        try:
            run_discovered(args, root, live, summary, runner, binaries)
        except Exception as exc:
            summary['jobs'].append(dict(name='Built-in web assessment', tool='checks', argv=[],
                command='', folder=str(root), outputs=[], status='incomplete', elapsed=0,
                note=reliability.record('web_stage', exc)))
        if live and not runner.stop.is_set():
            try:
                run_technology_plan(args, root, live, summary, runner, binaries)
            except Exception as exc:
                stage_failure(summary, root, 'Technology follow-up plan', 'wpscan', exc)
        if live and not args.dry_run and not runner.stop.is_set() and (any((args.api_discovery, args.contexts, args.idor, args.ssrf_canary, args.ssrf_metadata)) or any(page.get('jwt') for page in summary.get('crawl', {}).get('pages', []))):
            say('[ADVANCED] Scoped API inventory and bounded GET comparisons')
            folder = root / 'advanced'
            urls = [page['url'] for page in summary.get('crawl', {}).get('pages', []) if 'url' in page]
            urls += summary.get('crawl', {}).get('discovered', []) + live
            # Discovery may include metadata objects rather than literal URL strings.
            urls = [value if isinstance(value, str) else value.get('url', '') for value in urls]
            try:
                summary['advanced'] = with_progress('API and access-control assessment', advanced.run,
                    live, args.target, folder, runner.stop, args.request_gate, scan_ip=args.scan_ip,
                    timeout=args.http_timeout, budget=args.advanced_timeout, workers=args.http_workers,
                    api=args.api_discovery, contexts=args.context_objects, policies=args.context_policies,
                    idor=args.idor, alternatives=args.idor_value, candidates=[u for u in urls if u],
                    ssrf_canary=args.ssrf_canary, metadata=args.ssrf_metadata, session=args.session,
                    insecure=args.insecure, retain=args.retain_raw_evidence,
                    jwt_observations=[jwt for page in summary.get('crawl', {}).get('pages', []) for jwt in page.get('jwt', [])])
                say('[ADVANCED] ' + summary['advanced']['status'])
                summary['jobs'].append(dict(name='Advanced GET assessment', tool='advanced', argv=[],
                    command='Bounded scoped GET comparisons', folder=str(folder), outputs=['results.json'],
                    status=summary['advanced']['status'], elapsed=0, note='Candidates require validation'))
            except Exception as exc:
                summary['advanced'] = dict(status='incomplete', error=stage_failure(
                    summary, root, 'Advanced API stage', 'advanced', exc))
        if args.sqlmap_url and "sqlmap" not in args.skip:
            folder = root / "sqlmap"
            summary["jobs"].append(runner.execute(sqlmap_job(args, folder, args.sqlmap_url,
                                    args.sqlmap_param, 'SQLmap selected GET parameter')))
    except (KeyboardInterrupt, InterruptedError):
        runner.cancel()
        summary["outcome"] = "Run interrupted; reports contain only available evidence."
    except Exception as exc:
        runner.cancel()
        summary['execution_error'] = reliability.record('scan_orchestration', exc)
        summary['outcome'] = 'Execution stopped after an error; available evidence is incomplete. See diagnostics.'
    finally:
        if runner.stop.is_set():
            summary["outcome"] = "Run interrupted; results are incomplete."
        try:
            write_reports(root, summary)
            if export_path:
                say(f'Exported report: {export_reports(root, export_path)}')
            if args.show_helpers:
                for finding in summary.get('findings', [])[:20]:
                    if finding.get('reproduction'):
                        say('[REPRODUCE] ' + finding['reproduction'])
            if not args.dry_run and ('whatweb' in (args.only or []) or any(j.get('tool') == 'whatweb' for j in summary['jobs'])):
                UI.whatweb_results(summary)
            if args.only != ['whatweb']:
                UI.web_priorities(summary)
                UI.coverage_diagnostics(summary)
                for row in summary.get('tool_coverage', []):
                    say('[TOOL RESULT] ' + row['tool'] + ': ' + row['status'] + ' | ' + row['reason'])
                UI.severity_table(summary['coverage']['severity_counts'])
                UI.completion(summary['statistics'], summary['risk_assessment']['overall_priority'])
            say(f"\nReport: {root / 'report.html'}")
        except Exception as exc:
            summary['report_error'] = reliability.record('report_finalization', exc)
            try:
                (root / 'recovery.json').write_text(evidence.dumps(summary), encoding='utf-8')
            except Exception as recovery_error:
                reliability.record('report_recovery', recovery_error)
            say('Report could not be completed. Check output permissions and ws-r.log; existing evidence is preserved.')
    if summary.get('execution_error') or summary.get('report_error'):
        return 2
    if runner.stop.is_set():
        return 130
    if args.dry_run:
        return 0
    if args.assessment == 'network' and set(args.only or []) != {'tls'} and summary.get('nmap', {}).get('status') not in ('completed', 'completed_no_open_ports'):
        return 2
    # Report incomplete coverage even if other scanners succeeded.
    if args.assessment != 'network' and not any("status" in row for row in summary["probes"]) and not args.sqlmap_url and summary['nmap'].get('status') != 'completed_no_open_ports':
        return 2
    return 2 if (any("error" in row and not (row.get('fallback_candidate') and any(
                    'status' in other and origin(other['url'])[1:] == origin(row['url'])[1:]
                    and origin(other['url'])[0] != origin(row['url'])[0] for other in summary['probes']))
                    for row in summary['probes'])
                 or summary['coverage']['job_gaps']
                 or summary.get('comparison', {}).get('status') == 'incomplete'
                 or summary.get('nmap', {}).get('status') in ('partial', 'unavailable', 'inconclusive')
                 or (summary.get('injection', {}).get('excluded') and ((args.active_checks or args.builtin_sqli or args.time_sqli or args.template_checks) and not args.no_active_checks or not args.no_auto_sqli and 'sqlmap' not in args.skip))
                 or summary['coverage']['parsing_gaps'] or summary['coverage']['sqli_inconclusive']
                 or any('error' in page or page.get('truncated') for page in summary.get('crawl', {}).get('pages', []))) else 0


def main(argv=None):
    """CLI reliability boundary; argparse retains normal help/error exit semantics."""
    try:
        return _main(argv)
    except (KeyboardInterrupt, InterruptedError):
        return 130
    except Exception as exc:
        reliability.record('cli_boundary', exc)
        try:
            say('Unable to complete this operation. Check target, configuration, output permissions and diagnostics.')
        except Exception:
            pass
        return 2
    finally:
        reliability.close()


if __name__ == "__main__":
    raise SystemExit(main())
