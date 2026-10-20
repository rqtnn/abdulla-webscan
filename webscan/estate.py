"""Domain inventory and bounded multi-host orchestration; single-host scope stays intact.

Every (hostname, IP) is a separate process, preserving Host/SNI. Port inventories
are reused only for the exact IP and only after complete, successful discovery.
"""
from .paths import PROJECT_ROOT
from concurrent.futures import ThreadPoolExecutor
import datetime as dt
import hashlib
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid

from . import nmap_scan
from .scope import host, parse_target
from .brand import VERSION

RESOLVER = """import socket,sys,json
rows=socket.getaddrinfo(sys.argv[1],None,type=socket.SOCK_STREAM)
print(json.dumps(sorted(set(r[4][0] for r in rows if r[0] in (socket.AF_INET,socket.AF_INET6)))))
"""


def in_scope(name, domain):
    try:
        name = host(name)
    except ValueError:
        return False
    try:
        ipaddress.ip_address(name)
        return False
    except ValueError:
        return name == domain or name.endswith('.' + domain)


def normalize_names(lines, domain):
    names, rejected = set(), 0
    for raw in lines:
        raw = raw.strip()
        if not raw or raw.startswith('#'):
            continue
        try:
            name = host(raw)
            if not in_scope(name, domain):
                raise ValueError('Outside domain')
            names.add(name)
        except ValueError:
            rejected += 1
    return sorted(names), rejected


def resolve(name):
    """OS resolver in a timeout-bound process; no unkillable DNS worker threads."""
    try:
        result = subprocess.run([sys.executable, '-c', RESOLVER, name],
            capture_output=True, text=True, timeout=8, check=False)
        if result.returncode:
            return dict(host=name, addresses=[], status='unresolved')
        addresses = sorted({str(ipaddress.ip_address(ip)) for ip in json.loads(result.stdout)})
        return dict(host=name, addresses=addresses, status='resolved' if addresses else 'unresolved')
    except subprocess.TimeoutExpired:
        return dict(host=name, addresses=[], status='timeout')
    except (ValueError, OSError):
        return dict(host=name, addresses=[], status='error')


def read_names(path):
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError('Subdomain input exceeds 4 MiB; split or reduce it')
    return path.read_text(encoding='utf-8').splitlines()


def discover(args, domain, root):
    names, rejected = {domain}, 0
    sources = []
    if args.subdomain_file:
        values, count = normalize_names(read_names(args.subdomain_file), domain)
        names.update(values)
        rejected += count
        sources.append(dict(source='file', status='completed', accepted=len(values), rejected=count))
    if not args.no_passive:
        binary = shutil.which('subfinder')
        if not binary:
            sources.append(dict(source='subfinder', status='missing',
                note='Install Subfinder or supply --subdomain-file; discovery is incomplete.'))
        else:
            folder = root / 'subfinder'
            path = folder / 'names.txt'
            manager = Children()
            try:
                result = manager.execute([binary, '-d', domain, '-silent', '-o', str(path)],
                    folder, args.discovery_timeout)
            except BaseException:
                manager.cancel()
                raise
            status = result['status']
            if status == 'completed' and not path.is_file():
                status = 'incomplete'
            values, count = normalize_names(read_names(path) if path.is_file() else [], domain)
            names.update(values)
            rejected += count
            sources.append(dict(source='subfinder', status=status, accepted=len(values), rejected=count,
                log='subfinder/console.log',
                note='Passive provider coverage depends on configured API keys; not exhaustive.'))
    ordered = [domain] + sorted(names - {domain})
    chosen, deferred = ordered[:args.max_hosts], ordered[args.max_hosts:]
    with ThreadPoolExecutor(max_workers=min(8, args.host_workers * 2)) as pool:
        resolved = list(pool.map(resolve, chosen))
    # Detect likely wildcard DNS using two independent nonexistent-looking names.
    controls = [resolve('twiy-' + uuid.uuid4().hex + '.' + domain) for _ in range(2)]
    wildcard = set(controls[0]['addresses']) & set(controls[1]['addresses'])
    for row in resolved:
        row['wildcard_candidate'] = bool(row['host'] != domain and wildcard & set(row['addresses']))
    return dict(sources=sources, hosts=resolved, deferred=deferred, rejected=rejected,
        wildcard_controls=controls, wildcard_addresses=sorted(wildcard),
        note='Wildcard matches are marked, not confirmed sites. DNS names do not enumerate every virtual host. '
             'All resolved addresses are planned; shared/CDN IPs may belong to a hosting provider.')


def reuse_services(path, ip, selection=None):
    doc = json.loads(path.read_text(encoding='utf-8'))
    state = doc.get('nmap', {})
    if doc.get('scan_ip') != ip or doc.get('dry_run') or state.get('status') not in ('completed', 'completed_no_open_ports'):
        raise ValueError('Reusable inventory must be a completed real scan of the exact pinned IP')
    if selection is not None and state.get('selection') != selection:
        raise ValueError('Reusable inventory port selection differs from the requested scan')
    xml = path.parent / 'nmap' / 'services.xml'
    digest = hashlib.sha256(xml.read_bytes()).hexdigest()
    if digest != state.get('sha256'):
        raise ValueError('Reusable Nmap evidence hash does not match the summary')
    rows, details = nmap_scan.inventory(xml, ip, 'completed')
    if details['status'] not in ('completed', 'completed_no_open_ports'):
        raise ValueError('Reusable Nmap XML is incomplete')
    details.update(reused=True, source_summary=str(path), selection=state.get('selection'),
        note='Reused complete same-IP TCP inventory; web requests retain this hostname. Ports may change between scans.')
    return rows, details


def child_arguments(args, name, ip, output, inventory=None):
    cmd = [sys.executable, str((PROJECT_ROOT / 'twiy.py')), name,
        '--scan', 'server', '--connect-ip', ip, '--no-menu', '--no-banner',
        '--output', str(output), '--log-file', str(output / 'diagnostics.log'), '--ui', 'plain']
    for key in ('mode', 'profile', 'workers', 'http_workers', 'rate', 'delay', 'nmap_rate',
                'nmap_timeout', 'network_timeout', 'http_timeout', 'tool_timeout', 'nmap_scan',
                'version_intensity', 'crawl_pages', 'crawl_depth', 'crawl_timeout', 'checks_timeout',
                'file_limit', 'max_sqli_jobs', 'sqli_timeout', 'sqli_techniques', 'advanced_timeout', 'enum', 'wordlist', 'templates'):
        value = getattr(args, key)
        if value is not None:
            cmd += ['--' + key.replace('_', '-'), str(value)]
    for key in ('insecure', 'external_tools', 'retain_raw_evidence', 'service_checks', 'dry_run',
                'no_crawl', 'no_crawl_redirects', 'no_web_metadata', 'no_auto_sqli', 'no_active_checks',
                'active_checks', 'builtin_sqli', 'template_checks', 'sensitive_files', 'api_discovery'):
        # no_crawl_redirects is represented by the inverse dest in the CLI.
        if getattr(args, key, False):
            cmd += ['--' + key.replace('_', '-')]
    if not args.crawl_redirects:
        cmd.append('--no-crawl-redirects')
    if args.skip:
        cmd += ['--skip', *args.skip]
    if inventory:
        cmd += ['--reuse-services', str(inventory)]
    return cmd


class Children:
    def __init__(self):
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.active = set()

    @staticmethod
    def kill(proc):
        if os.name == 'posix':
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            proc.kill()
        proc.wait()

    def cancel(self):
        self.stop.set()
        with self.lock:
            for proc in list(self.active):
                self.kill(proc)

    def execute(self, argv, folder, timeout):
        folder.mkdir(parents=True, exist_ok=True)
        started = time.monotonic()
        with (folder / 'console.log').open('wb') as log:
            with self.lock:
                if self.stop.is_set():
                    return dict(status='cancelled', exit_code=None)
                proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL, start_new_session=True)
                self.active.add(proc)
            status = ''
            try:
                while proc.poll() is None:
                    if self.stop.wait(.1):
                        status = 'cancelled'
                        self.kill(proc)
                        break
                    if time.monotonic() - started >= timeout:
                        status = 'timeout'
                        self.kill(proc)
                        break
                return dict(status=status or ('completed' if proc.returncode == 0 else 'incomplete'),
                    exit_code=proc.returncode, elapsed=round(time.monotonic() - started, 2))
            except BaseException:
                self.kill(proc)
                raise
            finally:
                with self.lock:
                    self.active.discard(proc)


def write_report(root, summary):
    """Atomic checkpoint and a portable escaped cross-host report."""
    temporary = root / 'estate.json.tmp'
    temporary.write_text(json.dumps(summary, indent=2), encoding='utf-8')
    temporary.replace(root / 'estate.json')
    esc = lambda value: html.escape(str(value), quote=True)
    rows = []
    for row in summary['scans']:
        link = row.get('report', '')
        report = '<a href="' + esc(link) + '">Report</a>' if link else 'No report'
        rows.append('<tr>' + ''.join('<td>' + esc(row.get(k, '')) + '</td>' for k in
            ('host', 'ip', 'status', 'open_ports', 'web_origins', 'candidates')) + '<td>' + report + '</td></tr>')
    inventory = ''.join('<tr><td>' + esc(r['host']) + '</td><td>' + esc(', '.join(r['addresses'])) +
        '</td><td>' + esc(r['status']) + (' / possible wildcard' if r.get('wildcard_candidate') else '') +
        '</td></tr>' for r in summary.get('discovery', {}).get('hosts', []))
    document = '<!doctype html><meta charset="utf-8"><title>TWIY estate</title><style>' \
        'body{font:16px system-ui;background:#111827;color:#e5e7eb;padding:2rem}a{color:#67e8f9}' \
        'table{border-collapse:collapse;width:100%}td,th{border:1px solid #475569;padding:.6rem;text-align:left}' \
        '</style><h1>Domain / server assessment</h1><p>' + esc(summary['domain']) + ' — ' + esc(summary['status']) + \
        '</p><p>TCP only; observed DNS names and services, not every site or proof of security.</p>' + \
        '<h2>Discovery</h2><pre>' + esc(json.dumps(summary.get('discovery', {}).get('sources', []), indent=2)) + \
        '</pre><table><tr><th>Host</th><th>Addresses</th><th>DNS status</th></tr>' + inventory + '</table>' + \
        '<p>Deferred by host cap: ' + esc(len(summary.get('discovery', {}).get('deferred', []))) + '</p>' + \
        '<h2>Scans</h2><table><tr><th>Host</th><th>IP</th><th>Status</th><th>TCP ports</th>' \
        '<th>Web origins</th><th>Candidates</th><th>Evidence</th></tr>' + ''.join(rows) + '</table>'
    (root / 'report.html').write_text(document, encoding='utf-8')


def run(args):
    target = parse_target(args.target)
    try:
        ipaddress.ip_address(target.host)
    except ValueError:
        pass
    else:
        raise ValueError('Estate needs a domain; use --scan server for a single IP')
    if target.url or '.' not in target.host:
        raise ValueError('Use a bare domain for estate discovery, e.g. example.test')
    if (args.only or args.ports or args.top_ports or args.url_port_only or args.connect_ip
            or args.reuse_services or args.cookie_file or args.contexts or args.url or args.sqlmap_url
            or args.compare or args.idor or args.idor_value or args.ssrf_canary or args.ssrf_metadata or args.time_sqli):
        raise ValueError('Estate does not accept single-host port selections, credentials, comparisons or specialized probes; use a child scan separately')
    if 'nmap' in args.skip:
        raise ValueError('Estate server assessment requires Nmap')
    if args.host_workers > 4 or args.max_hosts > 500:
        raise ValueError('Use host-workers <= 4 and max-hosts <= 500')
    if args.external_tools and not args.retain_raw_evidence and not args.dry_run:
        raise ValueError('--external-tools requires --retain-raw-evidence')
    if args.output.suffix.lower() in ('.json', '.html'):
        raise ValueError('Estate --output must be a directory')
    root = args.output.expanduser().resolve() / ('estate_' + target.host + '_' + uuid.uuid4().hex[:8])
    root.mkdir(parents=True, mode=0o700)
    summary = dict(version=VERSION, domain=target.host, created=dt.datetime.now(dt.timezone.utc).isoformat(),
        status='running', scans=[], discovery={}, dry_run=args.dry_run,
        concurrency=dict(hosts=args.host_workers, tools_per_host=args.workers, mode=args.mode,
            note='Rate limits are per host/tool, not global across the estate.'))
    children = Children()
    cache = {}
    ip_locks = {}
    write_report(root, summary)
    try:
        if args.dry_run:
            summary['discovery'] = dict(sources=[dict(source='discovery', status='planned')],
                hosts=[], deferred=[], note='No discovery, DNS or child processes executed.')
            summary['status'] = 'planned'
            return 0
        summary['discovery'] = discover(args, target.host, root)
        write_report(root, summary)
        hosts = summary['discovery']['hosts']
        for row in hosts:
            for ip in row['addresses']:
                ip_locks.setdefault(ip, threading.Lock())

        def scan(item):
            name, ip = item
            folder = root / (name + '_' + hashlib.sha256(ip.encode()).hexdigest()[:10])
            # A host on the same IP waits for the first complete inventory, avoiding duplicate port scans.
            with ip_locks[ip]:
                if children.stop.is_set():
                    return dict(host=name, ip=ip, status='cancelled')
                output = folder / 'runs'
                output.mkdir(parents=True, exist_ok=True)
                argv = child_arguments(args, name, ip, output, cache.get(ip))
                try:
                    result = children.execute(argv, folder, args.host_timeout)
                except OSError as exc:
                    result = dict(status='failed', error=type(exc).__name__)
                row = dict(host=name, ip=ip, **result)
                summaries = sorted(output.glob('*/summary.json'))
                if summaries:
                    source = summaries[-1]
                    try:
                        doc = json.loads(source.read_text(encoding='utf-8'))
                        row.update(open_ports=len(doc.get('ports', [])),
                            web_origins=len({p['url'] for p in doc.get('probes', []) if 'status' in p}),
                            candidates=doc.get('statistics', {}).get('vulnerability_candidates', 0))
                        report = source.with_name('report.html')
                        if report.is_file():
                            row['report'] = report.relative_to(root).as_posix()
                        if doc.get('nmap', {}).get('status') in ('completed', 'completed_no_open_ports'):
                            # Verify the XML/digest before sharing it with another hostname.
                            reuse_services(source, ip)
                            cache[ip] = source
                    except (OSError, ValueError, KeyError, TypeError):
                        row['status'] = 'incomplete'
                else:
                    row['status'] = 'incomplete' if row['status'] == 'completed' else row['status']
                return row

        if not args.discover_only:
            tasks = [(row['host'], ip) for row in hosts for ip in row['addresses']]
            # Interleave IP groups so one busy shared IP cannot block unrelated servers.
            groups = {}
            for task in tasks:
                groups.setdefault(task[1], []).append(task)
            tasks = [group[i] for i in range(max(map(len, groups.values()), default=0))
                     for group in groups.values() if i < len(group)]
            pool = ThreadPoolExecutor(max_workers=args.host_workers)
            futures = []
            try:
                futures = [pool.submit(scan, task) for task in tasks]
                from concurrent.futures import as_completed
                for future in as_completed(futures):
                    row = future.result()
                    summary['scans'].append(row)
                    print('[ESTATE] ' + row['host'] + ' / ' + row['ip'] + ': ' + row['status'], flush=True)
                    write_report(root, summary)
            except BaseException:
                children.cancel()
                # Preserve completed and interrupted rows, including those not yet yielded.
                pool.shutdown(wait=True)
                summary['scans'] = [f.result() for f in futures if not f.cancelled() and f.exception() is None]
                raise
            finally:
                pool.shutdown(wait=True)
        incomplete = (bool(summary['discovery']['deferred']) or any(r['status'] != 'resolved' for r in hosts)
            or any(r['status'] != 'completed' for r in summary['discovery']['sources'])
            or any(r['status'] != 'completed' for r in summary['scans']))
        summary['status'] = 'incomplete' if incomplete else 'completed'
        return 2 if incomplete else 0
    except (KeyboardInterrupt, InterruptedError):
        children.cancel()
        summary['status'] = 'interrupted'
        return 130
    except BaseException:
        children.cancel()
        summary['status'] = 'failed'
        raise
    finally:
        write_report(root, summary)
        print('Estate report: ' + str(root / 'report.html'), flush=True)
