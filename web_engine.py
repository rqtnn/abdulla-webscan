"""Bounded adapters for complementary upstream web engines.

No shell, installers, OAST services, login flows or automatic WAF bypass.
CLI contracts are checked locally before sending any scanner request.
"""
import json
import re
import subprocess
import urllib.parse
from pathlib import Path

from scope import ACTION, origin, scoped_link

TOOLS = ('katana', 'dalfox', 'testssl')
CONTRACTS = {
    'katana': ('-h', ('-crawl-scope', '-crawl-out-scope', '-disable-redirects',
                      '-crawl-duration', '-rate-limit', '-jsonl', '-omit-body', '-config')),
    'dalfox': ('scan', ('--param', '--skip-mining', '--skip-reflection-header',
                       '--skip-reflection-cookie', '--skip-reflection-path',
                       '--rate-limit', '--insecure', '--waf-bypass', '--max-payloads-per-param',
                       '--config', '--include-url', '--exclude-url', '--skip-discovery')),
    'testssl': ('--help', ('--protocols', '--nodns', '--ip', '--jsonfile',
                         '--socket-timeout', '--openssl-timeout')),
}


def compatibility(tool, binary):
    if not binary:
        return f'{tool} is not installed/on PATH.'
    first, flags = CONTRACTS[tool]
    argv = [binary, first] + (['--help'] if tool == 'dalfox' else [])
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10,
                                stdin=subprocess.DEVNULL)
        help_text = result.stdout + result.stderr
        missing = [flag for flag in flags if flag not in help_text]
        if result.returncode not in (0, 1) or missing:
            return 'Unsupported CLI contract; review installed version: ' + ', '.join(missing)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 'Local CLI compatibility check failed: ' + type(exc).__name__
    return ''


def command(tool, binary, url, folder, args, parameter=None):
    """Return argv/output/deferral. Parent Runner enforces the wall-clock budget."""
    binary = binary or ('testssl.sh' if tool == 'testssl' else tool)
    output = 'results.jsonl' if tool == 'katana' else 'results.json'
    destination = str(folder / output)
    u = urllib.parse.urlsplit(url)
    reason = ''
    if getattr(args, 'session', None):
        reason = 'External engines do not inherit the authenticated session.'
    if tool == 'katana':
        # Upstream standard transport disables TLS verification. Never inherit
        # that behavior without the user's explicit insecure opt-in.
        if u.scheme == 'https' and not args.insecure:
            reason = 'Katana upstream bypasses TLS validation; HTTPS requires explicit --insecure.'
        scope = '^' + re.escape(u.scheme + '://' + u.netloc) + '(/|$)'
        argv = [binary, '-config', str(folder / 'engine.yaml'), '-u', url, '-d', str(args.crawl_depth), '-jc', '-dr',
                '-cs', scope, '-cos', '(?i)' + ACTION.pattern, '-ct', str(args.crawl_timeout) + 's',
                '-timeout', str(args.http_timeout), '-retry', '0', '-c', '1', '-p', '1',
                '-rl', str(args.rate), '-duc', '-j', '-or', '-ob', '-o', destination]
    elif tool == 'dalfox':
        scope = '^' + re.escape(u.scheme + '://' + u.netloc + u.path) + '(\\?|$)'
        argv = [binary, '--config', str(folder / 'engine.json'), 'scan', url,
                '--include-url', scope, '--exclude-url', '(?i)' + ACTION.pattern,
                '--param', parameter + ':query', '--method', 'GET', '--skip-discovery',
                '--skip-mining', '--skip-reflection-header', '--skip-reflection-cookie',
                '--skip-reflection-path', '--skip-waf-probe', '--waf-bypass', 'off',
                '--workers', '1', '--rate-limit', str(args.rate),
                '--timeout', str(args.http_timeout), '--scan-timeout', str(args.tool_timeout),
                '--max-payloads-per-param', '100',
                '--insecure=' + str(args.insecure).lower(), '--format', 'json', '-o', destination]
        if args.no_active_checks:
            reason = 'Dalfox injection disabled by --no-active-checks.'
    else:
        if u.scheme != 'https':
            reason = 'testssl protocol checks require an HTTPS origin.'
        ip = u.hostname
        ip = '[' + ip + ']' if ':' in ip else ip
        argv = [binary, '--protocols', '--nodns', 'none', '--ip', ip,
                '--warnings', 'batch', '--color', '0',
                '--socket-timeout', str(args.http_timeout), '--openssl-timeout', str(args.http_timeout),
                '--jsonfile', destination, url]
    return argv, output, reason


def prepare(tool, folder):
    """Keep user-global scanner profiles from enabling unrelated scan features."""
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    if tool == 'dalfox':
        (folder / 'engine.json').write_text('{"scan": {}}\n', encoding='utf-8')
    elif tool == 'katana':
        (folder / 'engine.yaml').write_text('{}\n', encoding='utf-8')


def documents(tool, doc):
    if tool == 'dalfox':
        if not isinstance(doc, dict) or not isinstance(doc.get('findings'), list) or not isinstance(doc.get('meta'), dict):
            raise ValueError('Expected Dalfox v3 findings/meta document')
        return doc['findings']
    return doc if isinstance(doc, list) else [doc]


def observations(tool, row, base):
    if tool == 'katana':
        request, response = row.get('request', {}), row.get('response', {})
        if request.get('method', 'GET').upper() != 'GET':
            return
        status = response.get('status_code')
        if not isinstance(status, int):
            raise ValueError('Katana record has no HTTP response status')
        yield 'endpoint', str(status), request['endpoint'], f'HTTP endpoint ({status})', 'info'
    elif tool == 'dalfox':
        kind = str(row.get('type', '')).upper()
        if kind not in ('V', 'A', 'R', 'I'):
            raise ValueError('Unknown Dalfox finding tier')
        url = row.get('data')
        if not isinstance(url, str) or not url.startswith(('http://', 'https://')):
            raise ValueError('Dalfox finding has no HTTP PoC URL')
        title = {'V': 'Dalfox XSS candidate', 'A': 'Dalfox DOM source-to-sink candidate',
                 'R': 'Reflection only; XSS not established', 'I': 'Dalfox informational observation'}[kind]
        yield ('scanner_match', 'dalfox-' + kind + ':' + str(row.get('param', '')),
               url, title, str(row.get('severity', 'unknown')).lower() if kind in ('V', 'A') else 'info')
    else:
        if not row.get('id') or not row.get('severity'):
            raise ValueError('Malformed testssl result')
        severity = str(row['severity']).lower()
        if severity in ('warn', 'warning', 'fatal'):
            raise ValueError('testssl runtime warning: ' + str(row.get('finding', ''))[:300])
        if severity in ('ok', 'info'):
            return
        if severity not in ('low', 'medium', 'high', 'critical'):
            raise ValueError('Unknown testssl severity')
        # Each job has a single target and --ip; no target is inferred from prose.
        if row.get('port') and int(row['port']) != origin(base)[2]:
            raise ValueError('testssl port differs from scheduled origin')
        yield 'scanner_match', str(row['id']), base, str(row.get('finding', row['id'])), severity


def discovered_urls(jobs, live, target, limit):
    """Read only completed scoped GET observations; never trust raw output as input."""
    allowed = {origin(url) for url in live}
    urls, rejected = [], 0
    for job in jobs:
        if job['tool'] != 'katana' or job['status'] not in ('completed', 'timeout'):
            continue
        try:
            lines = (Path(job['folder']) / 'results.jsonl').read_text(encoding='utf-8').splitlines()
        except OSError:
            continue
        for line in lines:
            if len(urls) >= limit:
                return urls, rejected
            try:
                row = json.loads(line)
                request = row['request']
                if request.get('method', 'GET').upper() != 'GET':
                    raise ValueError('Non-GET discovery')
                url = scoped_link(request['endpoint'], live[0], target, allowed)
                # Reuse candidate filtering to keep credential-bearing URLs out
                # of subsequent external scanners as well as GET checks.
                from crawler import SECRET
                if any(SECRET.search(name) for name, _ in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query)):
                    raise ValueError('Sensitive query')
                if url not in urls:
                    urls.append(url)
            except (ValueError, TypeError, KeyError, AttributeError):
                rejected += 1
    return urls, rejected


def completion(tool, folder):
    """An exit code alone does not mean coverage was complete."""
    path = Path(folder) / ('results.jsonl' if tool == 'katana' else 'results.json')
    try:
        if tool == 'dalfox':
            doc = json.loads(path.read_text(encoding='utf-8'))
            documents(tool, doc)
            if doc['meta'].get('incomplete'):
                return 'Dalfox reported incomplete coverage; partial findings retained.'
        elif tool == 'testssl':
            rows = json.loads(path.read_text(encoding='utf-8'))
            if not isinstance(rows, list) or not rows:
                return 'testssl produced no protocol records.'
            if any(str(row.get('severity', '')).upper() in ('WARN', 'WARNING', 'FATAL') for row in rows):
                return 'testssl reported runtime warnings; review partial output.'
        elif not path.exists():
            return 'Katana produced no output artifact; discovery coverage is unknown.'
    except (OSError, ValueError, TypeError, AttributeError):
        return 'Missing or invalid engine output; coverage is unknown.'
    return ''
