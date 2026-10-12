"""Offline scanner adapters. Matches are observations, never validated claims."""
import hashlib
import json
import re
import urllib.parse
from pathlib import Path


def normalize_url(value, target):
    u = urllib.parse.urlsplit(value)
    if (u.scheme not in ('http', 'https') or u.hostname != target or
            u.username or u.password or any(ord(c) < 32 for c in value)):
        raise ValueError('Result URL is outside the single-IP scope or invalid')
    port = u.port or (443 if u.scheme == 'https' else 80)
    if u.port is not None and not 1 <= u.port <= 65535:
        raise ValueError('Invalid result URL port')
    authority = target if port == (443 if u.scheme == 'https' else 80) else f'{target}:{port}'
    return urllib.parse.urlunsplit((u.scheme, authority, u.path or '/', u.query, ''))


def observations(tool, row, base):
    """Yield category, check identity, URL, title, scanner severity."""
    if not isinstance(row, dict):
        raise ValueError('Expected a result object')
    url = row.get('url') or row.get('target') or base
    if tool in ('ffuf', 'feroxbuster', 'gobuster', 'dirsearch'):
        if tool == 'feroxbuster' and row.get('type') != 'response':
            return
        if not row.get('url') and row.get('path'):
            url = urllib.parse.urljoin(base, row['path'])
        status = row.get('status', row.get('status_code'))
        if status is None:
            raise ValueError('Missing HTTP status')
        yield 'endpoint', str(status), url, f'HTTP endpoint ({status})', 'info'
    elif tool == 'nuclei':
        info = row.get('info', {})
        check = row.get('template-id')
        if not check:
            raise ValueError('Missing template-id')
        yield 'scanner_match', check + ':' + str(row.get('matcher-name', '')), row.get('matched-at') or url, info.get('name', check), info.get('severity', 'unknown')
    elif tool == 'nikto':
        if 'vulnerabilities' not in row:
            raise ValueError('Missing vulnerabilities array')
        if row.get('ip') and row['ip'] != urllib.parse.urlsplit(base).hostname:
            raise ValueError('Nikto host is outside the single-IP scope')
        for item in row.get('vulnerabilities', []):
            check = str(item.get('id') or item.get('OSVDB') or item.get('msg', ''))
            yield 'scanner_match', check + ':' + item.get('method', 'GET'), urllib.parse.urljoin(base, item.get('url', '/')), item.get('msg', check), 'unknown'
    elif tool == 'sqlmap':
        yield 'scanner_match', row['parameter'] + ':' + row['type'], base, row['title'], 'unknown'
    elif tool == 'crawler':
        if 'status' not in row:
            return
        yield 'endpoint', str(row['status']), url, f'HTTP endpoint ({row["status"]})', 'info'
        headers = {k.lower(): v for k, v in row.get('headers', [])}
        if 200 <= row['status'] < 300 and 'html' in headers.get('content-type', '').lower():
            checks = [('content-security-policy', 'Content-Security-Policy header missing'),
                      ('x-content-type-options', 'X-Content-Type-Options header missing')]
            if urllib.parse.urlsplit(url).scheme == 'https':
                checks.append(('strict-transport-security', 'HSTS header missing'))
            for header, title in checks:
                if header not in headers:
                    yield 'configuration', header, url, title, 'low'
    elif tool == 'httpx':
        if not row.get('url'):
            raise ValueError('Missing URL')
        yield 'technology', 'httpx', url, 'HTTP metadata', 'info'
    elif tool == 'whatweb':
        if not row.get('target') or not isinstance(row.get('plugins'), dict):
            raise ValueError('Missing target/plugins')
        for plugin in row['plugins']:
            yield 'technology', plugin, url, plugin, 'info'
    else:
        raise ValueError('Unsupported scanner format')


def collect(root, summary):
    root = Path(root).resolve()
    merged, issues = {}, []
    for job in summary.get('jobs', []):
        if job['status'] in ('planned', 'skipped'):
            continue
        tool = job['tool']
        if tool == 'nmap':
            continue  # Already parsed into the services table.
        base = next((v for v in job.get('argv', []) if v.startswith(('http://', 'https://'))), '')
        for filename in (['console.log'] if tool == 'sqlmap' else job.get('outputs', [])):
            path = (Path(job['folder']) / filename).resolve()
            try:
                rel = path.relative_to(root).as_posix()
                data = path.read_bytes()
                digest = hashlib.sha256(data).hexdigest()
                content = data.decode('utf-8-sig')
                if tool == 'sqlmap':
                    parameter = re.search(r'^Parameter:\s*(.+?)\s*\(GET\)\s*$', content, re.M)
                    blocks = list(re.finditer(r'^\s+Type:\s*(.+)\n\s+Title:\s*(.+)\n\s+Payload:\s*(.+)', content, re.M))
                    records = [(content[:m.start()].count('\n') + 1,
                                {'parameter': parameter[1], 'type': m[1].rstrip('\r'), 'title': m[2].rstrip('\r'), 'payload': m[3].rstrip('\r')})
                               for m in blocks] if parameter else []
                    issues.append({'job': job['name'], 'file': rel,
                                   'message': 'SQLmap adapter reads GET Type/Title/Payload blocks only; review console and session files for full coverage.'})
                elif filename.endswith('.jsonl'):
                    records = [(i, line) for i, line in enumerate(content.splitlines(), 1) if line.strip()]
                elif tool == 'gobuster':
                    records = [(i, line) for i, line in enumerate(content.splitlines(), 1) if line.strip()]
                else:
                    doc = json.loads(content)
                    if tool == 'ffuf':
                        doc = doc['results']
                    elif tool == 'dirsearch':
                        doc = doc['results']
                    elif tool == 'crawler':
                        doc = doc['pages']
                    records = list(enumerate(doc if isinstance(doc, list) else [doc], 1))
                for index, raw in records:
                    try:
                        if tool == 'gobuster':
                            match = re.search(r'^(\S+)\s+\(Status:\s*(\d+)\)', raw)
                            if not match:
                                raise ValueError('Unrecognized Gobuster line')
                            row = {'url': urllib.parse.urljoin(base, match[1]), 'status': int(match[2])}
                        else:
                            row = json.loads(raw) if isinstance(raw, str) else raw
                        for category, check, url, title, severity in observations(tool, row, base):
                            url = normalize_url(url, summary['target'])
                            key = (category, check if category == 'endpoint' else tool + ':' + check, url)
                            entry = merged.setdefault(key, {'id': hashlib.sha256(json.dumps(key).encode()).hexdigest()[:16],
                                'category': category, 'check': check, 'url': url, 'title': title,
                                'severity': severity, 'validation_status': 'needs_validation', 'evidence': []})
                            if tool == 'sqlmap':
                                entry['recommendation'] = 'Reproduce with a control request; if validated, use parameterized database queries and restrict database account privileges.'
                            elif category == 'configuration':
                                entry['recommendation'] = 'Review the response in application context and configure the indicated security header; a missing header alone does not prove exploitability.'
                            elif tool == 'nuclei':
                                entry['recommendation'] = row.get('info', {}).get('remediation') or 'Validate the template match and review the template references for remediation appropriate to the deployed version.'
                            elif category == 'endpoint':
                                entry['recommendation'] = 'Review intended exposure, authentication and access controls for this endpoint.'
                            else:
                                entry['recommendation'] = 'Validate the scanner observation in application context before assigning risk or remediation.'
                            entry['evidence'].append({'tool': tool, 'job': job['name'], 'job_status': job['status'],
                                'file': rel, 'record': index, 'sha256': digest, 'raw': raw})
                    except (ValueError, TypeError, KeyError, AttributeError) as exc:
                        issues.append({'job': job['name'], 'file': rel, 'record': index, 'message': str(exc)})
            except (OSError, ValueError, KeyError, TypeError) as exc:
                issues.append({'job': job['name'], 'file': filename, 'message': str(exc)})
    return sorted(merged.values(), key=lambda x: (x['url'], x['category'], x['check'])), issues
