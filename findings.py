"""Rqtn Tool offline adapters. Matches are observations requiring validation."""
import hashlib
import json
import re
import urllib.parse
from pathlib import Path
from scope import normalize_url
from checks import security_headers


def sqlmap_outcome(job):
    if job['status'] != 'completed':
        return 'incomplete'
    try:
        text = (Path(job['folder']) / 'console.log').read_text(encoding='utf-8', errors='replace')
    except OSError:
        return 'inconclusive'
    if re.search(r'^Parameter:.*\((?:GET|POST)\)', text, re.M) and re.search(
            r'^\s+Type:.*\n\s+Title:.*\n\s+Payload:', text, re.M):
        return 'candidate_needs_validation'
    if re.search(r'provided value for parameter.*is empty|\[ERROR\]|does not appear to be dynamic|not dynamic|connection.*(?:failed|error)', text, re.I):
        return 'inconclusive'
    if 'all tested parameters do not appear to be injectable' in text.lower():
        return 'no_match_in_tested_techniques'
    return 'inconclusive'


def finding_groups(findings):
    """Group header notes per origin, retaining individual finding references."""
    groups = {}
    for finding in findings:
        u = urllib.parse.urlsplit(finding['url'])
        key = ((finding['category'], finding['check'], u.scheme, u.netloc)
               if finding['category'] == 'configuration' else (finding['id'],))
        group = groups.setdefault(key, {k: finding[k] for k in ('title', 'severity', 'category', 'check', 'validation_status')})
        group.setdefault('finding_ids', []).append(finding['id'])
        group.setdefault('urls', []).append(finding['url'])
    return list(groups.values())


def observations(tool, row, base, scan_ip=None):
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
        if row.get('ip') and row['ip'] != (scan_ip or urllib.parse.urlsplit(base).hostname):
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
        if row.get('phpinfo_signature'):
            yield 'scanner_match', 'phpinfo-content', url, 'PHP configuration information exposed candidate', 'medium'
        for header, title in security_headers(url, row['status'], row.get('headers', [])):
            yield 'configuration', header, url, title, 'low'
    elif tool == 'httpx':
        if not row.get('url'):
            raise ValueError('Missing URL')
        yield 'technology', 'httpx', url, 'HTTP metadata', 'info'
    elif tool == 'checks':
        for match in row.get('matches', [row] if row.get('outcome') == 'candidate' else []):
            yield 'scanner_match', match['check'] + ':' + row.get('parameter', ''), url, match['title'], match['severity']
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
        if tool in ('nmap', 'network'):
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
                                   'kind': 'manual_review',
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
                        results = doc['results']
                        if isinstance(results, dict):
                            doc = []
                            for base_url, rows in results.items():
                                if not isinstance(rows, list):
                                    raise ValueError('Expected grouped Dirsearch result lists')
                                for row in rows:
                                    if not isinstance(row, dict):
                                        raise ValueError('Expected Dirsearch endpoint object')
                                    doc.append(dict(row, url=row.get('url') or urllib.parse.urljoin(base_url, row.get('path', ''))))
                        else:
                            doc = results
                    elif tool == 'crawler':
                        doc = doc['pages']
                    elif tool == 'checks':
                        doc = doc['checks']
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
                        for category, check, url, title, severity in observations(tool, row, base, summary.get('scan_ip')):
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
                                'file': rel, 'record': index, 'sha256': digest, 'raw': row if summary.get('retain_raw_evidence', True) else '[omitted]'})
                    except (ValueError, TypeError, KeyError, AttributeError) as exc:
                        issues.append({'job': job['name'], 'file': rel, 'record': index, 'message': str(exc)})
            except (OSError, ValueError, KeyError, TypeError) as exc:
                issues.append({'job': job['name'], 'file': filename, 'message': str(exc)})
    # A responding discovery probe is an endpoint observation even with crawl disabled.
    for row in summary.get('probes', []):
        if 'status' not in row:
            continue
        try:
            url = normalize_url(row['url'], summary['target'])
            key = ('endpoint', str(row['status']), url)
            merged.setdefault(key, {'id': hashlib.sha256(json.dumps(key).encode()).hexdigest()[:16],
                'category': 'endpoint', 'check': str(row['status']), 'url': url,
                'title': f'HTTP endpoint ({row["status"]})', 'severity': 'info',
                'validation_status': 'needs_validation', 'evidence': [],
                'recommendation': 'Review intended exposure and access controls; observed during HTTP discovery.'})
        except (ValueError, KeyError, TypeError) as exc:
            issues.append({'job': 'HTTP discovery', 'file': 'summary.json', 'message': str(exc)})
    return sorted(merged.values(), key=lambda x: (x['url'], x['category'], x['check'])), issues
