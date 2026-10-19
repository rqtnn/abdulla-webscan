"""Evidence-derived CVE metadata and manual web reproduction guidance."""
import re
import shlex
import urllib.parse

import evidence


def nuclei_metadata(row):
    info = row.get('info') or {}
    classification = info.get('classification') or {}
    if not isinstance(classification, dict):
        classification = {}
    values = classification.get('cve-id', [])
    values = values if isinstance(values, list) else [values]
    # Template identity is a fallback, never guess from a product banner.
    values.append(row.get('template-id', ''))
    cves = sorted({match.upper() for value in values if isinstance(value, str)
                   for match in re.findall(r'\bCVE-\d{4}-\d{4,}\b', value, re.I)})
    refs = info.get('reference', [])
    refs = refs if isinstance(refs, list) else [refs]
    safe_refs = []
    for value in refs:
        try:
            if (isinstance(value, str) and value.startswith(('https://', 'http://'))
                    and not any(c.isspace() for c in value) and urllib.parse.urlsplit(value).hostname
                    and not urllib.parse.urlsplit(value).username):
                safe_refs.append(evidence.url(value))
        except ValueError:
            continue
    return dict(cve_ids=cves, cve_status='scanner_reported_requires_validation' if cves else 'not_identified',
                cve_source='nuclei_template', references=list(dict.fromkeys(safe_refs))[:20],
                classification={k: classification[k] for k in ('cwe-id', 'cvss-score', 'cvss-metrics') if k in classification})


def guide(finding, target, scan_ip=None):
    """Use captured request URLs; commands are displayed only, never executed."""
    check = finding['check']
    urls = [finding['url']]
    origin_headers = []
    for item in finding.get('evidence', []):
        for poc in item.get('poc', []):
            value = poc.get('url', '')
            try:
                parsed = urllib.parse.urlsplit(value)
                if parsed.scheme in ('http', 'https') and parsed.hostname == target:
                    urls.append(value)
                    for name, header in poc.get('request', {}).get('headers', []):
                        if name.lower() == 'origin' and isinstance(header, str):
                            origin_headers.append((value, header))
            except ValueError:
                continue
    commands = []
    for value in dict.fromkeys(urls):
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme not in ('http', 'https'):
            continue
        pin = ''
        if scan_ip and parsed.hostname == target:
            address = '[' + scan_ip + ']' if ':' in scan_ip else scan_ip
            pin = ' --resolve ' + shlex.quote(f'{target}:{parsed.port or (443 if parsed.scheme == "https" else 80)}:{address}')
        commands.append('curl --max-time 10 --include' + pin + ' -- ' + shlex.quote(evidence.url(value)))
        for origin_url, header in origin_headers:
            if origin_url == value:
                commands.append('curl --max-time 10 --include' + pin + ' -H ' + shlex.quote('Origin: ' + header) + ' -- ' + shlex.quote(evidence.url(value)))
    steps = ['Repeat the recorded control and probe requests and compare their status, headers and body. Restore the authorized account context manually if required; credentials are omitted.']
    if 'unescaped-reflection' in check:
        steps.append('Locate the inert marker in the HTML and inspect its output context. Reflection alone does not establish executable XSS.')
    elif 'external-redirect' in check:
        steps.append('Compare the Location header with the supplied external URL. Do not follow the redirect; confirm the destination is user-controlled.')
    elif 'server-template-evaluation' in check:
        steps.append('Repeat both arithmetic expressions and inert controls. Confirm two different computed products between the recorded unique delimiters, rather than reflected expression text. Identify the template engine and rendering context; arithmetic evaluation does not establish operating-system command execution.')
    elif 'sql' in check.lower() or any(e.get('tool') == 'sqlmap' for e in finding.get('evidence', [])):
        steps.append('Compare baseline and probe database errors or repeated timing samples. Confirm parameter influence before calling this SQL injection; do not extract database data.')
    elif 'sensitive-file' in check or 'phpinfo' in check:
        steps.append('Compare with the recorded nonexistent-path control and verify the content signature. A 200 status or filename alone is insufficient. Check whether authentication should be required.')
    elif 'access-control' in check:
        steps.append('Repeat using the declared allowed and disallowed test accounts. Confirm ownership and protected data; identical public or login pages do not prove an authorization bypass.')
    elif 'cors' in check:
        steps.append('Repeat with two different untrusted Origin headers and confirm exact reflection plus Access-Control-Allow-Credentials: true. In an authorized browser session, verify that protected data can be read cross-origin; public content or browser-blocked responses do not establish data exposure.')
    elif any(e.get('tool') == 'nuclei' for e in finding.get('evidence', [])):
        steps.append('Inspect the matching Nuclei template, matcher and exported HTTP evidence. Check deployed product/version and advisory prerequisites before accepting the CVE match. The GET commands alone may not reproduce multi-request or POST templates.')
    else:
        steps.append('Verify the observation in application context and demonstrate its impact before assigning exploitability.')
    return dict(status='manual_validation_required', steps=steps, commands=commands[:8],
                note='Displayed commands are redacted GET helpers, not automatic exploitation or a claim of a confirmed vulnerability.')


def web_leads(findings):
    """Return evidence-linked web investigation leads, without asserting server access."""
    leads = []
    for finding in findings:
        if finding.get('category') != 'scanner_match' or not finding.get('url', '').startswith(('http://', 'https://')):
            continue
        check = finding.get('check', '').lower()
        if check.startswith(('dalfox-r:', 'dalfox-i:')):
            continue  # Reflection alone is an observation, not an XSS lead.
        text = (check + ' ' + finding.get('title', '')).lower()
        if any(term in text for term in ('server-template', 'ssti', 'remote code', 'command injection', 'rce', 'deserialization')):
            focus, priority = 'Server-side execution candidate', 1
            next_step = 'Validate the recorded request and engine/CVE prerequisites in the CTF lab. A scanner match or arithmetic evaluation alone does not prove a shell.'
        elif 'sql' in text:
            focus, priority = 'Database input candidate', 2
            next_step = 'Compare controls and payload evidence, identify the affected parameter and database privileges. SQL injection does not automatically imply operating-system access.'
        elif any(term in text for term in ('sensitive-file', 'phpinfo', 'traversal', 'file inclusion', 'lfi')):
            focus, priority = 'File/configuration exposure candidate', 2
            next_step = 'Confirm the content signature and access requirements against the nonexistent-path control; determine the actual data exposed.'
        elif 'access-control' in text:
            focus, priority = 'Authorization boundary candidate', 2
            next_step = 'Compare explicitly allowed and disallowed test accounts and verify resource ownership.'
        else:
            focus, priority = 'Other web candidate', 3
            next_step = 'Inspect the recorded evidence and manual verification instructions in application context.'
        leads.append(dict(finding_id=finding.get('id', ''), title=finding['title'], url=finding['url'],
                          focus=focus, priority=priority, next_step=next_step,
                          status='requires_manual_validation', cve_ids=finding.get('cve_ids', [])))
    return sorted(leads, key=lambda row: (row['priority'], row['url'], row['title']))
