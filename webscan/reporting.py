"""Evidence aggregation and offline HTML/JSON/CSV presentation."""
import base64
import hashlib
import html
import json
import os
from pathlib import Path
import re
import urllib.parse

from . import assessment, advanced, evidence, run_history, scan_diagnostics, tool_coverage, web_review
from .findings import collect, finding_groups
from .paths import PROJECT_ROOT
from .storage import atomic_text

REPORT_STYLE = (PROJECT_ROOT / 'assets' / 'report.css').read_text(encoding='utf-8')


def write_checkpoint(root, summary):
    """Save discovery progress without rereading scanner logs or rendering HTML.

The final report still performs the complete evidence aggregation. A terminated
process leaves checkpoint.json explicitly marked as incomplete live evidence.
"""
    summary.setdefault('performance', {}).setdefault('discovery_checkpoints', 0)
    summary['performance']['discovery_checkpoints'] += 1
    document = dict(summary, checkpoint_only=True,
        checkpoint_note='Live progress only; findings/statistics may be stale. Use the final summary/report when available.')
    atomic_text(root / 'checkpoint.json', evidence.dumps(document))


def export_reports(root, destination):
    """Export a report while keeping the complete evidence directory."""
    root = root.expanduser().resolve()
    destination = destination.expanduser().resolve()
    if destination.suffix.lower() not in ('.json', '.html'):
        raise ValueError('Report export requires .json or .html')
    destination.parent.mkdir(parents=True, exist_ok=True)
    prefix = Path(os.path.relpath(root, destination.parent)).as_posix()
    if destination.suffix.lower() == '.json':
        document = json.loads((root / 'summary.json').read_text(encoding='utf-8'))
        document['evidence_directory'] = prefix
        destination.write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding='utf-8')
    else:
        document = (root / 'report.html').read_text(encoding='utf-8')
        document = re.sub(r'href="([^"#]+)"', lambda match: match[0] if urllib.parse.urlsplit(html.unescape(match[1])).scheme or match[1].startswith('//') else 'href="' +
            html.escape(urllib.parse.quote(prefix, safe='/') + '/' + html.unescape(match[1]), quote=True) + '"', document)
        destination.write_text(document, encoding='utf-8')
    return destination


def write_reports(root, summary, *, tools, report_script, collector=collect):
    summary['run_directory'] = str(root)
    if summary.get('probes'):
        folder = root / 'discovery'
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        (folder / 'probes.json').write_text(evidence.dumps(summary['probes']), encoding='utf-8')
    summary['findings'], summary['parse_issues'] = collector(root, summary)
    summary['findings'].extend(assessment.findings(root, summary))
    summary['findings'].extend(advanced.findings(root, summary))
    for finding in summary['findings']:
        if finding['category'] in ('scanner_match', 'configuration') and finding['url'].startswith(('http://', 'https://')):
            finding.setdefault('reproduction', advanced.curl_helper(finding['url']))
    ranks = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
    summary['findings'].sort(key=lambda f: (ranks.get(str(f['severity']).lower(), 5), f['url'], f['check']))
    for finding in summary['findings']:
        if finding['category'] in ('scanner_match', 'configuration'):
            finding.setdefault('cve_ids', [])
            finding.setdefault('cve_status', 'not_identified')
            finding['how_to_exploit'] = web_review.guide(finding, summary['target'], summary.get('scan_ip'))
    summary['web_leads'] = web_review.web_leads(summary['findings'])
    summary['finding_groups'] = finding_groups(summary['findings'])
    summary['risk_assessment'], summary['statistics'] = assessment.unified_risk(summary, summary['finding_groups'])
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
        'javascript_pages': sum(urllib.parse.urlsplit(p['url']).path.lower().endswith('.js')
            for p in summary.get('crawl', {}).get('pages', [])),
        'session_scope': summary.get('session_scope', 'unauthenticated'),
        'discovery_assessment': ('limited_discovery' if summary.get('crawl', {}).get('requests', 0) <= 1
            else 'bounded_discovery; route count does not prove complete coverage'),
        'coverage_note': 'No automatic guarantee of authorization, business-logic, POST, or JavaScript execution coverage.',
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
    summary['coverage']['cors_status'] = summary.get('cors', {}).get('status', 'not_run')
    summary['coverage']['cors_requests'] = summary.get('cors', {}).get('requests', 0)
    summary['coverage']['sensitive_files_status'] = summary.get('sensitive_files', {}).get('status', 'not_run')
    summary['coverage']['sensitive_files_requests'] = summary.get('sensitive_files', {}).get('requests', 0)
    summary['coverage']['nmap_status'] = summary.get('nmap', {}).get('status', 'legacy_inventory')
    summary['coverage']['nmap_selection'] = summary.get('nmap', {}).get('selection', 'Not recorded by this scan version')
    summary['coverage']['open_tcp_ports'] = len(summary.get('ports', []))
    summary['coverage']['identified_service_versions'] = sum(bool(row.get('version')) for row in summary.get('ports', []))
    summary['coverage']['network_assessment_status'] = summary.get('network_assessment', {}).get('status', 'not_run')
    summary['coverage']['tls_handshakes'] = len(summary.get('network_assessment', {}).get('tls', []))
    summary['coverage']['advanced_status'] = summary.get('advanced', {}).get('status', 'not_run')
    summary['coverage']['api_routes'] = sum(len(doc.get('routes', [])) for doc in summary.get('advanced', {}).get('api', []))
    summary['coverage']['context_comparisons'] = len(summary.get('advanced', {}).get('matrix', []))
    summary['coverage']['jwt_structures_inspected'] = len(summary.get('advanced', {}).get('jwt', []))
    summary['coverage']['poc_artifact_only_findings'] = sum(
        not any(p.get('kind') in ('http', 'nmap_service', 'tls_handshake') and p.get('status') in ('captured', 'observed')
                for e in f.get('evidence', []) for p in e.get('poc', [])) for f in summary['findings'])
    summary['report_schema_version'] = 4
    run_history.export_csv(root / 'findings.csv', summary['findings'])
    if summary.get('comparison_base'):
        try:
            summary['comparison'] = run_history.compare(summary, run_history.load(root / summary['comparison_base']))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            summary['comparison'] = dict(status='incomplete', error=type(exc).__name__)
        (root / 'comparison.json').write_text(evidence.dumps(summary['comparison']), encoding='utf-8')
    summary['diagnostics'] = scan_diagnostics.explain(summary)
    summary['tool_coverage'] = tool_coverage.build(summary, tools)
    (root / "summary.json").write_text(evidence.dumps(summary), encoding="utf-8")
    summary = evidence.safe(summary)
    esc = lambda value: html.escape(str(value), quote=True)
    tool_rows = ''.join('<tr>' + ''.join('<td>' + esc(row.get(key, '')) + '</td>'
        for key in ('tool', 'status', 'jobs', 'observations', 'parse_issues', 'reason')) + '</tr>'
        for row in summary['tool_coverage'])
    diagnostic_rows = ''.join('<li><strong>' + esc(row['code']) + '</strong> ' +
        esc(row['url']) + ': ' + esc(row['message']) + ' ' + esc(row['action']) + '</li>'
        for row in summary['diagnostics'])
    technology_rows = ''.join('<tr><td>' + esc(row['url']) + '</td><td>' +
        esc(', '.join(sorted({s['name'] for s in row['technologies']})) or 'Unknown') +
        '</td><td>' + esc(row['wpscan']) + '</td><td>' + esc(row['reason']) + '</td></tr>'
        for row in summary.get('technology_plan', []))
    port_rows = "".join("<tr>" + "".join(f"<td>{esc(p.get(k, ''))}</td>" for k in
                                     ("port", "service", "product", "version", "extrainfo", "method", "cpe")) + "</tr>"
                        for p in summary["ports"])
    nmap_note = summary.get('nmap', {}).get('note', 'Inventory from the original scanner XML; blank versions were not identified.')
    if not port_rows:
        port_rows = '<tr><td colspan="7">' + esc(nmap_note) + '</td></tr>'
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
        poc = [p for e in finding.get('evidence', []) for p in e.get('poc', [])]
        proof = '<details><summary>Observed evidence / PoC</summary><pre>' + esc(json.dumps(poc, indent=2, ensure_ascii=False)) + '</pre></details>'
        if finding.get('reproduction'):
            proof += '<details><summary>GET reproduction helper (credentials omitted)</summary><pre>' + esc(finding['reproduction']) + '</pre></details>'
        cve_label = ' | '.join(finding.get('cve_ids', []))
        finding_rows.append(f'<tr data-finding data-category="{esc(finding["category"])}" data-severity="{esc(str(finding["severity"]).lower())}"><td>{esc(finding["title"])}<br><small>{esc(finding["category"])}</small><br><small>{esc(cve_label)}</small></td><td>{esc(finding["url"])}</td>'
                            f'<td>{esc(finding["severity"])}</td><td>needs_validation</td><td>{links}</td>'
                            f'<td>{esc(finding.get("recommendation", ""))}{proof}</td></tr>')
    web_lead_rows = ''.join('<tr><td>' + str(row['priority']) + '</td><td>' + esc(row['focus']) +
        '<br>' + esc(row['title']) + '</td><td>' + esc(row['url']) + '</td><td>' + esc(row['next_step']) +
        '</td></tr>' for row in summary['web_leads'])
    exploitation_rows = []
    for finding in summary['findings']:
        guide = finding.get('how_to_exploit')
        if not guide:
            continue
        cves = ' · '.join('<a href="https://www.cve.org/CVERecord?id=' + esc(cve) + '">' + esc(cve) + '</a>' for cve in finding.get('cve_ids', [])) or 'No CVE identified'
        steps = '<ol>' + ''.join('<li>' + esc(step) + '</li>' for step in guide['steps']) + '</ol>'
        refs = ' · '.join('<a rel="noreferrer" href="' + esc(ref) + '">Reference</a>' for ref in finding.get('references', []))
        exploitation_rows.append('<article><h3>' + esc(finding['title']) + '</h3><p>' + esc(finding['url']) + '</p><p>' + cves + ' · ' + esc(finding.get('cve_status', 'not_identified')) + '</p>' + refs + steps + '<pre>' + esc('\n'.join(guide['commands'])) + '</pre><p>' + esc(guide['note']) + '</p></article>')
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
    cards = ''.join(f'<div class="card"><strong>{severity_counts[s]}</strong><span>{s.title()} review groups</span></div>'
                    for s in ('critical', 'high', 'medium', 'low', 'info'))
    risk_rows = ''.join('<tr>' + ''.join(f'<td>{esc(row[k])}</td>' for k in
        ('severity', 'priority', 'network', 'web', 'groups', 'instances', 'confirmed')) + '</tr>'
        for row in summary['risk_assessment']['matrix'])
    statistics_rows = ''.join(f'<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>' for k, v in summary['statistics'].items())
    tls_rows = ''.join('<tr>' + ''.join(f'<td>{esc(row.get(k, ""))}</td>' for k in
        ('url', 'status', 'protocol', 'cipher', 'not_after', 'detail')) + '</tr>'
        for row in summary.get('network_assessment', {}).get('tls', []))
    script_hash = base64.b64encode(hashlib.sha256(report_script.encode()).digest()).decode()
    report = f"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-{script_hash}'">
<title>The World Is Yours — {esc(summary['target'])}</title>
<style>{REPORT_STYLE}</style><main><h1>The World Is Yours</h1><p>Target: {esc(summary['target'])} ·
{esc(summary['created'])} · Mode: {esc(summary['mode'])}</p>
<p>Assessment: {esc(summary.get('assessment_mode', 'web'))} · Version: {esc(summary.get('version', 'legacy'))}</p>
<nav aria-label="Report sections"><a href="#findings">Findings and remediation</a><a href="#tls">TLS</a><a href="#services">Services</a><a href="#tasks">Task status</a><a href="#how-to-exploit">How to exploit / CVE</a></nav>
<div class="cards">{cards}</div>
<h2>Scan plan</h2><pre>{esc(json.dumps(summary.get('scan_plan', {}), indent=2))}</pre><p><a href="findings.csv">Export findings CSV</a></p>
<h2>Run comparison</h2><details><summary>Changes from baseline (not proof of remediation)</summary><pre>{esc(json.dumps(summary.get('comparison', {'status': 'not_requested'}), indent=2))}</pre></details>
<h2>Assessment statistics</h2><table>{statistics_rows}</table>
<h2>Advanced API and context inventory</h2><details><summary>API routes, access matrix and JWT structure analysis</summary>
<pre>{esc(json.dumps(summary.get('advanced', {'status': 'not_run'}), indent=2, ensure_ascii=False))}</pre></details>
<h2>CTF web investigation priorities</h2><p>Evidence-linked leads, not confirmed attack chains or proof of server access. Technologies and missing headers are listed separately below.</p>
<table><thead><tr><th>Order</th><th>Web lead</th><th>URL</th><th>Next verification</th></tr></thead><tbody>{web_lead_rows or '<tr><td colspan="4">No web vulnerability candidates recorded in the tested scope.</td></tr>'}</tbody></table>
<h2>Unified triage matrix</h2><p>Overall priority: {esc(summary['risk_assessment']['overall_priority'])}.
{esc(summary['risk_assessment']['note'])} Ordinal priorities 0–4 are not CVSS scores.</p>
<div class="scroll"><table><tr><th>Severity</th><th>Priority</th><th>Network groups</th><th>Web groups</th>
<th>Total groups</th><th>Instances</th><th>Confirmed groups</th></tr>{risk_rows}</table></div>
<div class="note">{esc(summary['outcome'])}<br>Scanner matches require manual validation.
Completed means the process exited successfully; it does not certify the site is secure.
Skipped, failed, timeout and cancelled jobs leave gaps in coverage. This is an evidence index,
not a validated penetration testing report. Each active web job uses its own rate cap;
independent external jobs use the selected sequential/parallel mode. Parallel jobs add their per-tool rates. HTTP errors and redirects are recorded as responses.
Built-in discovery, crawler and checks share one start-rate gate. Raw bodies are omitted unless explicitly retained. Redirect destinations are displayed for review.</div>
<h2>Coverage diagnostics</h2><ul>{diagnostic_rows}</ul>
<h2>Tool coverage</h2><p>Every adapter is listed. Observations are parsed evidence, not confirmed vulnerabilities. A completed process with parsing errors leaves unknown coverage.</p>
<div class="scroll"><table><tr><th>Tool</th><th>Status</th><th>Jobs</th><th>Parsed observations</th><th>Parse issues</th><th>Reason / next step</th></tr>{tool_rows}</table></div>
<h2>Technology follow-up plan</h2><p>Passive WordPress inventory; vulnerability metadata needs a configured WPScan API token or database. Unknown technologies and empty results leave coverage gaps.</p><table><tr><th>URL</th><th>Observed technologies</th><th>WPScan</th><th>Reason</th></tr>{technology_rows}</table>
<h2>Assessment coverage</h2><p>Single-host web vulnerability assessment. Session scope: {esc(summary.get('session_scope', 'unauthenticated'))}. Nmap target: {esc(summary.get('scan_ip', summary['target']))}.
Built-in HTTP connects to the pinned Nmap address and retains the hostname for Host, TLS SNI and certificate verification. WhatWeb fingerprints pinned response snapshots for hostnames; other external scanners for hostnames are deferred. Severity counts group repeated header checks per origin; instance counts retain affected responses. All counts describe unvalidated scanner/configuration matches;
endpoint and technology observations are excluded from these counts. Coverage limits and gaps do not mean the target is secure.</p>
<div class="scroll"><table>{coverage_rows}</table></div>
<h2>Grouped assessment findings</h2><p>Repeated header notes are grouped; individual URLs and raw evidence remain below.</p>
<div class="scroll"><table><tr><th>Observation</th><th>Severity</th><th>Validation</th><th>Affected URLs</th></tr>{grouped_rows}</table></div>
<h2>Discovered GET parameter checks</h2><p>Candidates are not proof of injection. Built-in controls/probes and optional SQLmap detection preserve separate evidence.
POST forms, JavaScript execution and authenticated workflows require separate review.</p>
<div class="scroll"><table><tr><th>URL</th><th>Parameter</th><th>Job status</th><th>Detection outcome</th><th>Selection/review reason</th></tr>{injection_rows}</table></div>
<h2>Deferred forms</h2><div class="scroll"><table><tr><th>Source</th><th>Method</th><th>Action</th><th>Review reason</th></tr>{forms_rows}</table></div>
<h2 id="findings">Unified findings ({len(summary['findings'])})</h2><p>Severity is rule/scanner-reported; every observation needs validation.
Distinct checks, queries, schemes, ports and HTTP statuses remain separate.</p>
<label for="finding-search">Search findings</label><input id="finding-search" type="search" placeholder="Service, URL, title or recommendation">
<label for="finding-severity">Severity</label><select id="finding-severity"><option value="all">All</option>
{''.join(f'<option value="{s}">{s.title()}</option>' for s in ranks)}</select>
<label for="finding-category">Type</label><select id="finding-category"><option value="all">All observations</option>
<option value="scanner_match">Vulnerability candidates</option><option value="configuration">Configuration</option>
<option value="technology">Technologies</option><option value="endpoint">Endpoints</option><option value="observation">Other observations</option></select>
<button id="finding-reset" type="button">Reset filters</button><p id="finding-count" aria-live="polite"></p>
<div class="scroll"><table><tr><th>Observation</th><th>URL</th><th>Scanner severity</th><th>Validation</th><th>Evidence</th><th>Recommended review/remediation</th></tr>
{''.join(finding_rows)}</table></div><h2>Parsing and manual review gaps</h2><ul>{issues}</ul>
<h2 id="tls">TLS certificate and connection assessment</h2><p>Status: {esc(summary.get('network_assessment', {}).get('status', 'not_run'))}.
Verified handshakes use the pinned address and original hostname. A negotiation failure is inconclusive.
The negotiated protocol is not an exhaustive inventory of accepted protocols/ciphers; STARTTLS services are not tested.</p>
<div class="scroll"><table><tr><th>Origin</th><th>Status</th><th>Negotiated protocol</th><th>Cipher</th><th>Certificate expiry</th><th>Detail</th></tr>{tls_rows}</table></div>
<h2 id="services">Observed open TCP ports and versions</h2><p>{esc(nmap_note)}</p>
<div class="scroll"><table><tr><th>Port (TCP, open)</th><th>Service</th>
<th>Product</th><th>Version</th><th>Extra information</th><th>Detection method</th><th>CPE</th></tr>{port_rows}</table></div>
<h2>HTTP discovery</h2><div class="scroll"><table><tr><th>URL</th><th>Status</th><th>Title</th>
<th>Server</th><th>Redirect location</th><th>Probe error</th></tr>{url_rows}</table></div>
<h2 id="tasks">Tasks and evidence</h2><div class="scroll"><table><tr><th>Task</th><th>Status</th>
<th>Seconds</th><th>Notes</th><th>Files</th></tr>{''.join(job_rows)}</table></div>
<h2>Manual follow-up</h2><p>Use Burp Suite to inspect authentication, authorization, IDOR,
business logic, POST forms and XSS. Crawled GET parameters are selected for bounded SQLmap
checks; unlinked routes, JavaScript-only pages and authenticated endpoints may remain undiscovered.
</p><h2 id="how-to-exploit">How to exploit — manual verification and CVE</h2><p>CVE IDs come from scanner template metadata, require validation, and are never inferred from product banners. Application-specific flaws may have no CVE.</p>{"".join(exploitation_rows) or "<p>No vulnerability or configuration candidates were recorded.</p>"}<p><a href="summary.json">summary.json</a></p></main><script>{report_script}</script></html>"""
    (root / "report.html").write_text(report, encoding="utf-8")

