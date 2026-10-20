"""Offline, evidence-based adapter coverage; never infer safety from zero matches."""


def build(summary, tools):
    rows = []
    selection = summary.get('tool_selection', {})
    inventory = summary.get('tool_inventory', {})
    live = [p['url'] for p in summary.get('probes', []) if 'status' in p]
    for tool in tools:
        jobs = [j for j in summary.get('jobs', []) if j.get('tool') == tool]
        names = {j.get('name') for j in jobs}
        findings = [f for f in summary.get('findings', [])
                    if any(e.get('tool') == tool for e in f.get('evidence', []))]
        issues = [i for i in summary.get('parse_issues', [])
                  if i.get('job') in names and i.get('kind') != 'manual_review']
        reason = ''
        if jobs:
            states = {j.get('status', 'unknown') for j in jobs}
            if states == {'completed'} and not issues:
                status = 'completed_with_observations' if findings else 'completed_no_matches'
                reason = 'Parsed results available; manual validation required.' if findings else (
                    'No matches parsed for the checks that ran; this is not proof of safety.')
            elif states == {'planned'}:
                status, reason = 'planned', 'Dry-run plan; no requests were sent.'
            else:
                status = 'incomplete'
                reason = ', '.join(sorted(states))
                notes = list(dict.fromkeys(j.get('note', '') for j in jobs if j.get('note')))
                if notes:
                    reason += ': ' + '; '.join(notes)
                if issues:
                    reason += '; output parsing failed: inspect task evidence and console logs.'
        elif tool in selection.get('skipped', []):
            status, reason = 'disabled', 'Excluded by tool selection or external scanner policy.'
        elif tool != 'nmap' and summary.get('external_scanners', {}).get('enabled') is False:
            status, reason = 'disabled', 'Enable --all-tools (retains raw evidence) or --external-tools --retain-raw-evidence.'
        elif tool in inventory and not inventory[tool]:
            status, reason = 'unavailable', 'Executable missing or incompatible. Install the supported binary and run --check.'
        elif summary.get('assessment_mode') == 'network' and tool != 'nmap':
            status, reason = 'not_applicable', 'Network-only assessment selected.'
        elif not live:
            status, reason = 'not_run', 'No responding HTTP(S) URL yet; inspect discovery, ports and TLS diagnostics.'
        elif tool in ('ffuf', 'gobuster', 'feroxbuster', 'dirsearch'):
            status, reason = 'not_selected', 'Directory engine selection: ' + selection.get('enum', 'unknown') + '; use --all-tools or --enum all.'
        elif tool == 'testssl' and not any(u.startswith('https://') for u in live):
            status, reason = 'not_applicable', 'Only plain HTTP origins responded; no HTTPS protocol checks apply.'
        elif tool == 'wpscan':
            plans = summary.get('technology_plan', [])
            status = 'deferred' if plans and all(p.get('wpscan') == 'deferred' for p in plans) else 'not_run'
            reason = '; '.join(dict.fromkeys(p.get('reason', '') for p in plans)) or 'Awaiting WordPress fingerprint decision.'
        elif tool in ('dalfox', 'sqlmap'):
            if selection.get('session'):
                status, reason = 'deferred', 'External parameter scanners do not inherit the authenticated account.'
            elif tool == 'sqlmap' and selection.get('no_auto_sqli'):
                status, reason = 'disabled', 'Automatic SQLmap disabled by --no-auto-sqli.'
            elif tool == 'dalfox' and selection.get('no_active_checks'):
                status, reason = 'disabled', 'Active input checks disabled by --no-active-checks.'
            else:
                status, reason = 'no_candidates', 'No eligible discovered GET inputs; review crawl, forms, authentication and application path.'
        else:
            status, reason = 'not_run', 'No task result recorded; inspect stage errors and selected plan.'
        rows.append(dict(tool=tool, status=status, jobs=len(jobs), observations=len(findings),
                         parse_issues=len(issues), reason=reason))
    return rows
