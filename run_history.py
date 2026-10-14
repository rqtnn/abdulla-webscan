"""Offline comparison and spreadsheet-safe finding exports."""
import csv
import json
from pathlib import Path

import evidence


def load(path):
    path = Path(path).expanduser().resolve()
    path = path / 'summary.json' if path.is_dir() else path
    if path.stat().st_size > 33554432:
        raise ValueError('Baseline summary exceeds 32 MiB')
    doc = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(doc, dict) or not doc.get('target'):
        raise ValueError('Baseline must be a scan summary with a target')
    return doc


def compare(current, previous):
    if current['target'] != previous['target']:
        raise ValueError('Compare only runs for the same target')
    def index(doc):
        return {(f['category'], f['check'], evidence.url(f['url'])): evidence.safe(f)
                for f in doc.get('findings', []) if f['category'] in ('scanner_match', 'configuration')}
    old, new = index(previous), index(current)
    old_ports = {p['port'] for p in previous.get('ports', [])}
    new_ports = {p['port'] for p in current.get('ports', [])}
    return dict(status='completed', baseline_created=previous.get('created'),
        new_findings=[new[k] for k in sorted(new.keys() - old.keys())],
        not_observed_this_run=[old[k] for k in sorted(old.keys() - new.keys())],
        changed_findings=[dict(previous=old[k], current=new[k]) for k in sorted(old.keys() & new.keys())
                          if (old[k].get('severity'), old[k].get('validation_status')) !=
                             (new[k].get('severity'), new[k].get('validation_status'))],
        new_open_ports=sorted(new_ports - old_ports), ports_not_observed=sorted(old_ports - new_ports),
        note='Not observed does not mean fixed or closed. Compare selected tools, port scope, errors, credentials and budgets before drawing conclusions.')


def export_csv(path, findings):
    def cell(value):
        value = str(value)
        return "'" + value if value.startswith(('=', '+', '-', '@', '\t', '\r', '\n')) else value
    with Path(path).open('w', encoding='utf-8-sig', newline='') as output:
        writer = csv.writer(output)
        writer.writerow(('id', 'category', 'title', 'severity', 'validation', 'url', 'CVE', 'check', 'recommendation'))
        for row in evidence.safe(findings):
            writer.writerow([cell(v) for v in (row['id'], row['category'], row['title'], row['severity'],
                row['validation_status'], row['url'], '; '.join(row.get('cve_ids', [])), row['check'], row.get('recommendation', ''))])
