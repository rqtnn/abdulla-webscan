"""Offline comparison and spreadsheet-safe finding exports."""
import csv
import json
from pathlib import Path, PurePosixPath, PureWindowsPath

from . import evidence


def load(path):
    path = Path(path).expanduser().resolve()
    path = path / 'summary.json' if path.is_dir() else path
    if path.stat().st_size > 33554432:
        raise ValueError('Baseline summary exceeds 32 MiB')
    doc = json.loads(path.read_text(encoding='utf-8'))
    validate(doc)
    return doc


def validate(doc):
    if not isinstance(doc, dict) or not isinstance(doc.get('target'), str) or not doc['target']:
        raise ValueError('Baseline must be a scan summary with a target')
    if not isinstance(doc.get('findings', []), list) or not isinstance(doc.get('ports', []), list):
        raise ValueError('Baseline findings and ports must be lists')
    for row in doc.get('findings', []):
        if not isinstance(row, dict) or any(not isinstance(row.get(key), str) for key in ('category', 'check', 'url')):
            raise ValueError('Baseline contains an invalid finding')
    for row in doc.get('ports', []):
        if not isinstance(row, dict) or type(row.get('port')) is not int or not 1 <= row['port'] <= 65535:
            raise ValueError('Baseline contains an invalid TCP port')


def snapshot(root, doc):
    """Keep the comparison inputs portable without copying bodies or credentials."""
    validate(doc)
    keys = ('id', 'category', 'check', 'url', 'title', 'severity', 'validation_status', 'cve_ids', 'recommendation')
    baseline = dict(target=doc['target'], created=doc.get('created'),
                    ports=[{'port': row['port']} for row in doc.get('ports', [])],
                    findings=[{key: row[key] for key in keys if key in row} for row in doc.get('findings', [])])
    (Path(root) / 'baseline.json').write_text(evidence.dumps(baseline), encoding='utf-8')
    return 'baseline.json'


def foreign_path(value):
    value = str(value)
    return PureWindowsPath(value) if PureWindowsPath(value).drive else PurePosixPath(value)


def relocate(summary, root):
    """Rebind evidence locations when a report directory is copied or renamed."""
    root = Path(root).resolve()
    changes = []
    original = summary.get('run_directory')
    for job in summary.get('jobs', []):
        folder = foreign_path(job['folder'])
        relative = None
        if original:
            try:
                relative = folder.relative_to(foreign_path(original))
            except ValueError:
                raise ValueError('Job evidence folder is outside the recorded run directory')
        else:
            # Legacy reports recorded only absolute job folders. Prefer captured evidence paths.
            for finding in summary.get('findings', []):
                for item in finding.get('evidence', []):
                    if item.get('job') != job.get('name') or item.get('tool') != job.get('tool'):
                        continue
                    candidate = PurePosixPath(item.get('file', '')).parent
                    if candidate.parts and folder.parts[-len(candidate.parts):] == candidate.parts:
                        relative = candidate
                        break
                if relative is not None:
                    break
            if relative is None:
                ancestor = next((parent for parent in (folder, *folder.parents) if parent.name == root.name), None)
                if ancestor is not None:
                    relative = folder.relative_to(ancestor)
            if relative is None:
                stages = {'nmap', 'network', 'crawl', 'checks', 'cors', 'sensitive-files', 'advanced', 'sqlmap'}
                if folder.name in stages:
                    relative = PurePosixPath(folder.name)
                elif len(folder.parts) >= 2 and folder.parent.name.startswith('web-') and folder.parent.name[4:].isdigit():
                    parts = (folder.parent.name, folder.name)
                    if folder.parent.parent.name == 'discovered':
                        parts = ('discovered', *parts)
                    relative = PurePosixPath(*parts)
                elif folder.parent.name == 'auto-sqli' and folder.name.isdigit():
                    relative = PurePosixPath('auto-sqli', folder.name)
        if relative is None or relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Cannot locate legacy job evidence in this run directory')
        changes.append((job, str(root.joinpath(*relative.parts))))
    for job, folder in changes:
        job['folder'] = folder
    summary['run_directory'] = str(root)


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
