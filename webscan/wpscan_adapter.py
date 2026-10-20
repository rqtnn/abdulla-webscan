"""Read WPScan component inventory and supplied vulnerability metadata offline."""
import re


def components(row):
    if not isinstance(row, dict):
        raise ValueError('Expected WPScan result object')
    if row.get('scan_aborted'):
        raise ValueError('WPScan aborted; review console/output for the reason')
    if not any(key in row for key in ('version', 'plugins', 'main_theme', 'interesting_findings')):
        raise ValueError('Missing WPScan component inventory')
    if row.get('version'):
        yield 'core', row['version']
    if row.get('main_theme'):
        yield 'theme', row['main_theme']
    for slug, component in (row.get('plugins') or {}).items():
        yield 'plugin:' + slug, component


def records(row):
    for name, component in components(row):
        if not isinstance(component, dict):
            raise ValueError('Invalid WPScan component')
        yield 'technology', 'wpscan:' + name, 'WordPress ' + name, 'info', {}
        for index, vuln in enumerate(component.get('vulnerabilities') or []):
            if not isinstance(vuln, dict) or not isinstance(vuln.get('title'), str):
                raise ValueError('Invalid WPScan vulnerability')
            refs = vuln.get('references') or {}
            values = refs.get('cve') or []
            values = values if isinstance(values, list) else [values]
            cves = sorted({('CVE-' + v.removeprefix('CVE-')).upper() for v in values
                           if isinstance(v, str) and re.fullmatch(r'(?:CVE-)?\d{4}-\d{4,}', v, re.I)})
            metadata = dict(cve_ids=cves, cve_source='wpscan_component_metadata',
                cve_status='scanner_reported_requires_validation' if cves else 'not_identified',
                recommendation='Validate the installed component/version and advisory prerequisites. '
                               'Review the reported fixed version before updating or removing the component.')
            yield 'scanner_match', 'wpscan:' + name + ':' + str(index), vuln['title'], 'unknown', metadata


def metadata(row, check):
    return next((meta for _, key, _, _, meta in records(row) if key == check), {})
