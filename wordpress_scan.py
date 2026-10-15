"""Bounded WPScan command and strict JSON observations; no exploitation."""
import json
from scope import origin


def command(binary, url, folder, args):
    return [binary or 'wpscan', '--url', url, '--format', 'json', '--output', str(folder / 'results.json'),
            '--no-banner', '--no-update', '--ignore-main-redirect', '--detection-mode', 'passive',
            '--plugins-detection', 'passive', '--plugins-version-detection', 'passive',
            '--enumerate', 'p,t', '--max-threads', '1', '--throttle', str(max(1, int(1000 / args.rate))),
            '--connect-timeout', str(args.http_timeout), '--request-timeout', str(args.http_timeout),
            '--max-scan-duration', str(args.tool_timeout)] + (['--disable-tls-checks'] if args.insecure else [])


def load(path):
    row = json.loads(path.read_text(encoding='utf-8-sig'))
    if not isinstance(row, dict) or row.get('scan_aborted'):
        raise ValueError('WPScan aborted or invalid JSON')
    if not row.get('target_url') or not any(k in row for k in ('version', 'plugins', 'main_theme', 'interesting_findings')):
        raise ValueError('Missing WPScan target or inventory fields')
    if row.get('vuln_api') is not None and not isinstance(row['vuln_api'], dict):
        raise ValueError('Invalid WPScan API status')
    for key in ('plugins', 'themes'):
        if key in row and not isinstance(row[key], dict):
            raise ValueError('Invalid WPScan component inventory')
    return row


def observations(row, base):
    target = row.get('target_url')
    if not target or origin(target) != origin(base):
        raise ValueError('WPScan target is outside the requested origin')
    components = [('core', row.get('version'))]
    components += [('plugin:' + name, value) for name, value in row.get('plugins', {}).items()]
    components += [('theme:' + name, value) for name, value in row.get('themes', {}).items()]
    if row.get('main_theme'):
        components.append(('theme:' + str(row['main_theme'].get('slug', 'active')), row['main_theme']))
    yield 'technology', 'wordpress', target, 'WordPress inventory (WPScan)', 'info'
    for name, component in components:
        if component is None:
            continue
        if not isinstance(component, dict):
            raise ValueError('Invalid WPScan component')
        yield 'technology', name, target, 'WordPress ' + name, 'info'
        vulns = component.get('vulnerabilities', [])
        if not isinstance(vulns, list):
            raise ValueError('Invalid WPScan vulnerability list')
        for vuln in vulns:
            if not isinstance(vuln, dict) or not vuln.get('title'):
                raise ValueError('Invalid WPScan advisory')
            # WPScan advisories do not consistently supply severity; never invent CVSS.
            yield 'scanner_match', name + ':' + str(vuln.get('id') or vuln['title']), target, str(vuln['title']), 'unknown'


def environment(folder):
    """Do not inherit WPScan scan.yml files that could enable unrelated actions."""
    import os
    from pathlib import Path
    env = dict(os.environ)
    original_home = Path.home()
    home = folder / 'scanner-home'
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    env['HOME'] = str(home)
    env['XDG_CONFIG_HOME'] = str(home / '.config')
    env['XDG_CACHE_HOME'] = str(Path(os.environ.get('XDG_CACHE_HOME', str(original_home / '.cache'))).resolve())
    legacy_db = original_home / '.wpscan' / 'db'
    if legacy_db.is_dir():
        (home / '.wpscan').mkdir(exist_ok=True)
        link = home / '.wpscan' / 'db'
        if not link.exists():
            link.symlink_to(legacy_db, target_is_directory=True)
    return env
