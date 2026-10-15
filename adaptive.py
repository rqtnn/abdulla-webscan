"""Evidence-based reconnaissance and deterministic, bounded follow-up selection."""
from html.parser import HTMLParser
import re
from urllib.parse import urljoin, urlsplit, urlunsplit

from scope import origin

EXTENSIONS = {'PHP': ['php'], 'ASP.NET': ['aspx', 'ashx'], 'Java': ['jsp']}
FOLLOW_UP = {
    'WordPress': 'WPScan: passive WordPress core, plugin and theme inventory; supplied advisory matches need validation.',
    'PHP': 'Prioritize PHP route variants; retain GET controls and content-based configuration checks.',
    'ASP.NET': 'Prioritize ASPX/ASHX route variants; review authentication and configuration evidence.',
    'Java': 'Prioritize JSP route variants; review session boundaries and discovered API routes.',
    'Python': 'Review framework/debug disclosure and discovered GET inputs; do not assume a template engine.',
    'Ruby': 'Review Rails/session boundaries and discovered GET inputs; do not assume exploitable deserialization.',
    'Node.js': 'Review Express/session boundaries and discovered API inputs; browser JavaScript alone is not Node.js evidence.',
}


class Markup(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.generators, self.assets = [], []
        self.forms = self.scripts = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'meta' and a.get('name', '').lower() == 'generator':
            self.generators.append(a.get('content', '')[:200])
        if tag in ('link', 'script', 'img', 'a'):
            value = a.get('href') if tag in ('link', 'a') else a.get('src')
            if value and len(self.assets) < 2000:
                self.assets.append(value)
        self.forms += tag == 'form'
        self.scripts += tag == 'script'


def inspect(url, headers, body):
    """Keep allowlisted signal labels, never arbitrary body, header or cookie values."""
    parser = Markup()
    parser.feed(body[:65536])
    signals = []
    def add(tech, source, confidence='indicative', base=None):
        row = dict(technology=tech, source=source, confidence=confidence)
        if base:
            row['base_url'] = base
        if row not in signals:
            signals.append(row)
    base = urlunsplit((*urlsplit(url)[:2], urlsplit(url).path.rsplit('/', 1)[0] + '/', '', ''))
    if any(re.match(r'^WordPress(?:\s|$)', v, re.I) for v in parser.generators):
        add('WordPress', 'HTML generator metadata', 'strong', base)
    wp_paths = {}
    for value in parser.assets:
        try:
            asset = urljoin(url, value)
            if origin(asset) != origin(url):
                continue
            path = urlsplit(asset).path
        except ValueError:
            continue
        m = re.search(r'/(wp-content|wp-includes)/', path, re.I)
        if m:
            prefix = path[:m.start() + 1]
            wp_paths.setdefault(prefix, set()).add(m[1].lower())
    for prefix, families in wp_paths.items():
        if len(families) == 2:
            add('WordPress', 'Same-origin wp-content and wp-includes assets', 'strong',
                urlunsplit((*urlsplit(url)[:2], prefix, '', '')))
    for name, value in headers:
        name, value = name.lower(), value.lower()
        if name == 'x-powered-by':
            for pattern, tech in ((r'\bphp\b', 'PHP'), (r'asp\.net', 'ASP.NET'), (r'\bexpress\b', 'Node.js')):
                if re.search(pattern, value):
                    add(tech, 'X-Powered-By header')
        if name == 'server':
            for pattern, tech in ((r'\b(?:gunicorn|werkzeug|uvicorn)\b', 'Python'),
                                  (r'\b(?:tomcat|jetty)\b', 'Java'), (r'\bphusion passenger\b', 'Ruby')):
                if re.search(pattern, value):
                    add(tech, 'Server header')
        if name == 'set-cookie':
            cookie = value.split('=', 1)[0].strip()
            for prefix, tech in (('phpsessid', 'PHP'), ('asp.net_sessionid', 'ASP.NET'), ('jsessionid', 'Java')):
                if cookie == prefix:
                    add(tech, 'Session cookie name')
    for suffix, tech in (('.php', 'PHP'), ('.aspx', 'ASP.NET'), ('.jsp', 'Java')):
        if urlsplit(url).path.lower().endswith(suffix):
            add(tech, 'URL suffix (hint only)', 'weak')
    if any(s['technology'] == 'WordPress' for s in signals):
        add('PHP', 'WordPress platform dependency', 'indicative')
    return dict(url=url, signals=signals, forms=parser.forms, scripts=parser.scripts,
                note='Observed response only; backend languages and application behavior are not fully knowable from HTTP fingerprints.')


def plan(summary, enabled=True):
    sites = {}
    records = [p.get('recon') for p in summary.get('probes', [])]
    records += [p.get('recon') for p in summary.get('crawl', {}).get('pages', [])]
    records = list({r['url']: r for r in records if r}.values())
    for record in records:
        if not record:
            continue
        key = urlunsplit((*urlsplit(record['url'])[:2], '/', '', ''))
        site = sites.setdefault(key, dict(url=key, signals=[], forms=0, scripts=0))
        site['forms'] += record.get('forms', 0)
        site['scripts'] += record.get('scripts', 0)
        for signal in record.get('signals', []):
            if signal not in site['signals']:
                site['signals'].append(signal)
    aliases = {'wordpress': 'WordPress', 'php': 'PHP', 'asp-net': 'ASP.NET', 'asp.net': 'ASP.NET', 'asp_net': 'ASP.NET', 'apache-tomcat': 'Java',
               'ruby-on-rails': 'Ruby', 'express': 'Node.js', 'tomcat': 'Java', 'django': 'Python'}
    for finding in summary.get('findings', []):
        if finding.get('category') != 'technology' or not any(e.get('tool') == 'whatweb' for e in finding.get('evidence', [])):
            continue
        tech = aliases.get(finding.get('check', '').lower())
        if not tech:
            continue
        url = finding['url']
        key = urlunsplit((*urlsplit(url)[:2], '/', '', ''))
        site = sites.setdefault(key, dict(url=key, signals=[], forms=0, scripts=0))
        signal = dict(technology=tech, source='WhatWeb passive plugin', confidence='strong')
        if tech == 'WordPress':
            signal['base_url'] = urlunsplit((*urlsplit(url)[:2], urlsplit(url).path.rsplit('/', 1)[0] + '/', '', ''))
        if signal not in site['signals']:
            site['signals'].append(signal)
    for site in sites.values():
        technologies = sorted({s['technology'] for s in site['signals']})
        site['technologies'] = technologies
        site['extensions'] = list(dict.fromkeys(e for t in technologies for e in EXTENSIONS.get(t, []))) if enabled else []
        site['wordpress_bases'] = list(dict.fromkeys(s['base_url'] for s in site['signals']
            if s['technology'] == 'WordPress' and s.get('confidence') == 'strong' and s.get('base_url')))
        # A more specific asset root wins over directory inferred from a generator tag.
        asset_bases = [s['base_url'] for s in site['signals'] if s['source'].startswith('Same-origin wp-')]
        if asset_bases:
            site['wordpress_bases'] = list(dict.fromkeys(asset_bases))
        site['follow_up'] = [FOLLOW_UP[t] for t in technologies if t in FOLLOW_UP]
        if not technologies:
            site['follow_up'] = ['Unknown stack: retain generic HTTP, route and GET controls; do not guess a language.']
    return dict(status='ready' if sites else 'awaiting_discovery', enabled=enabled,
                phases=['HTTP/service reconnaissance', 'technology and route inventory', 'evidence-based checks'],
                sites=list(sites.values()), note='Fingerprints are hints, not vulnerability proof. Explicit --only selections remain isolated.')


def extensions(plan, url):
    return next((s['extensions'] for s in plan.get('sites', []) if origin(s['url']) == origin(url)), [])
