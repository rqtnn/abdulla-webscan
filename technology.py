"""Passive, origin-scoped technology hints and evidence-based follow-up plans."""
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit


def origin(url):
    parsed = urlsplit(url)
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80)


class Hints(HTMLParser):
    def __init__(self, url):
        super().__init__(convert_charrefs=True)
        self.url, self.rows = url, []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'meta' and (attrs.get('name') or '').lower() == 'generator':
            value = (attrs.get('content') or '').lower()
            for name in ('WordPress', 'Drupal', 'Joomla'):
                if value == name.lower() or value.startswith(name.lower() + ' '):
                    self.rows.append(dict(name=name, source='generator_meta'))
        if tag in ('script', 'link', 'img'):
            value = attrs.get('src') if tag != 'link' else attrs.get('href')
            if value:
                try:
                    asset = urljoin(self.url, value)
                    if origin(asset) == origin(self.url) and any(
                            segment in urlsplit(asset).path.lower().split('/')
                            for segment in ('wp-content', 'wp-includes')):
                        self.rows.append(dict(name='WordPress', source='same_origin_asset'))
                except ValueError:
                    pass


def detect(url, headers, body=''):
    """Do not infer a technology from prose, an error message or a file extension."""
    parser = Hints(url)
    parser.feed(body.decode('utf-8', 'replace') if isinstance(body, bytes) else body)
    for key, value in headers:
        if key.lower() == 'x-powered-by':
            for name, prefix in (('PHP', 'php/'), ('ASP.NET', 'asp.net'), ('Express', 'express')):
                if value.lower() == prefix.rstrip('/') or value.lower().startswith(prefix):
                    parser.rows.append(dict(name=name, source='x_powered_by'))
        if key.lower() == 'x-generator':
            for name in ('Drupal', 'WordPress', 'Joomla'):
                if value.lower() == name.lower() or value.lower().startswith(name.lower() + ' '):
                    parser.rows.append(dict(name=name, source='x_generator'))
    return [dict(name=name, source=source) for name, source in sorted(
        {(row['name'], row['source']) for row in parser.rows})]


def plan(urls, summary):
    """Use only captured response hints and parsed scanner fingerprints per origin."""
    observations = summary.get('probes', []) + summary.get('crawl', {}).get('pages', [])
    rows = []
    for url in urls:
        signals = []
        for page in observations:
            try:
                if 'status' in page and origin(page['url']) == origin(url):
                    signals.extend(dict(hint, url=page['url']) for hint in page.get('technologies', []))
            except (KeyError, ValueError):
                continue
        for finding in summary.get('findings', []):
            try:
                if finding['category'] == 'technology' and origin(finding['url']) == origin(url):
                    name = finding['check']
                    if name.lower() in ('wordpress', 'drupal', 'joomla', 'php', 'asp.net', 'express'):
                        signals.append(dict(name='WordPress' if name.lower() == 'wordpress' else name,
                                            source='scanner_fingerprint', url=finding['url']))
            except (KeyError, ValueError):
                continue
        signals = [dict(name=n, source=s, url=u) for n, s, u in sorted(
            {(r['name'], r['source'], r['url']) for r in signals})]
        wordpress = any(s['name'] == 'WordPress' for s in signals)
        rows.append(dict(url=url, technologies=signals, wpscan='eligible' if wordpress else 'deferred',
            reason='WordPress hint observed; validate the fingerprint.' if wordpress else
                   'No WordPress evidence observed; detection coverage may be incomplete.',
            next_steps=sorted(set(['Review WordPress core, plugins and themes.'] if wordpress else []) |
                set('Review PHP configuration and file exposure.' for s in signals if s['name'].lower() == 'php'))))
    return rows
