"""WS-R bounded HTML/JavaScript discovery for responding origins."""
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
import hashlib
from html.parser import HTMLParser
import http.client
import json
import re
import ssl
import time
import urllib.parse
import xml.etree.ElementTree as ET

from .transport import connection
from . import evidence
from . import reliability
from . import technology
from . import jwt_analyzer
from .brand import USER_AGENT

from .scope import normalize_url, origin, scoped_link, ACTION, RequestGate, resolve_one

STATIC = re.compile(r'\.(?:png|jpe?g|gif|svg|ico|woff2?|ttf|css|js|map|pdf|zip|mp4|mp3)$', re.I)
SECRET = evidence.SECRET
SCRIPT = re.compile(r'\.js$', re.I)


def robots_links(text):
    """Inventory concrete advertised paths; wildcard/action/scope checks remain in add()."""
    values = []
    for line in text.splitlines()[:4000]:
        name, sep, value = line.partition(':')
        value = value.split('#', 1)[0].strip()
        if sep and name.strip().lower() in ('allow', 'disallow', 'sitemap') and value and not any(c in value for c in '*$'):
            values.append(value)
    return list(dict.fromkeys(values))[:2000]


def sitemap_links(body):
    """Bounded XML inventory, including sitemap indexes, without external resolution."""
    try:
        root = ET.fromstring(body)
    except (ET.ParseError, ValueError):
        return []
    if root.tag.rsplit('}', 1)[-1] not in ('urlset', 'sitemapindex'):
        return []
    return list(dict.fromkeys(element.text.strip() for element in root.iter()
        if element.tag.rsplit('}', 1)[-1] == 'loc' and element.text and element.text.strip()))[:2000]


def openapi_get_routes(spec):
    """Inventory concrete GET routes and bounded, non-secret query inputs.

    Do not resolve references, generate path identifiers or use credential examples.
    Candidates pass through the crawler's normal origin/action and input checks.
    """
    paths = spec.get('paths', {})
    if not isinstance(paths, dict):
        return []
    routes = []
    for path, operations in list(paths.items())[:2000]:
        if (not isinstance(path, str) or '{' in path or not isinstance(operations, dict)
                or not isinstance(operations.get('get'), dict)):
            continue
        routes.append(path.lstrip('/'))
        parameters = {}
        for container in (operations, operations['get']):
            items = container.get('parameters', [])
            if not isinstance(items, list):
                continue
            for item in items[:100]:
                if not isinstance(item, dict):
                    continue
                name = item.get('name')
                if isinstance(name, str) and item.get('in') == 'query':
                    parameters[name] = item
        pairs = []
        for name, item in parameters.items():
            if SECRET.search(name) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', name):
                continue
            schema = item.get('schema', item)
            if not isinstance(schema, dict) or '$ref' in schema or '$ref' in item:
                continue
            kind = schema.get('type', 'string')
            if kind not in ('string', 'integer', 'number', 'boolean'):
                continue
            value = {'integer': '1', 'number': '1', 'boolean': 'true', 'string': 'wsr'}[kind]
            pairs.append((name, value))
        if pairs:
            separator = '&' if '?' in path else '?'
            routes.append(path.lstrip('/') + separator + urllib.parse.urlencode(pairs))
    return routes


def route_literals(text):
    """Conservative quoted URL inventory; never evaluate JavaScript."""
    literals = list(dict.fromkeys(m.group(2) for m in re.finditer(
        r'''(["'])(https?://[^\s<>"']+|/(?!/)[^\s<>"']*|\./[^\s<>"']+|\.\./[^\s<>"']+|[A-Za-z0-9_-]+/[^\s<>"']+)\1''', text)))[:2000]
    maps = re.findall(r'(?m)^\s*//[#@]\s*sourceMappingURL=([^\s]+)', text)
    return list(dict.fromkeys(literals + [value for value in maps if not value.startswith('data:')]))[:2000]


class Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.forms = [], []
        self.form = None
        self.base = None
        self.scripts, self.hints = [], []
        self.in_script = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'script':
            self.in_script = True
            if attrs.get('src') and len(self.scripts) < 2000:
                self.scripts.append(attrs['src'])
        if tag == 'base' and self.base is None:
            self.base = attrs.get('href')
        if tag in ('a', 'area', 'iframe') and attrs.get('href' if tag != 'iframe' else 'src'):
            if len(self.links) < 2000:
                self.links.append(attrs.get('href' if tag != 'iframe' else 'src'))
        if tag == 'form':
            if self.form is not None:
                self.forms.append(self.form)
            self.form = {'action': attrs.get('action', ''), 'method': attrs.get('method', 'get').lower(),
                         'enctype': attrs.get('enctype', 'application/x-www-form-urlencoded'), 'fields': [], 'controls': []}
        if tag == 'input' and self.form is not None and attrs.get('name'):
            kind = attrs.get('type', 'text').lower()
            self.form['controls'].append({'name': attrs['name'], 'type': kind,
                'disabled': 'disabled' in attrs, 'value': '[redacted]' if kind == 'password' or SECRET.search(attrs['name']) else attrs.get('value', '')})
            if kind == 'submit' and 'disabled' not in attrs and not self.form.get('submit'):
                self.form['submit'] = [attrs['name'], attrs.get('value', '')]
            if kind not in ('submit', 'button', 'reset', 'file', 'password', 'image') and 'disabled' not in attrs:
                if kind not in ('checkbox', 'radio') or 'checked' in attrs:
                    self.form['fields'].append([attrs['name'], attrs.get('value', '')])
            elif kind in ('file', 'password'):
                self.form['excluded_inputs'] = True
        if (tag == 'button' and self.form is not None and attrs.get('name')
                and attrs.get('type', 'submit').lower() == 'submit'
                and 'disabled' not in attrs and not self.form.get('submit')):
            if attrs.get('formaction') or attrs.get('formmethod'):
                self.form['excluded_inputs'] = True
            else:
                self.form['submit'] = [attrs['name'], attrs.get('value', '')]
        if tag in ('select', 'textarea') and self.form is not None:
            self.form['controls'].append({'name': attrs.get('name', ''), 'type': tag, 'disabled': 'disabled' in attrs})
            self.form['excluded_inputs'] = True

    def handle_endtag(self, tag):
        if tag == 'script':
            self.in_script = False
        if tag == 'form' and self.form is not None:
            self.forms.append(self.form)
            self.form = None

    def handle_data(self, data):
        if self.in_script:
            self.hints.extend(route_literals(data)[:max(0, 2000 - len(self.hints))])

    def handle_comment(self, data):
        self.hints.extend(route_literals(data)[:max(0, 2000 - len(self.hints))])


def fetch(url, insecure=False, timeout=5, max_bytes=262144, headers=None, scan_ip=None):
    """Direct GET with query intact; never follow redirects or use proxy settings."""
    u = urllib.parse.urlsplit(url)
    conn = connection(url, insecure, timeout, scan_ip)
    try:
        conn.request('GET', urllib.parse.urlunsplit(('', '', u.path or '/', u.query, '')),
                     headers={'User-Agent': USER_AGENT, 'Accept': 'text/html, application/javascript',
                              **(headers or {})})
        request = evidence.request_details(conn)
        response = conn.getresponse()
        body = response.read(max_bytes + 1)
        headers = [list(pair) for pair in response.getheaders()]
        return {'status': response.status, 'headers': headers, 'body': body[:max_bytes], 'request': request,
                'truncated': len(body) > max_bytes}
    finally:
        conn.close()


def select_candidates(urls, limit):
    """One representative URL per origin/path/query-name set and parameter."""
    selected, excluded, seen = [], [], set()
    # Prefer a real value over a blank form placeholder for the same check.
    for url in sorted(set(urls), key=lambda v: (sum(not x for _, x in urllib.parse.parse_qsl(
            urllib.parse.urlsplit(v).query, keep_blank_values=True)), v)):
        u = urllib.parse.urlsplit(url)
        pairs = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
        counts = Counter(k for k, _ in pairs)
        for name, value in pairs:
            if name.lower() in ('submit', 'button', 'commit', 'action'):
                continue  # Preserve dispatch fields in requests, do not inject them.
            key = (origin(url), u.path, tuple(sorted(counts)), name)
            if key in seen:
                continue
            seen.add(key)
            reason = ''
            if counts[name] != 1:
                reason = 'Repeated parameter name needs manual review'
            elif any(SECRET.search(k) for k, _ in pairs):
                reason = 'URL carries sensitive parameters; automatic checks deferred'
            elif not re.fullmatch(r'[A-Za-z0-9_.-]+', name) or SECRET.search(name):
                reason = 'Sensitive or unsupported parameter name'
            elif ACTION.search(urllib.parse.unquote(url)):
                reason = 'Action-like URL needs manual review'
            elif len(value) > 512:
                reason = 'Oversized parameter value'
            elif len(selected) >= limit:
                reason = 'Automatic SQLi job limit reached'
            entry = {'url': url, 'parameter': name, 'reason': reason or 'Discovered GET parameter; injection has not been established'}
            if not reason and not value:
                seed = '1' if name.lower() in ('id', 'uid', 'pid', 'item', 'number') else 'wsr'
                seeded = [(k, seed if k == name else v) for k, v in pairs]
                entry.update(discovered_url=url, url=urllib.parse.urlunsplit((u.scheme, u.netloc,
                    u.path, urllib.parse.urlencode(seeded), '')), seed_value=seed,
                    reason='Blank form value seeded for detection; handler execution still needs review')
            (excluded if reason else selected).append(entry)
    return selected, excluded


def crawl(seeds, target, folder, stop, max_pages=100, depth=3, rate=5, timeout=120,
          insecure=False, result=None, follow_redirects=False, session=None, workers=1, delay=0, gate=None, progress=None, scan_ip=None, retain_raw=False, api_paths=False, request_timeout=10, metadata_paths=False):
    if not 1 <= workers <= 8:
        raise ValueError('Crawler workers must be between 1 and 8')
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    result = result if result is not None else {}
    result.update(status='running', pages=[], discovered=[], forms=[], excluded=[], limits=[], requests=0,
                  routes=[], authenticated=bool(session))
    scan_ip = scan_ip or resolve_one(target)
    origins = {origin(normalize_url(url, target)) for url in seeds}
    queue, seen, discovered, variants = deque(), set(), set(), Counter()
    deadline = time.monotonic() + timeout
    max_discovered = max_pages * 10
    gate = gate or RequestGate(rate, delay)
    scheduled = deque()
    pool = ThreadPoolExecutor(max_workers=workers)

    def request(url):
        # Recheck immediately before I/O, not merely when a route is enqueued.
        scoped_link(url, url, target, origins)
        gate.wait(stop, deadline)
        remaining = deadline - time.monotonic()
        if stop.is_set():
            raise InterruptedError('Stopped')
        if remaining <= 0:
            raise TimeoutError('Crawler time budget reached')
        request_headers = session.headers_for(url) if session else {}
        response = (fetch(url, insecure, min(request_timeout, remaining), headers=request_headers, scan_ip=scan_ip)
                if request_headers else fetch(url, insecure, min(request_timeout, remaining), scan_ip=scan_ip))
        gate.observe(response)
        return response

    def checkpoint():
        result['discovered'] = sorted(discovered)
        (folder / 'crawl.json').write_text(evidence.dumps(result), encoding='utf-8')

    def add(value, base, level, source, kind='link'):
        try:
            url = scoped_link(value, base, target, origins)
            if source != 'seed' and any(SECRET.search(k) for k, _ in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query)):
                raise ValueError('Sensitive query parameters require manual review')
            if url in discovered:
                return
            if len(discovered) >= max_discovered:
                if 'discovery_limit' not in result['limits']:
                    result['limits'].append('discovery_limit')
                return
            discovered.add(url)
            result['routes'].append({'url': url, 'source': source, 'kind': kind})
            u = urllib.parse.urlsplit(url)
            signature = (origin(url), u.path, tuple(sorted(urllib.parse.parse_qs(u.query, keep_blank_values=True))))
            variants[signature] += 1
            if level > depth:
                if 'depth_limit' not in result['limits']:
                    result['limits'].append('depth_limit')
            elif STATIC.search(u.path) and not SCRIPT.search(u.path):
                result['excluded'].append({'url': url, 'reason': 'Static asset', 'source': source})
            elif variants[signature] > 3:
                result['excluded'].append({'url': url, 'reason': 'Query variant limit', 'source': source})
            else:
                queue.append((url, level))
        except (ValueError, TypeError) as exc:
            if len(result['excluded']) < max_discovered:
                result['excluded'].append({'url': urllib.parse.urljoin(base, str(value))[:4096], 'source': source, 'reason': str(exc)})

    for seed in seeds:
        add(seed, seed, 0, 'seed')
    if metadata_paths:
        for seed in dict.fromkeys(urllib.parse.urljoin(seed, '/') for seed in seeds):
            for path in ('/robots.txt', '/sitemap.xml'):
                add(path, seed, 1, 'web-metadata', 'metadata')
    if api_paths:
        for seed in seeds:
            for path in ('/api', '/api/v1', '/openapi.json', '/swagger.json', '/api-docs'):
                add(path, seed, 1, 'api-inventory', 'api-probe')
    checkpoint()
    try:
        while (queue or scheduled) and not stop.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                result['limits'].append('time_limit')
                break
            if not scheduled:
                while queue and len(scheduled) < workers and result['requests'] < max_pages:
                    url, level = queue.popleft()
                    if url in seen:
                        continue
                    seen.add(url)
                    result['requests'] += 1
                    scheduled.append((url, level, result['requests'], pool.submit(request, url)))
            if not scheduled:
                break
            url, level, number, future = scheduled.popleft()
            page = {'url': url, 'depth': level}
            result['pages'].append(page)
            try:
                while True:
                    try:
                        response = dict(future.result(timeout=0.25))
                        break
                    except FutureTimeoutError:
                        if future.done():
                            response = dict(future.result())  # Propagate a request error; handle completion races.
                            break
                        if progress:
                            progress(len(result['pages']) - 1, max_pages)
                        if stop.is_set():
                            raise InterruptedError('Stopped while waiting for HTTP')
                        if time.monotonic() >= deadline:
                            raise TimeoutError('Crawl time budget reached')
                body = response.pop('body')
                page['technologies'] = technology.detect(url, response.get('headers', []), body)
                page['jwt'] = jwt_analyzer.discover(body.decode('utf-8', errors='replace'))
                page.update(response)
                page.update(evidence.save_body(folder, f'body-{number:04d}.bin', body, retain_raw))
                headers = {k.lower(): v for k, v in page['headers']}
                if (200 <= page['status'] < 300 and 'html' in headers.get('content-type', '').lower()
                        and b'phpinfo()' in body and b'PHP Version' in body
                        and (b'Configuration' in body or b'PHP Variables' in body)):
                    page['phpinfo_signature'] = True
                if page['status'] in (301, 302, 303, 307, 308) and headers.get('location'):
                    page['redirect'] = dict(location=evidence.url(urllib.parse.urljoin(url, headers['location'])),
                                            decision='disabled')
                    if follow_redirects:
                        try:
                            destination = scoped_link(headers['location'], url, target, {origin(url)})
                            if any(SECRET.search(k) for k, _ in urllib.parse.parse_qsl(urllib.parse.urlsplit(destination).query)):
                                raise ValueError('Sensitive redirect query requires manual review')
                            page['redirect'].update(decision='queued', url=destination)
                            add(destination, url, level + 1, url, 'redirect')
                        except (ValueError, TypeError) as exc:
                            page['redirect'].update(decision='excluded', reason=str(exc))
                if 200 <= page['status'] < 300 and not page.get('truncated'):
                    metadata_kind = next((r['kind'] for r in result['routes'] if r['url'] == url), '')
                    path = urllib.parse.urlsplit(url).path.lower()
                    if path == '/robots.txt':
                        for value in robots_links(body.decode('utf-8', 'replace')):
                            add(value, url, level + 1, url, 'robots')
                    if path.endswith('.xml') or metadata_kind == 'sitemap':
                        for value in sitemap_links(body):
                            add(value, url, level + 1, url, 'sitemap')
                if 200 <= page['status'] < 300 and (SCRIPT.search(urllib.parse.urlsplit(url).path)
                        or 'javascript' in headers.get('content-type', '').lower()):
                    for hint in route_literals(body.decode('utf-8', 'replace')):
                        add(hint, url, level + 1, url, 'javascript-literal')
                if 200 <= page['status'] < 300 and 'json' in headers.get('content-type', '').lower():
                    try:
                        spec = json.loads(body)
                        if isinstance(spec, dict) and ('openapi' in spec or 'swagger' in spec):
                            base_path = spec.get('basePath', '/') if 'swagger' in spec else '/'
                            if 'openapi' in spec:
                                servers = spec.get('servers', [])
                                if servers and isinstance(servers[0], dict):
                                    base_path = servers[0].get('url', '/')
                            api_base = urllib.parse.urljoin(url, str(base_path).rstrip('/') + '/')
                            for path in openapi_get_routes(spec):
                                add(path, api_base, level + 1, url, 'openapi-get')
                    except (ValueError, TypeError):
                        pass
                # No forms are submitted during discovery.
                if 200 <= page['status'] < 300 and 'html' in headers.get('content-type', '').lower():
                    parser = Links()
                    parser.feed(body.decode('utf-8', 'replace'))
                    if parser.form is not None:
                        parser.forms.append(parser.form)
                    base = urllib.parse.urljoin(url, parser.base) if parser.base else url
                    for link in parser.links:
                        add(link, base, level + 1, url)
                    for script in parser.scripts:
                        add(script, base, level + 1, url, 'script-src')
                        # A script's directory is a discovery candidate, not a finding.
                        parent = urllib.parse.urljoin(urllib.parse.urljoin(base, script), '.')
                        add(parent, base, level + 1, url, 'script-directory')
                    for hint in parser.hints:
                        add(hint, base, level + 1, url, 'inline-or-comment')
                    for form in parser.forms:
                        form = dict(form, source=url)
                        result['forms'].append(form)
                        if (form['method'] != 'get' or form.get('excluded_inputs')
                                or any(SECRET.search(name) for name, _ in form['fields'])):
                            form['reason'] = 'Form requires manual review; not submitted'
                            continue
                        action = urllib.parse.urljoin(base, form['action']) if form['action'] else url
                        u = urllib.parse.urlsplit(action)
                        fields = [tuple(field) for field in form['fields']]
                        # A named submit control often gates the application's handler.
                        if form.get('submit'):
                            fields.append(tuple(form['submit']))
                        query = urllib.parse.urlencode(fields)
                        candidate = urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, query, ''))
                        try:
                            candidate = scoped_link(candidate, url, target, origins)
                            # Inventory only: do not submit the form during crawling.
                            if len(discovered) < max_discovered:
                                discovered.add(candidate)
                                form['candidate_url'] = candidate
                        except ValueError as exc:
                            form['reason'] = str(exc)
            except Exception as exc:
                page['error'] = reliability.record('crawl_request_or_parse', exc)
                if isinstance(exc, TimeoutError) and 'budget' in str(exc):
                    result['limits'].append('time_limit')
            checkpoint()
            if progress:
                progress(len(result['pages']), max_pages)
    except KeyboardInterrupt:
        stop.set()
        result['status'] = 'cancelled'
        checkpoint()
        raise
    finally:
        for _, _, _, future in scheduled:
            future.cancel()
        pool.shutdown(wait=True, cancel_futures=True)
        # Index completed in-flight responses even when time/cancellation stops parsing.
        for url, level, number, future in scheduled:
            page = {'url': url, 'depth': level, 'parsed': False}
            try:
                response = dict(future.result())
                body = response.pop('body')
                page.update(response)
                page.update(evidence.save_body(folder, f'body-{number:04d}.bin', body, retain_raw))
            except (Exception, KeyboardInterrupt) as exc:
                page['error'] = str(exc)[:500] or 'Cancelled before response'
            result['pages'].append(page)
        checkpoint()
    if queue and result['requests'] >= max_pages:
        result['limits'].append('page_limit')
    result['pending'] = len(queue) + len(scheduled)
    result['limits'] = sorted(set(result['limits']))
    result['status'] = 'cancelled' if stop.is_set() else ('limited' if result['limits'] else (
        'incomplete' if any('error' in page or page.get('truncated') for page in result['pages']) else 'completed'))
    checkpoint()
    return result
