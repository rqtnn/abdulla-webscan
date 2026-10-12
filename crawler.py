"""Bounded, unauthenticated HTML discovery for one host's responding origins."""
from collections import Counter, deque
import hashlib
from html.parser import HTMLParser
import http.client
import json
import re
import ssl
import time
import urllib.parse

from findings import normalize_url

STATIC = re.compile(r'\.(?:png|jpe?g|gif|svg|ico|woff2?|ttf|css|js|pdf|zip|mp4|mp3)$', re.I)
ACTION = re.compile(r'(?:^|[/_\W])(?:logout|signout|delete|remove|destroy|reset|unsubscribe|purchase|checkout)(?:$|[/_\W])', re.I)
SECRET = re.compile(r'password|passwd|csrf|token|session|authorization|secret|nonce', re.I)


def origin(url):
    u = urllib.parse.urlsplit(url)
    return u.scheme, u.hostname, u.port or (443 if u.scheme == 'https' else 80)


def scoped_link(value, base, target, origins):
    value = urllib.parse.urljoin(base, value.strip())
    value = normalize_url(value, target)
    if origin(value) not in origins:
        raise ValueError('Port/scheme was not a responding origin')
    if len(value) > 4096 or ACTION.search(urllib.parse.unquote(value)):
        raise ValueError('Action-like or oversized URL excluded from automatic requests')
    return value


class Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.forms = [], []
        self.form = None
        self.base = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'base' and self.base is None:
            self.base = attrs.get('href')
        if tag in ('a', 'area', 'iframe') and attrs.get('href' if tag != 'iframe' else 'src'):
            if len(self.links) < 2000:
                self.links.append(attrs.get('href' if tag != 'iframe' else 'src'))
        if tag == 'form':
            if self.form is not None:
                self.forms.append(self.form)
            self.form = {'action': attrs.get('action', ''), 'method': attrs.get('method', 'get').lower(), 'fields': []}
        if tag == 'input' and self.form is not None and attrs.get('name'):
            kind = attrs.get('type', 'text').lower()
            if kind == 'submit' and 'disabled' not in attrs and not self.form.get('submit'):
                self.form['submit'] = [attrs['name'], attrs.get('value', '')]
            if kind not in ('submit', 'button', 'reset', 'file', 'password', 'image') and 'disabled' not in attrs:
                if kind not in ('checkbox', 'radio') or 'checked' in attrs:
                    self.form['fields'].append([attrs['name'], attrs.get('value', '')])
            elif kind in ('file', 'password'):
                self.form['excluded_inputs'] = True
        if tag in ('select', 'textarea') and self.form is not None:
            self.form['excluded_inputs'] = True

    def handle_endtag(self, tag):
        if tag == 'form' and self.form is not None:
            self.forms.append(self.form)
            self.form = None


def fetch(url, insecure=False, timeout=5, max_bytes=262144):
    """Direct GET with query intact; never follow redirects or use proxy settings."""
    u = urllib.parse.urlsplit(url)
    if u.scheme == 'https':
        context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        conn = http.client.HTTPSConnection(u.hostname, u.port, timeout=timeout, context=context)
    else:
        conn = http.client.HTTPConnection(u.hostname, u.port, timeout=timeout)
    try:
        conn.request('GET', urllib.parse.urlunsplit(('', '', u.path or '/', u.query, '')),
                     headers={'User-Agent': 'Abdulla-WebScan/2.0', 'Accept': 'text/html'})
        response = conn.getresponse()
        body = response.read(max_bytes + 1)
        headers = [list(pair) for pair in response.getheaders()]
        return {'status': response.status, 'headers': headers, 'body': body[:max_bytes],
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
                seed = '1' if name.lower() in ('id', 'uid', 'pid', 'item', 'number') else 'webscan'
                seeded = [(k, seed if k == name else v) for k, v in pairs]
                entry.update(discovered_url=url, url=urllib.parse.urlunsplit((u.scheme, u.netloc,
                    u.path, urllib.parse.urlencode(seeded), '')), seed_value=seed,
                    reason='Blank form value seeded for detection; handler execution still needs review')
            (excluded if reason else selected).append(entry)
    return selected, excluded


def crawl(seeds, target, folder, stop, max_pages=100, depth=3, rate=5, timeout=120,
          insecure=False, result=None):
    folder.mkdir(parents=True, exist_ok=True)
    result = result if result is not None else {}
    result.update(status='running', pages=[], discovered=[], forms=[], excluded=[], limits=[], requests=0)
    origins = {origin(normalize_url(url, target)) for url in seeds}
    queue, seen, discovered, variants = deque(), set(), set(), Counter()
    deadline = time.monotonic() + timeout
    max_discovered = max_pages * 10

    def checkpoint():
        result['discovered'] = sorted(discovered)
        (folder / 'crawl.json').write_text(json.dumps(result, indent=2), encoding='utf-8')

    def add(value, base, level, source):
        try:
            url = scoped_link(value, base, target, origins)
            if url in discovered:
                return
            if len(discovered) >= max_discovered:
                if 'discovery_limit' not in result['limits']:
                    result['limits'].append('discovery_limit')
                return
            discovered.add(url)
            u = urllib.parse.urlsplit(url)
            signature = (origin(url), u.path, tuple(sorted(urllib.parse.parse_qs(u.query, keep_blank_values=True))))
            variants[signature] += 1
            if level > depth:
                if 'depth_limit' not in result['limits']:
                    result['limits'].append('depth_limit')
            elif STATIC.search(u.path):
                result['excluded'].append({'url': url, 'reason': 'Static asset', 'source': source})
            elif variants[signature] > 3:
                result['excluded'].append({'url': url, 'reason': 'Query variant limit', 'source': source})
            else:
                queue.append((url, level))
        except (ValueError, TypeError) as exc:
            if len(result['excluded']) < max_discovered:
                result['excluded'].append({'url': str(value)[:4096], 'source': source, 'reason': str(exc)})

    for seed in seeds:
        add(seed, seed, 0, 'seed')
    checkpoint()
    while queue and result['requests'] < max_pages and not stop.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            result['limits'].append('time_limit')
            break
        url, level = queue.popleft()
        if url in seen:
            continue
        seen.add(url)
        result['requests'] += 1
        page = {'url': url, 'depth': level}
        result['pages'].append(page)
        try:
            response = fetch(url, insecure, min(5, remaining))
            body = response.pop('body')
            page.update(response)
            page['body_file'] = f'body-{result["requests"]:04d}.bin'
            page['body_sha256'] = hashlib.sha256(body).hexdigest()
            (folder / page['body_file']).write_bytes(body)
            headers = {k.lower(): v for k, v in page['headers']}
            if (200 <= page['status'] < 300 and 'html' in headers.get('content-type', '').lower()
                    and b'phpinfo()' in body and b'PHP Version' in body
                    and (b'Configuration' in body or b'PHP Variables' in body)):
                page['phpinfo_signature'] = True
            # Redirects remain evidence only. No forms are submitted.
            if 200 <= page['status'] < 300 and 'html' in headers.get('content-type', '').lower():
                parser = Links()
                parser.feed(body.decode('utf-8', 'replace'))
                if parser.form is not None:
                    parser.forms.append(parser.form)
                base = urllib.parse.urljoin(url, parser.base) if parser.base else url
                for link in parser.links:
                    add(link, base, level + 1, url)
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
        except (OSError, ValueError, http.client.HTTPException) as exc:
            page['error'] = str(exc)[:500]
        checkpoint()
        if queue:
            stop.wait(min(1 / rate, max(0, deadline - time.monotonic())))
    if queue and result['requests'] >= max_pages:
        result['limits'].append('page_limit')
    result['pending'] = len(queue)
    result['status'] = 'cancelled' if stop.is_set() else ('limited' if result['limits'] else 'completed')
    checkpoint()
    return result
