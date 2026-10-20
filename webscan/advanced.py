"""WS-R bounded GET-only API, context, IDOR and SSRF assessment engine."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import shlex
import threading
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from . import api_analyzer
from . import crawler
from . import evidence
from . import jwt_analyzer
from . import reliability
from .scope import normalize_url, origin, scoped_link
from .session import Session


class Context:
    def __init__(self, name, role, base, session=None, bearer=None):
        self.name, self.role, self.allowed = name, role, origin(base)
        self.session, self.bearer = session, bearer

    def headers_for(self, url):
        if origin(url) != self.allowed:
            return {}
        headers = self.session.headers_for(url) if self.session else {}
        if self.bearer:
            headers['Authorization'] = 'Bearer ' + self.bearer
        return headers


def load_contexts(path, base):
    """Load explicit credentials from separate files; policy includes literal URLs."""
    path = Path(path).expanduser().resolve()
    if path.stat().st_size > 65536:
        raise ValueError('Context configuration exceeds 64 KiB')
    doc = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(doc, dict) or not isinstance(doc.get('contexts'), list) or not 2 <= len(doc['contexts']) <= 8:
        raise ValueError('Provide 2..8 explicit contexts')
    contexts = []
    names = set()
    for row in doc['contexts']:
        if not isinstance(row, dict):
            raise ValueError('Context must be an object')
        name, role = row.get('name'), row.get('role')
        if not isinstance(name, str) or not name.isidentifier() or name in names or not isinstance(role, str) or not role.isidentifier():
            raise ValueError('Unique context names and roles must be identifiers')
        names.add(name)
        cookie = Session(base, (path.parent / row['cookie_file']).resolve()) if row.get('cookie_file') else None
        bearer = None
        if row.get('bearer_file'):
            token_path = (path.parent / row['bearer_file']).resolve()
            if token_path.stat().st_size > 8192:
                raise ValueError('Bearer token exceeds 8 KiB')
            bearer = token_path.read_text(encoding='utf-8').strip()
            if not bearer or any(ord(c) < 33 or ord(c) > 126 for c in bearer):
                raise ValueError('Bearer token must be one ASCII value')
        contexts.append(Context(name, role, base, cookie, bearer))
    policies = doc.get('policies', [])
    if not isinstance(policies, list) or len(policies) > 32:
        raise ValueError('Provide at most 32 resource policies')
    for policy in policies:
        if not isinstance(policy, dict) or not isinstance(policy.get('allow'), list) or not policy['allow'] or not set(policy['allow']) <= names:
            raise ValueError('Each policy needs URL and allowed context names')
        policy['url'] = scoped_link(policy.get('url', ''), base, origin(base)[1], {origin(base)})
    return contexts, policies


def idor_variants(url, alternatives=()):
    """Only bounded existing ID-like GET parameters; do not guess missing inputs."""
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    result = []
    for index, (key, value) in enumerate(pairs):
        if key.lower() not in ('id', 'uid', 'user_id', 'account_id', 'order_id', 'document_id'):
            continue
        values = list(alternatives[:4])
        if value.isascii() and value.isdecimal() and len(value) <= 12:
            number = int(value)
            values = [str(number + 1)] + ([str(number - 1)] if number > 0 else []) + values
        for alternate in list(dict.fromkeys(values))[:4]:
            if alternate == value or not isinstance(alternate, str) or len(alternate) > 128:
                continue
            changed = pairs.copy()
            changed[index] = (key, alternate)
            result.append(urlunsplit(parsed._replace(query=urlencode(changed))))
    return result[:8]


def curl_helper(url):
    # No redirect following, credential embedding or local execution.
    return 'curl --max-time 10 --include -- ' + shlex.quote(evidence.url(url))


class Client:
    def __init__(self, target, bases, gate, stop, folder, scan_ip=None, timeout=10, budget=120,
                 insecure=False, retain=False, max_requests=120):
        self.target, self.origins = target, {origin(u) for u in bases}
        self.gate, self.stop, self.folder = gate, stop, Path(folder)
        self.scan_ip, self.timeout, self.insecure, self.retain = scan_ip, timeout, insecure, retain
        self.deadline, self.max_requests = time.monotonic() + budget, max_requests
        self.count, self.lock = 0, threading.Lock()

    def get(self, url, context=None):
        row = {'url': evidence.url(url), 'outcome': 'inconclusive'}
        try:
            url = scoped_link(url, url, self.target, self.origins)
            with self.lock:
                if self.count >= self.max_requests:
                    raise TimeoutError('Request limit')
                self.count += 1
                index = self.count
            self.gate.wait(self.stop, self.deadline)
            remaining = min(self.timeout, self.deadline - time.monotonic())
            if remaining <= 0:
                raise TimeoutError('Time limit')
            response = crawler.fetch(url, self.insecure, remaining,
                headers=context.headers_for(url) if context else None, scan_ip=self.scan_ip)
            self.gate.observe(response)
            body = response.pop('body', b'')
            if isinstance(body, str):
                body = body.encode()
            row.update(response)
            row.update(evidence.save_body(self.folder, f'response-{index:04d}.bin', body, self.retain))
            row['body_hash'] = hashlib.sha256(body).hexdigest()
            row['outcome'] = 'observed'
            row['jwt'] = jwt_analyzer.discover(body.decode('utf-8', errors='replace'))
            return row, body
        except Exception as exc:
            row['error'] = reliability.record('advanced_http', exc)
            return row, b''


def accessible(row):
    return row.get('status') == 200 and not row.get('truncated') and row.get('outcome') == 'observed'


def run(bases, target, folder, stop, gate, *, scan_ip=None, timeout=10, budget=120, workers=4,
        api=False, contexts=None, policies=None, idor=False, alternatives=(), candidates=(),
        ssrf_canary=None, metadata=False, session=None, insecure=False, retain=False, progress=None, jwt_observations=()):
    folder = Path(folder)
    state = {'status': 'completed', 'requests': 0, 'checks': [], 'api': [], 'matrix': [], 'jwt': list(jwt_observations)[:200], 'errors': []}
    client = Client(target, bases, gate, stop, folder, scan_ip, timeout, budget, insecure, retain)
    context = Context('scan', 'scan', bases[0], session) if bases else None

    def add(check, url, title, severity, responses, note):
        state['checks'].append({'check': check, 'url': evidence.url(url), 'title': title, 'severity': severity,
            'category': 'scanner_match', 'validation_status': 'needs_validation', 'note': note,
            'responses': responses, 'curl': curl_helper(url)})

    try:
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        if api:
            urls = []
            for base in bases[:8]:
                for path in api_analyzer.DOC_PATHS:
                    urls.append(scoped_link(path, base, target, client.origins))
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, max(1, workers))) as pool:
                for row, body in pool.map(lambda u: client.get(u, context), dict.fromkeys(urls)):
                    state['jwt'].extend(row.get('jwt', []))
                    if row.get('error'):
                        state['errors'].append(row)
                    if row.get('status') == 200:
                        doc = api_analyzer.parse_document(body, row['url'], target, client.origins)
                        state['api'].append(doc)
                        if doc['status'] in ('completed', 'limited'):
                            add('api-document', row['url'], 'Exposed OpenAPI specification', 'info', [row],
                                'Specification exposure may be intentional; route names do not prove broken access control.')
        contexts, policies = contexts or [], policies or []
        # Only explicitly declared resource ownership/role expectations produce candidates.
        for policy in policies[:32]:
            url = scoped_link(policy['url'], bases[0], target, client.origins)
            rows = []
            for ctx in contexts:
                first, _ = client.get(url, ctx)
                second, _ = client.get(url, ctx)
                stable = accessible(first) and accessible(second) and first.get('body_hash') == second.get('body_hash')
                rows.append({'context': ctx.name, 'role': ctx.role, 'expected_allowed': ctx.name in policy['allow'],
                             'stable_success': stable, 'responses': [first, second]})
                state['jwt'].extend(first.get('jwt', []))
                state['jwt'].extend(second.get('jwt', []))
                if first.get('error') or second.get('error'):
                    state['errors'].append({'context': ctx.name, 'error': 'context_request_incomplete'})
            state['matrix'].append({'url': evidence.url(url), 'contexts': rows})
            approved = [r for r in rows if r['expected_allowed'] and r['stable_success']]
            for row in rows:
                if row['expected_allowed'] or not row['stable_success']:
                    continue
                matched = next((good for good in approved if good['responses'][0]['body_hash'] == row['responses'][0]['body_hash']), None)
                if matched:
                    add('access-control', url, 'Declared access policy mismatch across contexts', 'high',
                        row['responses'] + matched['responses'],
                        'Stable identical response under allowed and disallowed contexts; validate protected data and cookie validity manually.')
        if idor:
            for url in list(dict.fromkeys(candidates))[:16]:
                scoped_link(url, url, target, client.origins)
                baseline, _ = client.get(url, context)
                for alternate in idor_variants(url, alternatives):
                    changed, _ = client.get(alternate, context)
                    state['matrix'].append({'url': evidence.url(alternate), 'kind': 'idor_inventory',
                        'baseline_status': baseline.get('status'), 'alternate_status': changed.get('status'),
                        'body_changed': baseline.get('body_hash') != changed.get('body_hash'),
                        'note': 'Object owner unknown: response differences are not proof of IDOR.', 'responses': [baseline, changed]})
        if ssrf_canary or metadata:
            payloads = [ssrf_canary] if ssrf_canary else []
            if metadata:
                payloads.append('http://169.254.169.254/')
            for url in list(dict.fromkeys(candidates))[:12]:
                parsed = urlsplit(scoped_link(url, url, target, client.origins))
                pairs = parse_qsl(parsed.query, keep_blank_values=True)
                for index, (key, value) in enumerate(pairs):
                    if key.lower() not in ('url', 'uri', 'endpoint', 'callback', 'feed', 'fetch_url', 'image_url'):
                        continue
                    baseline, basebody = client.get(url, context)
                    for payload in payloads:
                        changed = pairs.copy()
                        changed[index] = (key, payload)
                        probe = urlunsplit(parsed._replace(query=urlencode(changed)))
                        row, body = client.get(probe, context)
                        # A reflected URL or 200 status alone is not SSRF evidence.
                        signatures = (b'latest/meta-data', b'instance-id', b'computeMetadata')
                        if metadata and payload == 'http://169.254.169.254/' and accessible(row) and any(s in body and s not in basebody for s in signatures):
                            add('ssrf-metadata', probe, 'Metadata-shaped response through URL input', 'high', [baseline, row],
                                'Root metadata probe only; no credential paths. Validate server-side fetch versus synthetic response.')
                        else:
                            state['matrix'].append({'kind': 'ssrf_probe', 'url': evidence.url(probe),
                                'responses': [baseline, row], 'note': 'Unconfirmed. Check your canary server logs for a correlated server-side request.'})
        for page in state['matrix']:
            for row in page.get('responses', []):
                state['jwt'].extend(row.get('jwt', []))
        unique = {row.get('sha256'): row for row in state['jwt'] if row.get('sha256')}
        state['jwt'] = list(unique.values())
        for row in state['jwt']:
            if any(issue.startswith('unsigned_token') for issue in row['issues']):
                state['checks'].append({'check': 'jwt-unsigned', 'url': evidence.url(bases[0]),
                    'title': 'Unsigned JWT observed; acceptance untested', 'severity': 'medium', 'category': 'scanner_match',
                    'validation_status': 'needs_validation', 'responses': [], 'jwt': row,
                    'note': 'Local structure analysis only; signature validation and server acceptance are untested.'})
    except Exception as exc:
        state['errors'].append({'error': reliability.record('advanced_stage', exc)})
    state['requests'] = client.count
    if stop.is_set():
        state['status'] = 'cancelled'
    elif state['errors'] or any(r.get('error') or r.get('truncated') for p in state['matrix'] for r in p.get('responses', [])):
        state['status'] = 'incomplete'
    elif any(doc['status'] == 'limited' for doc in state['api']):
        state['status'] = 'limited'
    try:
        (folder / 'results.json').write_text(evidence.dumps(state), encoding='utf-8')
    except Exception as exc:
        state['status'] = 'incomplete'
        state['errors'].append({'error': reliability.record('advanced_save', exc)})
    return state


def findings(root, summary):
    """Reload immutable advanced evidence, including during offline report rebuilds."""
    path = Path(root) / 'advanced' / 'results.json'
    if not path.is_file():
        return []
    result = []
    try:
        raw = path.read_bytes()
        if len(raw) > 8388608:
            raise ValueError('Advanced artifact too large')
        state = json.loads(raw)
        for index, row in enumerate(state.get('checks', []), 1):
            url = normalize_url(row['url'], summary['target'])
            entry = dict(id=hashlib.sha256((row['check'] + url).encode()).hexdigest()[:16],
                category=row['category'], check=row['check'], url=url, title=row['title'],
                severity=row['severity'], validation_status='needs_validation',
                recommendation=row.get('note', 'Validate in application context.'), evidence=[])
            entry['evidence'].append(dict(tool='advanced', job='Advanced GET assessment',
                job_status=state['status'], file='advanced/results.json', record=index,
                sha256=hashlib.sha256(raw).hexdigest(), raw='[omitted]',
                poc=[evidence.http_poc(r, path.parent, summary.get('retain_raw_evidence', False)) for r in row.get('responses', [])]
                    + ([{'kind': 'jwt_structure', 'analysis': row['jwt']}] if row.get('jwt') else [])))
            entry['reproduction'] = row.get('curl', '')
            result.append(entry)
    except Exception as exc:
        reliability.record('advanced_findings', exc)
        summary.setdefault('parse_issues', []).append({'job': 'Advanced GET assessment',
            'file': 'advanced/results.json', 'message': 'Advanced artifact could not be parsed: ' + type(exc).__name__})
    return result
