"""Safe metadata serialization; raw bodies require explicit opt-in."""
import hashlib
import json
import re
import urllib.parse

SECRET = re.compile(r'password|passwd|csrf|token|session|authorization|secret|nonce|cookie|api[-_]?key|access[-_]?key', re.I)


def url(value):
    try:
        u = urllib.parse.urlsplit(value)
        netloc = u.netloc
        if u.username is not None or u.password is not None:
            hostname = u.hostname or ''
            netloc = ('[' + hostname + ']') if ':' in hostname else hostname
            if u.port is not None:
                netloc += ':' + str(u.port)
        pairs = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
        query = (urllib.parse.urlencode([(k, '[redacted]' if SECRET.search(k) else v) for k, v in pairs])
                 if any(SECRET.search(k) for k, _ in pairs) else u.query)
        return urllib.parse.urlunsplit((u.scheme, netloc, u.path,
            query, ''))
    except ValueError:
        return '[invalid URL]'


def safe(value):
    if isinstance(value, dict):
        if SECRET.search(str(value.get('name', ''))) and 'value' in value:
            value = dict(value, value='[redacted]')
        return {k: '[redacted]' if SECRET.search(str(k)) and k not in ('session_scope',) else safe(v)
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        if len(value) == 2 and isinstance(value[0], str) and SECRET.search(value[0]):
            return [value[0], '[redacted]']
        return [safe(v) for v in value]
    if isinstance(value, str):
        # A request block or body snippet is not a URL. Preserve its line structure.
        return url(value) if value.startswith(('http://', 'https://', '/')) and not any(c.isspace() for c in value) else value
    return value


def dumps(value):
    return json.dumps(safe(value), indent=2, ensure_ascii=False)


def save_body(folder, name, body, retain=False):
    stored = body if retain else b'[Response body omitted; use --retain-raw-evidence to retain it.]\n'
    (folder / name).write_bytes(stored)
    return {'body_file': name, 'body_sha256': hashlib.sha256(stored).hexdigest(),
            'response_sha256': hashlib.sha256(body).hexdigest(), 'body_retained': retain}


def request_details(conn):
    """Actual transmitted request header, with secret values always redacted."""
    data = getattr(conn, 'request_capture', b'')
    if not data:
        return {'status': 'unavailable', 'reason': 'No captured request bytes'}
    text = bytes(data).decode('iso-8859-1')
    header = text.partition('\r\n\r\n')[0]
    lines = header.splitlines()
    parts = lines[0].split(' ', 2)
    if len(parts) != 3:
        return {'status': 'unavailable', 'reason': 'Invalid captured request line'}
    method, target, protocol = parts
    headers = [line.split(':', 1) for line in lines[1:] if ':' in line]
    headers = [[k, '[redacted]' if SECRET.search(k) else v.strip()] for k, v in headers]
    safe_target = url(target)
    rendered = f'{method} {safe_target} {protocol}\r\n' + ''.join(f'{k}: {v}\r\n' for k, v in headers) + '\r\n'
    truncated = getattr(conn, 'request_bytes', len(data)) > len(data)
    return dict(status='captured', method=method, target=safe_target, protocol=protocol,
                headers=headers, text=rendered, redacted=rendered != text,
                truncated=truncated, exact=rendered == text and not truncated,
                sha256=conn.request_digest.hexdigest())


def http_poc(row, folder=None, retain=False):
    """Observed response metadata plus captured request; never invent missing bytes."""
    result = dict(kind='http', url=url(row.get('url', '')), status='captured' if 'status' in row else 'unavailable',
                  request=row.get('request', {'status': 'unavailable', 'reason': 'Legacy or imported record lacks a captured request'}),
                  response_status=row.get('status'), response_headers=safe(row.get('headers', [])),
                  response_sha256=row.get('response_sha256'), response_body_status='omitted',
                  response_snippet='[Body omitted by evidence policy]', truncated=bool(row.get('truncated')))
    if folder is not None and retain and row.get('body_retained') and row.get('body_file'):
        from pathlib import Path
        path = (Path(folder) / row['body_file']).resolve()
        try:
            path.relative_to(Path(folder).resolve())
            if path.stat().st_size > 262144:
                raise ValueError('Body exceeds the evidence size limit')
            digest = hashlib.sha256()
            snippet = bytearray()
            with path.open('rb') as source:
                for block in iter(lambda: source.read(65536), b''):
                    digest.update(block)
                    if len(snippet) < 2048:
                        snippet.extend(block[:2048 - len(snippet)])
            if digest.hexdigest() != row.get('body_sha256'):
                raise ValueError('Stored body hash mismatch')
            result.update(response_body_status='retained', response_snippet=bytes(snippet).decode('utf-8', 'replace'))
        except (OSError, ValueError) as exc:
            result.update(response_body_status='unavailable', response_snippet='[Unavailable]', integrity_error=str(exc))
    return result


def record_pocs(tool, row, folder, retain=False):
    sources = []
    if tool == 'crawler':
        sources = [row]
    elif tool == 'checks':
        sources = ([row['control_response']] if row.get('control_response') else []) + row.get('responses', [])
    if sources:
        return [http_poc(source, folder, retain) for source in sources]
    # Some JSON scanners export the HTTP exchange as strings. Preserve that
    # provenance separately from our own transport capture, redacting headers.
    if isinstance(row.get('request'), str) or isinstance(row.get('response'), str):
        from types import SimpleNamespace
        request = (row.get('request') if isinstance(row.get('request'), str) else '').encode('utf-8')
        capture = SimpleNamespace(request_capture=request, request_digest=hashlib.sha256(request), request_bytes=len(request))
        details = request_details(capture)
        details.update(source='scanner_export', exact=False,
                       exactness_note='Exported text; original network bytes were not captured by this tool.')
        response = row.get('response', '')
        header, _, body = response.partition('\r\n\r\n')
        if not _:
            header, _, body = response.partition('\n\n')
        lines = header.splitlines()
        status = re.match(r'HTTP/\S+\s+(\d{3})', lines[0]) if lines else None
        headers = [line.split(':', 1) for line in lines[1:] if ':' in line]
        proof = http_poc(dict(url=row.get('matched-at') or row.get('url', ''),
                             request=details, headers=headers, **({'status': int(status[1])} if status else {})))
        proof['source'] = 'scanner_export'
        if retain and body:
            proof.update(response_body_status='scanner_export', response_snippet=body[:2048])
        return [proof]
    if 'status' in row or 'status_code' in row:
        return [http_poc(dict(row, status=row.get('status', row.get('status_code'))))]
    # External tools may not export HTTP bytes. Do not fabricate a wire request.
    return [dict(kind='scanner_output', status='artifact_only', tool=tool,
                 detail='Original scanner record referenced by file, record index and SHA256; HTTP exchange unavailable.',
                 template=row.get('template-id'), payload=row.get('payload') if retain else '[omitted]')]
