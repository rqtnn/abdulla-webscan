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
        return urllib.parse.urlunsplit((u.scheme, netloc, u.path,
            urllib.parse.urlencode([(k, '[redacted]' if SECRET.search(k) else v) for k, v in pairs]), ''))
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
        return url(value) if re.search(r'https?://|[?#]', value) else value
    return value


def dumps(value):
    return json.dumps(safe(value), indent=2, ensure_ascii=False)


def save_body(folder, name, body, retain=False):
    stored = body if retain else b'[Response body omitted; use --retain-raw-evidence to retain it.]\n'
    (folder / name).write_bytes(stored)
    return {'body_file': name, 'body_sha256': hashlib.sha256(stored).hexdigest(),
            'response_sha256': hashlib.sha256(body).hexdigest(), 'body_retained': retain}
