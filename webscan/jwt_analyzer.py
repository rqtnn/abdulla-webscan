"""WS-R local JWT inspection; no token forgery or signature-verification claims."""
import base64
import hashlib
import json
import re
import time

TOKEN = re.compile(r'(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(?![A-Za-z0-9_-])')


def analyze(token, now=None):
    result = {'status': 'malformed', 'issues': [], 'signature_verified': False}
    try:
        if not isinstance(token, str) or len(token) > 8192:
            raise ValueError('Invalid token size/type')
        result['sha256'] = hashlib.sha256(token.encode()).hexdigest()
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError('Expected three segments')
        decoded = []
        for segment in parts[:2]:
            if not segment or not re.fullmatch(r'[A-Za-z0-9_-]+', segment):
                raise ValueError('Invalid base64url')
            raw = base64.b64decode(segment + '=' * (-len(segment) % 4), altchars=b'-_', validate=True)
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError('JWT segment is not an object')
            decoded.append(value)
        header, claims = decoded
        alg = header.get('alg')
        if not isinstance(alg, str) or len(alg) > 32:
            raise ValueError('Missing/invalid algorithm')
        if parts[2] and not re.fullmatch(r'[A-Za-z0-9_-]+', parts[2]):
            raise ValueError('Invalid signature encoding')
        if parts[2]:
            base64.b64decode(parts[2] + '=' * (-len(parts[2]) % 4), altchars=b'-_', validate=True)
        result.update(status='inspected', algorithm=alg, signature_present=bool(parts[2]),
                      claim_presence={key: key in claims for key in ('exp', 'iat', 'nbf', 'iss', 'aud')})
        if alg.lower() == 'none' or not parts[2]:
            result['issues'].append('unsigned_token_candidate; server acceptance untested')
        if alg.startswith('HS'):
            result['issues'].append('symmetric_algorithm_observed; key strength untested')
        for key in ('exp', 'iat', 'nbf'):
            if key in claims and (isinstance(claims[key], bool) or not isinstance(claims[key], (int, float))):
                result['issues'].append(f'invalid_{key}_type')
        exp = claims.get('exp')
        if isinstance(exp, (int, float)) and not isinstance(exp, bool) and exp < (time.time() if now is None else now):
            result['issues'].append('expired_token_observed; server acceptance untested')
    except Exception as exc:
        from .reliability import record
        result['error'] = record('jwt_parse', exc)
    return result


def discover(text, limit=20):
    if not isinstance(text, str):
        return []
    return [analyze(token) for token in list(dict.fromkeys(TOKEN.findall(text[:262144])))[:limit]]
