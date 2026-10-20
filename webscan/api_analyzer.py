"""WS-R bounded OpenAPI inventory. A route name is not an access-control finding."""
import json
import re
from urllib.parse import urlsplit
from .scope import scoped_link

DOC_PATHS = ('/openapi.json', '/swagger.json', '/api-docs', '/v3/api-docs', '/swagger/v1/swagger.json')
METHODS = frozenset(('get', 'post', 'put', 'patch', 'delete', 'head', 'options'))


def parse_document(body, url, target, origins, limit=200):
    result = {'url': url, 'status': 'inconclusive', 'routes': [], 'errors': []}
    try:
        if len(body) > 262144:
            raise ValueError('Document too large')
        doc = json.loads(body)
        if not isinstance(doc, dict) or not (doc.get('openapi') or doc.get('swagger')):
            raise ValueError('Not an OpenAPI/Swagger object')
        paths = doc.get('paths', {})
        if not isinstance(paths, dict):
            raise ValueError('Invalid paths object')
        # Ignore remote servers and references. Only source-origin paths are used.
        prefix = doc.get('basePath', '') if doc.get('swagger') else ''
        if not isinstance(prefix, str) or (prefix and not prefix.startswith('/')) or '://' in prefix:
            prefix = ''
        for path, operations in paths.items():
            if len(result['routes']) >= limit:
                result['errors'].append('route_limit')
                break
            if not isinstance(path, str) or not path.startswith('/') or path.startswith('//') or not isinstance(operations, dict):
                continue
            for method, operation in operations.items():
                if method not in METHODS or not isinstance(operation, dict):
                    continue
                if len(result['routes']) >= limit:
                    result['errors'].append('route_limit')
                    break
                try:
                    endpoint = scoped_link(prefix.rstrip('/') + path, url, target, origins)
                except ValueError:
                    continue
                declared = operation.get('security', doc.get('security', None))
                result['routes'].append({'url': endpoint, 'method': method.upper(),
                    'parameterized': bool(re.search(r'\{[^}]+\}', path)),
                    'administrative_hint': bool(re.search(r'admin|manage|internal', urlsplit(endpoint).path, re.I)),
                    'security_declared': bool(declared),
                    'note': 'Specification inventory only; authentication and authorization require validation.'})
        result['status'] = 'limited' if result['errors'] else 'completed'
    except Exception as exc:
        from .reliability import record
        result['errors'].append(record('openapi_parse', exc))
    return result
