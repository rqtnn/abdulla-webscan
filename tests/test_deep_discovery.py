import http.server
import json
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.parse

import checks
import cli
import crawler
import scan_modes


class ApiLab(http.server.BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        self.hits.append(self.path)
        url = urllib.parse.urlsplit(self.path)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json' if url.path == '/openapi.json' else 'text/html')
        self.end_headers()
        if url.path == '/openapi.json':
            self.wfile.write(json.dumps({'openapi': '3.0.0', 'paths': {
                '/lookup': {'get': {'parameters': [
                    {'in': 'query', 'name': 'q', 'schema': {'type': 'string'}}]}}
            }}).encode())
        elif url.path == '/lookup':
            self.wfile.write(urllib.parse.parse_qs(url.query).get('q', [''])[0].encode())

    def log_message(self, *args):
        pass


class DeepDiscoveryTests(unittest.TestCase):
    def test_openapi_only_input_reaches_real_http_checks(self):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), ApiLab)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        ApiLab.hits.clear()
        try:
            base = f'http://127.0.0.1:{server.server_port}'
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                state = crawler.crawl([base + '/openapi.json'], '127.0.0.1', root / 'crawl',
                                      threading.Event(), rate=100)
                selected, excluded = crawler.select_candidates(state['discovered'], 10)
                self.assertEqual([c['parameter'] for c in selected], ['q'])
                result = checks.run_checks(selected, '127.0.0.1', root / 'checks',
                                           threading.Event(), rate=100)
                self.assertTrue(any(c.get('check') == 'unescaped-reflection'
                                    and c['outcome'] == 'candidate' for c in result['checks']))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_schema_scope_secrets_references_and_method_restrictions(self):
        parameters = [
            {'in': 'query', 'name': 'id', 'type': 'integer'},
            {'in': 'query', 'name': 'token', 'type': 'string', 'default': 'secret'},
            {'in': 'query', 'name': 'q', 'schema': {'type': 'string'}},
            {'in': 'query', 'name': 'q', 'schema': {'type': 'boolean'}},
            {'in': 'query', 'name': 'items', 'schema': {'type': 'array'}},
            {'in': 'header', 'name': 'Authorization', 'type': 'string'},
            {'in': 'query', 'name': 'ref', 'schema': {'$ref': 'https://foreign.invalid/schema'}},
        ]
        routes = crawler.openapi_get_routes({'paths': {
            '/search': {'parameters': parameters[:1], 'get': {'parameters': parameters[1:]}},
            '/users/{id}': {'get': {}}, '/write': {'post': {}}, '/malformed': {'get': []},
        }})
        self.assertEqual(routes, ['search', 'search?id=1&q=true'])
        self.assertEqual(crawler.openapi_get_routes({'paths': []}), [])

    def test_named_button_preserves_get_dispatch_without_submitting(self):
        parser = crawler.Links()
        parser.feed('<form action="/search"><input name="q"><button name="submit" '
                    'value="Search">Search</button></form>')
        self.assertEqual(parser.forms[0]['submit'], ['submit', 'Search'])
        parser = crawler.Links()
        parser.feed('<form><input name="q"><button name="submit" formmethod="post">'
                    'Search</button></form>')
        self.assertTrue(parser.forms[0]['excluded_inputs'])

    def test_deep_mode_preserves_explicit_budgets_and_disabled_active_checks(self):
        argv = ['127.0.0.1', '--scan', 'deep', '--crawl-pages', '17', '--no-active-checks']
        args = cli.parser().parse_args(argv)
        cli.apply_profile(args, argv)
        scan_modes.apply(args, argv)
        self.assertEqual(args.crawl_pages, 17)
        self.assertEqual(args.crawl_depth, 5)
        self.assertFalse(args.template_checks or args.active_checks or args.builtin_sqli)
        self.assertFalse(args.external_tools or args.insecure)


if __name__ == '__main__':
    unittest.main()
