import hashlib
import http.server
from pathlib import Path
import tempfile
import threading
import unittest

import crawler
import checks
import cli
from unittest.mock import patch
from session import Session


class Handler(http.server.BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        type(self).hits.append((self.path, self.headers.get('Cookie')))
        if self.path in ('/loop-a', '/loop-b', '/external', '/action', '/directory'):
            self.send_response(302)
            self.send_header('Location', {'/loop-a': '/loop-b', '/loop-b': '/loop-a',
                '/external': 'http://127.0.0.2/never', '/action': '/reset',
                '/directory': '/directory/'}[self.path])
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('Content-Type', 'application/javascript' if self.path.endswith('.js') else 'text/html')
        self.end_headers()
        if self.path == '/':
            self.wfile.write(b'''<script src="/nested/login/script.js"></script>
            <script>const route = '/inline?q=hello';</script>
            <!-- old route: '/legacy?item=1' -->
            <script src="http://127.0.0.2/never.js"></script>''')
        elif self.path == '/nested/login/script.js':
            self.wfile.write(b'''fetch("./account?id=2"); const logout="/logout";
                const stylesheet="/css/site.css"; const external="//127.0.0.2/never";''')
        elif self.path == '/protected':
            self.wfile.write(b'<a href="/account?id=2">Account</a>' if self.headers.get('Cookie') == 'session=lab' else b'Login required')
        else:
            self.wfile.write(b'<html>ok</html>')

    def log_message(self, *args):
        pass


class DiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        Handler.hits.clear()

    def crawl(self, path='/', **options):
        return crawler.crawl([self.base + path], '127.0.0.1', self.folder / 'crawl',
            threading.Event(), rate=100, **options)

    def test_script_directory_and_literals_discovered_with_provenance_and_evidence(self):
        result = self.crawl()
        paths = {path for path, _ in Handler.hits}
        self.assertTrue({'/nested/login/', '/nested/login/script.js', '/nested/login/account?id=2',
            '/inline?q=hello', '/legacy?item=1'} <= paths)
        self.assertNotIn('/logout', paths)
        self.assertNotIn('/css/site.css', paths)
        self.assertNotIn('/never.js', paths)
        hint = next(r for r in result['routes'] if r['url'].endswith('/nested/login/account?id=2'))
        self.assertEqual(hint['kind'], 'javascript-literal')
        self.assertEqual(hint['source'], self.base + '/nested/login/script.js')
        for page in result['pages']:
            body = (self.folder / 'crawl' / page['body_file']).read_bytes()
            self.assertEqual(hashlib.sha256(body).hexdigest(), page['body_sha256'])

    def test_redirect_opt_in_loops_scope_and_action_exclusion(self):
        result = self.crawl('/loop-a', follow_redirects=True)
        self.assertEqual(result['requests'], 2)
        Handler.hits.clear()
        self.crawl('/directory', follow_redirects=True)
        self.assertIn(('/directory/', None), Handler.hits)
        Handler.hits.clear()
        self.crawl('/external', follow_redirects=True)
        self.assertEqual(Handler.hits, [('/external', None)])
        self.crawl('/action', follow_redirects=True)
        self.assertNotIn(('/reset', None), Handler.hits)

    def test_redirect_default_and_page_budget(self):
        self.crawl('/directory')
        self.assertEqual(Handler.hits, [('/directory', None)])
        result = self.crawl(max_pages=2)
        self.assertEqual(result['requests'], 2)
        self.assertIn('page_limit', result['limits'])

    def test_cookie_session_discovers_protected_links_and_is_origin_bound(self):
        path = self.folder / 'cookie.txt'
        path.write_text('session=lab\n', encoding='utf-8')
        session = Session(self.base, path)
        self.assertEqual(session.headers_for('http://127.0.0.1:1/'), {})
        self.assertEqual(session.headers_for(self.base.replace('http:', 'https:')), {})
        result = self.crawl('/protected', session=session)
        self.assertIn(self.base + '/account?id=2', result['discovered'])
        self.assertTrue(all(cookie == 'session=lab' for _, cookie in Handler.hits))
        self.assertNotIn('session=lab', (self.folder / 'crawl' / 'crawl.json').read_text())

    def test_cookie_invalid_values_rejected(self):
        path = self.folder / 'cookie.txt'
        for value in ('', 'session=a\r\nInjected: yes', 'x=\x00', 'x=' + 'a' * 17000):
            path.write_text(value, encoding='utf-8')
            with self.assertRaises(ValueError):
                Session(self.base, path)

    def test_checks_send_session_to_both_requests_and_empty_checks_are_explicit(self):
        path = self.folder / 'cookie.txt'
        path.write_text('session=lab', encoding='utf-8')
        session = Session(self.base, path)
        checks.run_checks([{'url': self.base + '/account?id=2', 'parameter': 'id'}],
            '127.0.0.1', self.folder / 'checks', threading.Event(), rate=100, session=session)
        self.assertEqual(len(Handler.hits), 2)
        self.assertTrue(all(cookie == 'session=lab' for _, cookie in Handler.hits))
        result = checks.run_checks([], '127.0.0.1', self.folder / 'empty', threading.Event())
        self.assertEqual(result['status'], 'no_candidates')
        self.assertEqual(result['requests'], 0)

    def test_session_pipeline_does_not_test_authenticated_candidates_with_unauthenticated_scanners(self):
        path = self.folder / 'cookie.txt'
        path.write_text('session=lab', encoding='utf-8')
        args = cli.parser().parse_args(['127.0.0.1', '--rate', '50'])
        args.session = Session(self.base, path)
        summary = {'target': '127.0.0.1', 'jobs': []}
        runner = cli.Runner()
        with patch.object(runner, 'execute', side_effect=AssertionError('Unauthenticated scanner used')):
            cli.run_discovered(args, self.folder, [self.base + '/protected'], summary, runner, {})
        self.assertEqual(summary['injection']['status'], 'requires_authenticated_scanner')
        self.assertEqual(summary['injection']['selected'][0]['parameter'], 'id')
