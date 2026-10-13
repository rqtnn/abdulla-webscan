"""Offline/local fixtures for the DNS, evidence, pacing and discovery boundaries."""
import contextlib
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

import checks
import crawler
import evidence
import findings
import scope
import transport
import cli
from cli_fixture import cli_platform


class Fixture(http.server.BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        type(self).hits.append((self.path, self.headers['Host'], time.monotonic()))
        content_type = 'text/html'
        body = b'<script src="/app.js"></script><a href="/?token=LINK_SECRET">private</a><form><input name="csrf_token" value="FORM_SECRET"></form>'
        if self.path == '/app.js':
            content_type, body = 'application/javascript', b'fetch("/openapi.json");fetch("/api/ping");'
        elif self.path == '/openapi.json':
            content_type = 'application/json'
            body = json.dumps({'openapi': '3.0.0', 'servers': [{'url': '/v1'}], 'paths': {
                '/items': {'get': {}}, '/mutate': {'post': {}}, '/users/{id}': {'get': {}}}}).encode()
        elif self.path == '/foreign-spec':
            content_type = 'application/json'
            body = json.dumps({'openapi': '3.0.0', 'servers': [{'url': 'http://foreign.invalid'}],
                'paths': {'/never': {'get': {}}}}).encode()
        elif self.path == '/.env':
            content_type, body = 'text/plain', b'DB_HOST=local\nDB_PASSWORD=BODY_SECRET\n'
        elif self.path.startswith('/wsr-nonexistent-'):
            body = b'not found'
        else:
            if self.path not in ('/', '/app.js'):
                content_type, body = 'application/json', b'{}'
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Set-Cookie', 'session=HEADER_SECRET')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class SecurityRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://pinned.invalid:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        Fixture.hits.clear()

    def test_pinned_hostname_all_builtin_stages_never_resolve_again(self):
        with patch.object(socket, 'getaddrinfo', side_effect=AssertionError('second DNS lookup')):
            self.assertEqual(cli.probe(self.base, scan_ip='127.0.0.1')['status'], 200)
            state = crawler.crawl([self.base], 'pinned.invalid', self.root / 'crawl', threading.Event(),
                scan_ip='127.0.0.1', rate=1000)
            check = checks.run_checks([{'url': self.base + '/api/ping?id=1', 'parameter': 'id'}],
                'pinned.invalid', self.root / 'checks', threading.Event(), scan_ip='127.0.0.1', rate=1000)
            wordlist = self.root / 'paths.txt'
            wordlist.write_text('.env\n')
            files = checks.run_sensitive_files([self.base], 'pinned.invalid', wordlist, self.root / 'files',
                threading.Event(), scan_ip='127.0.0.1', rate=1000)
        self.assertEqual(state['status'], 'completed')
        self.assertEqual(check['status'], 'completed')
        self.assertEqual(files['checks'][0]['outcome'], 'candidate')
        self.assertTrue(all(host == f'pinned.invalid:{self.server.server_port}' for _, host, _ in Fixture.hits))
        for file in self.root.rglob('*'):
            if file.is_file():
                content = file.read_bytes()
                for secret in (b'FORM_SECRET', b'HEADER_SECRET', b'BODY_SECRET', b'LINK_SECRET'):
                    self.assertNotIn(secret, content, str(file))

    def test_raw_evidence_opt_in_preserves_body_and_original_digest(self):
        state = crawler.crawl([self.base + '/.env'], 'pinned.invalid', self.root, threading.Event(),
            scan_ip='127.0.0.1', retain_raw=True)
        page = state['pages'][0]
        body = (self.root / page['body_file']).read_bytes()
        self.assertIn(b'BODY_SECRET', body)
        self.assertEqual(page['response_sha256'], hashlib.sha256(body).hexdigest())

    def test_tls_sni_and_ipv6_numeric_socket_without_dns(self):
        sock, context = MagicMock(), MagicMock()
        with patch.object(socket, 'socket', return_value=sock), patch.object(socket, 'getaddrinfo', side_effect=AssertionError()), \
             patch.object(transport.ssl, 'create_default_context', return_value=context):
            conn = transport.connection('https://pinned.invalid:443/', scan_ip='::1')
            conn.connect()
        sock.connect.assert_called_once_with(('::1', 443))
        context.wrap_socket.assert_called_once_with(sock, server_hostname='pinned.invalid')

    def test_sensitive_url_excludes_every_parameter(self):
        selected, excluded = crawler.select_candidates([self.base + '/?id=1&api_key=QUERY_SECRET'], 10)
        self.assertEqual(selected, [])
        self.assertEqual(len(excluded), 2)
        self.assertNotIn('QUERY_SECRET', evidence.dumps(excluded))

    def test_openapi_get_paths_js_routes_and_foreign_server_exclusion(self):
        state = crawler.crawl([self.base, self.base + '/foreign-spec'], 'pinned.invalid', self.root,
            threading.Event(), scan_ip='127.0.0.1', rate=1000)
        paths = {path for path, _, _ in Fixture.hits}
        self.assertTrue({'/api/ping', '/openapi.json', '/v1/items'} <= paths)
        self.assertNotIn('/v1/mutate', paths)
        self.assertFalse(any('{' in path or 'token=' in path for path in paths))
        self.assertTrue(any(r['kind'] == 'openapi-get' for r in state['routes']))
        self.assertTrue(any('foreign.invalid' in r['url'] for r in state['excluded']))

    def test_pipeline_paces_initial_probes_and_reports_without_optional_scanners(self):
        cli_platform(self)
        output = self.root / 'runs'
        with patch.object(scope, 'resolve_one', return_value='127.0.0.1'), \
             patch.object(cli, 'tool_paths', return_value={}), contextlib.redirect_stdout(io.StringIO()):
            code = cli.main([self.base, '--url', self.base + '/api/ping', '--skip', 'nmap',
                '--no-crawl', '--no-auto-sqli', '--rate', '10', '--delay', '.12', '--output', str(output)])
        self.assertEqual(code, 0)
        self.assertEqual(len(Fixture.hits), 2)
        self.assertGreaterEqual(Fixture.hits[1][2] - Fixture.hits[0][2], .10)
        document = json.loads(next(output.glob('*/summary.json')).read_text())
        self.assertEqual(len(document['findings']), 2)
        self.assertFalse(document['external_scanners']['enabled'])
        run = next(output.iterdir())
        if os.name == 'posix':
            self.assertEqual(run.stat().st_mode & 0o077, 0)

    def test_grouped_dirsearch_output_and_probe_inventory(self):
        (self.root / 'results.json').write_text(json.dumps({'results': {self.base + '/': [
            {'path': '/api/ping', 'status': 200}]}}))
        summary = {'target': 'pinned.invalid', 'probes': [{'url': self.base, 'status': 403}], 'jobs': [
            {'name': 'dirsearch', 'tool': 'dirsearch', 'status': 'completed', 'folder': str(self.root),
             'argv': ['dirsearch', '-u', self.base], 'outputs': ['results.json']}]}
        result, gaps = findings.collect(self.root, summary)
        self.assertEqual(gaps, [])
        self.assertEqual({r['check'] for r in result}, {'200', '403'})

    def test_rejected_url_credentials_and_fragments_are_not_persisted(self):
        body = b'<a href="http://alice:PASSWORD_SECRET@foreign.invalid/#access_token=FRAGMENT_SECRET">x</a>'
        with patch.object(crawler, 'fetch', return_value={'status': 200, 'headers': [['Content-Type', 'text/html']],
                'body': body, 'truncated': False}):
            crawler.crawl([self.base], 'pinned.invalid', self.root, threading.Event(), scan_ip='127.0.0.1')
        content = (self.root / 'crawl.json').read_text()
        self.assertNotIn('PASSWORD_SECRET', content)
        self.assertNotIn('FRAGMENT_SECRET', content)

    def test_retry_after_prevents_new_requests_beyond_stage_budget(self):
        gate = scope.RequestGate(rate=1000)
        gate.observe({'status': 429, 'headers': [['Retry-After', '10']]})
        with self.assertRaises(TimeoutError):
            gate.wait(threading.Event(), time.monotonic() + .05)
        gate = scope.RequestGate(rate=1000)
        gate.observe({'status': 503, 'retry_after': 'invalid'})
        gate.wait(threading.Event(), time.monotonic() + 1)

    def test_retry_after_updates_a_worker_already_waiting(self):
        gate = scope.RequestGate(rate=5)
        stop = threading.Event()
        gate.wait(stop, time.monotonic() + 1)
        errors = []
        def worker():
            try:
                gate.wait(stop, time.monotonic() + 1)
            except TimeoutError:
                errors.append('throttled')
        thread = threading.Thread(target=worker)
        thread.start()
        gate.observe({'status': 429, 'retry_after': '30'})
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, ['throttled'])

    def test_probe_backoff_is_a_reported_gap_without_cli_traceback(self):
        cli_platform(self)
        with patch.object(scope, 'resolve_one', return_value='127.0.0.1'), \
             patch.object(cli, 'probe', return_value={'url': self.base, 'status': 429, 'title': '', 'retry_after': '30'}), \
             patch.object(cli, 'tool_paths', return_value={}), contextlib.redirect_stdout(io.StringIO()):
            code = cli.main([self.base, '--url', self.base + '/api/ping', '--skip', 'nmap',
                '--no-crawl', '--output', str(self.root / 'runs')])
        self.assertEqual(code, 2)
        doc = json.loads(next((self.root / 'runs').glob('*/summary.json')).read_text())
        self.assertTrue(any('budget' in p.get('error', '') for p in doc['probes']))

    def test_complete_local_cli_exports_safe_nonempty_results(self):
        cli_platform(self)
        wordlist = self.root / 'paths.txt'
        wordlist.write_text('.env\n')
        destination = self.root / 'assessment.json'
        with patch.object(scope, 'resolve_one', return_value='127.0.0.1') as resolve, \
             patch.object(socket, 'getaddrinfo', side_effect=AssertionError('unpinned lookup')), \
             patch.object(cli, 'tool_paths', return_value={}), contextlib.redirect_stdout(io.StringIO()):
            code = cli.main([self.base, '--skip', 'nmap', '--sensitive-files', '--wordlist', str(wordlist),
                '--rate', '50', '--output', str(destination)])
        self.assertEqual(code, 0)
        resolve.assert_called_once_with('pinned.invalid')
        document = json.loads(destination.read_text())
        self.assertTrue(any(f['check'] == 'sensitive-file:' for f in document['findings']))
        self.assertTrue(any(f['url'].endswith('/v1/items') for f in document['findings']))
        self.assertEqual(document['crawl']['status'], 'completed')
        for file in self.root.rglob('*'):
            if file.is_file():
                for secret in (b'FORM_SECRET', b'HEADER_SECRET', b'BODY_SECRET', b'LINK_SECRET'):
                    self.assertNotIn(secret, file.read_bytes(), str(file))

    def test_external_scanners_deferred_for_hostname(self):
        cli_platform(self)
        with patch.object(scope, 'resolve_one', return_value='127.0.0.1'), \
             patch.object(cli, 'tool_paths', return_value={'httpx': '/bin/false'}), \
             patch.object(cli.subprocess, 'Popen', side_effect=AssertionError('external scanner')), \
             contextlib.redirect_stdout(io.StringIO()):
            code = cli.main([self.base, '--external-tools', '--retain-raw-evidence', '--no-crawl',
                '--skip', 'nmap', '--output', str(self.root / 'runs')])
        self.assertEqual(code, 2)
        document = json.loads(next((self.root / 'runs').glob('*/summary.json')).read_text())
        self.assertTrue(all(j['status'] == 'skipped' for j in document['jobs'] if j['tool'] != 'network'))
        self.assertEqual(document['network_assessment']['status'], 'completed')
        self.assertTrue(any('DNS pinning' in j['note'] for j in document['jobs']))


if __name__ == '__main__':
    unittest.main()
