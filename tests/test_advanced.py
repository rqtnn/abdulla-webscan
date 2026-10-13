"""WS-R failure handling and advanced checks against an isolated loopback lab."""
import base64
import contextlib
import hashlib
import http.server
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.parse

import advanced
import api_analyzer
import cli
import crawler
import checks
import jwt_analyzer
import reliability
from scope import RequestGate
from cli_fixture import cli_platform


def token(header, payload, signature=''):
    encode = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
    return encode(header) + '.' + encode(payload) + '.' + signature


class Lab(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append((self.path, self.headers.get('Cookie'), self.headers.get('Authorization')))
        path = urllib.parse.urlsplit(self.path).path
        if path == '/openapi.json':
            body = json.dumps({'openapi': '3.0.1', 'servers': [{'url': 'https://external.invalid'}],
                'paths': {'/admin/users': {'get': {}}, '/reset': {'post': {}},
                          '//external.invalid/route': {'get': {}}, '/objects/{id}': {'get': {}}}}).encode()
        elif path == '/protected':
            if self.server.enforce and self.headers.get('Cookie') != 'user=admin':
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b'forbidden')
                return
            body = b'protected laboratory record'
        elif path == '/token':
            body = token({'alg': 'none'}, {'sub': 'private-user', 'exp': 1}).encode()
        else:
            body = ('reflection:' + self.path).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class AdvancedTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.addCleanup(reliability.close)
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Lab)
        self.server.enforce, self.server.requests = False, []
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f'http://127.0.0.1:{self.server.server_port}'
        self.stop = threading.Event()

    def run_engine(self, **kwargs):
        return advanced.run([self.base], '127.0.0.1', self.root / 'advanced', self.stop,
            RequestGate(1000), budget=5, timeout=1, **kwargs)

    def contexts(self):
        (self.root / 'admin.cookie').write_text('user=admin')
        (self.root / 'guest.cookie').write_text('user=guest')
        path = self.root / 'contexts.json'
        path.write_text(json.dumps({'contexts': [
            {'name': 'admin', 'role': 'administrator', 'cookie_file': 'admin.cookie'},
            {'name': 'guest', 'role': 'user', 'cookie_file': 'guest.cookie'}],
            'policies': [{'url': '/protected', 'allow': ['admin']}]}))
        return advanced.load_contexts(path, self.base)

    def test_swagger_scoped_inventory_and_no_route_execution(self):
        state = self.run_engine(api=True, workers=3)
        doc = next(d for d in state['api'] if d['url'].endswith('/openapi.json'))
        self.assertEqual({r['url'] for r in doc['routes']}, {self.base + '/admin/users', self.base + '/objects/%7Bid%7D'})
        self.assertTrue(doc['routes'][0]['administrative_hint'])
        self.assertFalse(any('/admin/users' in path for path, _, _ in self.server.requests))
        self.assertEqual([c['severity'] for c in state['checks']], ['info'])

    def test_swagger_malformed_and_route_limit(self):
        for body in (b'{', b'null', b'[]', b'{"openapi":"3","paths":[]}', b'x' * 262145):
            self.assertEqual(api_analyzer.parse_document(body, self.base, '127.0.0.1', {advanced.origin(self.base)})['status'], 'inconclusive')
        body = json.dumps({'swagger': '2.0', 'paths': {f'/a{i}': {'get': {}, 'post': {}} for i in range(8)}}).encode()
        parsed = api_analyzer.parse_document(body, self.base, '127.0.0.1', {advanced.origin(self.base)}, limit=3)
        self.assertEqual(len(parsed['routes']), 3)
        self.assertEqual(parsed['status'], 'limited')

    def test_jwt_malformed_input_never_raises(self):
        for value in (None, 0, '', 'a.b.c', 'e30.W10.', 'x' * 9000,
                      token({'alg': None}, {}), token({'alg': 'HS256'}, {}, '!'),
                      token({'alg': 'none'}, []) ):
            self.assertEqual(jwt_analyzer.analyze(value)['status'], 'malformed')

    def test_jwt_unsigned_redacted_and_unverified(self):
        value = token({'alg': 'none'}, {'sub': 'secret-person', 'exp': 1})
        result = jwt_analyzer.analyze(value, now=2)
        self.assertFalse(result['signature_verified'])
        self.assertIn('unsigned_token_candidate; server acceptance untested', result['issues'])
        self.assertNotIn('secret-person', json.dumps(result))
        self.assertNotIn(value, json.dumps(result))
        self.assertEqual(result['sha256'], hashlib.sha256(value.encode()).hexdigest())
        self.assertEqual(len(jwt_analyzer.discover(value + ' ' + value)), 1)

    def test_jwt_claim_types_are_reported_without_failure(self):
        row = jwt_analyzer.analyze(token({'alg': 'HS256'}, {'exp': 'forever', 'iat': True}, 'YWJj'))
        self.assertEqual(row['status'], 'inspected')
        self.assertIn('invalid_exp_type', row['issues'])
        self.assertIn('invalid_iat_type', row['issues'])

    def test_idor_numeric_and_explicit_string_variants(self):
        self.assertEqual(advanced.idor_variants(self.base + '/?id=0'), [self.base + '/?id=1'])
        self.assertEqual(advanced.idor_variants(self.base + '/?id=abc'), [])
        self.assertEqual(advanced.idor_variants(self.base + '/'), [])
        self.assertEqual(advanced.idor_variants(self.base + '/?id=abc', ['xyz']), [self.base + '/?id=xyz'])
        self.assertEqual(advanced.idor_variants(self.base + '/?password=1'), [])

    def test_idor_inventory_is_not_claimed_as_a_vulnerability(self):
        state = self.run_engine(idor=True, candidates=[self.base + '/?id=1'])
        self.assertEqual(state['checks'], [])
        self.assertEqual(len(state['matrix']), 2)
        self.assertTrue(all('not proof' in row['note'] for row in state['matrix']))

    def test_rbac_declared_policy_mismatch_with_observed_proof(self):
        contexts, policies = self.contexts()
        state = self.run_engine(contexts=contexts, policies=policies)
        finding = state['checks'][0]
        self.assertEqual(finding['check'], 'access-control')
        self.assertEqual(len(finding['responses']), 4)
        self.assertTrue(all(row['request']['status'] == 'captured' for row in finding['responses']))
        self.assertEqual({cookie for _, cookie, _ in self.server.requests}, {'user=admin', 'user=guest'})
        saved = (self.root / 'advanced/results.json').read_text()
        self.assertNotIn('user=admin', saved)
        rows = advanced.findings(self.root, {'target': '127.0.0.1'})
        self.assertEqual(rows[0]['validation_status'], 'needs_validation')
        self.assertEqual(len(rows[0]['evidence'][0]['poc']), 4)

    def test_enforced_rbac_and_missing_policy_produce_no_match(self):
        self.server.enforce = True
        contexts, policies = self.contexts()
        self.assertEqual(self.run_engine(contexts=contexts, policies=policies)['checks'], [])
        self.assertEqual(self.run_engine(contexts=contexts)['checks'], [])

    def test_context_config_rejects_out_of_scope_and_invalid_shape(self):
        path = self.root / 'bad.json'
        for doc in ([], {}, {'contexts': [{}]}, {'contexts': [{'name': 'a', 'role': 'a'}, {'name': 'a', 'role': 'b'}]}):
            path.write_text(json.dumps(doc))
            with self.assertRaises(ValueError):
                advanced.load_contexts(path, self.base)
        contexts, _ = self.contexts()
        self.assertEqual(contexts[0].headers_for('http://external.invalid'), {})

    def test_ssrf_reflection_alone_does_not_confirm_fetch(self):
        state = self.run_engine(ssrf_canary='http://canary.invalid/wsr-test',
                                candidates=[self.base + '/?url=http://example.invalid'])
        self.assertEqual(state['checks'], [])
        self.assertEqual(len(state['matrix']), 1)
        self.assertIn('Unconfirmed', state['matrix'][0]['note'])

    def test_metadata_probe_is_root_only_and_never_direct(self):
        state = self.run_engine(metadata=True, candidates=[self.base + '/?url=test'])
        self.assertEqual(state['checks'], [])
        injected = urllib.parse.parse_qs(urllib.parse.urlsplit(self.server.requests[-1][0]).query)['url'][0]
        self.assertEqual(injected, 'http://169.254.169.254/')
        self.assertNotIn('credentials', injected)

    def test_client_scope_rejects_without_network_and_limits_requests(self):
        client = advanced.Client('127.0.0.1', [self.base], RequestGate(1000), self.stop, self.root, max_requests=1)
        before = len(self.server.requests)
        self.assertIn('error', client.get('http://external.invalid/')[0])
        self.assertEqual(len(self.server.requests), before)
        self.assertEqual(client.get(self.base)[0]['status'], 200)
        self.assertIn('error', client.get(self.base)[0])

    def test_unexpected_http_failure_is_structured_and_logged_without_secrets(self):
        reliability.configure(self.root / 'ws-r.log')
        with patch.object(crawler, 'fetch', side_effect=RuntimeError('Cookie: private-credential')):
            result = self.run_engine(api=True)
        self.assertEqual(result['status'], 'incomplete')
        log = (self.root / 'ws-r.log').read_text()
        self.assertIn('RuntimeError', log)
        self.assertNotIn('private-credential', log)

    def test_report_load_malformed_is_graceful(self):
        folder = self.root / 'advanced'
        folder.mkdir()
        (folder / 'results.json').write_text('null')
        self.assertEqual(advanced.findings(self.root, {'target': '127.0.0.1'}), [])

    def test_cli_boundary_catches_unexpected_failure_without_traceback(self):
        with patch.object(cli, '_main', side_effect=RuntimeError('secret')), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main([]), 2)
        self.assertNotIn('Traceback', output.getvalue())
        self.assertNotIn('secret', output.getvalue())

    def test_subprocess_setup_permission_error_is_failed_record(self):
        job = cli.Job('Nmap', 'nmap', ['nmap', '127.0.0.1'], self.root / 'nmap', 1, ['services.xml'])
        with patch.object(Path, 'mkdir', side_effect=PermissionError('private')):
            result = cli.Runner().execute(job)
        self.assertEqual(result['status'], 'failed')
        self.assertNotIn('private', result['note'])

    def test_failed_log_setup_does_not_crash(self):
        with patch.object(Path, 'mkdir', side_effect=PermissionError()):
            self.assertFalse(reliability.configure(self.root / 'log'))

    def test_helper_shell_quoting_and_secret_redaction(self):
        helper = advanced.curl_helper(self.base + '/?id=1&token=secret')
        self.assertNotIn('secret', helper)
        self.assertNotIn('--location', helper)
        self.assertIn('-- ', helper)

    def test_final_report_failure_writes_recovery_and_returns_error(self):
        cli_platform(self)
        with patch.object(cli, 'write_reports', side_effect=RuntimeError()), contextlib.redirect_stdout(io.StringIO()):
            code = cli.main([self.base, '--dry-run', '--skip', 'nmap', '--no-crawl', '--output', str(self.root / 'run')])
        self.assertEqual(code, 2)
        self.assertEqual(len(list((self.root / 'run').rglob('recovery.json'))), 1)

    def test_crawler_captures_jwt_without_retaining_token(self):
        result = crawler.crawl([self.base + '/token'], '127.0.0.1', self.root / 'crawl', self.stop,
            max_pages=1, rate=1000, api_paths=False, request_timeout=1)
        self.assertIn('unsigned_token', result['pages'][0]['jwt'][0]['issues'][0])
        self.assertNotIn('private-user', (self.root / 'crawl/crawl.json').read_text())

    def test_cli_api_pipeline_exports_one_banner_and_report_inventory(self):
        cli_platform(self)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = cli.main([self.base, '--assessment', 'web', '--skip', 'nmap',
                '--no-crawl', '--no-auto-sqli', '--api-discovery', '--rate', '50',
                '--output', str(self.root / 'report.html'), '--log-file', str(self.root / 'run.log')])
        self.assertEqual(code, 0, output.getvalue())
        self.assertEqual(output.getvalue().count('WS-R'), 1)
        self.assertIn('Advanced API and context inventory', (self.root / 'report.html').read_text())
        summary = json.loads(next((self.root / 'report.evidence').rglob('summary.json')).read_text())
        self.assertEqual(summary['advanced']['status'], 'completed')
        self.assertEqual(summary['coverage']['api_routes'], 2)
        self.assertTrue(any(f['check'] == 'api-document' for f in summary['findings']))

    def test_advanced_jwt_structure_candidates_have_fingerprinted_proof(self):
        observation = jwt_analyzer.analyze(token({'alg': 'none'}, {'sub': 'private'}))
        result = self.run_engine(jwt_observations=[observation])
        self.assertEqual(result['checks'][0]['check'], 'jwt-unsigned')
        findings = advanced.findings(self.root, {'target': '127.0.0.1'})
        self.assertEqual(findings[0]['evidence'][0]['poc'][0]['kind'], 'jwt_structure')

    def test_crawler_unexpected_worker_error_is_incomplete(self):
        with patch.object(crawler, 'fetch', side_effect=RuntimeError('hidden credential')):
            result = crawler.crawl([self.base], '127.0.0.1', self.root / 'crawl', self.stop,
                max_pages=1, rate=1000, api_paths=False)
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(result['pages'][0]['error'], 'RuntimeError')
