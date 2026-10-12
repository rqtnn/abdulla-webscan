"""Rqtn Tool concurrency, detection, presentation and export regression tests."""
import contextlib
import hashlib
import html
import http.server
import io
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
import urllib.parse
from unittest.mock import patch

import checks
import crawler
import findings
import scope
import terminal
import webscan


class Handler(http.server.BaseHTTPRequestHandler):
    active = maximum = 0
    lock = threading.Lock()

    def do_GET(self):
        with self.lock:
            type(self).active += 1
            type(self).maximum = max(type(self).maximum, type(self).active)
        try:
            u = urllib.parse.urlsplit(self.path)
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            if u.path.startswith('/slow'):
                time.sleep(.08)
            if u.path in ('/sql', '/broken'):
                value = urllib.parse.parse_qs(u.query).get('id', [''])[0]
                body = b'You have an error in your SQL syntax' if "'" in value or u.path == '/broken' else b'normal'
            elif u.path == '/.env':
                body = b'DB_HOST=localhost\nDB_NAME=lab\n'
            elif u.path == '/config.php.bak':
                body = b'<?php $db = "lab";'
            elif u.path == '/backup.zip':
                body = b'PK\x03\x04example'
            else:
                body = b'<html>generic fallback</html>'
            self.wfile.write(body)
        finally:
            with self.lock:
                type(self).active -= 1

    def log_message(self, *args):
        pass


class RqtnTests(unittest.TestCase):
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
        self.root = Path(self.temp.name)
        Handler.maximum = 0

    def test_crawler_has_bounded_parallelism_and_unique_body_evidence(self):
        result = crawler.crawl([self.base + f'/slow/{i}' for i in range(6)], '127.0.0.1',
            self.root / 'crawl', threading.Event(), workers=3, rate=1000)
        self.assertGreaterEqual(Handler.maximum, 2)
        self.assertLessEqual(Handler.maximum, 3)
        names = [page['body_file'] for page in result['pages']]
        self.assertEqual(len(set(names)), 6)
        for page in result['pages']:
            self.assertEqual(hashlib.sha256((self.root / 'crawl' / page['body_file']).read_bytes()).hexdigest(), page['body_sha256'])

    def test_checks_have_bounded_parallelism(self):
        checks.run_checks([dict(url=self.base + f'/slow/{i}?id=1', parameter='id') for i in range(6)],
            '127.0.0.1', self.root / 'checks', threading.Event(), workers=3, rate=1000)
        self.assertGreaterEqual(Handler.maximum, 2)
        self.assertLessEqual(Handler.maximum, 3)

    def test_shared_delay_spaces_request_starts_and_can_be_cancelled(self):
        starts, stop = [], threading.Event()
        gate = scope.RequestGate(rate=1000, delay=.035)

        def fetch(*args, **kwargs):
            starts.append(time.monotonic())
            time.sleep(.06)
            return dict(status=200, headers=[], body=b'ok', truncated=False)

        with patch.object(crawler, 'fetch', side_effect=fetch):
            crawler.crawl([self.base + f'/a{i}' for i in range(4)], '127.0.0.1', self.root / 'crawl',
                stop, workers=4, gate=gate)
        self.assertTrue(all(b - a >= .025 for a, b in zip(starts, starts[1:])))
        stop.set()
        with self.assertRaises(InterruptedError):
            gate.wait(stop, time.monotonic() + 10)

    def test_new_sql_error_is_candidate_but_broken_baseline_is_not(self):
        for endpoint, expected in (('sql', True), ('broken', False)):
            result = checks.run_checks([dict(url=self.base + f'/{endpoint}?id=1', parameter='id')],
                '127.0.0.1', self.root / endpoint, threading.Event(), rate=1000, sqli=True)
            matches = result['checks'][0].get('matches', [])
            self.assertEqual(any(m['check'] == 'sql-error' for m in matches), expected)
            self.assertEqual(result['requests'], 3)
            if expected:
                row = result['checks'][0]
                self.assertEqual(row['matches'][0]['dbms_signatures'], ['mysql'])
                self.assertEqual(len(row['responses']), 3)

    def test_opt_in_time_check_repeats_control_probe_pairs(self):
        def fetch(url, *args, **kwargs):
            if 'SLEEP' in urllib.parse.unquote(url):
                time.sleep(1)
            return dict(status=200, headers=[], body=b'stable', truncated=False)

        with patch.object(checks, 'fetch', side_effect=fetch):
            result = checks.run_checks([dict(url=self.base + '/sql?id=1', parameter='id')],
                '127.0.0.1', self.root / 'timing', threading.Event(), rate=1000, workers=4, time_sqli=True)
        self.assertEqual(result['requests'], 6)
        record = result['checks'][0]
        self.assertEqual(len(record['timing_samples']), 2)
        self.assertEqual(record['matches'][0]['check'], 'sql-timing-anomaly')

    def test_sensitive_files_require_content_signature_not_status_200(self):
        words = self.root / 'words.txt'
        words.write_text('.env\nbackup.zip\nconfig.php.bak\nmissing.sql\nhttp://127.0.0.2/foreign\nreset\n')
        result = checks.run_sensitive_files([self.base + '/'], '127.0.0.1', words,
            self.root / 'files', threading.Event(), workers=3, rate=1000)
        candidates = [row for row in result['checks'] if row['outcome'] == 'candidate']
        self.assertEqual(len(candidates), 3)
        self.assertEqual(result['requests'], 5)  # one soft-404 control and four scoped file requests
        self.assertEqual(sum(row['outcome'] == 'excluded' for row in result['checks']), 2)
        self.assertTrue(all(row['control_response']['body_sha256'] for row in candidates))

    def test_sensitive_file_limit_and_truncated_response_are_visible(self):
        words = self.root / 'words.txt'
        words.write_text('.env\nbackup.zip\n')
        with patch.object(checks, 'fetch', return_value=dict(status=200, headers=[], body=b'DB_NAME=a\nDB_HOST=b', truncated=True)):
            result = checks.run_sensitive_files([self.base + '/'], '127.0.0.1', words,
                self.root / 'files', threading.Event(), limit=1, rate=1000)
        self.assertIn('file_limit', result['limits'])
        self.assertEqual(result['checks'][0]['outcome'], 'inconclusive')

    def test_headers_handle_https_and_csp_framing_alternative(self):
        row = dict(url='https://127.0.0.1/', status=200, headers=[['Content-Type', 'text/html']])
        results = list(findings.observations('crawler', row, row['url']))
        names = {result[1] for result in results if result[0] == 'configuration'}
        self.assertEqual(names, {'content-security-policy', 'x-frame-options', 'x-content-type-options', 'strict-transport-security'})
        row['headers'].append(['Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'"])
        names = {result[1] for result in findings.observations('crawler', row, row['url'])}
        self.assertNotIn('x-frame-options', names)
        row['url'] = 'http://127.0.0.1/'
        self.assertNotIn('strict-transport-security', {r[1] for r in findings.observations('crawler', row, row['url'])})

    def test_get_post_form_inventory_masks_password_control(self):
        parser = crawler.Links()
        parser.feed('<form method="POST" action="/login"><input name="user"><input name="password" type="password" value="secret"><textarea name="body"></textarea></form>')
        form = parser.forms[0]
        self.assertEqual(form['method'], 'post')
        self.assertEqual(form['controls'][1]['value'], '[redacted]')
        self.assertTrue(form['excluded_inputs'])

    def test_js_absolute_and_bare_relative_literals_are_discovered_but_scoped(self):
        links = crawler.route_literals('fetch("api/items"); const a="https://foreign.example/api"; const text="hello world";')
        self.assertEqual(links, ['api/items', 'https://foreign.example/api'])
        with self.assertRaises(ValueError):
            scope.scoped_link(links[1], self.base, '127.0.0.1', {scope.origin(self.base)})

    def test_sensitive_checks_run_without_crawl_and_adapter_keeps_multiple_matches(self):
        args = webscan.parser().parse_args(['127.0.0.1', '--no-crawl', '--sensitive-files', '--rate', '50'])
        args.wordlist = self.root / 'words.txt'
        args.wordlist.write_text('.env\n')
        summary = dict(target='127.0.0.1', jobs=[])
        with contextlib.redirect_stdout(io.StringIO()):
            webscan.run_discovered(args, self.root, [self.base + '/'], summary, webscan.Runner(), {})
        self.assertEqual(summary['crawl']['status'], 'disabled')
        self.assertEqual(summary['sensitive_files']['requests'], 2)
        observed, issues = findings.collect(self.root, summary)
        self.assertEqual(issues, [])
        self.assertEqual(observed[0]['check'], 'sensitive-file:')
        self.assertEqual(observed[0]['validation_status'], 'needs_validation')
        row = dict(url=self.base + '/x?id=1', parameter='id', outcome='candidate', matches=[
            dict(check='unescaped-reflection', severity='low', title='reflection'),
            dict(check='sql-error', severity='medium', title='SQL')])
        self.assertEqual(len(list(findings.observations('checks', row, row['url']))), 2)

    def test_unstable_timing_controls_do_not_produce_sql_candidate(self):
        values = iter((b'baseline', b'normal', b'changed', b'normal', b'changed', b'normal'))

        def fetch(url, *args, **kwargs):
            return dict(status=200, headers=[], body=next(values), truncated=False)

        with patch.object(checks, 'fetch', side_effect=fetch):
            result = checks.run_checks([dict(url=self.base + '/sql?id=1', parameter='id')],
                '127.0.0.1', self.root / 'timing', threading.Event(), rate=1000, time_sqli=True)
        self.assertEqual(result['checks'][0]['outcome'], 'inconclusive')
        self.assertNotIn('matches', result['checks'][0])

    def test_protocol_inference_and_argument_validation(self):
        self.assertEqual(scope.parse_target('127.0.0.1:3000/api').url, 'http://127.0.0.1:3000/api')
        self.assertEqual(scope.parse_target('127.0.0.1').url, '')
        self.assertEqual(webscan.parser().parse_args(['--target', 'localhost:3000', '--delay', '.2']).target_option,
                         'http://localhost:3000/')
        for value in ('nan', 'inf', '-.1'):
            with self.assertRaises(Exception):
                webscan.nonnegative(value)

    def test_exports_keep_evidence_links_and_escape_markup(self):
        evidence = self.root / 'evidence'
        evidence.mkdir()
        (evidence / 'summary.json').write_text('{"findings": []}')
        (evidence / 'report.html').write_text('<h1>Rqtn Tool</h1><a href="crawl/crawl.json">Evidence</a>')
        webscan.export_reports(evidence, self.root / 'report.html')
        self.assertIn('href="evidence/crawl/crawl.json"', (self.root / 'report.html').read_text())
        webscan.export_reports(evidence, self.root / 'report.json')
        self.assertEqual(json.loads((self.root / 'report.json').read_text())['evidence_directory'], 'evidence')
        with self.assertRaises(ValueError):
            webscan.export_reports(evidence, self.root / 'report.txt')

    def test_cli_builtin_scan_exports_json_with_real_local_evidence(self):
        # Only the Linux CLI guard is adapted; no subprocess behavior is emulated here.
        class PosixGuard:
            name = 'posix'

            def __getattr__(self, name):
                return getattr(real_os, name)

        real_os = webscan.os
        target = self.root / 'report.json'
        with patch.object(webscan, 'os', PosixGuard()), contextlib.redirect_stdout(io.StringIO()):
            result = webscan.main([self.base + '/sql?id=1', '--enum', 'none', '--skip',
                *webscan.ALL_TOOLS, '--builtin-sqli', '--active-checks', '--rate', '50',
                '--no-banner', '--ui', 'plain', '--output', str(target)])
        self.assertEqual(result, 0)
        document = json.loads(target.read_text())
        self.assertEqual(document['version'], webscan.VERSION)
        self.assertEqual(document['coverage']['active_checks_requests'], 3)
        self.assertTrue(any(finding['check'] == 'sql-error:id' for finding in document['findings']))
        evidence = target.parent / document['evidence_directory']
        self.assertTrue((evidence / 'report.html').is_file())
        for finding in document['findings']:
            self.assertEqual(finding['validation_status'], 'needs_validation')
            self.assertTrue(all((evidence / item['file']).is_file() for item in finding['evidence']))

    def test_plain_ui_has_brand_and_severity_groups(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            ui = terminal.TerminalUI('plain')
            ui.message(terminal.BANNER)
            ui.severity_table({'high': 2})
        self.assertIn('RQTN TOOL', output.getvalue())
        self.assertIn('high=2', output.getvalue())

    @unittest.skipUnless(importlib.util.find_spec('rich'), 'Optional Rich dependency not installed')
    def test_rich_ui_progress_and_table_render_without_interpreting_target_markup(self):
        from rich.console import Console
        output = io.StringIO()
        ui = terminal.TerminalUI('rich')
        ui.console = Console(file=output, force_terminal=False, width=90)
        ui.message('[bold]untrusted target[/bold]')
        with ui.stage('HTTP checks') as progress:
            progress(1, 2)
            progress(2, 2)
        ui.severity_table({'critical': 1, 'low': 2})
        self.assertIn('[bold]untrusted target[/bold]', output.getvalue())
        self.assertIn('Critical', output.getvalue())
        self.assertIn('Rqtn Tool', output.getvalue())

    def test_rich_absence_falls_back_to_plain(self):
        import builtins
        original = builtins.__import__

        def no_rich(name, *args, **kwargs):
            if name.startswith('rich'):
                raise ImportError('fixture')
            return original(name, *args, **kwargs)

        with patch('builtins.__import__', side_effect=no_rich), contextlib.redirect_stdout(io.StringIO()) as output:
            ui = terminal.TerminalUI('rich')
            ui.message('Rqtn Tool')
        self.assertIsNone(ui.console)
        self.assertIn('Rqtn Tool', output.getvalue())
