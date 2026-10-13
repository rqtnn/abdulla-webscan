import hashlib
import contextlib
import io
import http.server
import html
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.parse

import checks
import crawler
import webscan


class Handler(http.server.BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        type(self).hits.append(self.path)
        u = urllib.parse.urlsplit(self.path)
        values = urllib.parse.parse_qs(u.query)
        value = values.get('q', values.get('redirect', ['']))[0]
        if u.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', value)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        if u.path == '/escaped':
            value = html.escape(value)
        self.wfile.write(('<html>' + value + '</html>').encode())

    def log_message(self, *args):
        pass


class DifferentialTests(unittest.TestCase):
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
        Handler.hits.clear()

    def run_checks(self, path, name='q', **kwargs):
        candidate = {'url': self.base + path, 'parameter': name}
        return checks.run_checks([candidate], '127.0.0.1', self.root / 'checks', threading.Event(), rate=50, **kwargs)

    def test_unescaped_reflection_keeps_control_probe_and_hashes(self):
        state = self.run_checks('/reflect?q=lab')
        record = state['checks'][0]
        self.assertEqual(record['outcome'], 'candidate')
        self.assertEqual(record['check'], 'unescaped-reflection')
        self.assertEqual(state['requests'], 2)
        self.assertNotIn('script', record['payload'])
        for response in record['responses']:
            body = (self.root / 'checks' / response['body_file']).read_bytes()
            self.assertEqual(response['body_sha256'], hashlib.sha256(body).hexdigest())
        summary = dict(target='127.0.0.1', jobs=[dict(name='check', tool='checks', argv=[],
            folder=str(self.root / 'checks'), status=state['status'], outputs=['checks.json'], elapsed=0, note='')],
            ports=[], probes=[], created='test', mode='sequential', outcome='test')
        webscan.write_reports(self.root, summary)
        self.assertEqual(len(summary['findings']), 1)
        self.assertEqual(summary['findings'][0]['validation_status'], 'needs_validation')
        self.assertEqual(summary['parse_issues'], [])

    def test_escaped_reflection_is_not_a_match(self):
        state = self.run_checks('/escaped?q=lab')
        self.assertEqual(state['checks'][0]['outcome'], 'no_match')

    def test_external_redirect_is_observed_without_following(self):
        state = self.run_checks('/redirect?redirect=/local', 'redirect')
        self.assertEqual(state['checks'][0]['check'], 'external-redirect')
        self.assertEqual(len(Handler.hits), 2)
        self.assertIn('rqtn.invalid', state['checks'][0]['payload'])

    def test_scope_rejection_happens_before_http(self):
        with patch.object(checks, 'fetch', side_effect=AssertionError('must not fetch')):
            state = checks.run_checks([dict(url='http://127.0.0.2/?q=x', parameter='q')],
                                     '127.0.0.1', self.root, threading.Event())
        self.assertEqual(state['status'], 'incomplete')
        self.assertEqual(state['requests'], 0)

    def test_errors_truncation_cancel_and_time_budget_are_visible(self):
        with patch.object(checks, 'fetch', side_effect=OSError('fixture network error')):
            state = self.run_checks('/reflect?q=lab')
        self.assertEqual(state['status'], 'incomplete')
        self.assertEqual(state['requests'], 1)
        response = dict(status=200, headers=[['Content-Type', 'text/html']], body=b'x', truncated=True)
        with patch.object(checks, 'fetch', side_effect=lambda *a, **kw: dict(response)):
            state = self.run_checks('/reflect?q=lab')
        self.assertEqual(state['checks'][0]['outcome'], 'inconclusive')
        state = self.run_checks('/reflect?q=lab', timeout=0)
        self.assertEqual(state['status'], 'limited')
        stop = threading.Event()
        stop.set()
        state = checks.run_checks([], '127.0.0.1', self.root, stop)
        self.assertEqual(state['status'], 'cancelled')

    def test_interrupt_preserves_partial_request_evidence(self):
        response = dict(status=200, headers=[], body=b'control', truncated=False)
        with patch.object(checks, 'fetch', side_effect=[response, KeyboardInterrupt]):
            with self.assertRaises(KeyboardInterrupt):
                self.run_checks('/reflect?q=lab')
        state = json.loads((self.root / 'checks/checks.json').read_text())
        self.assertEqual(state['status'], 'cancelled')
        self.assertEqual(len(state['checks'][0]['responses']), 1)

    def test_form_submit_and_blank_seed_keep_dispatch_and_provenance(self):
        parser = crawler.Links()
        parser.feed('<form><input name="id"><input type="submit" name="Submit" value="Submit"></form>')
        self.assertEqual(parser.forms[0]['submit'], ['Submit', 'Submit'])
        selected, excluded = crawler.select_candidates([self.base + '/sqli/?id=&Submit=Submit'], 10)
        self.assertEqual(excluded, [])
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]['parameter'], 'id')
        self.assertIn('id=1&Submit=Submit', selected[0]['url'])
        self.assertIn('id=&Submit=Submit', selected[0]['discovered_url'])

    def test_nonblank_candidate_wins_over_empty_placeholder(self):
        selected, _ = crawler.select_candidates([self.base + '/?id=', self.base + '/?id=5'], 10)
        self.assertEqual(selected[0]['url'], self.base + '/?id=5')

    def test_pipeline_runs_active_checks_independently_of_sqlmap(self):
        args = webscan.parser().parse_args(['127.0.0.1', '--active-checks', '--no-auto-sqli', '--rate', '50', '--skip', 'nuclei'])
        summary = dict(target='127.0.0.1', jobs=[])
        crawl_result = dict(status='completed', pages=[], forms=[], limits=[],
                            discovered=[self.base + '/reflect?q=lab'])
        def fake_crawl(*positional, **options):
            positional[2].mkdir(parents=True, exist_ok=True)
            positional[-1].update(crawl_result)
        with patch.object(webscan, 'crawl', side_effect=fake_crawl), contextlib.redirect_stdout(io.StringIO()):
            webscan.run_discovered(args, self.root, [self.base + '/'], summary, webscan.Runner(), {})
        self.assertEqual(summary['injection']['status'], 'disabled')
        self.assertEqual(summary['active_checks']['requests'], 2)
        self.assertEqual(summary['jobs'][-1]['tool'], 'checks')


if __name__ == '__main__':
    unittest.main()
