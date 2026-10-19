import contextlib
import http.server
import io
import json
from pathlib import Path
import ssl
import tempfile
import threading
import unittest
from unittest.mock import patch

import cli
import crawler
import nmap_scan
import scan_diagnostics


class Handler(http.server.BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        self.hits.append(self.path)
        self.send_response(301 if self.path == '/directory' else 200)
        if self.path == '/directory':
            self.send_header('Location', '/directory/')
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<a href="/search?q=example">Search</a>' if self.path == '/directory/' else b'<html>Local fixture</html>')

    def log_message(self, *args):
        pass


class DiscoveryDiagnostics(unittest.TestCase):
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
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        Handler.hits.clear()

    def test_http_success_suppresses_only_derived_opposite_protocol(self):
        probes = [dict(url=self.base + '/', status=200)]
        opposite = self.base.replace('http:', 'https:') + '/'
        self.assertTrue(scan_diagnostics.redundant_alternative(opposite, [], probes))
        self.assertFalse(scan_diagnostics.redundant_alternative(opposite, [opposite], probes))
        self.assertFalse(scan_diagnostics.redundant_alternative('https://127.0.0.1:1/', [], probes))
        # TLS listeners can answer plain HTTP with a protocol/upgrade error.
        for status in (400, 426):
            self.assertFalse(scan_diagnostics.redundant_alternative(opposite, [],
                [dict(url=self.base + '/', status=status)]))

    def test_handshake_failure_allows_fallback_but_certificate_failure_does_not(self):
        secure = self.base.replace('http:', 'https:') + '/'
        for kind, expected in [('tls_protocol', False), ('timeout', False), ('tls_certificate', True)]:
            self.assertEqual(scan_diagnostics.redundant_alternative(self.base + '/', [],
                [dict(url=secure, error_kind=kind)]), expected)

    def test_probe_classifies_tls_failure_without_disabling_verification(self):
        with patch.object(cli, 'connection', side_effect=ssl.SSLCertVerificationError(1, 'certificate verify failed')) as connect:
            result = cli.probe('https://127.0.0.1/', scan_ip='127.0.0.1')
        self.assertEqual(result['error_kind'], 'tls_certificate')
        self.assertEqual(connect.call_count, 1)
        self.assertFalse(connect.call_args.args[1])

    def test_default_cli_follows_same_origin_redirect_and_discovers_input(self):
        with contextlib.redirect_stdout(io.StringIO()):
            code = cli.main([self.base + '/directory', '--only', 'checks', '--rate', '50',
                '--no-web-metadata', '--crawl-pages', '10', '--output', str(self.root)])
        summary = json.loads(next(self.root.glob('*/summary.json')).read_text())
        self.assertEqual(code, 0)
        self.assertIn('/directory/', Handler.hits)
        self.assertEqual(summary['injection']['selected'][0]['parameter'], 'q')
        self.assertNotEqual(summary['active_checks']['status'], 'no_candidates')
        self.assertTrue(any(p.get('redirect', {}).get('decision') == 'queued' for p in summary['crawl']['pages']))

    def test_redirect_opt_out_leaves_actionable_no_candidate_diagnostics(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            cli.main([self.base + '/directory', '--only', 'checks', '--no-crawl-redirects',
                '--no-web-metadata', '--rate', '50', '--output', str(self.root)])
        summary = json.loads(next(self.root.glob('*/summary.json')).read_text())
        self.assertNotIn('/directory/', Handler.hits)
        codes = {r['code'] for r in summary['diagnostics']}
        self.assertTrue({'redirect_not_crawled', 'no_get_parameters'} <= codes)
        self.assertIn('[COVERAGE] no_get_parameters', output.getvalue())
        self.assertIn('Coverage diagnostics', next(self.root.glob('*/report.html')).read_text())

    def test_no_https_request_after_successful_http_discovery(self):
        port = self.server.server_port
        def execute(runner, job):
            self.assertEqual(job.tool, 'nmap')
            return dict(name=job.name, tool='nmap', folder=str(job.folder), argv=job.argv,
                        command='fixture', outputs=[], status='completed', elapsed=0, note='')
        with patch.object(cli.Runner, 'execute', execute), \
             patch.object(nmap_scan, 'inventory', return_value=([dict(port=port, service='http')],
                 dict(status='completed', note='fixture'))), \
             patch.object(cli, 'probe', wraps=cli.probe) as probe, contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(['127.0.0.1', '--only', 'nmap', 'crawl', '--ports', str(port),
                '--rate', '50', '--no-web-metadata', '--output', str(self.root)])
        self.assertEqual(code, 0)
        self.assertEqual(probe.call_count, 1)
        self.assertTrue(probe.call_args.args[0].startswith('http:'))
        summary = json.loads(next(self.root.glob('*/summary.json')).read_text())
        self.assertEqual(len(summary['probe_skips']), 1)

    def test_redirect_does_not_cross_origin_even_if_both_are_seeds(self):
        bases = ['http://127.0.0.1:8001/', 'http://127.0.0.1:8002/']
        def fetch(url, *args, **kwargs):
            return dict(status=302 if url == bases[0] else 200, body=b'',
                        headers=[['Location', bases[1] + 'private']])
        with patch.object(crawler, 'fetch', side_effect=fetch) as request:
            result = crawler.crawl(bases, '127.0.0.1', self.root, threading.Event(),
                                   scan_ip='127.0.0.1', rate=100, follow_redirects=True)
        self.assertEqual(request.call_count, 2)
        self.assertEqual(result['pages'][0]['redirect']['decision'], 'excluded')

    def test_tls_redirect_and_external_tools_coverage_survive_offline_rebuild(self):
        summary = dict(target='127.0.0.1', created='fixture', mode='sequential', outcome='fixture', probes=[
            dict(url='http://127.0.0.1/', status=301, location='https://127.0.0.1/'),
            dict(url='https://127.0.0.1/', error_kind='tls_certificate')], jobs=[], ports=[],
            active_checks=dict(status='no_candidates'), external_scanners=dict(enabled=False))
        cli.write_reports(self.root, summary)
        rebuilt = json.loads((self.root / 'summary.json').read_text())
        self.assertEqual({r['code'] for r in rebuilt['diagnostics']},
                         {'tls_certificate', 'redirect_not_crawled', 'no_get_parameters', 'external_disabled'})
        cli.write_reports(self.root, rebuilt)
        self.assertEqual(rebuilt['diagnostics'], summary['diagnostics'])


if __name__ == '__main__':
    unittest.main()
