import contextlib
import http.server
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import crawler
import webscan


class LabHandler(http.server.BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        type(self).hits.append(self.path)
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', '/never')
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        if self.path == '/':
            self.wfile.write(b'''<a href="/product?id=1">product</a><a href="/product?id=2">variant</a>
            <a href="http://127.0.0.2/foreign">foreign</a><a href="http://127.0.0.1:1/foreign">port</a>
            <a href="/redirect">redirect</a><a href="/logout">logout</a><a href="/">cycle</a>
            <form action="/search"><input name="q" value="lab"><input type="submit"></form>
            <form method="post" action="/change"><input name="id" value="1"></form>''')
        else:
            self.wfile.write(b'<a href="/deep">deep</a>')

    def log_message(self, *args):
        pass


class CrawlerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), LabHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.server.server_port}/'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        LabHandler.hits.clear()

    def run_crawl(self, **kwargs):
        return crawler.crawl([self.base], '127.0.0.1', self.root / 'crawl', threading.Event(), rate=50, **kwargs)

    def test_local_crawl_query_scope_redirect_forms_and_evidence(self):
        result = self.run_crawl()
        self.assertIn('/product?id=1', LabHandler.hits)
        self.assertNotIn('/never', LabHandler.hits)
        self.assertNotIn('/logout', LabHandler.hits)
        self.assertNotIn('/search?q=lab', LabHandler.hits)
        self.assertNotIn('/change', LabHandler.hits)
        self.assertTrue(any('single-host' in e['reason'] for e in result['excluded']))
        self.assertTrue(any('responding origin' in e['reason'] for e in result['excluded']))
        selected, _ = crawler.select_candidates(result['discovered'], 10)
        self.assertEqual({s['parameter'] for s in selected}, {'id', 'q'})
        self.assertEqual(len(selected), 2)
        for page in result['pages']:
            self.assertTrue((self.root / 'crawl' / page['body_file']).exists())
        self.assertEqual(json.loads((self.root / 'crawl' / 'crawl.json').read_text()), result)

    def test_page_depth_and_time_limits_are_reported(self):
        result = self.run_crawl(max_pages=1)
        self.assertEqual(result['requests'], 1)
        self.assertIn('page_limit', result['limits'])
        result = self.run_crawl(depth=0)
        self.assertEqual(result['requests'], 1)
        self.assertIn('depth_limit', result['limits'])
        result = self.run_crawl(timeout=0)
        self.assertEqual(result['requests'], 0)
        self.assertIn('time_limit', result['limits'])

    def test_candidate_dedup_exclusions_and_job_cap(self):
        urls = [self.base + p for p in ('a?id=1', 'a?id=2', 'b?q=hello', 'c?token=x',
                'd?id=1&id=2', 'delete?id=1', 'e?other=x')]
        selected, excluded = crawler.select_candidates(urls, 2)
        self.assertEqual(len(selected), 2)
        reasons = {e['reason'] for e in excluded}
        self.assertIn('Repeated parameter name needs manual review', reasons)
        self.assertIn('Sensitive or unsupported parameter name', reasons)
        self.assertIn('Action-like URL needs manual review', reasons)
        self.assertIn('Automatic SQLi job limit reached', reasons)

    def test_stop_and_truncated_response_preserve_coverage(self):
        stop = threading.Event()
        stop.set()
        result = crawler.crawl([self.base], '127.0.0.1', self.root / 'cancelled', stop)
        self.assertEqual(result['status'], 'cancelled')
        self.assertEqual(result['requests'], 0)
        with patch.object(crawler, 'fetch', return_value={'status': 200, 'headers': [], 'body': b'x', 'truncated': True}):
            result = self.run_crawl()
        self.assertTrue(result['pages'][0]['truncated'])

    def test_offline_plan_and_disabled_crawl_do_not_fetch_or_spawn(self):
        for options in (['--dry-run'], ['--no-crawl']):
            args = webscan.parser().parse_args(['127.0.0.1', *options])
            summary = {'target': '127.0.0.1', 'jobs': []}
            with patch.object(crawler, 'fetch', side_effect=AssertionError('Unexpected fetch')):
                webscan.run_discovered(args, self.root, [self.base], summary, webscan.Runner(True), {})
            self.assertEqual(summary['jobs'], [])

    def test_pipeline_selects_and_runs_checks_then_reports(self):
        args = webscan.parser().parse_args(['127.0.0.1', '--rate', '50', '--skip', 'nuclei'])
        summary = dict(target='127.0.0.1', jobs=[], ports=[], probes=[], created='test', mode='sequential', outcome='test')

        class FakeRunner:
            stop = threading.Event()

            def execute(inner, job):
                job.folder.mkdir(parents=True)
                parameter = job.argv[job.argv.index('-p') + 1]
                (job.folder / 'console.log').write_text(f'Parameter: {parameter} (GET)\n    Type: boolean-based blind\n    Title: Fixture match\n    Payload: test\n')
                (job.folder / 'traffic.log').write_text('Fixture request/response')
                self.assertIn('--risk=1', job.argv)
                self.assertIn('--ignore-redirects', job.argv)
                self.assertIn('--technique=BEU', job.argv)
                self.assertNotIn('--dump', job.argv)
                return dict(name=job.name, tool=job.tool, argv=job.argv, folder=str(job.folder),
                            outputs=job.outputs, status='completed', elapsed=0, note='')

        with contextlib.redirect_stdout(io.StringIO()):
            webscan.run_discovered(args, self.root, [self.base], summary, FakeRunner(), {})
        webscan.write_reports(self.root, summary)
        self.assertEqual(summary['coverage']['sqli_selected'], 2)
        self.assertEqual(summary['coverage']['sqli_status'], 'completed')
        matches = [f for f in summary['findings'] if f['category'] == 'scanner_match']
        self.assertEqual(len(matches), 2)
        self.assertTrue(all(f['validation_status'] == 'needs_validation' for f in matches))
        self.assertTrue(any(f['category'] == 'configuration' for f in summary['findings']))

    def test_discovered_urls_feed_nuclei_when_auto_sqli_is_disabled(self):
        args = webscan.parser().parse_args(['127.0.0.1', '--rate', '50', '--no-auto-sqli'])
        summary = dict(target='127.0.0.1', jobs=[])
        calls = []

        class FakeRunner:
            stop = threading.Event()

            def execute(inner, job):
                calls.append(job)
                return dict(name=job.name, tool=job.tool, status='planned')

        with contextlib.redirect_stdout(io.StringIO()):
            webscan.run_discovered(args, self.root, [self.base], summary, FakeRunner(), {})
        self.assertEqual(len(calls), 1)
        job = calls[0]
        self.assertEqual(job.tool, 'nuclei')
        self.assertNotIn('-u', job.argv)
        path = Path(job.argv[job.argv.index('-l') + 1])
        self.assertIn(self.base + 'product?id=1', path.read_text())
        self.assertIn('cve', job.argv[job.argv.index('-tags') + 1])
        self.assertEqual(summary['injection']['status'], 'disabled')

    def test_interrupt_indexes_partial_crawl_evidence(self):
        args = webscan.parser().parse_args(['127.0.0.1'])
        summary = dict(target='127.0.0.1', jobs=[])

        def interrupted(*positional):
            folder = positional[2]
            folder.mkdir(parents=True)
            state = positional[-1]
            state.update(pages=[{'url': self.base, 'status': 200, 'headers': []}], limits=[], status='running')
            raise KeyboardInterrupt

        with patch.object(webscan, 'crawl', side_effect=interrupted), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                webscan.run_discovered(args, self.root, [self.base], summary, webscan.Runner(), {})
        self.assertEqual(summary['jobs'][0]['status'], 'cancelled')
        findings, issues = webscan.collect(self.root, summary)
        self.assertEqual(len(findings), 1)
        self.assertEqual(issues, [])
        self.assertEqual(findings[0]['evidence'][0]['job_status'], 'cancelled')

    def test_named_submit_is_preserved_and_csrf_forms_are_deferred(self):
        body = b'''<form><input name="id"><input name="Submit" type="submit" value="Submit"></form>
        <form><input name="id"><input name="csrf_token" value="fixture"></form>'''
        with patch.object(crawler, 'fetch', return_value=dict(status=200,
                headers=[['Content-Type', 'text/html']], body=body, truncated=False)):
            result = self.run_crawl()
        self.assertIn(self.base + '?id=&Submit=Submit', result['discovered'])
        self.assertNotIn('candidate_url', result['forms'][1])
        self.assertIn('manual review', result['forms'][1]['reason'])

    def test_phpinfo_content_is_detected_and_body_evidence_retained(self):
        body = b'<html>phpinfo() PHP Version 8.0 Configuration</html>'
        with patch.object(crawler, 'fetch', return_value=dict(status=200,
                headers=[['Content-Type', 'text/html']], body=body, truncated=False)):
            result = self.run_crawl()
        self.assertTrue(result['pages'][0]['phpinfo_signature'])
        self.assertEqual((self.root / 'crawl' / result['pages'][0]['body_file']).read_bytes(), body)


if __name__ == '__main__':
    unittest.main()
