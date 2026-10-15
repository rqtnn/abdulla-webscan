"""Regression coverage for real menu selection, pinned fingerprinting and metadata scope."""
import contextlib
import http.server
import io
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from unittest.mock import patch

import cli
import crawler
import whatweb_snapshot
from scope import RequestGate


class WebExpansion(unittest.TestCase):
    def test_snapshot_is_pinned_and_maps_scanner_results_to_original_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            snapshot = dict(url='https://lab.invalid:8443/', scan_ip='127.0.0.1', insecure=False, timeout=2)
            with patch('whatweb_snapshot.fetch', return_value=dict(status=200, headers=[['Server', 'Fixture/1']], body=b'<title>Lab</title>')) as fetch:
                whatweb_snapshot.prepare(snapshot, folder, threading.Event(), RequestGate(50))
            self.assertEqual(fetch.call_args.kwargs['scan_ip'], '127.0.0.1')
            self.assertEqual(fetch.call_args.args[0], snapshot['url'])
            self.assertTrue((folder / 'response.http').read_bytes().startswith(b'HTTP/1.1 200 OK\r\nServer: Fixture/1\r\n\r\n'))
            output = folder / 'results.json'
            output.write_text(json.dumps([dict(target=str(folder / 'response.http'), plugins={'Title': {'string': ['Lab']}})]))
            whatweb_snapshot.remap(output, snapshot['url'])
            self.assertEqual(json.loads(output.read_text())[0]['target'], snapshot['url'])

    def test_snapshot_rejects_truncated_data_and_cancellation_without_scanning(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = dict(url='http://lab.invalid/', scan_ip='127.0.0.1', insecure=False, timeout=2)
            stop = threading.Event(); stop.set()
            with patch('whatweb_snapshot.fetch') as fetch:
                with self.assertRaises(InterruptedError):
                    whatweb_snapshot.prepare(snapshot, Path(tmp), stop, RequestGate(50))
                fetch.assert_not_called()
            with patch('whatweb_snapshot.fetch', return_value={'truncated': True}):
                with self.assertRaises(ValueError):
                    whatweb_snapshot.prepare(snapshot, Path(tmp), threading.Event(), RequestGate(50))

    def test_metadata_discovers_hidden_parameters_and_nested_sitemaps_with_scope_controls(self):
        base = 'http://127.0.0.1/'
        pages = {
            '/': ('text/html', b'<script src="/bundle.js"></script>'),
            '/robots.txt': ('text/plain', b'Disallow: /hidden?id=1\nDisallow: /delete?id=1\nDisallow: /wild*\nSitemap: /nested.xml'),
            '/sitemap.xml': ('application/xml', b'<sitemapindex><sitemap><loc>http://127.0.0.1/child.xml</loc></sitemap></sitemapindex>'),
            '/child.xml': ('application/xml', b'<urlset xmlns="urn:sitemap"><url><loc>http://127.0.0.1/search?q=test</loc></url><url><loc>https://outside.invalid/private</loc></url></urlset>'),
            '/nested.xml': ('text/xml', b'<urlset><url><loc>/extra</loc></url></urlset>'),
            '/bundle.js': ('text/javascript', b'fetch("/api/items?id=2");\n//# sourceMappingURL=bundle.js.map')
        }
        requested = []
        def fetch(url, *args, **kwargs):
            from urllib.parse import urlsplit
            u = urlsplit(url)
            self.assertEqual(u.hostname, '127.0.0.1')
            requested.append(u.path)
            kind, body = pages.get(u.path, ('text/plain', b'ok'))
            return dict(status=200, headers=[['Content-Type', kind]], body=body, truncated=False)
        with tempfile.TemporaryDirectory() as tmp, patch('crawler.fetch', side_effect=fetch):
            state = crawler.crawl([base], '127.0.0.1', Path(tmp), threading.Event(), metadata_paths=True,
                max_pages=30, depth=5, rate=10000, scan_ip='127.0.0.1')
        self.assertIn(base + 'hidden?id=1', state['discovered'])
        self.assertIn(base + 'search?q=test', state['discovered'])
        self.assertIn(base + 'api/items?id=2', state['discovered'])
        self.assertIn(base + 'bundle.js.map', state['discovered'])
        self.assertNotIn('/bundle.js.map', requested)
        self.assertNotIn('/delete', requested)
        self.assertNotIn('/wild*', requested)
        self.assertTrue(any('outside.invalid' in item['url'] for item in state['excluded']))
        self.assertLessEqual(state['requests'], 30)

    @unittest.skipUnless(shutil.which('whatweb'), 'Requires Ruby WhatWeb installed in Linux CI')
    def test_real_choice_five_for_hostname_prints_whatweb_information(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            server_version = 'TWIYFixture/4.1'
            def do_GET(self):
                self.server.hosts.append(self.headers.get('Host'))
                body = b'<html><title>Pinned Hostname Fixture</title><body>test</body></html>'
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers(); self.wfile.write(body)
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.hosts = []
        worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
        try:
            with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()) as output, \
                    patch('scope.resolve_one', return_value='127.0.0.1'), patch('builtins.input', return_value='5'):
                url = f'http://lab.invalid:{server.server_port}/'
                code = cli.main([url, '--menu', '--ui', 'plain', '--tool-timeout', '30', '--output', tmp, '--log-file', tmp + '/log'])
                summary = json.loads(next(Path(tmp).glob('*/summary.json')).read_text())
                self.assertEqual(code, 0, (summary['jobs'], output.getvalue()))
                self.assertIn('Title | Pinned Hostname Fixture', output.getvalue())
                self.assertIn('HTTPServer | TWIYFixture/4.1', output.getvalue())
                self.assertIn('Pinned snapshot', output.getvalue())
                self.assertTrue(all(value == f'lab.invalid:{server.server_port}' for value in server.hosts))
                self.assertEqual(len(server.hosts), 2)  # discovery and pinned capture only
                self.assertTrue(all(row['url'] == url for row in summary['findings']))
                self.assertEqual([job['tool'] for job in summary['jobs']], ['whatweb'])
        finally:
            server.shutdown(); server.server_close(); worker.join(timeout=2)
