import json
import http.server
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import checks
import cli
from cli_fixture import cli_platform
from web_review import guide, nuclei_metadata


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        if self.path == '/reflect' and self.headers.get('Origin'):
            self.send_header('Access-Control-Allow-Origin', self.headers['Origin'])
            self.send_header('Access-Control-Allow-Credentials', 'true')
        elif self.path == '/wildcard':
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Credentials', 'true')
        self.end_headers()
        self.wfile.write(b'public data')

    def log_message(self, *args):
        pass


class WebReviewTests(unittest.TestCase):
    def test_metadata_uses_classification_not_product_guesses(self):
        result = nuclei_metadata({'template-id': 'cve-2024-12345', 'info': {
            'classification': {'cve-id': ['CVE-2024-12345', 'bad'], 'cvss-score': 7.5},
            'reference': ['javascript:alert(1)', 'https://[invalid', 'https://example.org/advisory']}})
        self.assertEqual(result['cve_ids'], ['CVE-2024-12345'])
        self.assertEqual(result['references'], ['https://example.org/advisory'])
        self.assertEqual(nuclei_metadata({'template-id': 'wordpress-version', 'info': {'name': 'WordPress 6'}})['cve_ids'], [])

    def test_report_preserves_cve_without_raw_and_escapes_guidance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            row = {'template-id': 'CVE-2024-12345', 'matched-at': 'http://127.0.0.1/?q=%3Cx%3E',
                   'info': {'name': '<script>bad</script>', 'severity': 'high',
                            'classification': {'cve-id': 'CVE-2024-12345'}}}
            (root / 'results.jsonl').write_text(json.dumps(row))
            summary = dict(target='127.0.0.1', scan_ip='127.0.0.1', ports=[], probes=[], created='test',
                           mode='sequential', outcome='test', retain_raw_evidence=False,
                           jobs=[dict(name='nuclei', tool='nuclei', folder=str(root), outputs=['results.jsonl'],
                                      status='completed', argv=[], elapsed=0, note='')])
            cli.write_reports(root, summary)
            persisted = json.loads((root / 'summary.json').read_text())
            self.assertEqual(persisted['findings'][0]['cve_ids'], ['CVE-2024-12345'])
            self.assertEqual(persisted['findings'][0]['evidence'][0]['raw'], '[omitted]')
            html = (root / 'report.html').read_text()
            self.assertIn('How to exploit', html)
            self.assertIn('CVE-2024-12345', html)
            self.assertNotIn('<script>bad</script>', html)
            cli.write_reports(root, persisted)
            self.assertEqual(summary['findings'], persisted['findings'])

    def test_guidance_includes_observed_probe_and_pin_without_cookie(self):
        finding = dict(check='unescaped-reflection:q', url='http://site.test/?q=original', evidence=[
            {'poc': [{'url': 'http://site.test/?q=probe', 'request': {'headers': [['Cookie', '[redacted]']]}},
                     {'url': 'http://other.test/'}]}])
        result = guide(finding, 'site.test', '127.0.0.1')
        commands = '\n'.join(result['commands'])
        self.assertIn('q=probe', commands)
        self.assertIn('--resolve site.test:80:127.0.0.1', commands)
        self.assertNotIn('other.test', commands)
        self.assertNotIn('Cookie', commands)

    def test_web_profile_honors_disabled_active_checks(self):
        args = cli.parser().parse_args(['--profile', 'web', '--no-active-checks'])
        cli.apply_profile(args, ['--profile', 'web', '--no-active-checks'])
        self.assertFalse(args.active_checks)
        self.assertFalse(args.builtin_sqli)
        self.assertTrue(args.sensitive_files)
        self.assertTrue(args.api_discovery)

    def test_cors_reflection_candidate_but_wildcard_not_credential_exploit(self):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                base = f'http://127.0.0.1:{server.server_port}'
                state = checks.run_cors([base + '/reflect', base + '/wildcard'], '127.0.0.1',
                    Path(tmp), threading.Event(), scan_ip='127.0.0.1')
                self.assertEqual(state['status'], 'completed')
                self.assertEqual([row['outcome'] for row in state['checks']], ['candidate', 'no_match'])
                self.assertEqual(state['requests'], 6)
                from evidence import record_pocs
                row = state['checks'][0]
                result = guide(dict(check=row['check'], url=row['url'], evidence=[
                    {'poc': record_pocs('checks', row, Path(tmp))}]), '127.0.0.1')
                self.assertEqual(sum('Origin:' in command for command in result['commands']), 2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_file_control_failure_does_not_skip_other_origin(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wordlist = root / 'words.txt'
            wordlist.write_text('.env\n')
            def fetch(url, *args, **kwargs):
                if ':81/' in url:
                    raise TimeoutError('one origin down')
                body = b'not found' if 'wsr-nonexistent' in url else b'APP_NAME=lab\nDB_PASSWORD=private-value\n'
                return dict(status=200, headers=[], body=body, truncated=False)
            with patch('checks.fetch', side_effect=fetch):
                state = checks.run_sensitive_files(['http://127.0.0.1:81/', 'http://127.0.0.1:82/'],
                    '127.0.0.1', wordlist, root / 'files', threading.Event(), rate=50, scan_ip='127.0.0.1')
            self.assertEqual(state['status'], 'incomplete')
            self.assertEqual(len(state['control_errors']), 1)
            self.assertEqual(state['checks'][0]['outcome'], 'candidate')

    def test_web_profile_runs_through_cli_progress_wrapper(self):
        cli_platform(self)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                base = f'http://127.0.0.1:{server.server_port}/reflect'
                cli.main([base, '--profile', 'web', '--assessment', 'web', '--skip', 'nmap',
                    '--enum', 'none', '--no-auto-sqli', '--rate', '50', '--crawl-pages', '10',
                    '--output', tmp, '--log-file', tmp + '/scan.log', '--ui', 'plain', '--no-banner'])
                summary_file = next(Path(tmp).glob('*/summary.json'))
                result = json.loads(summary_file.read_text())
                self.assertEqual(result['cors']['status'], 'completed')
                self.assertEqual(result['crawl']['status'], 'completed')
                self.assertTrue(any('cors-credentials' in f['check'] for f in result['findings']))
                self.assertIn('Origin:', summary_file.with_name('report.html').read_text())
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
