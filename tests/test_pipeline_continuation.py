import contextlib
import http.server
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.parse

import cli
from cli_fixture import cli_platform


class WebLab(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        value = urllib.parse.parse_qs(parsed.query).get('q', [''])[0]
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        if parsed.path == '/':
            body = '<html><a href="/search?q=original">Search</a></html>'
        elif parsed.path == '/search':
            body = '<html>' + value + '</html>'
            if "'" in value:
                body += 'You have an error in your SQL syntax'
        else:
            body = '<html>Not found</html>'
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


class PipelineTests(unittest.TestCase):
    def test_default_enables_checks_and_explicit_standard_remains_passive(self):
        default = cli.parser().parse_args([])
        cli.apply_profile(default, [])
        self.assertEqual(default.profile, 'web')
        self.assertTrue(default.active_checks and default.builtin_sqli and default.api_discovery)
        passive = cli.parser().parse_args(['--profile', 'standard'])
        cli.apply_profile(passive, ['--profile', 'standard'])
        self.assertFalse(passive.active_checks)

    def test_partial_crawl_and_prior_stage_failures_still_run_checks_and_sqlmap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = cli.parser().parse_args(['127.0.0.1', '--skip', 'nuclei'])
            cli.apply_profile(args, [])
            summary = dict(target='127.0.0.1', jobs=[])
            def crawl(*positional, **options):
                positional[9]['discovered'] = ['http://127.0.0.1/search?q=value']
                raise RuntimeError('interrupted parsing')
            runner = cli.Runner()
            result = dict(status='completed', folder=str(root), name='sqlmap', tool='sqlmap')
            with contextlib.redirect_stdout(io.StringIO()), \
                    patch('cli.run_file_stage', side_effect=RuntimeError('file worker')), \
                    patch('cli.run_cors', side_effect=RuntimeError('cors worker')), \
                    patch('cli.crawl', side_effect=crawl), \
                    patch('cli.run_checks', return_value=dict(status='completed')) as checks, \
                    patch.object(runner, 'execute', return_value=result) as external:
                cli.run_discovered(args, root, ['http://127.0.0.1/'], summary, runner, {})
            self.assertEqual(summary['crawl']['status'], 'incomplete')
            self.assertEqual(summary['active_checks']['status'], 'completed')
            self.assertEqual(checks.call_args.args[0][0]['parameter'], 'q')
            self.assertEqual(external.call_args.args[0].tool, 'sqlmap')
            self.assertFalse(runner.stop.is_set())

    def test_failed_checks_and_nuclei_setup_still_attempt_sqlmap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = cli.parser().parse_args(['127.0.0.1', '--profile', 'standard', '--active-checks'])
            summary = dict(target='127.0.0.1', jobs=[])
            def crawl(*positional, **options):
                positional[9].update(status='completed', discovered=['http://127.0.0.1/search?q=value'])
            runner = cli.Runner()
            with contextlib.redirect_stdout(io.StringIO()), patch('cli.crawl', side_effect=crawl), \
                    patch('cli.run_checks', side_effect=RuntimeError('check failure')), \
                    patch('cli.build_jobs', side_effect=RuntimeError('nuclei setup')), \
                    patch.object(runner, 'execute', return_value=dict(status='completed', folder=tmp,
                        name='sqlmap', tool='sqlmap')) as external:
                cli.run_discovered(args, root, ['http://127.0.0.1/'], summary, runner, {})
            self.assertEqual(summary['active_checks']['status'], 'incomplete')
            self.assertEqual(external.call_args.args[0].tool, 'sqlmap')
            self.assertTrue(any(j['name'] == 'Discovered Nuclei stage' for j in summary['jobs']))

    def test_default_cli_produces_post_crawl_reflection_and_sql_error_findings(self):
        cli_platform(self)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), WebLab)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()) as console:
                base = f'http://127.0.0.1:{server.server_port}/'
                result = cli.main([base, '--assessment', 'web', '--skip', 'nmap', '--enum', 'none',
                    '--no-auto-sqli', '--rate', '50', '--file-limit', '2', '--crawl-pages', '10',
                    '--output', tmp, '--log-file', tmp + '/scan.log', '--ui', 'plain', '--no-banner'])
                path = next(Path(tmp).glob('*/summary.json'))
                summary = json.loads(path.read_text())
                self.assertEqual(summary['active_checks']['status'], 'completed')
                self.assertGreaterEqual(summary['active_checks']['requests'], 3)
                names = {f['check'] for f in summary['findings']}
                self.assertIn('unescaped-reflection:q', names)
                self.assertIn('sql-error:q', names)
                self.assertEqual(summary['advanced']['status'], 'completed')
                self.assertIn('[POST-CRAWL]', console.getvalue())
                self.assertIn('[GET CHECKS] completed', console.getvalue())
                self.assertIn('How to exploit', path.with_name('report.html').read_text())
                # Deliberate file limit is incomplete coverage, not a stopped pipeline.
                self.assertEqual(result, 2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
