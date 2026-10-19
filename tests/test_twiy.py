"""Linux-only web workflow and CTF arithmetic regression fixtures."""
import contextlib
import http.server
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import threading
import unittest
import urllib.parse
from unittest.mock import patch

import checks
import cli
import scan_modes
import terminal
import web_review


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        value = urllib.parse.parse_qs(parsed.query).get('q', ['plain'])[0]
        if parsed.path == '/template':
            value = re.sub(r'\{\{(\d+)\*(\d+)\}\}', lambda m: str(int(m[1])*int(m[2])), value)
        elif parsed.path == '/dollar':
            value = re.sub(r'\$\{(\d+)\*(\d+)\}', lambda m: str(int(m[1])*int(m[2])), value)
        elif parsed.path == '/static':
            value = '49 777 123456'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(value.encode())

    def log_message(self, *args):
        pass


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux only')
class WebWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.base = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.worker.join(timeout=2)

    def test_template_evaluation_requires_two_products_and_rejects_reflection_and_static(self):
        for path, expected in (('/template', True), ('/dollar', True), ('/reflect', False), ('/static', False)):
            with self.subTest(path=path), tempfile.TemporaryDirectory() as tmp:
                state = checks.run_checks([dict(url=self.base+path+'?q=hello', parameter='q')], '127.0.0.1',
                    Path(tmp), threading.Event(), rate=10000, template_checks=True)
                record = state['checks'][0]
                matches = [m for m in record.get('matches', []) if m['check']=='server-template-evaluation']
                self.assertEqual(bool(matches), expected)
                if expected:
                    matched = [s for s in record['template_samples'] if s['matched']]
                    self.assertEqual(len(matched), 2)
                    self.assertNotEqual(matched[0]['expected'], matched[1]['expected'])
                    self.assertTrue(all('probe_url' in s for s in matched))

    def test_template_probes_are_opt_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = checks.run_checks([dict(url=self.base+'/template?q=hello', parameter='q')], '127.0.0.1',
                Path(tmp), threading.Event(), rate=10000)
            self.assertNotIn('template_samples', state['checks'][0])

    def test_custom_port_overrides_url_seed_and_probes_unusual_web_port_without_nmap(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), \
                patch('cli.probe', return_value=dict(url=self.base+'/', status=200, headers=[])) as probe:
            code = cli.main(['https://127.0.0.1/old?x=1', '--scan', 'port', '--ports', str(self.server.server_port),
                '--skip', 'nmap', '--profile', 'standard', '--no-crawl', '--enum', 'none',
                '--output', tmp, '--log-file', tmp+'/log'])
            self.assertEqual(code, 0)
            urls = [c.args[0] for c in probe.call_args_list]
            self.assertEqual(set(urls), {self.base+'/'})
            self.assertFalse(any('/old' in u or ':443/' in u for u in urls))
            summary = json.loads(next(Path(tmp).glob('*/summary.json')).read_text())
            self.assertEqual(summary['probe_skips'][0]['url'], self.base.replace('http:', 'https:')+'/')
            self.assertEqual(summary['assessment_mode'], 'web')
            self.assertNotIn('network_assessment', summary)

    def test_authenticated_port_conflict_is_not_rebound(self):
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()), \
                patch('cli.probe', side_effect=AssertionError('no requests')):
            with self.assertRaises(SystemExit):
                cli.main(['https://127.0.0.1', '--ports', '8080', '--cookie-file', '/nonexistent', '--dry-run'])

    def test_ctf_and_opt_out_select_web_checks(self):
        for flags, expected in (([], True), (['--no-active-checks'], False)):
            argv = ['127.0.0.1', '--scan', 'ctf', *flags]
            args = cli.parser().parse_args(argv)
            cli.apply_profile(args, argv); scan_modes.apply(args, argv)
            self.assertEqual(args.assessment, 'web')
            self.assertEqual(args.template_checks, expected)
            self.assertFalse(args.external_tools)

    def test_menu_and_brand(self):
        with patch('builtins.input', return_value='١٠'), contextlib.redirect_stdout(io.StringIO()) as out:
            ui = terminal.TerminalUI('plain'); ui.startup(cli.VERSION); result=ui.prompt_scan()
            self.assertEqual(result['scan'], 'ctf')
            self.assertIn('The World Is Yours', out.getvalue())

    def test_web_priorities_exclude_technology_headers_and_network(self):
        def finding(category, check, url='http://127.0.0.1/'):
            return dict(category=category, check=check, title=check, url=url)
        rows = [finding('configuration', 'header'), finding('technology','php'),
                finding('scanner_match','sql-error'), finding('scanner_match','server-template-evaluation'),
                finding('scanner_match','network-ftp','tcp://127.0.0.1:21')]
        leads = web_review.web_leads(rows)
        self.assertEqual(len(leads), 2)
        self.assertEqual(leads[0]['priority'], 1)
        self.assertTrue(all(r['status']=='requires_manual_validation' for r in leads))

    def test_linux_only_ci_and_launcher(self):
        workflow = Path('.github/workflows/python-tests.yml').read_text()
        self.assertNotIn('windows-latest', workflow)
        self.assertEqual(cli.parser().parse_args([]).assessment, 'web')
        self.assertTrue(Path('twiy.py').is_file())
