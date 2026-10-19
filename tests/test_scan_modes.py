import contextlib
import csv
import io
import json
import http.server
import os
import shutil
import threading
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import cli
import run_history
import scan_modes
from cli_fixture import cli_platform


class ScanModeTests(unittest.TestCase):
    def args(self, argv):
        args = cli.parser().parse_args(argv)
        cli.apply_profile(args, argv)
        scan_modes.apply(args, argv)
        return args

    def test_only_tools_disable_unrelated_stages(self):
        nmap = self.args(['127.0.0.1', '--only', 'nmap'])
        self.assertEqual(nmap.assessment, 'network')
        self.assertTrue(nmap.no_crawl and nmap.no_active_checks)
        self.assertFalse(nmap.api_discovery or nmap.sensitive_files or nmap.external_tools)
        whatweb = self.args(['127.0.0.1', '--only', 'whatweb'])
        self.assertEqual(set(cli.ALL_TOOLS) - set(whatweb.skip), {'whatweb'})
        self.assertFalse(whatweb.active_checks or whatweb.api_discovery or whatweb.sensitive_files)
        cors = self.args(['127.0.0.1', '--only', 'cors'])
        self.assertTrue(cors.cors_checks and not cors.no_active_checks)
        self.assertTrue(cors.no_crawl)
        checks = self.args(['127.0.0.1', '--only', 'checks'])
        self.assertFalse(checks.no_crawl)
        self.assertTrue(checks.builtin_sqli)

    def test_quick_mode_preserves_explicit_limits_and_port_mode_requires_scope(self):
        args = self.args(['127.0.0.1', '--scan', 'quick', '--crawl-pages', '7', '--ports', '443'])
        self.assertEqual(args.crawl_pages, 7)
        self.assertEqual(args.ports, '443')
        self.assertIsNone(args.top_ports)
        self.assertEqual(args.version_intensity, 2)
        with self.assertRaises(ValueError):
            self.args(['127.0.0.1', '--scan', 'port'])
        with self.assertRaises(ValueError):
            self.args(['127.0.0.1', '--only', 'nmap', '--skip', 'nmap'])

    def execute(self, job):
        job.folder.mkdir(parents=True, exist_ok=True)
        if job.tool == 'nmap':
            (job.folder / 'services.xml').write_text('<nmaprun><host><address addr="127.0.0.1"/><ports>'
                '<port protocol="tcp" portid="8000"><state state="open"/><service name="http"/></port>'
                '</ports></host><runstats><finished exit="success"/></runstats></nmaprun>')
        elif job.tool == 'whatweb':
            (job.folder / 'results.json').write_text(json.dumps([{'target': 'http://127.0.0.1:8000/',
                'plugins': {'Lab': {'version': ['1']}, 'HTTPServer': {'string': ['fixture-server']}}}]))
        else:
            self.fail('Unselected tool started: ' + job.tool)
        return dict(name=job.name, tool=job.tool, folder=str(job.folder), argv=job.argv,
                    status='completed', outputs=job.outputs, note='', elapsed=0, exit_code=0)

    def test_nmap_only_cli_has_no_http_crawl_tls_or_other_scanners(self):
        cli_platform(self)
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), \
                patch.object(cli.Runner, 'execute', side_effect=self.execute) as execute, \
                patch('cli.probe', side_effect=AssertionError('HTTP started')), \
                patch('cli.assessment.run', side_effect=AssertionError('TLS started')), \
                patch('cli.crawl', side_effect=AssertionError('crawl started')):
            code = cli.main(['127.0.0.1', '--only', 'nmap', '--output', tmp, '--log-file', tmp + '/log'])
            self.assertEqual(code, 0)
            self.assertEqual(execute.call_count, 1)
            summary = json.loads(next(Path(tmp).glob('*/summary.json')).read_text())
            self.assertEqual([j['tool'] for j in summary['jobs']], ['nmap'])
            self.assertEqual(summary['probes'], [])
            self.assertEqual(summary['scan_plan']['requested_tools'], ['nmap'])

    def test_whatweb_only_cli_and_menu_launch_exactly_one_external_tool(self):
        cli_platform(self)
        for options in (['--only', 'whatweb', '--retain-raw-evidence'], ['--menu']):
            with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()) as output, \
                    patch.object(cli.TerminalUI, 'prompt_scan', return_value=dict(scan='full',
                        only=['whatweb'], retain_raw_evidence=True)), \
                    patch('cli.probe', return_value=dict(url='http://127.0.0.1:8000/', status=200)), \
                    patch('cli.shutil.which', return_value='/fake/whatweb'), \
                    patch('cli.subprocess.run', side_effect=AssertionError('unselected help process')), \
                    patch.object(cli.Runner, 'execute', side_effect=self.execute) as execute, \
                    patch('cli.crawl', side_effect=AssertionError('crawl started')):
                code = cli.main(['http://127.0.0.1:8000/', *options, '--output', tmp, '--log-file', tmp + '/log'])
                self.assertEqual(code, 0)
                self.assertEqual(execute.call_count, 1)
                summary = json.loads(next(Path(tmp).glob('*/summary.json')).read_text())
                self.assertEqual([j['tool'] for j in summary['jobs']], ['whatweb'])
                self.assertTrue(any(f['category'] == 'technology' for f in summary['findings']))
                self.assertIn('[WHATWEB RESULTS]', output.getvalue())
                self.assertIn('HTTPServer | fixture-server', output.getvalue())
                self.assertIn('[WHATWEB] http://127.0.0.1:8000/ | Lab | version: 1', output.getvalue())
                self.assertNotIn('Unvalidated severity groups:', output.getvalue())
                self.assertIn('--follow-redirect=never', execute.call_args.args[0].argv)

    def test_menu_is_vertical_and_accepts_arabic_digits(self):
        ui = cli.TerminalUI('plain')
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch('builtins.input', return_value='٥'):
            selection = ui.prompt_scan()
        self.assertEqual(selection['only'], ['whatweb'])
        lines = output.getvalue().splitlines()
        for number in range(1, 10):
            self.assertEqual(sum(line.startswith(str(number) + ' ') for line in lines), 1)
        self.assertNotIn(' | ', output.getvalue())

    def test_menu_all_ports_and_manual_ports_have_distinct_scopes(self):
        ui = cli.TerminalUI('plain')
        with contextlib.redirect_stdout(io.StringIO()), patch('builtins.input', return_value='٨') as ask:
            selection = ui.prompt_scan()
            self.assertEqual(ask.call_count, 1)
        args = self.args(['127.0.0.1', '--scan', selection['scan']])
        self.assertTrue(args.all_ports)
        self.assertIsNone(args.ports)
        self.assertEqual(args.nmap_timeout, 3600)
        self.assertEqual(self.args(['127.0.0.1', '--scan', 'all-ports', '--nmap-timeout', '120']).nmap_timeout, 120)
        with contextlib.redirect_stdout(io.StringIO()), patch('builtins.input', side_effect=['9', '8080,8443']):
            self.assertEqual(ui.prompt_scan()['ports'], '8080,8443')
        for restricted in (['--ports', '80,443'], ['--url-port-only'], ['--skip', 'nmap']):
            with self.assertRaises(ValueError):
                self.args(['127.0.0.1', '--scan', 'all-ports', *restricted])

    def test_all_ports_follow_up_uses_unusual_web_service_not_only_80_443(self):
        cli_platform(self)
        def inventory_job(job):
            self.assertEqual(job.tool, 'nmap')
            self.assertEqual(job.argv[job.argv.index('-p') + 1], '1-65535')
            job.folder.mkdir(parents=True)
            (job.folder / 'services.xml').write_text('<nmaprun><host><address addr="127.0.0.1"/><ports>'
                '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>'
                '<port protocol="tcp" portid="18081"><state state="open"/><service name="http"/></port>'
                '</ports></host><runstats><finished exit="success"/></runstats></nmaprun>')
            return dict(name=job.name, tool=job.tool, argv=job.argv, folder=str(job.folder),
                status='completed', outputs=job.outputs, elapsed=0, note='')
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), \
                patch.object(cli.Runner, 'execute', side_effect=inventory_job), \
                patch('cli.probe', side_effect=lambda url, *a, **k: dict(url=url, status=200)) as probe, \
                patch('cli.assessment.run', return_value=dict(status='completed', checks=[])), \
                patch('cli.crawl', side_effect=AssertionError('crawl disabled')):
            code = cli.main(['127.0.0.1', '--scan', 'all-ports', '--profile', 'standard',
                '--no-crawl', '--output', tmp, '--log-file', tmp + '/log'])
            self.assertEqual(code, 0)
            urls = [call.args[0] for call in probe.call_args_list]
            self.assertEqual(set(urls), {'http://127.0.0.1:18081/'})
            summary = json.loads(next(Path(tmp).glob('*/summary.json')).read_text())
            self.assertEqual(summary['probe_skips'][0]['url'], 'https://127.0.0.1:18081/')
            self.assertEqual([row['port'] for row in summary['ports']], [22, 18081])

    def test_whatweb_empty_missing_and_failed_output_is_explicit(self):
        ui = cli.TerminalUI('plain')
        cases = [([], 'No job started'),
            ([dict(tool='whatweb', status='skipped', note='whatweb is not installed/on PATH.')], 'sudo apt install whatweb'),
            ([dict(tool='whatweb', status='failed', note='See console.log', folder='/run/whatweb')], '/run/whatweb/console.log'),
            ([dict(tool='whatweb', status='completed', name='WhatWeb')], 'No technology fingerprints parsed')]
        for jobs, message in cases:
            with self.subTest(message=message), contextlib.redirect_stdout(io.StringIO()) as output:
                ui.whatweb_results(dict(jobs=jobs, findings=[]))
                self.assertIn(message, output.getvalue())

    def test_interactive_bare_ip_discovers_https_for_whatweb(self):
        cli_platform(self)
        probes = []
        def https_only(url, *args, **kwargs):
            probes.append(url)
            return dict(url=url, status=200) if url == 'https://127.0.0.1:443/' else dict(url=url, error='closed')
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), \
                patch.object(cli.TerminalUI, 'prompt_target', return_value='127.0.0.1'), \
                patch('builtins.input', return_value='5'), \
                patch('cli.probe', side_effect=https_only), \
                patch('cli.shutil.which', return_value='/fake/whatweb'), \
                patch.object(cli.Runner, 'execute', side_effect=self.execute) as execute:
            cli.main(['--menu', '--output', tmp, '--log-file', tmp + '/log'])
            self.assertIn('https://127.0.0.1:443/', probes)
            self.assertEqual(execute.call_count, 1)
            self.assertEqual(execute.call_args.args[0].tool, 'whatweb')
            self.assertIn('https://127.0.0.1:443/', execute.call_args.args[0].argv)

    @unittest.skipUnless(os.name == 'posix' and shutil.which('whatweb'), 'Requires installed WhatWeb (Linux CI installs it)')
    def test_real_whatweb_binary_fingerprints_loopback_and_prints_results(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            server_version = 'WSRFixture/1.0'
            def do_GET(self):
                body = b'<html><head><title>WSR WhatWeb Fixture</title></head><body>local test</body></html>'
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()) as output:
                code = cli.main([f'http://127.0.0.1:{server.server_port}/', '--only', 'whatweb',
                    '--retain-raw-evidence', '--tool-timeout', '60', '--ui', 'plain',
                    '--output', tmp, '--log-file', tmp + '/log'])
                summary = json.loads(next(Path(tmp).glob('*/summary.json')).read_text())
                self.assertEqual(code, 0, summary['jobs'])
                self.assertEqual([job['status'] for job in summary['jobs']], ['completed'])
                self.assertIn('HTTPServer | WSRFixture/1.0', output.getvalue())
                self.assertIn('Title | WSR WhatWeb Fixture', output.getvalue())
                self.assertIn('[WHATWEB RESULTS]', output.getvalue())
                self.assertNotIn('Unvalidated severity groups:', output.getvalue())
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)

    def test_comparison_uses_stable_identity_and_does_not_claim_fixed(self):
        row = dict(id='1', category='scanner_match', check='sql-error:q', url='http://127.0.0.1/?q=1',
                   title='SQL error', severity='medium', validation_status='needs_validation')
        previous = dict(target='127.0.0.1', findings=[row], ports=[{'port': 80}])
        current = dict(target='127.0.0.1', findings=[], ports=[{'port': 443}])
        result = run_history.compare(current, previous)
        self.assertEqual(result['new_open_ports'], [443])
        self.assertEqual(len(result['not_observed_this_run']), 1)
        self.assertIn('does not mean fixed', result['note'])
        with self.assertRaises(ValueError):
            run_history.compare(dict(current, target='127.0.0.2'), previous)

    def test_csv_neutralizes_formulas_and_redacts_query_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'findings.csv'
            run_history.export_csv(path, [dict(id='1', category='technology', title='=HYPERLINK("bad")',
                severity='info', validation_status='needs_validation', url='http://127.0.0.1/?token=SECRET', check='test')])
            rows = list(csv.reader(io.StringIO(path.read_text(encoding='utf-8-sig'))))
            self.assertTrue(rows[1][2].startswith("'="))
            self.assertNotIn('SECRET', rows[1][5])

    def test_exported_html_keeps_advisory_url_and_relocates_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'run'
            root.mkdir()
            (root / 'report.html').write_text('<a href="https://www.cve.org/CVERecord?id=CVE-2024-12345">CVE</a>'
                '<a href="findings.csv">CSV</a>')
            cli.export_reports(root, Path(tmp) / 'export.html')
            output = (Path(tmp) / 'export.html').read_text()
            self.assertIn('href="https://www.cve.org/', output)
            self.assertIn('href="run/findings.csv"', output)

    def test_report_only_comparison_is_offline_and_exports_csv(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(tmp) / 'current'
            root.mkdir()
            current = dict(target='127.0.0.1', created='current', mode='sequential', outcome='fixture',
                           jobs=[], ports=[], probes=[])
            (root / 'summary.json').write_text(json.dumps(current))
            baseline = Path(tmp) / 'old.json'
            baseline.write_text(json.dumps(dict(current, created='previous', findings=[dict(id='old',
                category='scanner_match', check='fixture', url='http://127.0.0.1/', title='Fixture',
                severity='medium', validation_status='needs_validation')])))
            with patch.object(cli.Runner, 'execute', side_effect=AssertionError('scanner executed')), \
                    patch('cli.connection', side_effect=AssertionError('network request')):
                self.assertEqual(cli.main(['--report-only', str(root), '--compare', str(baseline)]), 0)
            comparison = json.loads((root / 'comparison.json').read_text())
            self.assertEqual(len(comparison['not_observed_this_run']), 1)
            self.assertTrue((root / 'findings.csv').is_file())
            self.assertIn('Run comparison', (root / 'report.html').read_text())
