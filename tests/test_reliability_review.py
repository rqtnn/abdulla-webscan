"""Regression cases found during the complete runtime/report review."""
import contextlib
import io
import http.server
import os
import zipfile
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from unittest.mock import patch

import cli
import build_release
import run_history
import scan_modes
import terminal
from cli_fixture import cli_platform

BASE = 'http://127.0.0.1:8000/'


def crawl_result(*args, **kwargs):
    state = args[9]
    state.update(status='completed', requests=1, pages=[dict(url=BASE, status=200,
        headers=[['Content-Type', 'text/html']], truncated=False)],
        discovered=[BASE, BASE + '?token=private'], limits=[])
    return state


class ReliabilityReview(unittest.TestCase):
    def run_crawl(self, parent, extra=()):
        cli_platform(self)
        with contextlib.redirect_stdout(io.StringIO()), patch('cli.probe', return_value=dict(url=BASE,
                status=200, headers=[['Content-Type', 'text/html']])), patch('cli.crawl', side_effect=crawl_result):
            code = cli.main([BASE, '--only', 'crawl', '--output', str(parent), '--log-file', str(parent / 'log'), *extra])
        root = next(parent.glob('*/summary.json')).parent
        return code, root, json.loads((root / 'summary.json').read_text())

    def test_crawl_only_does_not_fail_for_excluded_injection_parameters(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, root, summary = self.run_crawl(Path(tmp))
            self.assertTrue(summary['injection']['excluded'])
            self.assertEqual(code, 0)

    def test_network_stage_failure_still_runs_independent_web_discovery(self):
        cli_platform(self)
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), \
                patch('cli.assessment.run', side_effect=RuntimeError('broken TLS worker')), \
                patch('cli.probe', return_value=dict(url=BASE, status=200)) as probe:
            code = cli.main([BASE, '--skip', 'nmap', '--profile', 'standard', '--no-crawl',
                '--enum', 'none', '--output', tmp, '--log-file', tmp + '/log'])
            self.assertEqual(code, 2)
            self.assertTrue(probe.called)
            summary = json.loads(next(Path(tmp).glob('*/summary.json')).read_text())
            self.assertEqual(summary['network_assessment']['status'], 'incomplete')
            self.assertNotIn('execution_error', summary)

    def test_tls_only_checks_requested_port_without_http_or_other_scanners(self):
        cli_platform(self)
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), \
                patch('assessment.tls_check', return_value=dict(url='https://127.0.0.1:8443/', status='completed')) as tls, \
                patch('cli.probe', side_effect=AssertionError('HTTP discovery must not run')), \
                patch.object(cli.Runner, 'execute', side_effect=AssertionError('No external scanner')):
            code = cli.main(['127.0.0.1', '--only', 'tls', '--ports', '8443', '--output', tmp, '--log-file', tmp + '/log'])
            self.assertEqual(code, 0)
            self.assertEqual(tls.call_args.args[0], 'https://127.0.0.1:8443/')
            summary = json.loads(next(Path(tmp).glob('*/summary.json')).read_text())
            self.assertEqual(summary['probes'], [])
            self.assertEqual(summary['ports'], [])

    def test_successful_closed_port_inventory_does_not_trigger_common_port_fallback(self):
        cli_platform(self)
        def closed(job):
            job.folder.mkdir(parents=True)
            (job.folder / 'services.xml').write_text('<nmaprun><host><address addr="127.0.0.1"/><ports/>'
                '</host><runstats><finished exit="success"/></runstats></nmaprun>')
            return dict(name=job.name, tool=job.tool, argv=job.argv, folder=str(job.folder), outputs=job.outputs,
                status='completed', elapsed=0, note='')
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), \
                patch.object(cli.Runner, 'execute', side_effect=closed), \
                patch('cli.probe', side_effect=AssertionError('No open web ports')) as probe:
            code = cli.main(['127.0.0.1', '--profile', 'standard', '--no-crawl', '--output', tmp, '--log-file', tmp + '/log'])
            self.assertFalse(probe.called)
            self.assertEqual(code, 0)

    def test_moved_and_renamed_run_rebuild_keeps_findings_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            code, root, summary = self.run_crawl(parent / 'original')
            moved = parent / 'renamed'
            shutil.move(root, moved)
            with contextlib.redirect_stdout(io.StringIO()), patch('cli.probe', side_effect=AssertionError('offline')), \
                    patch.object(cli.Runner, 'execute', side_effect=AssertionError('offline')):
                code = cli.main(['--report-only', str(moved), '--log-file', str(parent / 'rebuild.log')])
            self.assertEqual(code, 0)
            rebuilt = json.loads((moved / 'summary.json').read_text())
            self.assertEqual(len(rebuilt['findings']), len(summary['findings']))
            self.assertFalse(rebuilt['parse_issues'])
            self.assertTrue(all(Path(job['folder']).is_relative_to(moved) for job in rebuilt['jobs']))

    def test_comparison_snapshot_survives_original_baseline_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            baseline = parent / 'baseline.json'
            baseline.write_text(json.dumps(dict(target='127.0.0.1', findings=[], ports=[], created='baseline')))
            _, root, summary = self.run_crawl(parent / 'run', ['--compare', str(baseline)])
            baseline.unlink()
            with contextlib.redirect_stdout(io.StringIO()):
                code = cli.main(['--report-only', str(root), '--log-file', str(parent / 'rebuild.log')])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads((root / 'summary.json').read_text())['comparison']['status'], 'completed')

    def test_malformed_baseline_is_rejected_before_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'bad.json'
            path.write_text(json.dumps(dict(target='127.0.0.1', findings=[None], ports=[])))
            with self.assertRaises(ValueError):
                run_history.load(path)

    def test_explicit_opt_outs_are_not_silently_reenabled_by_only_selection(self):
        for argv in (['--only', 'crawl', '--no-crawl'], ['--only', 'checks', '--no-active-checks'],
                     ['--only', 'sqlmap', '--no-auto-sqli']):
            args = cli.parser().parse_args(['127.0.0.1', *argv])
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                scan_modes.apply(args, argv)

    def test_repeated_tool_names_are_normalized(self):
        args = cli.parser().parse_args(['127.0.0.1', '--only', 'whatweb', 'whatweb'])
        scan_modes.apply(args, [])
        self.assertEqual(args.only, ['whatweb'])

    def test_bad_menu_choice_can_be_corrected_without_restarting(self):
        with contextlib.redirect_stdout(io.StringIO()), patch('builtins.input', side_effect=['0', '٥']):
            self.assertEqual(terminal.TerminalUI('plain').prompt_scan()['only'], ['whatweb'])

    def test_reporting_incomplete_comparison_has_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            _, root, _ = self.run_crawl(parent)
            summary = json.loads((root / 'summary.json').read_text())
            summary['comparison_base'] = str(parent / 'missing.json')
            (root / 'summary.json').write_text(json.dumps(summary))
            with contextlib.redirect_stdout(io.StringIO()):
                code = cli.main(['--report-only', str(root), '--log-file', str(parent / 'rebuild.log')])
            self.assertEqual(code, 2)


    def test_legacy_report_can_be_renamed_using_captured_evidence_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            _, root, summary = self.run_crawl(parent / 'old')
            summary.pop('run_directory', None)
            (root / 'summary.json').write_text(json.dumps(summary))
            moved = parent / 'legacy-renamed'
            shutil.move(root, moved)
            with contextlib.redirect_stdout(io.StringIO()):
                code = cli.main(['--report-only', str(moved), '--log-file', str(parent / 'log')])
            self.assertEqual(code, 0)
            self.assertEqual(len(json.loads((moved / 'summary.json').read_text())['findings']), len(summary['findings']))

    def test_cross_platform_report_job_paths_are_rebased(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = dict(run_directory=r'C:\old\run', jobs=[dict(folder=r'C:\old\run\crawl')])
            run_history.relocate(state, Path(tmp))
            self.assertEqual(state['jobs'][0]['folder'], str(Path(tmp) / 'crawl'))

    def test_menu_retries_invalid_port_and_normalizes_arabic_port_input(self):
        with contextlib.redirect_stdout(io.StringIO()), patch('builtins.input', side_effect=['9', '0', '9', '٨٠،٤٤٣']):
            self.assertEqual(terminal.TerminalUI('plain').prompt_scan()['ports'], '80,443')
        self.assertEqual(cli.ports('٨٠-٨١،٤٤٣'), '80-81,443')

    def test_explicit_sqlmap_does_not_force_crawling_or_http_discovery(self):
        cli_platform(self)
        def execute(job):
            self.assertEqual(job.tool, 'sqlmap')
            job.folder.mkdir(parents=True)
            (job.folder / 'console.log').write_text('all tested parameters do not appear to be injectable')
            return dict(name=job.name, tool=job.tool, argv=job.argv, folder=str(job.folder),
                outputs=job.outputs, status='completed', elapsed=0, note='')
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), \
                patch('cli.probe', side_effect=AssertionError('No discovery')), \
                patch('cli.crawl', side_effect=AssertionError('No crawl')), \
                patch.object(cli.Runner, 'execute', side_effect=execute) as scanner:
            code = cli.main(['127.0.0.1', '--only', 'sqlmap', '--sqlmap-url', BASE + '?id=1',
                '--sqlmap-param', 'id', '--no-auto-sqli', '--no-crawl', '--retain-raw-evidence',
                '--output', tmp, '--log-file', tmp + '/log'])
            self.assertEqual(code, 0)
            self.assertEqual(scanner.call_count, 1)

    def test_release_contains_readme_comparison_document_and_manifest(self):
        path = build_release.build()
        with zipfile.ZipFile(path) as archive:
            self.assertIn('ws-r/SN1PER_COMPARISON.md', archive.namelist())
            self.assertIn('SN1PER_COMPARISON.md', archive.read('ws-r/MANIFEST.sha256').decode())

    @unittest.skipUnless(os.name == 'posix' and shutil.which('nmap'), 'Requires installed Nmap (Linux CI installs it)')
    def test_real_nmap_binary_records_a_loopback_open_port(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'<title>WSR local Nmap fixture</title>'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), \
                    patch('cli.probe', side_effect=AssertionError('No separate HTTP discovery')):
                code = cli.main(['127.0.0.1', '--only', 'nmap', '--ports', str(server.server_port),
                    '--version-intensity', '0', '--nmap-timeout', '30', '--ui', 'plain',
                    '--output', tmp, '--log-file', tmp + '/log'])
                summary = json.loads(next(Path(tmp).glob('*/summary.json')).read_text())
                self.assertEqual(code, 0, summary['jobs'])
                self.assertEqual([row['port'] for row in summary['ports']], [server.server_port])
                self.assertEqual(summary['nmap']['status'], 'completed')
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)


    def test_network_error_keeps_partial_checkpoint_findings(self):
        cli_platform(self)
        def fail(*args, **kwargs):
            folder = args[4]
            folder.mkdir(parents=True)
            row = dict(check='network-ftp', url='tcp://127.0.0.1:21', title='FTP service exposed',
                severity='medium', recommendation='Review encryption', service_evidence=dict(port=21, service='ftp'))
            (folder / 'assessment.json').write_text(json.dumps(dict(status='running', checks=[row], tls=[])))
            raise RuntimeError('later TLS check failed')
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), \
                patch('cli.assessment.run', side_effect=fail), patch('cli.probe', return_value=dict(url=BASE, status=200)):
            code = cli.main([BASE, '--skip', 'nmap', '--profile', 'standard', '--no-crawl', '--enum', 'none',
                '--output', tmp, '--log-file', tmp + '/log'])
            self.assertEqual(code, 2)
            summary = json.loads(next(Path(tmp).glob('*/summary.json')).read_text())
            self.assertTrue(any(f['check'] == 'network-ftp' for f in summary['findings']))
            self.assertEqual(summary['network_assessment']['status'], 'incomplete')

    def test_legacy_empty_findings_still_rebase_known_scanner_folders(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = dict(jobs=[dict(folder='/old/run/nmap', name='Nmap', tool='nmap'),
                dict(folder='/old/run/web-01/whatweb', name='WhatWeb', tool='whatweb')], findings=[])
            run_history.relocate(summary, Path(tmp))
            self.assertEqual(summary['jobs'][0]['folder'], str(Path(tmp) / 'nmap'))
            self.assertEqual(summary['jobs'][1]['folder'], str(Path(tmp) / 'web-01' / 'whatweb'))
