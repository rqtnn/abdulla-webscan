"""Linux fixtures for reconnaissance, conditional WPScan and evidence attribution."""
import contextlib
import http.server
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import adaptive
import cli
import findings
import wordpress_scan


class AdaptiveTests(unittest.TestCase):
    def test_fingerprints_require_structural_same_origin_evidence(self):
        url = 'http://127.0.0.1/blog/'
        negatives = ['WordPress tutorial wp-content', '<script src="https://cdn.test/wp-content/a.js"></script><script src="https://cdn.test/wp-includes/a.js"></script>',
                     '<script src="/wp-content/a.js"></script>', '<script src="http://[bad"></script>', '<script>const language="PHP";</script>']
        for body in negatives:
            self.assertFalse(adaptive.inspect(url, [], body)['signals'], body)
        body = '<script src="/blog/wp-includes/a.js"></script><link href="/blog/wp-content/t.css">'
        signal = adaptive.inspect(url, [], body)
        plan = adaptive.plan({'probes': [{'recon': signal}]})
        site = plan['sites'][0]
        self.assertIn('WordPress', site['technologies'])
        self.assertEqual(site['wordpress_bases'], [url])
        self.assertEqual(site['extensions'], ['php'])

    def test_language_hints_unknown_stack_and_frontend_javascript(self):
        for header, expected in [(['X-Powered-By', 'PHP/8'], 'PHP'), (['Server', 'gunicorn'], 'Python'),
                                  (['Set-Cookie', 'JSESSIONID=SECRET'], 'Java'), (['X-Powered-By', 'Express'], 'Node.js')]:
            record = adaptive.inspect('http://127.0.0.1/', [header], '<script src="app.js"></script>')
            self.assertIn(expected, [s['technology'] for s in record['signals']])
            self.assertNotIn('SECRET', json.dumps(record))
        record = adaptive.inspect('http://127.0.0.1/', [], '<script src="app.js"></script>')
        self.assertFalse(record['signals'])
        self.assertEqual(record['scripts'], 1)
        plan = adaptive.plan({'probes': [{'recon': record}]})
        self.assertIn('Unknown stack', plan['sites'][0]['follow_up'][0])

    def test_whatweb_and_subdirectory_asset_evidence(self):
        record = adaptive.inspect('http://127.0.0.1/article/', [], '<meta name="generator" content="WordPress 6.0"><script src="/cms/wp-includes/a.js"></script><img src="/cms/wp-content/a.png">')
        plan = adaptive.plan({'probes': [{'recon': record}], 'findings': [dict(category='technology', check='PHP', url='http://127.0.0.1/', evidence=[{'tool': 'whatweb'}])]})
        self.assertEqual(plan['sites'][0]['wordpress_bases'], ['http://127.0.0.1/cms/'])
        self.assertIn('PHP', plan['sites'][0]['technologies'])
        self.assertFalse(adaptive.plan({'probes': [{'recon': record}]}, False)['sites'][0]['extensions'])

    def test_wpscan_json_keeps_inventory_and_advisory_candidates_separate(self):
        base = 'http://127.0.0.1/cms/'
        doc = dict(target_url=base, version={'number': '6.0', 'vulnerabilities': [{'id': 'abc', 'title': 'Fixture advisory'}]}, plugins={}, vuln_api={'error': 'No token'})
        rows = list(wordpress_scan.observations(doc, base))
        self.assertEqual(sum(row[0] == 'scanner_match' for row in rows), 1)
        self.assertEqual(rows[-1][-1], 'unknown')
        with self.assertRaises(ValueError):
            list(wordpress_scan.observations(dict(doc, target_url='http://outside.invalid/'), base))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'out.json'
            for invalid in ({}, {'scan_aborted': 'Not WordPress'}, {'target_url': base, 'plugins': []}):
                path.write_text(json.dumps(invalid))
                with self.assertRaises(ValueError):
                    wordpress_scan.load(path)

    def test_wpscan_success_exit_five_is_not_execution_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            scanner = folder / 'wpscan'
            scanner.write_text('#!/usr/bin/env python3\nimport sys,json\nfrom pathlib import Path\nPath(sys.argv[sys.argv.index("--output")+1]).write_text(json.dumps({"target_url":"http://127.0.0.1/","plugins":{},"vuln_api":{"error":"No API token"}}))\nassert not Path.home().joinpath(".wpscan/scan.yml").exists()\nsys.exit(5)\n')
            scanner.chmod(0o700)
            out = folder / 'job'
            job = cli.Job('WPScan fixture', 'wpscan', [str(scanner), '--url', 'http://127.0.0.1/', '--output', str(out / 'results.json')], out, 10, ['results.json'])
            with contextlib.redirect_stdout(io.StringIO()):
                result = cli.Runner().execute(job)
            self.assertEqual(result['status'], 'completed')
            self.assertIn('API unavailable', result['note'])
            parsed, issues = findings.collect(folder, {'target': '127.0.0.1', 'jobs': [result]})
            self.assertFalse(issues)
            self.assertTrue(parsed)
            self.assertTrue(all(f['validation_status'] == 'needs_validation' for f in parsed))

    def test_real_pipeline_detects_wordpress_then_runs_only_selected_adapter(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('X-Powered-By', 'PHP/8')
                self.end_headers()
                self.wfile.write(b'<meta name="generator" content="WordPress 6.7"><form action="/search"></form>')
            def log_message(self, *_):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                scanner = root / 'wpscan'
                scanner.write_text('#!/usr/bin/env python3\nimport sys,json\nfrom pathlib import Path\nurl=sys.argv[sys.argv.index("--url")+1]\nPath(sys.argv[sys.argv.index("--output")+1]).write_text(json.dumps({"target_url":url,"version":{"number":"6.7"},"plugins":{},"vuln_api":{"error":"No token"}}))\n')
                scanner.chmod(0o700)
                url = f'http://127.0.0.1:{server.server_port}/'
                with patch.dict(os.environ, PATH=tmp + os.pathsep + os.environ['PATH']), contextlib.redirect_stdout(io.StringIO()):
                    code = cli.main([url, '--only', 'wpscan', '--retain-raw-evidence', '--output', str(root / 'runs'), '--log-file', str(root / 'log')])
                self.assertEqual(code, 0)
                summary = json.loads(next((root / 'runs').glob('*/summary.json')).read_text())
                self.assertEqual([j['tool'] for j in summary['jobs']], ['wpscan'])
                self.assertEqual(summary['wordpress']['status'], 'completed')
                self.assertEqual(summary['crawl']['status'], 'disabled')
                self.assertIn('WordPress', summary['adaptive_plan']['sites'][0]['technologies'])
                argv = summary['jobs'][0]['argv']
                self.assertEqual(argv[argv.index('--enumerate')+1], 'p,t')
                self.assertNotIn('--force', argv)
                self.assertNotIn('--passwords', argv)
                report = next((root / 'runs').glob('*/report.html')).read_text()
                self.assertIn('Reconnaissance and adaptive assessment plan', report)
        finally:
            server.shutdown(); server.server_close(); worker.join()

    def test_extension_commands_and_explicit_tool_isolation(self):
        args = cli.parser().parse_args(['127.0.0.1', '--enum', 'all'])
        args.adaptive_plan = {'sites': [{'url': 'http://127.0.0.1/', 'extensions': ['php']}]}
        with tempfile.TemporaryDirectory() as tmp:
            jobs = cli.build_jobs(args, Path(tmp), ['http://127.0.0.1/'], {})
            for tool, flag in [('ffuf', '-e'), ('gobuster', '-x'), ('feroxbuster', '-x'), ('dirsearch', '-e')]:
                job = next(j for j in jobs if j.tool == tool)
                self.assertIn('php', ' '.join(job.argv[job.argv.index(flag):]))
        args.only = ['whatweb']
        summary = {'probes': [{'recon': adaptive.inspect('http://127.0.0.1/', [['X-Powered-By', 'PHP']], '')}]}
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            cli.update_adaptive(args, Path(tmp), summary)
        self.assertFalse(args.adaptive_plan['enabled'])
        self.assertEqual(args.adaptive_plan['sites'][0]['extensions'], [])


    def test_recon_crawl_is_before_checks_and_reused(self):
        args = cli.parser().parse_args(['127.0.0.1', '--profile', 'standard', '--no-auto-sqli', '--skip', *cli.ALL_TOOLS])
        args.no_crawl = False
        args.sensitive_files = True
        args.cors_checks = False
        args.request_gate = cli.RequestGate(50)
        args.scan_ip = '127.0.0.1'
        summary = {'jobs': [], 'target': '127.0.0.1'}
        events = []
        def crawl(*values, **kwargs):
            events.append('crawl')
            state = values[10]
            state.update(status='completed', limits=[], discovered=['http://127.0.0.1/'], pages=[], forms=[])
        with tempfile.TemporaryDirectory() as tmp, patch('cli.crawl', side_effect=crawl) as crawler, \
                patch('cli.run_file_stage', side_effect=lambda *a: events.append('checks')), contextlib.redirect_stdout(io.StringIO()):
            root = Path(tmp)
            runner = cli.Runner()
            cli.run_discovered(args, root, ['http://127.0.0.1/'], summary, runner, {}, discovery_only=True)
            self.assertEqual(events, ['crawl'])
            cli.run_discovered(args, root, ['http://127.0.0.1/'], summary, runner, {})
            self.assertEqual(events, ['crawl', 'checks'])
            self.assertEqual(crawler.call_count, 1)

    def test_wordpress_absent_disabled_and_missing_binary_are_explicit(self):
        args = cli.parser().parse_args(['127.0.0.1'])
        args.session = None
        args.contexts = None
        record = adaptive.inspect('http://127.0.0.1/', [], '<meta name="generator" content="WordPress 6">')
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            summary = {'jobs': [], 'adaptive_plan': adaptive.plan({})}
            cli.run_wordpress(args, Path(tmp), summary, cli.Runner(), {})
            self.assertEqual(summary['wordpress']['status'], 'not_detected')
            self.assertFalse(summary['jobs'])
            summary['adaptive_plan'] = adaptive.plan({'probes': [{'recon': record}]})
            args.skip = ['wpscan']
            cli.run_wordpress(args, Path(tmp), summary, cli.Runner(), {})
            self.assertEqual(summary['wordpress']['status'], 'disabled')
            self.assertFalse(summary['jobs'])
            args.skip = []
            cli.run_wordpress(args, Path(tmp), summary, cli.Runner(), {})
            self.assertEqual(summary['jobs'][0]['status'], 'skipped')
            self.assertIn('not installed', summary['jobs'][0]['note'])

    def test_hostname_wpscan_preserves_scope_restriction(self):
        args = cli.parser().parse_args(['lab.invalid', '--only', 'wpscan'])
        args.session = None
        args.contexts = None
        record = adaptive.inspect('http://lab.invalid/', [], '<meta name="generator" content="WordPress">')
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            runner = cli.Runner()
            runner.web_skip_reason = 'External scanner deferred: cannot guarantee DNS pinning for this hostname.'
            summary = {'jobs': [], 'adaptive_plan': adaptive.plan({'probes': [{'recon': record}]})}
            cli.run_wordpress(args, Path(tmp), summary, runner, {'wpscan': '/bin/false'})
            self.assertEqual(summary['jobs'][0]['status'], 'skipped')
            self.assertIn('DNS pinning', summary['jobs'][0]['note'])
