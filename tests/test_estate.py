"""Controlled estate discovery, DNS pinning, reuse, timeouts and regression tests."""
import contextlib
import hashlib
import http.server
import io
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

import cli
import estate
import scan_modes
import scope


class EstateTests(unittest.TestCase):
    def args(self, *extra):
        argv = ['lab.test', '--scan', 'estate', '--no-passive', '--no-menu', *extra]
        args = cli.parser().parse_args(argv)
        cli.apply_profile(args, argv)
        scan_modes.apply(args, argv)
        return args

    def resolved(self, name):
        if name.startswith('twiy-'):
            return dict(host=name, addresses=[], status='unresolved')
        return dict(host=name, addresses=['127.0.0.1'], status='resolved')

    def xml(self, folder, ip='127.0.0.1'):
        (folder / 'nmap').mkdir(parents=True, exist_ok=True)
        text = '<nmaprun><host><address addr="' + ip + '"/><ports>' \
            '<port protocol="tcp" portid="18081"><state state="open"/><service name="http"/></port>' \
            '</ports></host><runstats><finished exit="success"/></runstats></nmaprun>'
        (folder / 'nmap/services.xml').write_text(text)
        return dict(status='completed', selection='TCP 1-65535', sha256=hashlib.sha256(text.encode()).hexdigest())

    def test_exact_domain_boundary_idna_and_invalid_names(self):
        values, rejected = estate.normalize_names(['a.lab.test', 'A.LAB.TEST.', '*.lab.test',
            'lab.test.evil', 'evillab.test', '-bad.lab.test', 'http://a.lab.test', '127.0.0.1',
            'a.lab.test', '# comment'], 'lab.test')
        self.assertEqual(values, ['a.lab.test'])
        self.assertEqual(rejected, 6)
        self.assertFalse(estate.in_scope('-bad.lab.test', 'lab.test'))
        self.assertTrue(estate.in_scope('xn--bcher-kva.lab.test', 'lab.test'))

    def test_discovery_cap_dedup_missing_source_and_wildcard(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            names = root / 'names'
            names.write_text('b.lab.test\na.lab.test\na.lab.test\nevil.test\n')
            args = self.args('--subdomain-file', str(names), '--max-hosts', '2')
            args.no_passive = False
            def wildcard(name):
                return dict(host=name, addresses=['127.0.0.1'], status='resolved')
            with patch('estate.shutil.which', return_value=None), patch('estate.resolve', side_effect=wildcard):
                doc = estate.discover(args, 'lab.test', root)
            self.assertEqual([r['host'] for r in doc['hosts']], ['lab.test', 'a.lab.test'])
            self.assertEqual(doc['deferred'], ['b.lab.test'])
            self.assertTrue(doc['hosts'][1]['wildcard_candidate'])
            self.assertEqual(doc['sources'][1]['status'], 'missing')

    def test_resolver_is_timeout_bound_and_validates_addresses(self):
        with patch('estate.subprocess.run', side_effect=subprocess.TimeoutExpired('dns', 8)):
            self.assertEqual(estate.resolve('lab.test')['status'], 'timeout')
        with patch('estate.subprocess.run', return_value=types.SimpleNamespace(returncode=0, stdout='["not an IP"]')):
            self.assertEqual(estate.resolve('lab.test')['status'], 'error')

    def test_dry_run_never_resolves_or_starts_processes(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), \
                patch('estate.resolve', side_effect=AssertionError('DNS')), \
                patch('estate.subprocess.Popen', side_effect=AssertionError('process')):
            self.assertEqual(estate.run(self.args('--dry-run', '--output', tmp)), 0)
            doc = json.loads(next(Path(tmp).glob('*/estate.json')).read_text())
            self.assertEqual(doc['status'], 'planned')

    def test_child_options_parse_and_keep_name_separate_from_ip(self):
        args = self.args('--all-tools', '--mode', 'parallel', '--no-crawl-redirects', '--service-checks')
        cmd = estate.child_arguments(args, 'app.lab.test', '127.0.0.1', Path('out'))
        parsed = cli.parser().parse_args(cmd[2:])
        self.assertEqual(parsed.target, 'app.lab.test')
        self.assertEqual(str(parsed.connect_ip), '127.0.0.1')
        self.assertEqual(parsed.scan, 'server')
        self.assertTrue(parsed.external_tools and parsed.retain_raw_evidence)
        self.assertEqual(parsed.enum, 'all')
        self.assertFalse(parsed.crawl_redirects)

    def test_reuse_verifies_ip_selection_hash_and_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = self.xml(root)
            doc = dict(scan_ip='127.0.0.1', nmap=state)
            source = root / 'summary.json'
            source.write_text(json.dumps(doc))
            rows, details = estate.reuse_services(source, '127.0.0.1', 'TCP 1-65535')
            self.assertEqual(rows[0]['port'], 18081)
            self.assertTrue(details['reused'])
            for ip, selection in [('127.0.0.2', 'TCP 1-65535'), ('127.0.0.1', 'TCP 80')]:
                with self.assertRaises(ValueError):
                    estate.reuse_services(source, ip, selection)
            doc['nmap']['status'] = 'partial'
            source.write_text(json.dumps(doc))
            with self.assertRaises(ValueError):
                estate.reuse_services(source, '127.0.0.1')
            doc['nmap']['status'] = 'completed'
            source.write_text(json.dumps(doc))
            (root / 'nmap/services.xml').write_text('changed')
            with self.assertRaises(ValueError):
                estate.reuse_services(source, '127.0.0.1')

    def test_estate_reuses_inventory_for_two_hostnames_and_reports_both(self):
        commands = []
        def child(argv, folder, timeout):
            commands.append(argv)
            output = Path(argv[argv.index('--output') + 1]) / 'run'
            output.mkdir(parents=True)
            state = self.xml(output)
            (output / 'summary.json').write_text(json.dumps(dict(scan_ip='127.0.0.1',
                nmap=state, ports=[dict(port=18081)], probes=[dict(url='http://' + argv[2], status=200)])))
            (output / 'report.html').write_text('fixture')
            return dict(status='completed', exit_code=0)
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            names = Path(tmp) / 'names'
            names.write_text('app.lab.test')
            with patch('estate.resolve', side_effect=self.resolved), patch.object(estate.Children, 'execute', side_effect=child):
                code = estate.run(self.args('--output', tmp, '--subdomain-file', str(names)))
            self.assertEqual(code, 0)
            self.assertEqual(len(commands), 2)
            self.assertNotIn('--reuse-services', commands[0])
            self.assertIn('--reuse-services', commands[1])
            doc = json.loads(next(Path(tmp).glob('estate_*/estate.json')).read_text())
            self.assertEqual(len(doc['scans']), 2)
            self.assertTrue(all(r['open_ports'] == 1 for r in doc['scans']))

    def test_missing_subfinder_is_incomplete_not_clean(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), \
                patch('estate.resolve', side_effect=self.resolved), patch('estate.shutil.which', return_value=None):
            args = self.args('--discover-only', '--output', tmp)
            args.no_passive = False
            self.assertEqual(estate.run(args), 2)

    def test_passive_timeout_retains_partial_names_and_missing_output_is_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.args()
            args.no_passive = False
            root = Path(tmp)
            def partial(argv, folder, timeout):
                folder.mkdir(exist_ok=True)
                (folder / 'names.txt').write_text('partial.lab.test\nevil.test\n')
                return dict(status='timeout')
            with patch('estate.shutil.which', return_value='/fake/subfinder'), \
                    patch('estate.resolve', side_effect=self.resolved), \
                    patch.object(estate.Children, 'execute', side_effect=partial):
                doc = estate.discover(args, 'lab.test', root)
            self.assertEqual(doc['sources'][0]['status'], 'timeout')
            self.assertEqual([r['host'] for r in doc['hosts']], ['lab.test', 'partial.lab.test'])
            (root / 'subfinder/names.txt').unlink()
            with patch('estate.shutil.which', return_value='/fake/subfinder'), \
                    patch('estate.resolve', side_effect=self.resolved), \
                    patch.object(estate.Children, 'execute', return_value=dict(status='completed')):
                self.assertEqual(estate.discover(args, 'lab.test', root)['sources'][0]['status'], 'incomplete')

    def test_estate_refuses_ignored_single_host_options(self):
        for extra in (['--cookie-file', 'secret'], ['--ports', '80'], ['--connect-ip', '127.0.0.1'],
                      ['--max-hosts', '501'], ['--host-workers', '5'], ['--skip', 'nmap'], ['--time-sqli']):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                estate.run(self.args(*extra))

    def test_host_process_timeout_and_cancel(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = estate.Children()
            result = runner.execute([__import__('sys').executable, '-c', 'import time;time.sleep(10)'], Path(tmp), .1)
            self.assertEqual(result['status'], 'timeout')
            self.assertFalse(runner.active)
            runner.cancel()
            self.assertEqual(runner.execute([], Path(tmp), 1)['status'], 'cancelled')

    def test_server_plan_uses_all_tcp_and_network_assessment(self):
        args = cli.parser().parse_args(['127.0.0.1', '--scan', 'server'])
        scan_modes.apply(args, [])
        self.assertTrue(args.all_ports)
        self.assertEqual(args.assessment, 'full')
        self.assertEqual(args.nmap_timeout, 3600)

    def test_explicit_pin_avoids_dns_and_retains_http_host(self):
        seen = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.headers['Host'])
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'<title>fixture</title>')
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            args = cli.parser().parse_args(['app.lab.test', '--connect-ip', '127.0.0.1'])
            with patch('scope.resolve_one', side_effect=AssertionError('DNS lookup')):
                scope.prepare_target(args)
                row = cli.probe('http://app.lab.test:' + str(server.server_port), scan_ip=args.scan_ip)
            self.assertEqual(row['status'], 200)
            self.assertEqual(seen, ['app.lab.test:' + str(server.server_port)])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)

    def test_cli_parallel_flag_reaches_main_batch(self):
        # Real CLI orchestration, mocked scanner execution: catches the old hardcoded sequential mode.
        import sys
        proxy = types.SimpleNamespace(**{k: getattr(sys, k) for k in ('stdin', 'stdout', 'argv')}, platform='linux')
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), \
                patch('cli.sys', proxy), patch('cli.probe', return_value=dict(status=200, url='http://127.0.0.1/')), \
                patch('cli.run_batch', return_value=[]) as batch:
            cli.main(['127.0.0.1', '--skip', 'nmap', '--profile', 'standard', '--no-crawl',
                '--mode', 'parallel', '--output', tmp, '--log-file', tmp + '/log', '--no-menu'])
            self.assertTrue(batch.called)
            self.assertEqual(batch.call_args_list[0].args[2], 'parallel')

    def test_server_cli_reuse_keeps_both_virtual_host_names(self):
        import sys
        seen = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.headers['Host'])
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'<title>local fixture</title>')
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def execute(job):
            self.assertEqual(job.tool, 'nmap')
            job.folder.mkdir(parents=True)
            (job.folder / 'services.xml').write_text('<nmaprun><host><address addr="127.0.0.1"/><ports>'
                '<port protocol="tcp" portid="' + str(server.server_port) + '"><state state="open"/>'
                '<service name="http"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>')
            return dict(name=job.name, tool=job.tool, folder=str(job.folder), argv=job.argv,
                outputs=job.outputs, status='completed', elapsed=0, note='', exit_code=0)
        proxy = types.SimpleNamespace(**{k: getattr(sys, k) for k in ('stdin', 'stdout', 'argv')}, platform='linux')
        try:
            with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), \
                    patch('cli.sys', proxy), patch('scope.resolve_one', side_effect=AssertionError('Unexpected DNS')), \
                    patch.object(cli.Runner, 'execute', side_effect=execute) as jobs:
                common = ['--scan', 'server', '--connect-ip', '127.0.0.1', '--profile', 'standard',
                    '--no-crawl', '--no-menu', '--ui', 'plain', '--log-file', tmp + '/log']
                self.assertEqual(cli.main(['first.lab.test', *common, '--output', tmp + '/first']), 0)
                source = next(Path(tmp + '/first').glob('*/summary.json'))
                self.assertEqual(cli.main(['second.lab.test', *common, '--output', tmp + '/second',
                    '--reuse-services', str(source)]), 0)
                self.assertEqual(jobs.call_count, 1)
                result = json.loads(next(Path(tmp + '/second').glob('*/summary.json')).read_text())
                self.assertTrue(result['nmap']['reused'])
                self.assertEqual(result['ports'][0]['port'], server.server_port)
                self.assertTrue(any(h.startswith('first.lab.test:') for h in seen))
                self.assertTrue(any(h.startswith('second.lab.test:') for h in seen))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)

    def test_aggregate_escapes_report_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            estate.write_report(Path(tmp), dict(domain='<script>', status='incomplete',
                scans=[dict(host='<img>', ip='127.0.0.1', status='failed')], discovery={}))
            doc = (Path(tmp) / 'report.html').read_text()
            self.assertNotIn('<script>', doc)
            self.assertIn('&lt;img&gt;', doc)
