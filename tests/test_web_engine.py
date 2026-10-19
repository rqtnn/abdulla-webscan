import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import cli
from findings import collect
import scan_modes
import web_engine
from web_review import web_leads


class WebEngineTests(unittest.TestCase):
    def args(self, *extra):
        args = cli.parser().parse_args(['127.0.0.1', '--external-tools', '--retain-raw-evidence', *extra])
        scan_modes.apply(args, [])
        return args

    def test_isolated_plans_and_crawl_dependency(self):
        for tool in web_engine.TOOLS:
            args = self.args('--only', tool)
            self.assertEqual(set(cli.ALL_TOOLS) - set(args.skip), {tool})
            self.assertEqual(args.no_crawl, tool != 'dalfox')
        with self.assertRaises(ValueError):
            self.args('--only', 'dalfox', '--no-active-checks')

    def test_commands_have_limits_and_no_automatic_redirect_or_waf_bypass(self):
        args = self.args()
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            k, _, reason = web_engine.command('katana', None, 'https://127.0.0.1:8443/', folder, args)
            self.assertIn('--insecure', reason)
            self.assertIn('-dr', k)
            self.assertEqual(k[k.index('-rl') + 1], '5')
            scope = k[k.index('-cs') + 1]
            import re
            self.assertIsNone(re.search(scope, 'https://127.0.0.1:84430/'))
            self.assertIsNone(re.search(scope, 'https://127.0.0.2:8443/'))
            d, _, _ = web_engine.command('dalfox', None, 'http://127.0.0.1/?q=one', folder, args, 'q')
            self.assertIn('--insecure=false', d)
            self.assertIn('--skip-discovery', d)
            self.assertIn('--skip-mining', d)
            self.assertEqual(d[d.index('--waf-bypass') + 1], 'off')
            self.assertNotIn('--blind-oob', d)
            t, _, _ = web_engine.command('testssl', None, 'https://127.0.0.1:8443/', folder, args)
            self.assertIn('--protocols', t)
            self.assertIn('none', t)
            self.assertNotIn('--vulnerable', t)
            web_engine.prepare('dalfox', folder)
            self.assertEqual(json.loads((folder / 'engine.json').read_text()), {'scan': {}})

    def test_cli_contract_rejects_unsupported_versions_without_scan(self):
        with patch('web_engine.subprocess.run') as run:
            run.return_value.returncode = 0
            run.return_value.stdout = 'old dalfox url usage'
            run.return_value.stderr = ''
            self.assertIn('Unsupported CLI', web_engine.compatibility('dalfox', '/fake/dalfox'))
            self.assertEqual(run.call_args.args[0], ['/fake/dalfox', 'scan', '--help'])

    def test_discovery_filters_method_host_origin_actions_and_secrets(self):
        base = 'http://127.0.0.1:8080/'
        urls = [(base + '?q=1', 'GET'), (base + 'api?id=2', 'GET'),
                ('http://127.0.0.1:8081/', 'GET'), ('http://other.test/', 'GET'),
                (base + 'logout', 'GET'), (base + '?token=x', 'GET'), (base, 'POST')]
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / 'results.jsonl').write_text('\n'.join(json.dumps(dict(request=dict(endpoint=url, method=method))) for url, method in urls))
            job = dict(tool='katana', status='completed', folder=tmp)
            found, rejected = web_engine.discovered_urls([job], [base], '127.0.0.1', 20)
            self.assertEqual(found, [base + '?q=1', base + 'api?id=2'])
            self.assertEqual(rejected, 5)
            self.assertEqual(len(web_engine.discovered_urls([job], [base], '127.0.0.1', 1)[0]), 1)

    def test_dalfox_findings_exit_one_partial_coverage_and_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            doc = dict(meta=dict(incomplete=False), findings=[dict(type='V', data='http://127.0.0.1/?q=proof', param='q', severity='High', confidence='high')])
            fake = folder / 'dalfox'
            fake.write_text('#!' + sys.executable + '\nfrom pathlib import Path\nimport sys\n'
                           'Path(sys.argv[sys.argv.index("-o")+1]).write_text(' + repr(json.dumps(doc)) + ')\nraise SystemExit(1)\n')
            fake.chmod(0o755)
            args = self.args('--only', 'dalfox')
            argv, output, reason = web_engine.command('dalfox', str(fake), 'http://127.0.0.1/?q=1', folder, args, 'q')
            with contextlib.redirect_stdout(io.StringIO()):
                result = cli.Runner().execute(cli.Job('Dalfox fixture', 'dalfox', argv, folder, 5, [output], reason))
            self.assertEqual((result['status'], result['exit_code']), ('completed', 1))
            findings, issues = collect(folder, dict(target='127.0.0.1', jobs=[result], retain_raw_evidence=True))
            self.assertEqual(issues, [])
            self.assertEqual(findings[0]['detection_tier'], 'V')
            self.assertEqual(findings[0]['confidence'], 'high')
            self.assertTrue(findings[0]['evidence'][0]['sha256'])
            doc['meta']['incomplete'] = True
            (folder / output).write_text(json.dumps(doc))
            self.assertIn('incomplete', web_engine.completion('dalfox', folder))

    def test_reflection_not_promoted_to_xss_lead_and_foreign_results_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            rows = [dict(type='R', data='http://127.0.0.1/?q=a', param='q'),
                    dict(type='V', data='http://127.0.0.1:81/?q=a', param='q')]
            (folder / 'results.json').write_text(json.dumps(dict(meta={}, findings=rows)))
            job = dict(name='fixture', tool='dalfox', status='completed', folder=tmp,
                       argv=['dalfox', 'scan', 'http://127.0.0.1/'], outputs=['results.json'])
            findings, issues = collect(folder, dict(target='127.0.0.1', jobs=[job]))
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]['severity'], 'info')
            self.assertEqual(web_leads(findings), [])
            self.assertEqual(len(issues), 1)

    def test_tls_warning_is_a_coverage_gap_not_a_vulnerability(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / 'results.json').write_text(json.dumps([dict(id='problem', severity='WARN', finding='No connection')]))
            self.assertIn('warnings', web_engine.completion('testssl', folder))
            with self.assertRaises(ValueError):
                list(web_engine.observations('testssl', dict(id='problem', severity='WARN'), 'https://127.0.0.1/'))
            self.assertEqual(list(web_engine.observations('testssl', dict(id='TLS1_2', severity='OK'), 'https://127.0.0.1/')), [])

    def test_dalfox_stage_independent_of_sqlmap_and_authenticated_deferral(self):
        args = self.args('--only', 'dalfox', '--no-auto-sqli', '--dry-run')
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            summary = dict(jobs=[])
            cli.run_web_engines(args, Path(tmp), ['http://127.0.0.1/'], summary, cli.Runner(True), {},
                                [dict(url='http://127.0.0.1/?q=1', parameter='q')])
            self.assertEqual([j['tool'] for j in summary['jobs']], ['dalfox'])
            args.session = object()
            with patch.object(cli.Runner, 'execute') as execute:
                cli.run_web_engines(args, Path(tmp), ['http://127.0.0.1/'], summary, cli.Runner(), {})
                execute.assert_not_called()

    def test_timeout_kills_engine_process_and_no_output_is_not_clean(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            folder = Path(tmp)
            fake = folder / 'slow'
            fake.write_text('#!' + sys.executable + '\nimport time\ntime.sleep(20)\n')
            fake.chmod(0o755)
            job = cli.Job('slow fixture', 'katana', [str(fake)], folder, 0.1, ['results.jsonl'])
            self.assertEqual(cli.Runner().execute(job)['status'], 'timeout')
            self.assertIn('unknown', web_engine.completion('katana', folder))

    def test_katana_parameters_feed_dalfox_with_sqlmap_disabled(self):
        """Exercise orchestration and both external processes, using controlled exports."""
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(tmp)
            base = 'http://127.0.0.1:8080/'
            row = dict(request=dict(method='GET', endpoint=base + 'search?q=word'),
                       response=dict(status_code=200))
            binaries = {}
            for tool, content in [('katana', json.dumps(row) + '\n'),
                                  ('dalfox', json.dumps(dict(meta=dict(incomplete=False), findings=[])))]:
                fake = root / tool
                _, flags = web_engine.CONTRACTS[tool]
                fake.write_text('#!' + sys.executable + '\nimport sys\nfrom pathlib import Path\n'
                    'if "-h" in sys.argv or "--help" in sys.argv:\n print(' + repr(' '.join(flags)) + ');raise SystemExit(0)\n'
                    'Path(sys.argv[sys.argv.index("-o")+1]).write_text(' + repr(content) + ')\n')
                fake.chmod(0o755)
                binaries[tool] = str(fake)
            args = self.args('--only', 'katana', 'dalfox', '--no-auto-sqli')
            args.active_checks = False
            args.sensitive_files = False
            args.scan_ip = '127.0.0.1'
            summary = dict(target='127.0.0.1', jobs=[])
            runner = cli.Runner()
            cli.run_web_engines(args, root, [base], summary, runner, binaries)
            def local_crawl(seeds, target, folder, stop, pages, depth, rate, timeout, insecure, result, **options):
                self.assertIn(base + 'search?q=word', seeds)
                result.update(status='completed', discovered=[], pages=[], forms=[], limits=[])
            with patch.object(cli, 'crawl', side_effect=local_crawl):
                cli.run_discovered(args, root, [base], summary, runner, binaries)
            self.assertEqual([j['tool'] for j in summary['jobs']], ['katana', 'crawler', 'dalfox'])
            self.assertEqual(summary['injection']['selected'][0]['parameter'], 'q')
            self.assertEqual(summary['injection']['status'], 'disabled')
            self.assertEqual(summary['jobs'][-1]['status'], 'completed')


if __name__ == '__main__':
    unittest.main()
