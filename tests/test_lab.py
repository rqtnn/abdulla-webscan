import json
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import findings
import webscan


class LabTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_nikto_hostname_allows_dns_and_keeps_host_sni(self):
        args = webscan.parser().parse_args(['https://lab.example:4280', '--dry-run'])
        jobs = webscan.build_jobs(args, self.root, ['https://lab.example:4280/'], {})
        job = next(j for j in jobs if j.tool == 'nikto')
        self.assertNotIn('-nolookup', job.argv)
        self.assertEqual(job.argv[job.argv.index('-h') + 1], 'https://lab.example:4280/')
        self.assertIn('-nocheck', job.argv)

    def test_template_discovery_env_xdg_explicit_and_empty(self):
        home = self.root / 'home'
        home.mkdir()
        xdg = self.root / 'xdg'
        templates = xdg / 'nuclei/nuclei-templates'
        templates.mkdir(parents=True)
        (templates / 'test.yaml').write_text('id: fixture')
        args = webscan.parser().parse_args(['127.0.0.1'])
        with patch.object(webscan.Path, 'home', return_value=home), patch.dict(webscan.os.environ,
                {'NUCLEI_TEMPLATES_DIR': '', 'XDG_DATA_HOME': str(xdg), 'XDG_DATA_DIRS': str(self.root / 'empty')}):
            self.assertEqual(webscan.template_path(args), templates.resolve())
            args.templates = self.root / 'explicit-missing'
            self.assertEqual(webscan.template_path(args), args.templates.resolve())
            jobs = webscan.build_jobs(args, self.root, ['http://127.0.0.1/'], {})
            self.assertIn('No YAML templates', next(j for j in jobs if j.tool == 'nuclei').skip_reason)

    def test_lab_profile_respects_explicit_limits_and_opt_out(self):
        argv = ['127.0.0.1', '--profile', 'lab', '--crawl-pages=12', '--sqli-techniques', 'BEU', '--no-active-checks']
        args = webscan.parser().parse_args(argv)
        webscan.apply_profile(args, argv)
        self.assertEqual(args.crawl_pages, 12)
        self.assertEqual(args.sqli_techniques, 'BEU')
        self.assertEqual(args.crawl_depth, 5)
        self.assertFalse(args.active_checks)
        job = webscan.sqlmap_job(args, self.root, 'http://127.0.0.1/?id=1', 'id', 'test', True)
        self.assertIn('--technique=BEU', job.argv)
        self.assertEqual(job.timeout, 180)

    def test_sqlmap_outcomes_distinguish_handler_gaps_matches_and_clean_exit(self):
        job = dict(status='completed', folder=str(self.root))
        cases = [('ordinary exit', 'inconclusive'),
                 ('[CRITICAL] all tested parameters do not appear to be injectable', 'no_match_in_tested_techniques'),
                 ("[WARNING] provided value for parameter 'id' is empty\n[CRITICAL] all tested parameters do not appear to be injectable", 'inconclusive'),
                 ('Parameter: id (GET)\n    Type: boolean-based blind\n    Title: fixture\n    Payload: id=1\n', 'candidate_needs_validation'),
                 ('[ERROR] connection failed', 'inconclusive')]
        for text, expected in cases:
            with self.subTest(expected=expected):
                (self.root / 'console.log').write_text(text)
                self.assertEqual(findings.sqlmap_outcome(job), expected)
        self.assertEqual(findings.sqlmap_outcome(dict(job, status='timeout')), 'incomplete')

    def test_grouped_headers_keep_individual_evidence_and_origin_boundaries(self):
        crawl = self.root / 'crawl'
        crawl.mkdir()
        pages = [dict(url=u, status=200, headers=[['Content-Type', 'text/html']]) for u in (
            'https://127.0.0.1/a', 'https://127.0.0.1/b', 'https://127.0.0.1:8443/a')]
        (crawl / 'crawl.json').write_text(json.dumps(dict(pages=pages)))
        summary = dict(target='127.0.0.1', jobs=[dict(name='crawl', tool='crawler', argv=[],
            folder=str(crawl), outputs=['crawl.json'], status='completed', elapsed=0, note='')],
            ports=[], probes=[], created='test', mode='sequential', outcome='test')
        webscan.write_reports(self.root, summary)
        self.assertEqual(summary['coverage']['severity_counts']['low'], 8)
        self.assertEqual(summary['coverage']['severity_instance_counts']['low'], 12)
        self.assertEqual(len([f for f in summary['findings'] if f['category'] == 'configuration']), 12)
        self.assertTrue(all(f['evidence'][0]['sha256'] for f in summary['findings']))
        self.assertIn('2 affected URL(s)', (self.root / 'report.html').read_text())

    def test_phpinfo_requires_content_signature_not_filename(self):
        row = dict(url='http://127.0.0.1/phpinfo.php', status=200, headers=[])
        self.assertEqual(len(list(findings.observations('crawler', row, row['url']))), 1)
        row['phpinfo_signature'] = True
        observations = list(findings.observations('crawler', row, row['url']))
        self.assertEqual(observations[-1][1], 'phpinfo-content')

    def test_report_only_is_offline_and_preserves_source_run_version(self):
        summary = dict(version='1.2.0', target='127.0.0.1', jobs=[], ports=[], probes=[],
                       created='fixture', mode='sequential', outcome='existing run')
        (self.root / 'summary.json').write_text(json.dumps(summary))
        with patch.object(webscan, 'probe', side_effect=AssertionError('no HTTP')), \
             patch.object(webscan, 'tool_paths', side_effect=AssertionError('no subprocess')), \
             contextlib.redirect_stdout(io.StringIO()):
            result = webscan.main(['--report-only', str(self.root)])
        self.assertEqual(result, 0)
        updated = json.loads((self.root / 'summary.json').read_text())
        self.assertEqual(updated['version'], '1.2.0')
        self.assertEqual(updated['report_generator_version'], webscan.VERSION)
        self.assertEqual(updated['report_schema_version'], 3)


if __name__ == '__main__':
    unittest.main()
