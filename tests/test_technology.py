import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import cli
from findings import collect
import scan_modes
import technology
import wpscan_adapter


class TechnologyTests(unittest.TestCase):
    def test_html_signals_and_malformed_optional_attributes(self):
        hints = technology.detect('http://127.0.0.1/blog/', [],
            '<meta name><meta name="generator" content><meta name="generator" content="WordPress 6.7">'
            '<script src="/blog/wp-includes/test.js"></script>')
        self.assertEqual({h['source'] for h in hints}, {'generator_meta', 'same_origin_asset'})

    def test_prose_and_foreign_assets_are_not_fingerprints(self):
        self.assertEqual(technology.detect('http://127.0.0.1/', [],
            'This article mentions WordPress <script src="https://foreign.test/wp-content/a.js"></script>'), [])

    def test_headers_produce_explicit_observations(self):
        self.assertEqual(technology.detect('http://127.0.0.1/', [('X-Powered-By', 'PHP/8.2')]),
                         [dict(name='PHP', source='x_powered_by')])

    def test_wordpress_is_scoped_to_scheme_and_port(self):
        summary = dict(probes=[dict(url='http://127.0.0.1:8080/', status=200,
            technologies=[dict(name='WordPress', source='generator_meta')])])
        rows = technology.plan(['http://127.0.0.1:8080/', 'http://127.0.0.1:8081/',
                                'https://127.0.0.1:8080/'], summary)
        self.assertEqual([r['wpscan'] for r in rows], ['eligible', 'deferred', 'deferred'])

    def test_whatweb_can_supply_wordpress_hint(self):
        row = dict(category='technology', check='WordPress', url='http://127.0.0.1/')
        self.assertEqual(technology.plan([row['url']], dict(findings=[row]))[0]['wpscan'], 'eligible')

    def test_explicit_tool_plan_stays_isolated(self):
        args = cli.parser().parse_args(['127.0.0.1', '--only', 'wpscan'])
        scan_modes.apply(args, [])
        self.assertEqual(set(cli.ALL_TOOLS) - set(args.skip), {'wpscan'})
        self.assertTrue(args.no_crawl)
        self.assertFalse(args.api_discovery)

    def test_non_wordpress_does_not_start_specialized_scanner(self):
        args = cli.parser().parse_args(['127.0.0.1', '--dry-run'])
        with tempfile.TemporaryDirectory() as tmp, patch.object(cli.Runner, 'execute') as execute:
            summary = dict(probes=[], jobs=[])
            cli.run_technology_plan(args, Path(tmp), ['http://127.0.0.1/'], summary, cli.Runner(True), {})
            execute.assert_not_called()
            self.assertEqual(summary['technology_plan'][0]['wpscan'], 'deferred')

    def test_wpscan_exit_five_is_completed_and_has_bounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = root / 'wpscan'
            fake.write_text('#!' + sys.executable + '\nimport json,sys\nfrom pathlib import Path\n'
                'Path(sys.argv[sys.argv.index("--output")+1]).write_text(json.dumps({"version":{"number":"6.7"},"plugins":{}}))\n'
                'raise SystemExit(5)\n')
            fake.chmod(0o755)
            args = cli.parser().parse_args(['127.0.0.1', '--only', 'wpscan'])
            summary = dict(target='127.0.0.1', probes=[], jobs=[])
            with contextlib.redirect_stdout(io.StringIO()):
                cli.run_technology_plan(args, root, ['http://127.0.0.1/'], summary, cli.Runner(), {'wpscan': str(fake)})
            job = summary['jobs'][0]
            self.assertEqual((job['status'], job['exit_code']), ('completed', 5))
            self.assertIn('--request-timeout', job['argv'])
            self.assertIn('--ignore-main-redirect', job['argv'])
            self.assertEqual(job['argv'][job['argv'].index('--enumerate') + 1], 'vp,vt')
            findings, issues = collect(root, summary)
            self.assertFalse(issues)
            self.assertEqual(findings[0]['category'], 'technology')

    def test_offline_component_cve_metadata_has_no_guessed_severity(self):
        doc = dict(version=dict(number='6.7', vulnerabilities=[dict(title='Example advisory',
            references=dict(cve=['2025-12345']), fixed_in='6.7.1')]), plugins={})
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'results.json').write_text(json.dumps(doc))
            summary = dict(target='127.0.0.1', jobs=[dict(name='WPScan', tool='wpscan', status='completed',
                argv=['wpscan', '--url', 'http://127.0.0.1/'], folder=str(root), outputs=['results.json'])])
            findings, issues = collect(root, summary)
            self.assertFalse(issues)
            vuln = next(f for f in findings if f['category'] == 'scanner_match')
            self.assertEqual(vuln['cve_ids'], ['CVE-2025-12345'])
            self.assertEqual(vuln['severity'], 'unknown')
            self.assertIn('fixed version', vuln['recommendation'])
            self.assertTrue(vuln['evidence'][0]['sha256'])

    def test_aborted_scan_is_not_an_empty_success(self):
        with self.assertRaises(ValueError):
            list(wpscan_adapter.records(dict(scan_aborted='Not WordPress')))


if __name__ == '__main__':
    unittest.main()
