from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import cli
import scan_modes
import tool_coverage
import web_engine
from terminal import TerminalUI


class CoverageTests(unittest.TestCase):
    def args(self, *options):
        argv = ['127.0.0.1', *options]
        args = cli.parser().parse_args(argv)
        cli.apply_profile(args, argv)
        scan_modes.apply(args, argv)
        return args

    def test_all_tools_enables_all_directory_engines_and_external_policy(self):
        args = self.args('--scan', 'deep', '--all-tools')
        self.assertTrue(args.external_tools and args.retain_raw_evidence)
        self.assertEqual(args.enum, 'all')
        with tempfile.TemporaryDirectory() as temp:
            jobs = cli.build_jobs(args, Path(temp), ['http://127.0.0.1/'], {})
        self.assertEqual({j.tool for j in jobs},
                         {'httpx', 'whatweb', 'ffuf', 'gobuster', 'feroxbuster',
                          'dirsearch', 'nikto', 'nuclei'})
        self.assertEqual(args.skip, [])
        args = self.args('--all-tools', '--enum', 'none', '--skip', 'nikto', '--no-auto-sqli')
        self.assertEqual(args.enum, 'none')
        self.assertIn('nikto', args.skip)
        self.assertTrue(args.no_auto_sqli)
        with self.assertRaises(ValueError):
            self.args('--all-tools', '--only', 'whatweb')
        with self.assertRaises(ValueError):
            self.args('--all-tools', '--assessment', 'network')

    def test_menu_twelve_selects_complete_deep_plan(self):
        with patch('builtins.input', return_value='12'), patch.object(TerminalUI, 'message'):
            result = TerminalUI('plain').prompt_scan()
        self.assertEqual(result, dict(scan='deep', only=None, all_tools=True))

    def test_partial_jobs_and_parser_failures_never_become_clean_results(self):
        summary = dict(jobs=[dict(tool='nuclei', name='scan', status='completed'),
                             dict(tool='nikto', name='timeout', status='timeout', note='Budget reached')],
                       parse_issues=[dict(job='scan', kind='parse_error')], findings=[])
        rows = tool_coverage.build(summary, ['nuclei', 'nikto'])
        self.assertTrue(all(r['status'] == 'incomplete' for r in rows))
        self.assertEqual(rows[0]['parse_issues'], 1)
        self.assertIn('Budget reached', rows[1]['reason'])
        summary['parse_issues'] = []
        self.assertEqual(tool_coverage.build(summary, ['nuclei'])[0]['status'], 'completed_no_matches')

    def test_missing_disabled_and_inapplicable_have_distinct_explanations(self):
        summary = dict(tool_inventory={'nuclei': None, 'testssl': '/testssl', 'dalfox': '/dalfox'},
                       probes=[dict(url='http://127.0.0.1/', status=200)],
                       tool_selection={'skipped': ['nikto']})
        rows = {r['tool']: r for r in tool_coverage.build(summary, ['nuclei', 'testssl', 'dalfox', 'nikto'])}
        self.assertEqual(rows['nuclei']['status'], 'unavailable')
        self.assertEqual(rows['testssl']['status'], 'not_applicable')
        self.assertEqual(rows['dalfox']['status'], 'no_candidates')
        self.assertEqual(rows['nikto']['status'], 'disabled')

    def test_dalfox_reflections_are_observations_not_vulnerability_matches(self):
        for tier in ('R', 'I', 'V', 'A'):
            row = list(web_engine.observations('dalfox',
                dict(type=tier, data='http://127.0.0.1/?q=test', param='q', severity='high'),
                'http://127.0.0.1/'))[0]
            self.assertEqual(row[0], 'scanner_match' if tier in ('V', 'A') else 'observation')
            if tier in ('R', 'I'):
                self.assertEqual(row[-1], 'info')


if __name__ == '__main__':
    unittest.main()
