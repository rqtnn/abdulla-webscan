"""Local/offline regressions for the HTTPS-only-port and silent-stop report."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import nmap_scan
import scope
import webscan


class URLPortDiscovery(unittest.TestCase):
    def test_https_defaults_to_top_1000_without_dns_in_plan(self):
        args = webscan.parser().parse_args(['https://lab.invalid', '--dry-run'])
        with patch.object(scope, 'resolve_one', side_effect=AssertionError('DNS')):
            scope.prepare_target(args)
        self.assertFalse(args.url_only)
        command = nmap_scan.command(args, Path('/tmp/plan'))
        self.assertNotIn('-p', command)
        self.assertEqual(command[command.index('--top-ports') + 1], '1000')

    def test_explicit_single_port_and_syn_modes(self):
        args = webscan.parser().parse_args(['https://lab.invalid', '--url-port-only', '--nmap-scan', 'syn', '--dry-run'])
        scope.prepare_target(args)
        command = nmap_scan.command(args, Path('/tmp/plan'))
        self.assertIn('-sS', command)
        self.assertEqual(command[command.index('-p') + 1], '443')
        with self.assertRaises(ValueError):
            scope.prepare_target(webscan.parser().parse_args(['127.0.0.1', '--url-port-only', '--dry-run']))

    def test_single_port_conflicts_are_rejected(self):
        for flags in (['--all-ports'], ['--ports', '443'], ['--top-ports', '1000']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                webscan.parser().parse_args(['https://lab.invalid', '--url-port-only', *flags])

    def test_other_observed_web_ports_are_probed_and_tls_errors_printed(self):
        with tempfile.TemporaryDirectory() as temp:
            root, output, seen = Path(temp), io.StringIO(), []
            def execute(runner, job):
                self.assertEqual(job.tool, 'nmap')
                self.assertIn('--top-ports', job.argv)
                return dict(name=job.name, tool='nmap', folder=str(job.folder), argv=job.argv,
                    command='fixture', outputs=[], status='completed', elapsed=0, note='')
            def probe(url, *args, **kwargs):
                seen.append(url)
                if url.startswith('https:'):
                    return {'url': url, 'error': 'CERTIFICATE_VERIFY_FAILED fixture'}
                return {'url': url, 'status': 200, 'title': ''}
            services = [dict(port=p, service='http') for p in (80, 8080)]
            with patch.object(scope, 'resolve_one', return_value='127.0.0.1'), \
                 patch.object(webscan.Runner, 'execute', execute), \
                 patch.object(nmap_scan, 'inventory', return_value=(services, {'status': 'completed', 'note': ''})), \
                 patch.object(webscan, 'probe', side_effect=probe), \
                 patch.object(webscan, 'tool_paths', return_value={}), contextlib.redirect_stdout(output):
                code = webscan.main(['https://lab.invalid', '--no-crawl', '--output', str(root), '--rate', '50'])
            self.assertEqual(code, 2)  # Explicit HTTPS failure remains an honest coverage gap.
            self.assertIn('http://lab.invalid:80/', seen)
            self.assertIn('http://lab.invalid:8080/', seen)
            self.assertIn('[HTTP ERROR]', output.getvalue())
            self.assertIn('[TLS]', output.getvalue())
            self.assertIn('[DISCOVERY]', output.getvalue())
            document = json.loads(next(root.glob('*/summary.json')).read_text())
            self.assertEqual(len(document['ports']), 2)
            self.assertTrue(document['findings'])


if __name__ == '__main__':
    unittest.main()
