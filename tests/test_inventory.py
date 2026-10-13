"""Rqtn Tool service inventory and high-impact exposure regression coverage."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import checks
import findings
import nmap_scan
import scope
import terminal
import webscan


class InventoryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.xml = self.root / 'services.xml'

    def xml_text(self):
        return '''<nmaprun><host><address addr="127.0.0.2"/><ports>
        <port protocol="tcp" portid="99"><state state="open"/></port></ports></host>
        <host><address addr="127.0.0.1"/><ports>
        <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"
          product="OpenSSH" version="8.9" extrainfo="lab &amp; fixture" method="probed" conf="10">
          <cpe>cpe:/a:openbsd:openssh:8.9</cpe></service></port>
        <port protocol="tcp" portid="80"><state state="open"/><service name="http" method="table"/></port>
        <port protocol="tcp" portid="bad"><state state="open"/></port>
        <port protocol="tcp" portid="443"><state state="filtered"/></port>
        <port protocol="udp" portid="53"><state state="open"/></port>
        </ports></host><runstats><finished exit="success"/></runstats></nmaprun>'''

    def test_inventory_versions_cpe_target_and_evidence_hash(self):
        self.xml.write_text(self.xml_text())
        rows, details = nmap_scan.inventory(self.xml, '127.0.0.1', 'completed')
        self.assertEqual([r['port'] for r in rows], [22, 80])
        self.assertEqual(rows[0]['version'], '8.9')
        self.assertEqual(rows[0]['extrainfo'], 'lab & fixture')
        self.assertEqual(rows[0]['cpe'], ['cpe:/a:openbsd:openssh:8.9'])
        self.assertEqual(rows[1]['version'], '')
        self.assertEqual(rows[1]['method'], 'table')
        self.assertEqual(details['status'], 'completed')
        self.assertEqual(details['sha256'], hashlib.sha256(self.xml.read_bytes()).hexdigest())

    def test_planned_does_not_read_stale_xml_and_missing_is_unavailable(self):
        self.xml.write_text(self.xml_text())
        self.assertEqual(nmap_scan.inventory(self.xml, 'lab.example', 'planned')[0], [])
        rows, details = nmap_scan.inventory(self.root / 'missing.xml', '127.0.0.1', 'failed')
        self.assertEqual(rows, [])
        self.assertEqual(details['status'], 'unavailable')

    def test_truncated_xml_preserves_completed_hosts_as_partial(self):
        self.xml.write_text(self.xml_text().split('<runstats>')[0] + '<host>')
        rows, details = nmap_scan.inventory(self.xml, '127.0.0.1', 'timeout')
        self.assertEqual([r['port'] for r in rows], [22, 80])
        self.assertEqual(details['status'], 'partial')
        self.assertTrue(details['xml_error'])
        with self.assertRaises(webscan.ET.ParseError):
            webscan.parse_nmap(self.xml, '127.0.0.1')

    def test_empty_missing_host_and_failure_are_distinct(self):
        for text, expected in (
            ('<nmaprun><host><address addr="127.0.0.1"/></host></nmaprun>', 'completed_no_open_ports'),
            ('<nmaprun><host><address addr="127.0.0.2"/></host></nmaprun>', 'inconclusive'),
            ('<nmaprun><host timedout="true"><address addr="127.0.0.1"/></host></nmaprun>', 'partial'),
            ('<nmaprun><host><address addr="127.0.0.1"/></host><runstats><finished exit="error"/></runstats></nmaprun>', 'partial')):
            self.xml.write_text(text)
            self.assertEqual(nmap_scan.inventory(self.xml, '127.0.0.1', 'completed')[1]['status'], expected)

    def test_url_top_ports_all_ports_and_version_command_are_explicit(self):
        for flags, expected in (([], ['--top-ports', '1000']), (['--url-port-only'], ['-p', '4280']), (['--top-ports', '2000'], ['--top-ports', '2000']),
                                (['--all-ports'], ['-p', '1-65535']), (['--ports', '22,4280'], ['-p', '22,4280'])):
            args = webscan.parser().parse_args(['https://lab.example:4280/', '--dry-run', *flags])
            with patch.object(scope, 'resolve_one', side_effect=AssertionError('No DNS')):
                scope.prepare_target(args)
            argv = nmap_scan.command(args, self.root)
            self.assertEqual(argv[argv.index(expected[0]):argv.index(expected[0]) + 2], expected)
            self.assertEqual(argv[argv.index('--version-intensity') + 1], '7')
            self.assertNotIn('--version-light', argv)
            self.assertEqual(args.url_only, '--url-port-only' in flags)
        args = webscan.parser().parse_args(['::1', '--dry-run', '--version-intensity', '9'])
        scope.prepare_target(args)
        self.assertIn('-6', nmap_scan.command(args, self.root))

    def test_conflicting_port_options_and_bad_intensity_are_rejected(self):
        for flags in (['--ports', '80', '--top-ports', '1000'], ['--top-ports', '1000', '--all-ports'], ['--version-intensity', '10']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                webscan.parser().parse_args(['127.0.0.1', *flags])

    def test_plain_service_table_shows_unknown_and_detected_versions(self):
        self.xml.write_text(self.xml_text())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            terminal.TerminalUI('plain').services_table(webscan.parse_nmap(self.xml, '127.0.0.1'))
        text = output.getvalue()
        self.assertIn('22/tcp open | ssh | OpenSSH 8.9 lab & fixture | probed', text)
        self.assertIn('80/tcp open | http | not identified | table', text)

    def test_cli_dry_run_records_port_selection_without_processes_or_http(self):
        real_os = webscan.os
        class PosixGuard:
            name = 'posix'
            def __getattr__(self, name):
                return getattr(real_os, name)
        output = self.root / 'plan.json'
        with patch.object(webscan, 'os', PosixGuard()), \
             patch.object(webscan.subprocess, 'Popen', side_effect=AssertionError('No process')), \
             patch.object(webscan, 'probe', side_effect=AssertionError('No HTTP')), \
             patch.object(scope, 'resolve_one', side_effect=AssertionError('No DNS')), \
             contextlib.redirect_stdout(io.StringIO()):
            code = webscan.main(['http://127.0.0.1', '--dry-run', '--top-ports', '1000',
                                 '--no-banner', '--output', str(output)])
        self.assertEqual(code, 0)
        document = json.loads(output.read_text())
        self.assertEqual(document['nmap']['status'], 'planned')
        self.assertEqual(document['nmap']['selection'], 'Top 1000 TCP ports')
        self.assertEqual(document['ports'], [])

    def test_cli_uses_inventory_and_partial_result_causes_coverage_exit(self):
        real_os = webscan.os
        class PosixGuard:
            name = 'posix'
            def __getattr__(self, name):
                return getattr(real_os, name)
        def execute(runner, job):
            self.assertEqual(job.tool, 'nmap')
            job.folder.mkdir(parents=True, exist_ok=True)
            (job.folder / 'services.xml').write_text(self.xml_text().split('<runstats>')[0])
            return dict(name=job.name, tool=job.tool, argv=job.argv, folder=str(job.folder),
                        outputs=job.outputs, status='timeout', elapsed=1, note='fixture')
        output = self.root / 'partial.json'
        terminal_text = io.StringIO()
        with patch.object(webscan, 'os', PosixGuard()), patch.object(webscan.Runner, 'execute', execute), \
             patch.object(webscan, 'tool_paths', return_value={}), \
             patch.object(webscan, 'probe', return_value=dict(url='http://127.0.0.1/', status=200, title='fixture')), \
             contextlib.redirect_stdout(terminal_text):
            code = webscan.main(['http://127.0.0.1', '--no-banner', '--ui', 'plain', '--enum', 'none',
                                 '--no-crawl', '--no-auto-sqli', '--skip', *[t for t in webscan.ALL_TOOLS if t != 'nmap'],
                                 '--output', str(output)])
        self.assertEqual(code, 2)
        document = json.loads(output.read_text())
        self.assertEqual(document['nmap']['status'], 'partial')
        self.assertEqual([r['port'] for r in document['ports']], [22, 80])
        self.assertIn('OpenSSH 8.9', terminal_text.getvalue())

    def test_report_shows_plan_reason_and_service_metadata_escaped(self):
        summary = dict(target='127.0.0.1', created='fixture', mode='sequential', outcome='Plan only',
                       ports=[], probes=[], jobs=[], nmap=dict(status='planned', selection='TCP 80', note='Plan only: scan not executed'))
        webscan.write_reports(self.root, summary)
        self.assertIn('scan not executed', (self.root / 'report.html').read_text())
        self.assertEqual(summary['coverage']['nmap_status'], 'planned')
        summary['ports'] = [dict(port=80, service='http', product='<script>bad</script>', version='1.2', cpe=['fixture'])]
        webscan.write_reports(self.root, summary)
        report = (self.root / 'report.html').read_text()
        self.assertIn('&lt;script&gt;bad&lt;/script&gt;', report)
        self.assertEqual(summary['coverage']['identified_service_versions'], 1)

    def test_high_impact_signatures_and_false_positive_controls(self):
        positives = [('/.env.production', b'DB_HOST=lab\nDB_PASSWORD=s3cret-lab\n'),
                     ('/backup.sql', b'INSERT INTO users VALUES (1, "lab");'),
                     ('/database.db', b'SQLite format 3\x00fixture'),
                     ('/server.key.pem', b'-----BEGIN PRIVATE KEY-----\nfixture'),
                     ('/wp-config.php.bak', b"<?php define('DB_PASSWORD', 'lab-secret');"),
                     ('/actuator/env', json.dumps({'propertySources': [{'properties': {'db.password': {'value': 'lab-secret'}}}]}).encode())]
        for path, body in positives:
            title = checks.sensitive_signature(path, body)
            self.assertTrue(title, path)
            self.assertEqual(checks.exposure_severity(title), 'high')
        for body in (b'<html>DB_HOST=lab\nDB_PASSWORD=fixture</html>', b'not found', b'{"propertySources": "invalid"}'):
            self.assertEqual(checks.sensitive_signature('/.env', body), '')
        masked = json.dumps({'propertySources': [{'properties': {'db.password': {'value': '******'}}}]}).encode()
        self.assertEqual(checks.sensitive_signature('/actuator/env', masked), '')
        self.assertEqual(checks.exposure_severity(checks.sensitive_signature('/.env', b'DB_HOST=lab\nDB_PASSWORD=${SECRET}\n')), 'medium')
        self.assertFalse(checks.credential_fields(b'DB_PASSWORD="" # empty\nDB_TOKEN=****** # masked\n'))
        self.assertTrue(checks.sensitive_signature('/.git/config', b'[core]\nrepositoryformatversion = 0\n'))

    def test_exposure_evidence_keeps_secrets_out_of_title_and_adapter_labels(self):
        wordlist = self.root / 'paths.txt'
        wordlist.write_text('.env.production\n')
        def fetch(url, *args, **kwargs):
            body = b'DB_HOST=lab\nDB_PASSWORD=lab-secret-value\n' if url.endswith('.env.production') else b'not found'
            return dict(status=200, headers=[], body=body, truncated=False)
        folder = self.root / 'files'
        with patch.object(checks, 'fetch', side_effect=fetch):
            state = checks.run_sensitive_files(['http://127.0.0.1/'], '127.0.0.1', wordlist, folder, threading.Event(), rate=1000, retain_raw=True)
        row = state['checks'][0]
        self.assertEqual(row['severity'], 'high')
        self.assertNotIn('lab-secret-value', row['title'])
        self.assertIn(b'lab-secret-value', (folder / row['responses'][0]['body_file']).read_bytes())
        summary = dict(target='127.0.0.1', jobs=[dict(name='files', tool='checks', status='completed', folder=str(folder), outputs=['checks.json'], argv=[])])
        observations, issues = findings.collect(self.root, summary)
        self.assertEqual(issues, [])
        self.assertEqual(observations[0]['validation_status'], 'needs_validation')
        self.assertEqual(observations[0]['severity'], 'high')
