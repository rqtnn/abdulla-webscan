"""Network assessment and slow-peer integration: loopback only, no external targets."""
import base64
import contextlib
import hashlib
import http.server
import io
import json
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import assessment
import crawler
import nmap_scan
import transport
import webscan
from scope import RequestGate


class SlowHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/headers':
            wire = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'
        else:
            self.send_response(200)
            self.send_header('Content-Length', '30')
            self.end_headers()
            wire = b'x' * 30
        try:
            for byte in wire:
                self.connection.sendall(bytes([byte]))
                time.sleep(0.04)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *args):
        pass


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_service_identity_wins_over_port_and_no_version_cve_inference(self):
        rows = assessment.inventory_checks('lab.invalid', [
            dict(port=3306, service='http', version='ancient'),
            dict(port=9999, service='mysql', version='0.0'),
            dict(port=21, service='ftp', tunnel='ssl'),
            dict(port=22, service='ssh')])
        self.assertEqual([r['check'] for r in rows], ['network-database', 'network-management'])
        self.assertEqual(rows[0]['url'], 'tcp://lab.invalid:9999')
        self.assertFalse(any('CVE' in r['title'] for r in rows))

    def test_port_convention_is_explicitly_lower_confidence(self):
        rows = assessment.inventory_checks('::1', [dict(port=6379, service='unknown'), dict(port=3306, service='mysql', method='table')])
        self.assertEqual(rows[0]['confidence'], 'port_convention_only')
        self.assertEqual(rows[0]['url'], 'tcp://[::1]:6379')
        self.assertEqual(rows[1]['confidence'], 'port_convention_only')

    def test_service_script_allowlist_and_host_script_scope(self):
        args = webscan.parser().parse_args(['127.0.0.1', '--service-checks', '--dry-run'])
        args.scan_ip = '127.0.0.1'
        cmd = nmap_scan.command(args, self.root)
        self.assertEqual(cmd[cmd.index('--script') + 1], 'ssh2-enum-algos,smb2-security-mode')
        path = self.root / 'services.xml'
        path.write_text('''<nmaprun><host><address addr="127.0.0.1"/><ports>
          <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/>
          <script id="ssh2-enum-algos"><table key="kex_algorithms"><elem>diffie-hellman-group1-sha1</elem></table></script>
          <script id="unapproved" output="ignored"/></port>
          <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
          </ports><hostscript><script id="smb2-security-mode" output="Message signing enabled but not required"/></hostscript></host>
          <host><address addr="127.0.0.2"/><ports><port protocol="tcp" portid="21"><state state="open"/></port></ports></host></nmaprun>''')
        ports, _ = nmap_scan.read_xml(path, '127.0.0.1')
        self.assertEqual([s['id'] for s in ports[0]['scripts']], ['ssh2-enum-algos'])
        checks = assessment.inventory_checks('127.0.0.1', ports)
        self.assertIn('network-smb-signing', [r['check'] for r in checks])
        self.assertIn('network-ssh-legacy-algorithms', [r['check'] for r in checks])
        self.assertNotIn('network-ftp', [r['check'] for r in checks])
        disabled = assessment.inventory_checks('127.0.0.1', [dict(port=445, service='microsoft-ds',
            scripts=[dict(id='smb2-security-mode', output='Message signing disabled')])])
        self.assertIn('network-smb-signing', [r['check'] for r in disabled])

    def test_required_signing_and_modern_ssh_are_not_weak_configuration_matches(self):
        rows = assessment.inventory_checks('127.0.0.1', [
            dict(port=445, service='microsoft-ds', scripts=[dict(id='smb2-security-mode', output='Message signing enabled and required')]),
            dict(port=22, service='ssh', scripts=[dict(id='ssh2-enum-algos', values=['curve25519-sha256', 'ssh-ed25519'])])])
        self.assertFalse(any(r['check'] in ('network-smb-signing', 'network-ssh-legacy-algorithms') for r in rows))

    def test_tls_expiry_and_failure_are_separate_from_negotiation_errors(self):
        conn = MagicMock()
        conn.sock.getpeercert.side_effect = lambda binary_form=False: b'cert' if binary_form else {'notAfter': 'Jan 10 00:00:00 2030 GMT'}
        conn.sock.cipher.return_value = ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
        conn.sock.version.return_value = 'TLSv1.3'
        with patch.object(assessment, 'connection', return_value=conn), \
             patch.object(assessment.time, 'time', return_value=ssl.cert_time_to_seconds('Jan 01 00:00:00 2030 GMT')):
            row = assessment.tls_check('https://lab.invalid/', '127.0.0.1', 1)
        self.assertEqual(row['check'], 'tls-expiring')
        self.assertTrue(row['certificate_verified'])
        self.assertEqual(row['expires_in_days'], 9)
        conn.close.assert_called_once()
        conn.reset_mock()
        conn.connect.side_effect = TimeoutError('timed out')
        with patch.object(assessment, 'connection', return_value=conn):
            row = assessment.tls_check('https://lab.invalid/', '127.0.0.1', 1)
        self.assertEqual(row['status'], 'inconclusive')
        self.assertNotIn('severity', row)

    def test_network_mode_runs_without_http_or_optional_binaries_and_rebuilds_offline(self):
        def execute(runner, job):
            return dict(name=job.name, tool=job.tool, argv=job.argv, folder=str(job.folder),
                        outputs=[], status='completed', elapsed=0, note='')
        with patch.object(webscan.Runner, 'execute', execute), \
             patch.object(nmap_scan, 'inventory', return_value=([dict(port=6379, service='redis')], {'status': 'completed', 'note': 'fixture'})), \
             patch.object(webscan, 'probe', side_effect=AssertionError('No HTTP')), \
             patch.object(webscan, 'tool_paths', side_effect=AssertionError('No optional scanners')), \
             contextlib.redirect_stdout(io.StringIO()):
            code = webscan.main(['127.0.0.1', '--assessment', 'network', '--output', str(self.root)])
        self.assertEqual(code, 0)
        root = next(self.root.glob('*/summary.json')).parent
        data = json.loads((root / 'summary.json').read_text())
        self.assertEqual(data['coverage']['severity_counts']['medium'], 1)
        item = data['findings'][0]
        artifact = root / item['evidence'][0]['file']
        self.assertEqual(item['evidence'][0]['sha256'], hashlib.sha256(artifact.read_bytes()).hexdigest())
        with patch.object(assessment, 'run', side_effect=AssertionError('No network')), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(webscan.main(['--report-only', str(root)]), 0)
        rebuilt = json.loads((root / 'summary.json').read_text())
        self.assertEqual(rebuilt['findings'], data['findings'])
        report = (root / 'report.html').read_text()
        digest = base64.b64encode(hashlib.sha256(webscan.REPORT_SCRIPT.encode()).digest()).decode()
        self.assertIn("script-src 'sha256-" + digest + "'", report)
        self.assertIn('Redis service reachable', report)
        self.assertIn('id="finding-search"', report)

    def test_network_without_inventory_does_not_claim_complete_coverage(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(webscan.main(['127.0.0.1', '--assessment', 'network', '--skip', 'nmap', '--output', str(self.root)]), 2)

    def test_slow_headers_and_body_obey_absolute_request_deadline(self):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), SlowHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for path in ('/headers', '/body'):
                with self.subTest(path=path):
                    started = time.monotonic()
                    row = webscan.probe(f'http://127.0.0.1:{server.server_port}{path}', timeout=0.25, scan_ip='127.0.0.1')
                    self.assertIn('error', row)
                    if path == '/body':
                        self.assertEqual(row['status'], 200)  # Slow bodies must not erase a responding service.
                    else:
                        self.assertNotIn('status', row)
                    self.assertLess(time.monotonic() - started, 0.8)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_crawl_emits_waiting_progress_and_preserves_partial_result(self):
        def fetch(*args, **kwargs):
            time.sleep(0.6)
            return dict(status=200, headers=[], body=b'', truncated=False)
        progress = []
        with patch.object(crawler, 'fetch', side_effect=fetch):
            state = crawler.crawl(['http://127.0.0.1/'], '127.0.0.1', self.root, threading.Event(),
                scan_ip='127.0.0.1', progress=lambda c, t: progress.append((c, t)), request_timeout=1)
        self.assertIn((0, 100), progress)
        self.assertEqual(state['status'], 'completed')
        self.assertEqual(state['pages'][0]['status'], 200)

    def test_real_tls_pinned_sni_trust_and_untrusted_certificate(self):
        cert, key = self.root / 'cert.pem', self.root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
            '-subj', '/CN=lab.invalid', '-addext', 'subjectAltName=DNS:lab.invalid',
            '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), http.server.BaseHTTPRequestHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        original = ssl.create_default_context
        try:
            url = f'https://lab.invalid:{server.server_port}/'
            with patch.object(socket, 'getaddrinfo', side_effect=AssertionError('Unpinned DNS')), \
                 patch.object(transport.ssl, 'create_default_context', side_effect=lambda: original(cafile=str(cert))):
                row = assessment.tls_check(url, '127.0.0.1', 2)
            self.assertTrue(row['certificate_verified'])
            self.assertEqual(row['check'], 'tls-expiring')
            self.assertEqual(len(row['certificate_sha256']), 64)
            with patch.object(transport.ssl, 'create_default_context', side_effect=lambda: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)):
                row = assessment.tls_check(url, '127.0.0.1', 2)
            self.assertFalse(row['certificate_verified'])
            self.assertEqual(row['check'], 'tls-certificate')
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_assessment_budget_and_cancel_do_not_claim_clean_tls(self):
        state = assessment.run('127.0.0.1', '127.0.0.1', [], ['https://127.0.0.1/'],
            self.root, threading.Event(), RequestGate(5), timeout=0)
        self.assertEqual(state['status'], 'limited')
        self.assertEqual(state['tls'], [])
        stop = threading.Event()
        stop.set()
        state = assessment.run('127.0.0.1', '127.0.0.1', [], ['https://127.0.0.1/'],
            self.root, stop, RequestGate(5))
        self.assertEqual(state['status'], 'cancelled')


if __name__ == '__main__':
    unittest.main()
