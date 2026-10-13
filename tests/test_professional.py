"""Unified priority, observed PoC, startup and session-isolation regressions."""
import contextlib
import hashlib
import http.server
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import assessment
import checks
import crawler
import evidence
import findings
import session
import terminal
import cli
from cli_fixture import cli_platform


class Fixture(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append(dict(path=self.path, host=self.headers['Host'], cookie=self.headers.get('Cookie')))
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('X-Lab', 'fixture')
        self.end_headers()
        self.wfile.write(b'<html><script>untrusted evidence</script></html>')

    def log_message(self, *args):
        pass


class ProfessionalTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def server(self):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
        server.requests = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def cleanup():
            server.shutdown()
            server.server_close()
            thread.join()
        self.addCleanup(cleanup)
        return server, f'http://127.0.0.1:{server.server_port}'

    def test_actual_get_poc_redacts_secrets_without_mangling_request_lines(self):
        server, base = self.server()
        row = crawler.fetch(base + '/item?id=1&token=QUERY_SECRET', headers={'Cookie': 'SESSION_SECRET'}, scan_ip='127.0.0.1')
        request = row['request']
        self.assertEqual(server.requests[0]['path'], '/item?id=1&token=QUERY_SECRET')
        self.assertEqual(server.requests[0]['cookie'], 'SESSION_SECRET')
        self.assertEqual(request['method'], 'GET')
        self.assertFalse(request['exact'])
        self.assertTrue(request['redacted'])
        self.assertIn('GET /item?id=1&token=', request['text'])
        self.assertIn('\r\nHost: 127.0.0.1:', request['text'])
        document = evidence.dumps(row['request'])
        self.assertNotIn('QUERY_SECRET', document)
        self.assertNotIn('SESSION_SECRET', document)
        self.assertEqual(json.loads(document)['text'], request['text'])
        self.assertEqual(len(request['sha256']), 64)

    def test_request_is_exact_when_no_redaction_was_needed(self):
        _, base = self.server()
        row = cli.probe(base + '/item?id=1', scan_ip='127.0.0.1')
        self.assertTrue(row['request']['exact'])
        self.assertEqual(hashlib.sha256(row['request']['text'].encode('iso-8859-1')).hexdigest(), row['request']['sha256'])
        self.assertEqual(dict(row['headers'])['X-Lab'], 'fixture')

    def test_scanner_exchange_provenance_and_missing_request_are_explicit(self):
        row = dict(url='http://127.0.0.1/', request='GET /?token=SECRET HTTP/1.1\r\nCookie: PRIVATE\r\n\r\n',
                   response='HTTP/1.1 200 OK\r\nSet-Cookie: RESPONSE_SECRET\r\nContent-Type: text/plain\r\n\r\nlab response')
        proof = evidence.record_pocs('nuclei', row, self.root)[0]
        self.assertEqual(proof['response_status'], 200)
        self.assertEqual(proof['request']['source'], 'scanner_export')
        self.assertFalse(proof['request']['exact'])
        self.assertNotIn('PRIVATE', evidence.dumps(proof))
        self.assertNotIn('RESPONSE_SECRET', evidence.dumps(proof))
        self.assertEqual(proof['response_body_status'], 'omitted')
        self.assertEqual(evidence.record_pocs('nuclei', row, self.root, True)[0]['response_snippet'], 'lab response')
        proof = evidence.record_pocs('nuclei', dict(response=row['response']), self.root)[0]
        self.assertEqual(proof['request']['status'], 'unavailable')

    def test_poc_body_opt_in_hash_integrity_and_path_boundaries(self):
        body = b'bounded evidence'
        row = dict(url='http://127.0.0.1/', status=200, headers=[], **evidence.save_body(self.root, 'body.bin', body, True))
        self.assertEqual(evidence.http_poc(row, self.root)['response_body_status'], 'omitted')
        self.assertEqual(evidence.http_poc(row, self.root, True)['response_snippet'], 'bounded evidence')
        (self.root / 'body.bin').write_bytes(b'tampered')
        self.assertIn('hash mismatch', evidence.http_poc(row, self.root, True)['integrity_error'])
        self.assertIn('integrity_error', evidence.http_poc(dict(row, body_file='../outside'), self.root, True))

    def test_concurrent_crawl_keeps_cookie_bound_to_one_origin(self):
        allowed, base = self.server()
        foreign, other = self.server()
        cookie = self.root / 'cookie.txt'
        cookie.write_text('sid=LAB_SECRET')
        bound = session.Session(base, cookie)
        state = crawler.crawl([base + '/a', base + '/b', other + '/c'], '127.0.0.1', self.root / 'crawl',
                              threading.Event(), workers=3, rate=1000, session=bound, scan_ip='127.0.0.1')
        self.assertEqual(state['status'], 'completed')
        self.assertTrue(all(r['cookie'] == 'sid=LAB_SECRET' for r in allowed.requests))
        self.assertTrue(all(r['cookie'] is None for r in foreign.requests))
        self.assertNotIn('LAB_SECRET', (self.root / 'crawl' / 'crawl.json').read_text())

    def test_unified_matrix_counts_groups_not_duplicate_header_instances(self):
        rows = [dict(id='a', title='CSP', severity='low', category='configuration', check='csp', url='http://lab/a', validation_status='needs_validation', evidence=[{'tool': 'crawler'}]),
                dict(id='b', title='CSP', severity='low', category='configuration', check='csp', url='http://lab/b', validation_status='needs_validation', evidence=[{'tool': 'crawler'}]),
                dict(id='c', title='Redis', severity='medium', category='configuration', check='redis', url='tcp://lab:6379', validation_status='needs_validation', evidence=[{'tool': 'network'}]),
                dict(id='d', title='SQLi', severity='high', category='scanner_match', check='sqli', url='http://lab/item', validation_status='needs_validation', evidence=[{'tool': 'checks'}]),
                dict(id='e', title='Endpoint', severity='info', category='endpoint', check='200', url='http://lab/', validation_status='needs_validation', evidence=[])]
        risk, stats = assessment.unified_risk(dict(findings=rows, ports=[{'port': 80}, {'port': 6379}], nmap={'status': 'completed'}), findings.finding_groups(rows))
        matrix = {r['severity']: r for r in risk['matrix']}
        self.assertEqual(matrix['low']['groups'], 1)
        self.assertEqual(matrix['low']['instances'], 2)
        self.assertEqual(matrix['medium']['network'], 1)
        self.assertEqual(matrix['high']['web'], 1)
        self.assertEqual(stats['vulnerability_candidates'], 1)
        self.assertEqual(stats['configuration_findings'], 2)
        self.assertEqual(stats['confirmed_vulnerabilities'], 0)
        self.assertEqual(stats['open_ports'], 2)
        self.assertEqual(risk['priority_score'], 3)
        self.assertEqual(risk['overall_priority'], 'high')

    def test_no_scan_does_not_count_a_host_or_imply_verified_safety(self):
        risk, stats = assessment.unified_risk(dict(dry_run=True, findings=[], ports=[], nmap={'status': 'planned'}), [])
        self.assertEqual(stats['hosts_assessed'], 0)
        self.assertEqual(risk['overall_priority'], 'not_assessed')
        self.assertIsNone(risk['priority_score'])

    def test_network_findings_have_observed_service_proof(self):
        folder = self.root / 'network'
        folder.mkdir()
        state = dict(status='completed', checks=assessment.inventory_checks('127.0.0.1', [dict(port=3306, service='mysql', product='MySQL', version='8.0', method='probed')]), tls=[])
        (folder / 'assessment.json').write_text(json.dumps(state))
        row = assessment.findings(self.root, dict(network_assessment=state))[0]
        proof = row['evidence'][0]['poc'][0]
        self.assertEqual(proof['kind'], 'nmap_service')
        self.assertEqual(proof['data']['version'], '8.0')
        self.assertEqual(row['validation_status'], 'needs_validation')

    def test_startup_brand_once_and_interactive_ipv6_parsing(self):
        cli_platform(self)
        output = io.StringIO()
        with patch('builtins.input', return_value='::1'), patch.object(cli, 'tool_paths', return_value={}), contextlib.redirect_stdout(output):
            code = cli.main(['--dry-run', '--no-crawl', '--ui', 'plain', '--output', str(self.root / 'plan.json')])
        self.assertEqual(code, 0)
        self.assertEqual(output.getvalue().count('WS-R'), 1)
        self.assertIn('Findings', output.getvalue().replace('findings', 'Findings'))
        document = json.loads((self.root / 'plan.json').read_text())
        self.assertEqual(document['input_url'], 'http://[::1]/')
        self.assertEqual(document['statistics']['hosts_assessed'], 0)

    def test_report_poc_is_escaped_and_offline_rebuild_keeps_stats(self):
        server, base = self.server()
        row = cli.probe(base, scan_ip='127.0.0.1')
        row['request']['text'] += '<script>target-controlled</script>'
        summary = dict(target='127.0.0.1', created='fixture', mode='sequential', outcome='Local fixture', ports=[], probes=[row], jobs=[])
        cli.write_reports(self.root, summary)
        report = (self.root / 'report.html').read_text()
        self.assertIn('Unified triage matrix', report)
        self.assertIn('&lt;script&gt;target-controlled&lt;/script&gt;', report)
        self.assertNotIn('<script>target-controlled</script>', report)
        before = json.loads((self.root / 'summary.json').read_text())
        reference = before['findings'][0]['evidence'][0]
        self.assertEqual(reference['sha256'], hashlib.sha256((self.root / reference['file']).read_bytes()).hexdigest())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['--report-only', str(self.root)]), 0)
        after = json.loads((self.root / 'summary.json').read_text())
        self.assertEqual(before['risk_assessment'], after['risk_assessment'])
        self.assertEqual(before['statistics'], after['statistics'])
