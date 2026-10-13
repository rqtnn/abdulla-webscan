import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import cli
from findings import collect


class FindingsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.summary = dict(target='127.0.0.1', jobs=[], ports=[], probes=[],
                            created='test', mode='sequential', outcome='test')

    def job(self, tool, data, extension='json', status='completed'):
        folder = self.root / str(len(self.summary['jobs'])) / tool
        folder.mkdir(parents=True)
        filename = 'results.' + extension
        content = data if isinstance(data, str) else json.dumps(data)
        (folder / filename).write_text(content, encoding='utf-8')
        self.summary['jobs'].append(dict(name=tool, tool=tool, folder=str(folder),
            outputs=[filename], argv=[tool, '-u', 'http://127.0.0.1/'],
            status=status, elapsed=0, note=''))
        return folder / filename

    def test_merge_endpoints_preserves_all_records_and_hashes(self):
        a = self.job('ffuf', {'results': [{'url': 'http://127.0.0.1:80/admin', 'status': 200}]})
        self.job('gobuster', '/admin (Status: 200) [Size: 40]\n', 'txt')
        findings, issues = collect(self.root, self.summary)
        self.assertEqual(issues, [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(findings[0]['evidence']), 2)
        self.assertEqual(findings[0]['validation_status'], 'needs_validation')
        self.assertEqual(findings[0]['evidence'][0]['sha256'], hashlib.sha256(a.read_bytes()).hexdigest())
        self.assertIn('url', findings[0]['evidence'][0]['raw'])

    def test_distinct_checks_queries_statuses_ports_and_schemes(self):
        self.job('ffuf', {'results': [dict(url=u, status=s) for u, s in [
            ('http://127.0.0.1/a?q=1', 200), ('http://127.0.0.1/a?q=2', 200),
            ('https://127.0.0.1/a?q=1', 200), ('http://127.0.0.1:81/a?q=1', 200),
            ('http://127.0.0.1/a?q=1', 403)]]})
        self.job('nuclei', '\n'.join(json.dumps({'template-id': c, 'matched-at': 'http://127.0.0.1/a',
            'info': {'name': c, 'severity': 'high'}}) for c in ('a', 'b')), 'jsonl')
        findings, issues = collect(self.root, self.summary)
        self.assertEqual(len(findings), 7)
        self.assertEqual(issues, [])

    def test_partial_jsonl_continues_and_retains_failed_job_evidence(self):
        self.job('nuclei', '{broken\n' + json.dumps({'template-id': 'test',
            'matched-at': 'http://127.0.0.1/', 'info': {}}), 'jsonl', 'timeout')
        findings, issues = collect(self.root, self.summary)
        self.assertEqual(len(findings), 1)
        self.assertEqual(issues[0]['record'], 1)
        self.assertEqual(findings[0]['evidence'][0]['job_status'], 'timeout')

    def test_scope_and_markup_are_untrusted(self):
        self.job('ffuf', {'results': [{'url': 'http://127.0.0.2/a', 'status': 200}]})
        self.job('nuclei', json.dumps({'template-id': 'x', 'matched-at': 'http://127.0.0.1/',
            'info': {'name': '<script>alert(1)</script>'}}), 'jsonl')
        cli.write_reports(self.root, self.summary)
        report = (self.root / 'report.html').read_text()
        self.assertNotIn('<script>alert', report)
        self.assertEqual(report.count('<script>'), 1)  # Only the fixed, CSP-hashed report filter.
        self.assertIn('&lt;script&gt;', report)
        self.assertEqual(len(self.summary['findings']), 1)
        self.assertEqual(len(self.summary['parse_issues']), 1)

    def test_metadata_nikto_ferox_and_empty_results(self):
        self.job('httpx', json.dumps({'url': 'http://127.0.0.1/', 'tech': ['Lab']}), 'jsonl')
        self.job('whatweb', [{'target': 'http://127.0.0.1/', 'plugins': {'Lab': {'version': ['1']}}}])
        self.job('nikto', [{'vulnerabilities': [{'id': '1', 'url': '/admin', 'msg': 'Review access'}]}])
        self.job('feroxbuster', json.dumps({'type': 'response', 'url': 'http://127.0.0.1/admin', 'status': 200}), 'jsonl')
        self.job('ffuf', {'results': []})
        findings, issues = collect(self.root, self.summary)
        self.assertEqual(len(findings), 4)
        self.assertEqual(issues, [])

    def test_missing_output_and_unknown_format_are_visible(self):
        path = self.job('ffuf', {})
        self.job('nuclei', '{"unknown": true}', 'jsonl')
        path.unlink()
        findings, issues = collect(self.root, self.summary)
        self.assertEqual(findings, [])
        self.assertEqual(len(issues), 2)

    def test_dirsearch_flat_results_and_sqlmap_positive_block(self):
        self.job('dirsearch', {'results': [{'url': 'http://127.0.0.1/a', 'status': 200}]})
        path = self.job('sqlmap', 'Parameter: id (GET)\n    Type: boolean-based blind\n    Title: Test candidate\n    Payload: id=1 AND 1=1\n', 'txt')
        path.rename(path.parent / 'console.log')
        findings, issues = collect(self.root, self.summary)
        self.assertEqual(len(findings), 2)
        candidate = next(f for f in findings if f['category'] == 'scanner_match')
        self.assertEqual(candidate['evidence'][0]['raw']['payload'], 'id=1 AND 1=1')
        self.assertEqual(candidate['validation_status'], 'needs_validation')
        self.assertEqual(len(issues), 1)

    def test_stable_ids_repeated_reports_do_not_duplicate_evidence(self):
        self.job('ffuf', {'results': [{'url': 'http://127.0.0.1/a', 'status': 200}]})
        cli.write_reports(self.root, self.summary)
        first = json.loads((self.root / 'summary.json').read_text())['findings']
        cli.write_reports(self.root, self.summary)
        self.assertEqual(first, self.summary['findings'])

    def test_invalid_port_and_foreign_nikto_host_are_not_findings(self):
        self.job('ffuf', {'results': [{'url': 'http://127.0.0.1:0/a', 'status': 200}]})
        self.job('nikto', {'ip': '127.0.0.2', 'vulnerabilities': [
            {'id': 'x', 'url': '/a', 'msg': 'Foreign host'}]})
        findings, issues = collect(self.root, self.summary)
        self.assertEqual(findings, [])
        self.assertEqual(len(issues), 2)


if __name__ == '__main__':
    unittest.main()
