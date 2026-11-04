import http.client
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import webapp


class WebConsoleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.console = webapp.Console(self.temp.name)
        self.server = webapp.ThreadingHTTPServer(('127.0.0.1', 0), webapp.handler(self.console))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def request(self, method, path, data=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        conn.request(method, path, json.dumps(data) if data is not None else None, headers or {})
        response = conn.getresponse()
        result = response.status, response.read(), dict(response.getheaders())
        conn.close()
        return result

    def test_cross_site_and_missing_token_cannot_start_scans(self):
        for headers in ({}, {'X-Console-Token': self.console.token, 'Origin': 'https://evil.invalid'},
                        {'X-Console-Token': self.console.token, 'Host': 'evil.invalid'}):
            code, _, _ = self.request('POST', '/api/scans', {'url': 'http://127.0.0.1/'}, headers)
            self.assertEqual(code, 403)
        self.assertFalse(self.console.jobs)

    def test_web_plan_preserves_url_port_and_never_accepts_shell_arguments(self):
        command = webapp.scan_command('https://example.invalid:8443/path?q=1', Path(self.temp.name))
        self.assertEqual(command[3], 'https://example.invalid:8443/path?q=1')
        self.assertIn('--url-port-only', command)
        self.assertEqual(command[command.index('--skip')+1], 'nmap')
        for value in ('example.invalid', 'file:///etc/passwd', 'https://user:password@example.invalid/'):
            with self.assertRaises(ValueError):
                webapp.scan_command(value, Path(self.temp.name))

    def test_http_scan_to_report_and_traversal_boundary(self):
        def fake_command(url, folder):
            script = "from pathlib import Path; import json; p=Path(%r)/'run'; p.mkdir(); (p/'summary.json').write_text(json.dumps({'statistics':{'vulnerability_candidates':1},'findings':[]})); (p/'report.html').write_text('<h1>Fixture report</h1>'); print('done')" % str(folder)
            return [sys.executable, '-u', '-c', script]
        with patch('webapp.scan_command', side_effect=fake_command):
            code, body, _ = self.request('POST', '/api/scans', {'url':'http://127.0.0.1/'},
                {'X-Console-Token':self.console.token})
            self.assertEqual(code, 202)
            key = json.loads(body)['id']
            for _ in range(100):
                state = self.console.snapshot(key)
                if state['status'] != 'running':
                    break
                time.sleep(.02)
            self.assertEqual(state['status'], 'completed')
            self.assertTrue(state['report'])
            self.assertEqual(state['statistics']['vulnerability_candidates'], 1)
            code, body, _ = self.request('GET', '/report/'+key+'/report.html')
            self.assertEqual(code, 200)
            self.assertIn(b'Fixture report', body)
            code, _, _ = self.request('GET', '/report/'+key+'/%2e%2e/%2e%2e/webapp.py')
            self.assertEqual(code, 404)

    def test_only_one_scan_and_local_dashboard(self):
        self.console.active = 'busy'
        with self.assertRaises(ValueError):
            self.console.start('https://example.invalid/')
        code, body, headers = self.request('GET', '/')
        self.assertEqual(code, 200)
        self.assertIn(self.console.token.encode(), body)
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        self.assertNotIn(b'__TOKEN__', body)


if __name__ == '__main__':
    unittest.main()
