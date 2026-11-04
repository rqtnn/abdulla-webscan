"""Loopback-only web console for the existing bounded scanner. No extra packages."""
import argparse
from collections import deque
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid

from scope import parse_target

ROOT = Path(__file__).resolve().parent


def scan_command(url, output):
    target = parse_target(url)
    if not target.url:
        raise ValueError('Enter a complete http:// or https:// URL.')
    return [sys.executable, '-u', str(ROOT / 'twiy.py'), target.url,
            '--scan', 'deep', '--all-tools', '--allow-hostname-scanners',
            '--url-port-only', '--skip', 'nmap', '--no-menu', '--no-banner', '--ui', 'plain',
            '--tool-timeout', '180', '--sqli-timeout', '60', '--rate', '3',
            '--output', str(output), '--log-file', str(output / 'diagnostics.log')]


class Console:
    def __init__(self, output):
        self.output = Path(output).resolve()
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.jobs = {}
        self.active = None

    def start(self, url):
        if not isinstance(url, str) or len(url) > 4096:
            raise ValueError('Enter a URL of at most 4096 characters.')
        key = uuid.uuid4().hex
        folder = self.output / key
        command = scan_command(url, folder)
        with self.lock:
            if self.active:
                raise ValueError('A scan is already running. Wait or stop it first.')
            if len(self.jobs) >= 100:
                raise ValueError('Session limit reached. Restart the console to start a new session.')
            folder.mkdir(parents=True, mode=0o700)
            job = dict(id=key, url=command[3], status='running', started=time.time(),
                       lines=deque(maxlen=400), process=None, folder=folder, result=None,
                       cancelled=False)
            self.jobs[key] = job
            self.active = key
        threading.Thread(target=self.run, args=(job, command), daemon=True).start()
        return key

    def stop(self, job):
        with self.lock:
            job['cancelled'] = True
            proc = job['process']
        if proc and proc.poll() is None:
            try:
                # Scanner owns child process groups; SIGINT lets its Runner stop them.
                proc.send_signal(signal.SIGINT)
            except ProcessLookupError:
                pass

    def run(self, job, command):
        proc = None
        timer = None
        try:
            proc = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, errors='replace')
            with self.lock:
                job['process'] = proc
                cancelled = job['cancelled']
            if cancelled:
                self.stop(job)
            timer = threading.Timer(1800, lambda: self.stop(job))
            timer.daemon = True
            timer.start()
            for line in proc.stdout:
                with self.lock:
                    job['lines'].append(line.rstrip()[:2000])
            code = proc.wait()
            summaries = list(job['folder'].glob('*/summary.json'))
            with self.lock:
                if summaries:
                    job['result'] = summaries[0].parent
                job['status'] = ('stopped' if job['cancelled'] else
                                 'completed' if code == 0 else 'partial' if summaries else 'failed')
                job['exit_code'] = code
        except Exception as exc:
            with self.lock:
                job['status'] = 'failed'
                job['lines'].append('Unable to run scanner: ' + type(exc).__name__)
        finally:
            if timer:
                timer.cancel()
            if proc and proc.stdout:
                proc.stdout.close()
            with self.lock:
                job['process'] = None
                job['finished'] = time.time()
                self.active = None

    def snapshot(self, key):
        with self.lock:
            job = self.jobs[key]
            state = {k: job[k] for k in ('id', 'url', 'status', 'started')}
            state['elapsed'] = int(job.get('finished', time.time()) - job['started'])
            state['log'] = '\n'.join(job['lines'])
            state['report'] = bool(job['result'])
            folder = job['result']
        if folder:
            try:
                doc = json.loads((folder / 'summary.json').read_text(encoding='utf-8'))
                state['statistics'] = doc.get('statistics', {})
                state['coverage'] = doc.get('tool_coverage', [])
                state['findings'] = [{k: f.get(k, '') for k in
                    ('title', 'severity', 'category', 'validation_status', 'url')}
                    for f in doc.get('findings', [])][:500]
                state['diagnostics'] = doc.get('diagnostics', [])
            except (OSError, ValueError):
                state['report_error'] = 'Summary unavailable; inspect scanner log.'
        return state


def handler(console):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, *_):
            pass

        def send(self, code, data, kind='application/json; charset=utf-8'):
            if not isinstance(data, bytes):
                data = json.dumps(data).encode()
            self.send_response(code)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('X-Frame-Options', 'DENY')
            if kind.startswith('text/html') and self.path == '/':
                self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.end_headers()
            self.wfile.write(data)

        def allowed(self):
            # Reject DNS rebinding and cross-site browser requests, including GET polling.
            expected = '127.0.0.1:' + str(self.server.server_port)
            return (self.headers.get('Host') == expected and
                    self.headers.get('Sec-Fetch-Site', 'same-origin') in ('same-origin', 'none') and
                    self.headers.get('Origin', 'http://' + expected) == 'http://' + expected)

        def do_GET(self):
            if not self.allowed():
                return self.send(403, {'error': 'Use the loopback URL printed by the console.'})
            path = urllib.parse.urlsplit(self.path).path
            if path == '/':
                data = (ROOT / 'assets/console.html').read_text().replace('__TOKEN__', console.token)
                return self.send(200, data.encode(), 'text/html; charset=utf-8')
            if path in ('/console.js', '/console.css'):
                return self.send(200, (ROOT / 'assets' / path[1:]).read_bytes(),
                                 'text/javascript' if path.endswith('.js') else 'text/css')
            parts = path.strip('/').split('/')
            if len(parts) == 3 and parts[:2] == ['api', 'scans']:
                try:
                    return self.send(200, console.snapshot(parts[2]))
                except KeyError:
                    pass
            if len(parts) >= 2 and parts[0] == 'report':
                with console.lock:
                    job = console.jobs.get(parts[1])
                    folder = job and job['result']
                if folder:
                    if len(parts) == 2:
                        self.send_response(302)
                        self.send_header('Location', '/report/' + parts[1] + '/report.html')
                        self.end_headers()
                        return
                    file = (folder / urllib.parse.unquote('/'.join(parts[2:]))).resolve()
                    if file.is_relative_to(folder.resolve()) and file.is_file():
                        kind = 'text/html; charset=utf-8' if file == folder.resolve() / 'report.html' else 'text/plain; charset=utf-8'
                        return self.send(200, file.read_bytes(), kind)
            return self.send(404, {'error': 'Not found'})

        def do_POST(self):
            if not self.allowed() or not hmac.compare_digest(self.headers.get('X-Console-Token', ''), console.token):
                return self.send(403, {'error': 'Invalid console session. Reload the page.'})
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 8192:
                    raise ValueError('Invalid request size')
                doc = json.loads(self.rfile.read(size))
                if not isinstance(doc, dict):
                    raise ValueError('Expected a JSON object')
                if self.path == '/api/scans':
                    return self.send(202, {'id': console.start(doc.get('url'))})
                parts = self.path.strip('/').split('/')
                if len(parts) == 4 and parts[:2] == ['api', 'scans'] and parts[3] == 'stop':
                    with console.lock:
                        job = console.jobs.get(parts[2])
                    if not job:
                        return self.send(404, {'error': 'Scan not found'})
                    console.stop(job)
                    return self.send(200, {'status': 'stopping'})
                return self.send(404, {'error': 'Not found'})
            except (ValueError, TypeError) as exc:
                return self.send(400, {'error': str(exc)})
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--output', type=Path, default=ROOT / 'results/web-console')
    args = parser.parse_args()
    if not sys.platform.startswith('linux'):
        parser.error('Linux is required for scanner process management.')
    if not 1024 <= args.port <= 65535:
        parser.error('Choose a port from 1024 to 65535.')
    console = Console(args.output)
    server = ThreadingHTTPServer(('127.0.0.1', args.port), handler(console))
    print(f'Open http://127.0.0.1:{args.port} — local console; Ctrl+C stops the server.', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        for job in list(console.jobs.values()):
            if job['status'] == 'running':
                console.stop(job)
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
