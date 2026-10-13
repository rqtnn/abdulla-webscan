import concurrent.futures
import contextlib
import http.server
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webscan


class Handler(http.server.BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        self.hits.append(self.path)
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/never-follow")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<title>Local &amp; Lab</title>Test only")

    def log_message(self, *args):
        pass


class WebScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_ip_rejects_command_injection_and_ranges(self):
        for bad in ("127.0.0.1;id", "127.0.0.1/24", "--help", "example.com", "999.1.1.1"):
            with self.assertRaises(webscan.argparse.ArgumentTypeError):
                webscan.ipv4(bad)

    def test_scope_rejects_other_ip_credentials_and_scheme(self):
        for bad in ("http://127.0.0.2/", "http://example.com/", "file:///etc/passwd",
                    "http://u:p@127.0.0.1/", "http://127.0.0.1/#frag"):
            with self.assertRaises((ValueError, webscan.argparse.ArgumentTypeError)):
                webscan.scoped_url(bad, "127.0.0.1")

    def test_invalid_port_ranges(self):
        for bad in ("0", "80-1", "65536", "80;id"):
            with self.assertRaises(webscan.argparse.ArgumentTypeError):
                webscan.ports(bad)

    def test_parse_nmap_only_target_open_tcp(self):
        xml = self.root / "scan.xml"
        xml.write_text('''<nmaprun><host><address addr="127.0.0.2"/><ports>
        <port protocol="tcp" portid="99"><state state="open"/></port></ports></host>
        <host><address addr="127.0.0.1"/><ports>
        <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Lab"/></port>
        <port protocol="tcp" portid="81"><state state="closed"/></port>
        <port protocol="udp" portid="82"><state state="open"/></port>
        </ports></host></nmaprun>''')
        self.assertEqual(webscan.parse_nmap(xml, "127.0.0.1"),
                         [{"port": 80, "service": "http", "product": "Lab", "version": "", "tunnel": ""}])

    def test_probe_parses_title(self):
        result = webscan.probe(f"http://127.0.0.1:{self.port}/")
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["title"], "Local & Lab")

    def test_probe_does_not_follow_redirect(self):
        Handler.hits.clear()
        result = webscan.probe(f"http://127.0.0.1:{self.port}/redirect")
        self.assertEqual(result["status"], 302)
        self.assertEqual(result["location"], "/never-follow")
        self.assertEqual(Handler.hits, ["/redirect"])

    @unittest.skipUnless(os.name == 'posix', 'CLI requires Kali/Linux/WSL')
    def test_dry_run_never_starts_process_or_probe(self):
        with patch.object(webscan.subprocess, "Popen", side_effect=AssertionError("No subprocess")), \
             patch.object(webscan.subprocess, "run", side_effect=AssertionError("No tool help")), \
             patch.object(webscan, "probe", side_effect=AssertionError("No network")), \
             contextlib.redirect_stdout(io.StringIO()):
            code = webscan.main(["127.0.0.1", "--dry-run", "--ports", "80", "--output", str(self.root)])
        self.assertEqual(code, 0)
        data = json.loads(next(self.root.glob("*/summary.json")).read_text())
        self.assertTrue(data["dry_run"])
        self.assertTrue(all(job["status"] == "planned" for job in data["jobs"]))

    def test_runner_missing_binary(self):
        job = webscan.Job("missing", "missing", ["webscan-no-such-binary-zz"], self.root / "missing", 1)
        with contextlib.redirect_stdout(io.StringIO()):
            result = webscan.Runner().execute(job)
        self.assertEqual(result["status"], "skipped")

    def test_runner_failed_process(self):
        job = webscan.Job("failed", "test", [sys.executable, "-c", "raise SystemExit(7)"], self.root / "failed", 2)
        with contextlib.redirect_stdout(io.StringIO()):
            result = webscan.Runner().execute(job)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["exit_code"], 7)

    @unittest.skipUnless(os.name == 'posix', 'Process-group termination requires POSIX')
    def test_runner_timeout_terminates_process(self):
        job = webscan.Job("timeout", "test", [sys.executable, "-c", "import time;time.sleep(10)"], self.root / "time", 1)
        start = time.monotonic()
        with contextlib.redirect_stdout(io.StringIO()):
            result = webscan.Runner().execute(job)
        self.assertEqual(result["status"], "timeout")
        self.assertLess(time.monotonic() - start, 4)

    def test_argument_array_does_not_execute_shell(self):
        marker = self.root / "injected"
        text = f"hello;touch {marker}"
        job = webscan.Job("argv", "test", [sys.executable, "-c", "import sys;print(sys.argv[1])", text],
                          self.root / "argv", 2)
        with contextlib.redirect_stdout(io.StringIO()):
            result = webscan.Runner().execute(job)
        self.assertEqual(result["status"], "completed")
        self.assertEqual((job.folder / "console.log").read_text().strip(), text)
        self.assertFalse(marker.exists())

    def test_parallel_limit_and_result_order(self):
        class FakeRunner:
            def __init__(self):
                self.active = 0
                self.peak = 0
                self.lock = threading.Lock()

            def execute(self, job):
                with self.lock:
                    self.active += 1
                    self.peak = max(self.peak, self.active)
                time.sleep(0.03)
                with self.lock:
                    self.active -= 1
                return job

        runner = FakeRunner()
        self.assertEqual(webscan.run_batch(runner, list(range(7)), "parallel", 2), list(range(7)))
        self.assertEqual(runner.peak, 2)

    def test_report_escapes_target_response_markup(self):
        summary = {"target": "127.0.0.1", "created": "test", "mode": "sequential", "outcome": "test",
                   "ports": [], "jobs": [], "probes": [{"url": "http://127.0.0.1/",
                   "status": 200, "title": '<script>alert("x")</script>'}]}
        webscan.write_reports(self.root, summary)
        report = (self.root / "report.html").read_text()
        self.assertIn("&lt;script&gt;", report)
        self.assertNotIn("<script>alert", report)
        self.assertEqual(report.count('<script>'), 1)

    @unittest.skipUnless(os.name == 'posix', 'CLI requires Kali/Linux/WSL')
    def test_rejects_sqlmap_parameter_not_in_query(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            webscan.main(["127.0.0.1", "--sqlmap-url", "http://127.0.0.1/?id=1", "--sqlmap-param", "other"])

    @unittest.skipUnless(os.name == 'posix', 'CLI requires Kali/Linux/WSL')
    def test_rejects_sqlmap_url_outside_requested_ports(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            webscan.main(["127.0.0.1", "--ports", "443", "--sqlmap-url", "http://127.0.0.1/?id=1",
                          "--sqlmap-param", "id"])

    @unittest.skipUnless(os.name == 'posix', 'Executable scanner fixtures require POSIX')
    def test_end_to_end_with_local_server_and_fake_scanners(self):
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        templates = self.root / "templates"
        templates.mkdir()
        (templates / 'fixture.yaml').write_text('id: fixture')
        fake = '''#!PYTHON
import sys,json,os
from pathlib import Path
args=sys.argv[1:]
name=Path(sys.argv[0]).name
if name=="httpx-toolkit" and args==["-h"]:
    print("-no-fallback-scheme -json");raise SystemExit(0)
if name=="nmap":
    out=Path(args[args.index("-oX")+1])
    port=os.environ["TEST_WEBSCAN_PORT"]
    out.write_text('<nmaprun><host><address addr="127.0.0.1"/><ports><port protocol="tcp" portid="'+port+'"><state state="open"/><service name="http" product="TEST FIXTURE"/></port></ports></host></nmaprun>')
else:
    out=None
    for flag in ("-o","-output"):
        if flag in args:out=Path(args[args.index(flag)+1])
    for arg in args:
        if arg.startswith("--log-json="):out=Path(arg.split("=",1)[1])
    url=args[args.index("-u")+1] if "-u" in args else args[-1]
    if name=="nikto":url=args[args.index("-h")+1]
    endpoint=url.replace("FUZZ", "")+"admin"
    row={"url":endpoint,"status":200}
    payload={"test_fixture":True,"tool":name}
    if name in ("ffuf","dirsearch"):payload={"results":[row]}
    if name=="feroxbuster":payload=dict(row,type="response")
    if name=="httpx-toolkit":payload={"url":url,"tech":["Lab"]}
    if name=="whatweb":payload=[{"target":url,"plugins":{"Lab":{}}}]
    if name=="nikto":payload={"vulnerabilities":[{"id":"test","url":"/admin","msg":"Test observation"}]}
    if name=="nuclei":payload={"template-id":"test","matched-at":endpoint,"info":{"name":"Test observation","severity":"info"}}
    if out:out.write_text(("/admin (Status: 200) [Size: 40]" if name=="gobuster" else json.dumps(payload))+"\\n")
    if name=="sqlmap" and "-t" in args:Path(args[args.index("-t")+1]).write_text("TEST FIXTURE TRAFFIC")
print("TEST FIXTURE",name)
'''.replace("PYTHON", sys.executable)
        for name in ("nmap", "httpx-toolkit", "whatweb", *webscan.ENUM_TOOLS, "nikto", "nuclei", "sqlmap"):
            path = bin_dir / name
            path.write_text(fake)
            path.chmod(0o755)
        env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ.get("PATH", ""),
                   TEST_WEBSCAN_PORT=str(self.port))
        with patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(io.StringIO()):
            code = webscan.main(["127.0.0.1", "--ports", str(self.port), "--enum", "all", "--mode", "parallel",
                                 "--external-tools", "--retain-raw-evidence", "--templates", str(templates), "--output", str(self.root / "runs"), "--no-crawl",
                                 "--sqlmap-url", f"http://127.0.0.1:{self.port}/?id=1", "--sqlmap-param", "id"])
        self.assertEqual(code, 0)
        data = json.loads(next((self.root / "runs").glob("*/summary.json")).read_text())
        self.assertEqual(len(data["jobs"]), 11)
        self.assertTrue(all(row["status"] == "completed" for row in data["jobs"]))
        self.assertEqual(data["jobs"][0]["tool"], "nmap")
        self.assertEqual(data["jobs"][-1]["tool"], "sqlmap")
        self.assertEqual(data["ports"][0]["port"], self.port)
        self.assertTrue(data['findings'])
        self.assertTrue(all(f['validation_status'] == 'needs_validation' for f in data['findings']))
        endpoint = next(f for f in data['findings'] if f['category'] == 'endpoint' and f['url'].endswith('/admin'))
        self.assertEqual(len(endpoint['evidence']), 4)
        self.assertEqual({e['tool'] for e in endpoint['evidence']}, set(webscan.ENUM_TOOLS))
        self.assertTrue(all(i['job'] == 'SQLmap selected GET parameter' for i in data['parse_issues']))
        for job in data["jobs"]:
            if job['tool'] != 'network':
                self.assertTrue((Path(job["folder"]) / "console.log").exists())
            for output in job["outputs"]:
                self.assertTrue((Path(job["folder"]) / output).exists())


if __name__ == "__main__":
    unittest.main()
