import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import crawler
import scope
import webscan
from findings import collect


class ScopeTests(unittest.TestCase):
    def test_ip_hostname_url_idna_and_ipv6_inputs(self):
        expected = [
            ('127.0.0.1', '127.0.0.1', ''),
            ('2001:db8::1', '2001:db8::1', ''),
            ('Lab.Example.', 'lab.example', ''),
            ('https://Lab.Example:4280/app?id=1#section', 'lab.example', 'https://lab.example:4280/app?id=1'),
            ('http://[2001:db8::1]:8080/a?q=1', '2001:db8::1', 'http://[2001:db8::1]:8080/a?q=1'),
            ('https://bücher.example/بحث?q=تجربة', 'xn--bcher-kva.example',
             'https://xn--bcher-kva.example/%D8%A8%D8%AD%D8%AB?q=%D8%AA%D8%AC%D8%B1%D8%A8%D8%A9'),
        ]
        for value, host, url in expected:
            with self.subTest(value=value):
                actual = scope.parse_target(value)
                self.assertEqual((actual.host, actual.url), (host, url))

    def test_rejects_multiple_targets_credentials_bad_ports_and_non_http(self):
        for value in ('192.168.1.0/24', 'example.com;id', 'example.com other.com',
                      '--script=test', 'ftp://example.com/', 'https://user:pw@example.com/',
                      'https://@example.com/', 'https://example.com:0/', 'http://example.com:65536/',
                      '127.1', 'https://example.com/\n', 'https://example.com:bad/', ''):
            with self.subTest(value=value), self.assertRaises(ValueError):
                scope.parse_target(value)

    def test_dry_run_has_no_dns_and_url_infers_port(self):
        args = webscan.parser().parse_args(['https://lab.example:4280/app?id=1', '--dry-run'])
        with patch.object(scope.socket, 'getaddrinfo', side_effect=AssertionError('No DNS in dry-run')):
            scope.prepare_target(args)
        self.assertEqual(args.target, 'lab.example')
        self.assertEqual(args.ports, '4280')
        self.assertEqual(args.scan_ip, 'lab.example')
        self.assertEqual(args.input_url, 'https://lab.example:4280/app?id=1')
        self.assertTrue(args.url_only)
        args = webscan.parser().parse_args(['https://lab.example:4280/', '--all-ports', '--dry-run'])
        scope.prepare_target(args)
        self.assertFalse(args.url_only)
        self.assertIsNone(args.ports)

    def test_resolves_one_nmap_address_preferring_ipv4(self):
        addresses = [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2001:db8::1', 0, 0, 0)),
                     (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.1', 0)),
                     (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.2', 0))]
        with patch.object(scope.socket, 'getaddrinfo', return_value=addresses):
            self.assertEqual(scope.resolve_one('lab.example'), '192.0.2.1')
        with patch.object(scope.socket, 'getaddrinfo', return_value=addresses[:1]):
            self.assertEqual(scope.resolve_one('lab.example'), '2001:db8::1')
        with patch.object(scope.socket, 'getaddrinfo', side_effect=AssertionError('Literal IP needs no DNS')):
            self.assertEqual(scope.resolve_one('127.0.0.1'), '127.0.0.1')

    def test_hostname_scope_rejects_other_hosts_even_if_they_share_an_ip(self):
        url = 'https://lab.example:4280/a'
        origins = {crawler.origin(url)}
        self.assertEqual(crawler.scoped_link('/x?id=1', url, 'lab.example', origins), 'https://lab.example:4280/x?id=1')
        for foreign in ('https://other.example:4280/x', 'https://sub.lab.example:4280/x',
                        'https://127.0.0.1:4280/x', 'http://lab.example:4280/x', 'https://lab.example:443/x'):
            with self.subTest(foreign=foreign), self.assertRaises(ValueError):
                crawler.scoped_link(foreign, url, 'lab.example', origins)

    def test_https_probe_and_crawler_use_hostname_sni_host_and_query(self):
        body = b'<title>Local TLS</title>'
        wire = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
        for fetch in (webscan.probe, crawler.fetch):
            fake_socket = MagicMock()
            fake_socket.makefile.return_value = io.BytesIO(wire)
            context = MagicMock()
            context.wrap_socket.return_value = fake_socket
            with patch.object(socket, 'create_connection', return_value=fake_socket), \
                 patch.object(webscan.ssl, 'create_default_context', return_value=context):
                result = fetch('https://lab.example:4280/app?id=1')
            self.assertEqual(result['status'], 200)
            self.assertEqual(context.wrap_socket.call_args.kwargs['server_hostname'], 'lab.example')
            request = b''.join(c.args[0] for c in fake_socket.sendall.call_args_list)
            self.assertIn(b'GET /app?id=1 HTTP/1.1', request)
            self.assertIn(b'Host: lab.example:4280', request)

    def test_file_url_query_is_not_used_as_directory_fuzz_base(self):
        args = webscan.parser().parse_args(['lab.example', '--dry-run', '--enum', 'ffuf'])
        jobs = webscan.build_jobs(args, Path('results'), ['https://lab.example:4280/app/item.php?id=1'], {})
        job = next(j for j in jobs if j.tool == 'ffuf')
        self.assertEqual(job.argv[job.argv.index('-u') + 1], 'https://lab.example:4280/app/FUZZ')
        nuclei = next(j for j in jobs if j.tool == 'nuclei')
        self.assertIn('https://lab.example:4280/app/item.php?id=1', nuclei.argv)

    def test_nikto_hostname_ip_metadata_and_ipv6_services(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'results.json').write_text(json.dumps({'ip': '192.0.2.1', 'vulnerabilities': [{'id': 'test', 'url': '/x', 'msg': 'test'}]}))
            summary = {'target': 'lab.example', 'scan_ip': '192.0.2.1', 'jobs': [
                dict(name='nikto', tool='nikto', status='completed', folder=str(root),
                     argv=['nikto', '-h', 'https://lab.example:4280/'], outputs=['results.json'])]}
            findings, issues = collect(root, summary)
            self.assertEqual(issues, [])
            self.assertEqual(findings[0]['url'], 'https://lab.example:4280/x')
            (root / 'services.xml').write_text('<nmaprun><host><address addr="2001:db8:0:0:0:0:0:1"/>'
                '<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>')
            services = webscan.parse_nmap(root / 'services.xml', '2001:db8::1')
            self.assertEqual(services[0]['port'], 80)
            self.assertIn('http://[2001:db8::1]:80/', webscan.candidates('2001:db8::1', services))


if __name__ == '__main__':
    unittest.main()
