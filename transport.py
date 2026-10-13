"""Connections pinned to a numeric address, retaining HTTP Host and TLS identity."""
import http.client
import ipaddress
import socket
import ssl
import urllib.parse
from scope import resolve_one


def connection(url, insecure=False, timeout=5, scan_ip=None):
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ('http', 'https') or not u.hostname or u.username is not None:
        raise ValueError('Expected an HTTP(S) URL without credentials')
    address = str(ipaddress.ip_address(scan_ip or resolve_one(u.hostname)))
    context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    conn = (http.client.HTTPSConnection(u.hostname, u.port, timeout=timeout, context=context)
            if u.scheme == 'https' else http.client.HTTPConnection(u.hostname, u.port, timeout=timeout))

    def connect():
        # Numeric socket address: no second getaddrinfo, even if DNS has changed.
        sock = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect((address, conn.port))
            conn.sock = context.wrap_socket(sock, server_hostname=u.hostname) if u.scheme == 'https' else sock
        except BaseException:
            sock.close()
            raise
    conn.connect = connect
    return conn
