"""Connections pinned to a numeric address, retaining HTTP Host and TLS identity."""
import http.client
import ipaddress
import io
import socket
import ssl
import time
import urllib.parse
from scope import resolve_one


class DeadlineReader(io.RawIOBase):
    """A trickling peer cannot reset the request budget on every socket read."""
    def __init__(self, source, sock, deadline):
        self.source, self.sock, self.deadline = source, sock, deadline

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('HTTP request time budget reached')
        self.sock.settimeout(remaining)
        data = self.source.read1(len(buffer))
        buffer[:len(data)] = data
        return len(data)

    def close(self):
        try:
            self.source.close()
        finally:
            super().close()


def connection(url, insecure=False, timeout=5, scan_ip=None):
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ('http', 'https') or not u.hostname or u.username is not None:
        raise ValueError('Expected an HTTP(S) URL without credentials')
    address = str(ipaddress.ip_address(scan_ip or resolve_one(u.hostname)))
    context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    conn = (http.client.HTTPSConnection(u.hostname, u.port, timeout=timeout, context=context)
            if u.scheme == 'https' else http.client.HTTPConnection(u.hostname, u.port, timeout=timeout))
    deadline = time.monotonic() + timeout

    class Response(http.client.HTTPResponse):
        def __init__(self, sock, *args, **kwargs):
            super().__init__(sock, *args, **kwargs)
            self.fp = io.BufferedReader(DeadlineReader(self.fp, sock, deadline))
    conn.response_class = Response

    def connect():
        # Numeric socket address: no second getaddrinfo, even if DNS has changed.
        sock = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            sock.connect((address, conn.port))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Connection time budget reached')
            sock.settimeout(remaining)
            conn.sock = context.wrap_socket(sock, server_hostname=u.hostname) if u.scheme == 'https' else sock
        except BaseException:
            sock.close()
            raise
    conn.connect = connect
    return conn
