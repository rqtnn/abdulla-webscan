"""WS-R single-host parsing, scope enforcement and HTTP pacing."""
import dataclasses
import ipaddress
import re
import socket
import urllib.parse
import threading
import time
import math
import datetime as dt
import email.utils

ACTION = re.compile(r'(?:^|[/_\W])(?:logout|signout|delete|remove|destroy|reset|unsubscribe|purchase|checkout)(?:$|[/_\W])', re.I)


def origin(url):
    u = urllib.parse.urlsplit(url)
    return u.scheme, u.hostname, u.port or (443 if u.scheme == 'https' else 80)


def scoped_link(value, base, target, origins):
    value = normalize_url(urllib.parse.urljoin(base, value.strip()), target)
    if origin(value) not in origins:
        raise ValueError('Port/scheme was not a responding origin')
    if len(value) > 4096 or ACTION.search(urllib.parse.unquote(value)):
        raise ValueError('Action-like or oversized URL excluded from automatic requests')
    return value


class RequestGate:
    """One start-rate limit shared by built-in HTTP workers; cancellable waits."""
    def __init__(self, rate=5, delay=0):
        if not math.isfinite(rate) or not math.isfinite(delay) or rate <= 0 or delay < 0:
            raise ValueError('Rate must be positive and delay nonnegative')
        self.interval = max(1 / rate, delay)
        self.next_start = 0
        self.lock = threading.Lock()

    def observe(self, response):
        """Honor Retry-After for throttled/unavailable responses across HTTP stages."""
        if response.get('status') not in (429, 503):
            return
        value = response.get('retry_after', '')
        for name, header in response.get('headers', []):
            if name.lower() == 'retry-after':
                value = header
        try:
            seconds = float(value) if str(value).isdigit() else (
                email.utils.parsedate_to_datetime(value) - dt.datetime.now(dt.timezone.utc)).total_seconds()
            if not math.isfinite(seconds) or seconds <= 0:
                return
        except (ValueError, TypeError, OverflowError):
            return
        with self.lock:
            self.next_start = max(self.next_start, time.monotonic() + seconds)

    def wait(self, stop, deadline):
        while True:
            if stop.is_set():
                raise InterruptedError('Stopped')
            with self.lock:
                now = time.monotonic()
                slot = max(now, self.next_start)
                if slot >= deadline:
                    raise TimeoutError('HTTP stage time budget reached')
                if slot <= now:
                    self.next_start = now + self.interval
                    return
                pause = slot - now
            # Keep the lock available for Retry-After updates during a paced wait.
            if stop.wait(pause):
                raise InterruptedError('Stopped')
            # Recheck both the deadline and any backoff installed during the wait.


def host(value):
    value = value.rstrip('.').lower()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise ValueError('Invalid hostname') from exc
    if (not value or len(value) > 253 or re.fullmatch(r'[\d.]+', value)
            or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                   for label in value.split('.'))):
        raise ValueError('Use one IP address or hostname, not a range or command')
    return value


def authority(value, port=None):
    value = host(value)
    value = f'[{value}]' if ':' in value else value
    return value + (f':{port}' if port is not None else '')


def normalize_url(value, target):
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Control characters are not allowed in URLs')
    u = urllib.parse.urlsplit(value)
    if (u.scheme not in ('http', 'https') or u.username is not None or u.password is not None
            or host(u.hostname or '') != host(target)):
        raise ValueError('Result URL is outside the single-host scope or invalid')
    if u.port is not None and not 1 <= u.port <= 65535:
        raise ValueError('Invalid URL port')
    default = 443 if u.scheme == 'https' else 80
    port = u.port if u.port != default else None
    path = urllib.parse.quote(u.path or '/', safe="/%:@!$&'()*+,;=-._~")
    query = urllib.parse.quote(u.query, safe="/?[]:@!$&'()*+,;=%-._~")
    return urllib.parse.urlunsplit((u.scheme, authority(target, port), path, query, ''))


@dataclasses.dataclass(frozen=True)
class Target:
    host: str
    url: str = ''


def parse_target(value):
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Control characters are not allowed in targets')
    value = value.strip()
    if '://' in value:
        u = urllib.parse.urlsplit(value)
        name = host(u.hostname or '')
        return Target(name, normalize_url(value, name))
    # Keep bare IP/hostname scanning compatible; accept explicit ports/paths without a scheme.
    try:
        return Target(str(ipaddress.ip_address(value)))
    except ValueError:
        pass
    if ':' in value or '/' in value:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            pass
        else:
            raise ValueError('IP ranges are not supported')
        u = urllib.parse.urlsplit('http://' + value)
        name = host(u.hostname or '')
        return Target(name, normalize_url('http://' + value, name))
    # Bare IPs (including IPv6) and hostnames; URLs must include their scheme.
    return Target(host(value))


def resolve_one(value):
    """Choose one address for Nmap. Prefer IPv4; web tools retain the hostname."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        addresses = socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)
        ips = list(dict.fromkeys(a[4][0] for a in addresses if a[0] in (socket.AF_INET, socket.AF_INET6)))
        if not ips:
            raise ValueError('No IPv4/IPv6 addresses found for target')
        return next((ip for ip in ips if ':' not in ip), ips[0])


def prepare_target(args):
    original = args.target
    target = parse_target(original)
    explicit_ports = bool(args.ports or args.all_ports or getattr(args, 'top_ports', None))
    args.target = target.host
    args.input_target = original
    args.input_url = target.url
    args.url_only = bool(getattr(args, 'url_port_only', False))
    if args.url_only and (not target.url or explicit_ports):
        raise ValueError('--url-port-only requires a URL and cannot be combined with another port selection')
    if args.url_only:
        u = urllib.parse.urlsplit(target.url)
        args.ports = str(u.port or (443 if u.scheme == 'https' else 80))
    args.scan_ip = target.host if args.dry_run else resolve_one(target.host)
    return target
