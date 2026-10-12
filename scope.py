"""Single-host target parsing and URL canonicalization without network access."""
import dataclasses
import ipaddress
import re
import socket
import urllib.parse


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
    explicit_ports = bool(args.ports or args.all_ports)
    args.target = target.host
    args.input_target = original
    args.input_url = target.url
    args.url_only = bool(target.url and not explicit_ports)
    if args.url_only:
        u = urllib.parse.urlsplit(target.url)
        args.ports = str(u.port or (443 if u.scheme == 'https' else 80))
    args.scan_ip = target.host if args.dry_run else resolve_one(target.host)
    return target
