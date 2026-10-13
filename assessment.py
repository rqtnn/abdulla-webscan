"""Bounded single-host network configuration assessment, without exploit probes."""
import hashlib
import json
import re
import ssl
import time
import urllib.parse
from pathlib import Path

import evidence
from scope import authority, normalize_url
from transport import connection


# Exposure is a configuration review item, not a version-to-CVE assertion.
RULES = (
    ('telnet', {23}, {'telnet'}, 'medium', 'Telnet service exposed',
     'Replace Telnet with SSH and restrict management access to trusted networks.', True),
    ('ftp', {21}, {'ftp'}, 'medium', 'FTP service exposed',
     'Require encrypted file transfer; disable anonymous access and restrict reachability.', True),
    ('database', {1433, 1521, 3306, 5432, 27017}, {'ms-sql-s', 'oracle', 'mysql', 'postgresql', 'mongodb'}, 'medium',
     'Database service reachable', 'Restrict database access to application hosts; verify authentication and encryption.', False),
    ('redis', {6379}, {'redis'}, 'medium', 'Redis service reachable',
     'Restrict network access, require appropriate ACLs and encryption, and disable unnecessary commands.', False),
    ('memcached', {11211}, {'memcached'}, 'medium', 'Memcached service reachable',
     'Bind to trusted interfaces and restrict access with network controls.', False),
    ('remote-desktop', {3389, 5900, 5901}, {'ms-wbt-server', 'vnc'}, 'low', 'Remote desktop service reachable',
     'Restrict access through a VPN or management gateway and require strong authentication.', False),
    ('smb', {139, 445}, {'netbios-ssn', 'microsoft-ds'}, 'low', 'SMB service reachable',
     'Restrict SMB to required internal hosts; review guest access, signing and supported protocol versions.', False),
    ('rpc', {111}, {'rpcbind'}, 'low', 'RPC service reachable',
     'Restrict RPC to required hosts and disable unused RPC services.', False),
    ('management', {22}, {'ssh'}, 'info', 'SSH management service reachable',
     'Restrict management access, review authentication policy and maintain supported software.', False),
)


def inventory_checks(target, ports):
    rows = []
    for service in ports:
        port = service['port']
        name = service.get('service', 'unknown').lower()
        # An identified service takes precedence over a conventional port number.
        unknown = name in ('unknown', '', 'tcpwrapped')
        for check, numbers, names, severity, title, recommendation, cleartext in RULES:
            if name not in names and not (unknown and port in numbers):
                continue
            if cleartext and service.get('tunnel') == 'ssl':
                continue
            rows.append(dict(check='network-' + check, url='tcp://' + authority(target, port),
                title=title, severity=severity, recommendation=recommendation,
                status='observed', confidence='service_identified' if not unknown else 'port_convention_only',
                detail=f"TCP {port}: {name}; reachability does not establish unauthorized access."))
        for script in service.get('scripts', []):
            values = script.get('values', [])
            output = script.get('output', '')
            if script.get('id') == 'smb2-security-mode' and any(
                    'message signing enabled but not required' in text.lower() for text in [output, *values]):
                rows.append(dict(check='network-smb-signing', url='tcp://' + authority(target, port),
                    title='SMB2/SMB3 signing is not required', severity='medium', status='observed',
                    confidence='protocol_negotiation', detail='Nmap smb2-security-mode reports optional message signing.',
                    recommendation='Require SMB signing where compatible and restrict SMB to trusted hosts; validate client compatibility before rollout.'))
            if script.get('id') == 'ssh2-enum-algos':
                weak = [algo for algo in ('diffie-hellman-group1-sha1', 'ssh-dss') if algo in values or
                        re.search(r'(?m)^\s*' + re.escape(algo) + r'\s*$', output)]
                if weak:
                    rows.append(dict(check='network-ssh-legacy-algorithms', url='tcp://' + authority(target, port),
                        title='SSH advertises legacy algorithms', severity='low', status='observed',
                        confidence='protocol_negotiation', detail=', '.join(weak),
                        recommendation='Remove obsolete key exchange/host key algorithms after confirming supported client compatibility.'))
    return rows


def tls_check(url, scan_ip, timeout):
    """One verified handshake; never bypass certificate checks for assessment."""
    conn = connection(url, False, timeout, scan_ip)
    row = dict(url=url, check='tls-handshake', status='inconclusive')
    try:
        conn.connect()
        cert = conn.sock.getpeercert()
        row.update(status='completed', protocol=conn.sock.version(), cipher=conn.sock.cipher()[0],
                   certificate_sha256=hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest(),
                   not_after=cert.get('notAfter', ''), certificate_verified=True)
        if cert.get('notAfter'):
            row['expires_in_days'] = int((ssl.cert_time_to_seconds(cert['notAfter']) - time.time()) // 86400)
            if row['expires_in_days'] < 30:
                row.update(check='tls-expiring', title='TLS certificate expires within 30 days', severity='low',
                    recommendation='Renew the certificate and verify the deployed chain before expiration.')
    except ssl.SSLCertVerificationError as exc:
        row.update(status='observed', check='tls-certificate', title='TLS certificate verification failed',
                   severity='medium', certificate_verified=False, verification_code=exc.verify_code,
                   detail=str(exc)[:500], recommendation='Verify hostname, validity dates and certificate chain. '
                   'For a private lab CA, configure trust on the scanner before treating this as a server defect.')
    except (OSError, ssl.SSLError, ValueError) as exc:
        row['detail'] = str(exc)[:500]
    finally:
        conn.close()
    return row


def run(target, scan_ip, ports, explicit_urls, folder, stop, gate, timeout=60, request_timeout=10, progress=None):
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    state = dict(status='running', checks=inventory_checks(target, ports), tls=[], limits=[],
                 scope='Single pinned host; TCP inventory, optional allowlisted SSH/SMB negotiation and verified TLS; no login or exploit attempts.')
    deadline = time.monotonic() + timeout
    urls = list(explicit_urls)
    urls += ['https://' + authority(target, s['port']) + '/' for s in ports
             if s.get('tunnel') == 'ssl' or 'https' in s.get('service', '').lower()]
    urls = list(dict.fromkeys(urllib.parse.urlunsplit((*urllib.parse.urlsplit(normalize_url(u, target))[:2], '/', '', ''))
                              for u in urls if urllib.parse.urlsplit(u).scheme == 'https'))
    def save():
        (folder / 'assessment.json').write_text(evidence.dumps(state), encoding='utf-8')
    save()
    try:
        for index, url in enumerate(urls):
            if stop.is_set():
                break
            if index >= 32:
                state['limits'].append('tls_target_limit')
                break
            try:
                gate.wait(stop, deadline)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('Assessment time budget reached')
                state['tls'].append(tls_check(url, scan_ip, min(request_timeout, remaining)))
            except TimeoutError:
                state['limits'].append('time_limit')
                break
            save()
            if progress:
                progress(index + 1, len(urls))
    finally:
        state['status'] = ('cancelled' if stop.is_set() else 'limited' if state['limits'] else
                           'incomplete' if any(r['status'] == 'inconclusive' for r in state['tls']) else 'completed')
        save()
    return state


def findings(root, summary):
    """Use the persisted assessment artifact as evidence, including offline rebuilds."""
    path = Path(root) / 'network' / 'assessment.json'
    state = summary.get('network_assessment', {})
    if not path.is_file() or not state:
        return []
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    results = []
    for index, row in enumerate(state.get('checks', []) + state.get('tls', []), 1):
        if not row.get('title'):
            continue
        key = (row['check'], row['url'])
        results.append(dict(id=hashlib.sha256(json.dumps(key).encode()).hexdigest()[:16],
            category='configuration', check=row['check'], url=row['url'], title=row['title'],
            severity=row['severity'], validation_status='needs_validation', recommendation=row['recommendation'],
            detail=row.get('detail', ''), confidence=row.get('confidence', 'direct_handshake'),
            evidence=[dict(tool='network', job='Network configuration and TLS', job_status=state['status'],
                           file='network/assessment.json', record=index, sha256=digest, raw='[omitted]')]))
    return results
