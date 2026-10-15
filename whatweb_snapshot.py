"""Run WhatWeb's Ruby passive plugins against a DNS-pinned HTTP packet file.

WhatWeb supports local HTTP packet files natively. No proxy, browser, target
JavaScript, second DNS resolution or additional remote plugin request is needed.
URL/DNS/TLS-only plugins are intentionally unavailable in this mode.
"""
import json
import hashlib
import time
from http import HTTPStatus

from crawler import fetch


def prepare(snapshot, folder, stop, gate):
    deadline = time.monotonic() + snapshot['timeout']
    gate.wait(stop, deadline)
    if stop.is_set():
        raise InterruptedError('Stopped before fingerprint capture')
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('Snapshot budget reached')
    response = fetch(snapshot['url'], snapshot['insecure'], remaining, scan_ip=snapshot['scan_ip'])
    gate.observe(response)
    # A truncated packet can produce incomplete fingerprints; report it explicitly.
    if response.get('truncated'):
        raise ValueError('Response exceeds the 256 KiB snapshot limit')
    if any(k.lower() == 'content-encoding' and v.lower() not in ('identity', '') for k, v in response['headers']):
        raise ValueError('Encoded snapshot requires decoding; fingerprinting deferred')
    status = response['status']
    phrase = HTTPStatus(status).phrase if status in HTTPStatus._value2member_map_ else 'Response'
    headers = []
    for key, value in response['headers']:
        if key.lower() not in ('transfer-encoding', 'content-length', 'connection', 'content-encoding'):
            if '\r' in key + value or '\n' in key + value:
                raise ValueError('Invalid HTTP header')
            headers.append(key + ': ' + value)
    packet = ('\r\n'.join(['HTTP/1.1 ' + str(status) + ' ' + phrase, *headers]) + '\r\n\r\n').encode('utf-8') + response['body']
    path = folder / 'response.http'
    path.write_bytes(packet)
    path.chmod(0o600)


def remap(path, url):
    rows = json.loads(path.read_text(encoding='utf-8-sig'))
    if not isinstance(rows, list) or not rows:
        raise ValueError('Expected nonempty WhatWeb packet results')
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('plugins'), dict):
            raise ValueError('Expected WhatWeb target/plugins')
        row['snapshot_target'] = row.get('target')
        row['snapshot_file'] = 'response.http'
        packet = path.parent / 'response.http'
        if packet.is_file():
            row['snapshot_sha256'] = hashlib.sha256(packet.read_bytes()).hexdigest()
        row['target'] = url
        row['fingerprint_mode'] = 'pinned_http_snapshot'
        row['coverage_note'] = 'Passive header/body plugins only; URL, DNS and TLS plugins are unavailable.'
    path.write_text(json.dumps(rows, ensure_ascii=False), encoding='utf-8')
