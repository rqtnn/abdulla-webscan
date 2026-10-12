"""Bounded GET differential checks; never follow redirects or execute markup."""
import hashlib
import http.client
import json
import time
import urllib.parse
import uuid

from crawler import fetch, origin, scoped_link


def run_checks(candidates, target, folder, stop, rate=5, timeout=120, insecure=False):
    folder.mkdir(parents=True, exist_ok=True)
    state = {'status': 'running', 'requests': 0, 'checks': [], 'limits': []}
    deadline = time.monotonic() + timeout

    def save():
        (folder / 'checks.json').write_text(json.dumps(state, indent=2), encoding='utf-8')

    def request(url, label):
        if stop.is_set():
            raise InterruptedError('Stopped')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Check time budget reached')
        if state['requests']:
            stop.wait(min(1 / rate, remaining))
        if stop.is_set():
            raise InterruptedError('Stopped')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Check time budget reached')
        state['requests'] += 1
        response = fetch(url, insecure, min(5, remaining))
        body = response.pop('body')
        name = f'{state["requests"]:04d}-{label}.bin'
        (folder / name).write_bytes(body)
        response.update(url=url, body_file=name, body_sha256=hashlib.sha256(body).hexdigest())
        return response, body

    save()
    try:
        for candidate in candidates:
            if stop.is_set():
                break
            url, name = candidate['url'], candidate['parameter']
            # Revalidate every request independently, even for caller-provided candidates.
            allowed = {origin(url)}
            record = {'url': url, 'parameter': name, 'outcome': 'inconclusive', 'responses': []}
            state['checks'].append(record)
            try:
                scoped_link(url, url, target, allowed)
                control, body = request(url, 'control')
                record['responses'].append(control)
                marker = 'webscan' + uuid.uuid4().hex
                redirect = name.lower() in ('redirect', 'url', 'next', 'return', 'returnto', 'redirect_uri', 'dest', 'destination')
                payload = f'https://webscan.invalid/{marker}' if redirect else f'<{marker}>'
                u = urllib.parse.urlsplit(url)
                pairs = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
                probe = urllib.parse.urlunsplit((u.scheme, u.netloc, u.path,
                    urllib.parse.urlencode([(k, payload if k == name else v) for k, v in pairs]), ''))
                scoped_link(probe, url, target, allowed)
                response, changed = request(probe, 'probe')
                record['responses'].append(response)
                record.update(payload=payload, outcome='no_match')
                if any(r.get('truncated') for r in record['responses']):
                    record['outcome'] = 'inconclusive'
                elif redirect:
                    headers = {k.lower(): v for k, v in response['headers']}
                    baseline = {k.lower(): v for k, v in control['headers']}
                    if 300 <= response['status'] < 400 and headers.get('location') == payload and baseline.get('location') != payload:
                        record.update(outcome='candidate', check='external-redirect', severity='medium',
                                      title='User-controlled external redirect candidate')
                elif (200 <= control['status'] < 300 and 200 <= response['status'] < 300
                      and 'html' in dict((k.lower(), v) for k, v in response['headers']).get('content-type', '').lower()
                      and payload.encode() in changed and payload.encode() not in body):
                    record.update(outcome='candidate', check='unescaped-reflection', severity='low',
                                  title='Unescaped HTML reflection candidate (XSS not established)')
                elif not (200 <= control['status'] < 300 and 200 <= response['status'] < 400):
                    record['outcome'] = 'inconclusive'
            except InterruptedError:
                record['error'] = 'Stopped'
                break
            except (OSError, ValueError, http.client.HTTPException) as exc:
                record['error'] = str(exc)[:500]
                if time.monotonic() >= deadline:
                    state['limits'].append('time_limit')
                    break
            finally:
                save()
    except KeyboardInterrupt:
        stop.set()
        raise
    finally:
        state['status'] = 'cancelled' if stop.is_set() else ('limited' if state['limits'] else (
            'incomplete' if any(c['outcome'] == 'inconclusive' for c in state['checks']) else 'completed'))
        save()
    return state
