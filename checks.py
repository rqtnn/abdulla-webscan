"""Rqtn Tool bounded GET checks; never follow redirects or execute markup."""
import hashlib
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import time
import urllib.parse
import uuid
import re
import threading

from crawler import fetch, origin, scoped_link
from scope import RequestGate

SQL_ERRORS = {
    'mysql': re.compile(rb'you have an error in your sql syntax|SQL syntax.*?MySQL|mysqli?_sql_exception', re.I),
    'postgresql': re.compile(rb'PG::SyntaxError|PostgreSQL.*?ERROR|syntax error at or near', re.I),
    'sqlite': re.compile(rb'SQLiteException|sqlite3\.OperationalError|SQLITE_ERROR', re.I),
    'mssql': re.compile(rb'Unclosed quotation mark|Microsoft.*?SQL Server.*?Driver', re.I),
    'oracle': re.compile(rb'ORA-00933|ORA-01756|ORA-00936', re.I),
}


def security_headers(url, status, headers):
    """Return missing-header notes for successful HTML, respecting CSP framing."""
    headers = {key.lower(): value for key, value in headers}
    if not 200 <= status < 300 or 'html' not in headers.get('content-type', '').lower():
        return []
    expected = [('content-security-policy', 'Content-Security-Policy header missing'),
                ('x-content-type-options', 'X-Content-Type-Options header missing')]
    if not re.search(r'(?:^|;)\s*frame-ancestors\s', headers.get('content-security-policy', ''), re.I):
        expected.append(('x-frame-options', 'X-Frame-Options missing without CSP frame-ancestors'))
    if urllib.parse.urlsplit(url).scheme == 'https':
        expected.append(('strict-transport-security', 'HSTS header missing'))
    return [(name, title) for name, title in expected if name not in headers]


def replace_parameter(url, name, value):
    u = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, urllib.parse.urlencode([
        (k, value if k == name else v) for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True)]), ''))


def run_checks(candidates, target, folder, stop, rate=5, timeout=120, insecure=False, session=None,
               workers=1, delay=0, gate=None, sqli=False, time_sqli=False, progress=None):
    if not 1 <= workers <= 8:
        raise ValueError('Check workers must be between 1 and 8')
    if time_sqli:
        workers = 1  # Avoid creating our own concurrent timing interference.
    folder.mkdir(parents=True, exist_ok=True)
    state = {'status': 'running', 'requests': 0, 'checks': [], 'limits': []}
    deadline = time.monotonic() + timeout
    lock = threading.Lock()
    gate = gate or RequestGate(rate, delay)

    def save():
        with lock:
            (folder / 'checks.json').write_text(json.dumps(state, indent=2), encoding='utf-8')

    def request(url, label):
        if stop.is_set():
            raise InterruptedError('Stopped')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Check time budget reached')
        gate.wait(stop, deadline)
        if stop.is_set():
            raise InterruptedError('Stopped')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Check time budget reached')
        with lock:
            state['requests'] += 1
            number = state['requests']
        headers = session.headers_for(url) if session else {}
        started = time.monotonic()
        response = (fetch(url, insecure, min(5, remaining), headers=headers)
                    if headers else fetch(url, insecure, min(5, remaining)))
        response = dict(response)
        body = response.pop('body')
        response['elapsed'] = time.monotonic() - started
        name = f'{number:04d}-{label}.bin'
        (folder / name).write_bytes(body)
        response.update(url=url, body_file=name, body_sha256=hashlib.sha256(body).hexdigest())
        return response, body

    save()
    def check(candidate):
        if stop.is_set():
            return
        url, name = candidate['url'], candidate['parameter']
        # Revalidate every request independently, even for caller-provided candidates.
        allowed = {origin(url)}
        record = {'url': url, 'parameter': name, 'outcome': 'inconclusive', 'responses': []}
        try:
            scoped_link(url, url, target, allowed)
            control, body = request(url, 'control')
            record['responses'].append(control)
            marker = 'rqtn' + uuid.uuid4().hex
            redirect = name.lower() in ('redirect', 'url', 'next', 'return', 'returnto', 'redirect_uri', 'dest', 'destination')
            payload = f'https://rqtn.invalid/{marker}' if redirect else f'<{marker}>'
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
            if record['outcome'] == 'candidate':
                record['matches'] = [{k: record[k] for k in ('check', 'severity', 'title')}]
            value = dict(pairs).get(name, '')
            if sqli and not control.get('truncated') and 200 <= control['status'] < 300:
                quoted = replace_parameter(url, name, value + "'")
                scoped_link(quoted, url, target, allowed)
                sql_response, sql_body = request(quoted, 'sql-error')
                record['responses'].append(sql_response)
                signatures = [db for db, regex in SQL_ERRORS.items() if regex.search(sql_body) and not regex.search(body)]
                if sql_response.get('truncated'):
                    record['outcome'] = 'inconclusive'
                elif signatures:
                    record.setdefault('matches', []).append({'check': 'sql-error', 'severity': 'medium',
                        'title': 'New database error after quote probe (SQLi needs validation)', 'dbms_signatures': signatures})
                    record['outcome'] = 'candidate'
            if time_sqli and 200 <= control['status'] < 300 and not control.get('truncated'):
                samples = []
                delayed = replace_parameter(url, name, value + ' AND SLEEP(1)')
                scoped_link(delayed, url, target, allowed)
                for repeat in range(2):
                    baseline, baseline_body = request(url, 'timing-control')
                    timed, timed_body = request(delayed, 'timing-probe')
                    record['responses'].extend([baseline, timed])
                    samples.append({'control': baseline['elapsed'], 'probe': timed['elapsed'],
                        'delta': timed['elapsed'] - baseline['elapsed'],
                        'usable': baseline['status'] == timed['status'] == 200
                            and not baseline.get('truncated') and not timed.get('truncated')
                            and hashlib.sha256(baseline_body).digest() == hashlib.sha256(body).digest()})
                record['timing_samples'] = samples
                if all(sample['usable'] and sample['delta'] >= .8 for sample in samples):
                    record.setdefault('matches', []).append({'check': 'sql-timing-anomaly', 'severity': 'low',
                        'title': 'Repeated one-second MySQL delay anomaly (SQLi not established)'})
                    record['outcome'] = 'candidate'
                elif not all(sample['usable'] for sample in samples):
                    record['outcome'] = 'inconclusive'
        except InterruptedError:
            record['error'] = 'Stopped'
            return
        except (OSError, ValueError, http.client.HTTPException) as exc:
            record['outcome'] = 'inconclusive'
            record['error'] = str(exc)[:500]
            if time.monotonic() >= deadline:
                state['limits'].append('time_limit')
                return
        finally:
            with lock:
                state['checks'].append(record)

    pool = ThreadPoolExecutor(max_workers=workers)
    save()
    try:
        futures = [pool.submit(check, candidate) for candidate in candidates]
        for index, future in enumerate(futures, 1):
            future.result()
            save()
            if progress:
                progress(index, len(candidates))
    except KeyboardInterrupt:
        stop.set()
        raise
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
        state['limits'] = sorted(set(state['limits']))
        state['status'] = 'cancelled' if stop.is_set() else ('no_candidates' if not candidates else ('limited' if state['limits'] else (
            'incomplete' if any(c['outcome'] == 'inconclusive' for c in state['checks']) else 'completed')))
        save()
    return state


def sensitive_signature(path, body):
    path = urllib.parse.urlsplit(path).path.lower()
    if path.endswith('/.git/head') and re.match(rb'ref: refs/(?:heads|tags)/[^\r\n]+', body):
        return 'Exposed Git HEAD reference'
    if path.endswith('.env') and len(re.findall(rb'(?m)^[A-Z][A-Z0-9_]{1,80}\s*=.+$', body)) >= 2:
        return 'Environment configuration content exposed'
    if path.endswith(('.sql', '.sql.bak')) and re.search(rb'CREATE TABLE|INSERT INTO|MySQL dump|PostgreSQL database dump', body, re.I):
        return 'Database backup content exposed'
    if path.endswith(('.zip', '.zip.bak')) and body.startswith(b'PK\x03\x04'):
        return 'Backup archive content exposed'
    if path.endswith(('.php.bak', '.php~', '.php.old')) and b'<?php' in body:
        return 'PHP source backup content exposed'
    return ''


def run_sensitive_files(bases, target, wordlist, folder, stop, rate=5, timeout=120,
                        insecure=False, session=None, workers=1, delay=0, gate=None, limit=100, progress=None):
    """Bounded GET-only inventory with per-origin soft-404 controls and content signatures."""
    from collections import deque
    if not 1 <= workers <= 8 or not 1 <= limit <= 1000:
        raise ValueError('Use workers 1..8 and file limit 1..1000')
    folder.mkdir(parents=True, exist_ok=True)
    state = {'status': 'running', 'requests': 0, 'checks': [], 'limits': []}
    gate = gate or RequestGate(rate, delay)
    deadline, lock = time.monotonic() + timeout, threading.Lock()
    allowed = {origin(url) for url in bases}
    # Read bounded input; large third-party wordlists do not become unbounded jobs.
    paths = []
    with wordlist.open(encoding='utf-8', errors='replace') as source:
        for index, line in enumerate(source):
            if index >= 10000:
                state['limits'].append('wordlist_read_limit')
                break
            line = line.strip()
            if line and not line.startswith('#') and line not in paths:
                paths.append(line)
            if len(paths) > limit:
                state['limits'].append('file_limit')
                paths = paths[:limit]
                break
    controls, tasks, seen = {}, [], set()

    def request(url, label):
        scoped_link(url, url, target, allowed)
        gate.wait(stop, deadline)
        with lock:
            state['requests'] += 1
            number = state['requests']
        headers = session.headers_for(url) if session else {}
        remaining = min(5, deadline - time.monotonic())
        response = fetch(url, insecure, remaining, **({'headers': headers} if headers else {}))
        response = dict(response)
        body = response.pop('body')
        name = f'{number:04d}-{label}.bin'
        (folder / name).write_bytes(body)
        response.update(url=url, body_file=name, body_sha256=hashlib.sha256(body).hexdigest())
        return response, body

    def save():
        (folder / 'checks.json').write_text(json.dumps(state, indent=2), encoding='utf-8')

    def check(url):
        record = {'url': url, 'outcome': 'inconclusive', 'responses': []}
        try:
            control = controls[origin(url)]
            record['control_response'] = control
            response, body = request(url, 'file')
            record['responses'].append(response)
            title = sensitive_signature(url, body)
            record['outcome'] = 'no_match'
            if response.get('truncated') or control.get('truncated'):
                record['outcome'] = 'inconclusive'
            elif response['status'] == 200 and title and response['body_sha256'] != control['body_sha256']:
                record.update(outcome='candidate', check='sensitive-file', title=title,
                    severity='medium', parameter='')
        except (OSError, ValueError, http.client.HTTPException) as exc:
            record['error'] = str(exc)[:500]
            if time.monotonic() >= deadline:
                with lock:
                    state['limits'].append('time_limit')
        return record

    save()
    pool = ThreadPoolExecutor(max_workers=workers)
    pending = deque()
    try:
        for base in bases:
            base = scoped_link('/', base, target, allowed)
            if origin(base) not in controls:
                url = scoped_link('/rqtn-nonexistent-' + uuid.uuid4().hex, base, target, allowed)
                response, _ = request(url, 'file-control')
                controls[origin(base)] = response
            for path in paths:
                try:
                    url = scoped_link(path, base, target, allowed)
                    if url not in seen:
                        if len(tasks) >= limit:
                            state['limits'].append('file_limit')
                            break
                        seen.add(url)
                        tasks.append(url)
                except ValueError as exc:
                    state['checks'].append({'url': path, 'outcome': 'excluded', 'error': str(exc), 'responses': []})
        iterator = iter(tasks)
        exhausted = False
        while not stop.is_set() and (pending or not exhausted):
            while len(pending) < workers and not exhausted:
                try:
                    pending.append(pool.submit(check, next(iterator)))
                except StopIteration:
                    exhausted = True
            if pending:
                state['checks'].append(pending.popleft().result())
                save()
                if progress:
                    progress(len(state['checks']), len(tasks))
            if time.monotonic() >= deadline:
                state['limits'].append('time_limit')
                break
    except KeyboardInterrupt:
        stop.set()
        raise
    except (OSError, ValueError, http.client.HTTPException) as exc:
        state['error'] = str(exc)[:500]
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
        for future in pending:
            if not future.cancelled():
                try:
                    state['checks'].append(future.result())
                except (Exception, KeyboardInterrupt) as exc:
                    state['error'] = str(exc)[:500] or 'Interrupted file request'
        state['limits'] = sorted(set(state['limits']))
        state['status'] = 'cancelled' if stop.is_set() else ('limited' if state['limits'] else (
            'incomplete' if state.get('error') or any(c['outcome'] == 'inconclusive' for c in state['checks']) else 'completed'))
        save()
    return state
