"""Offline discovery decisions and explanations of incomplete web coverage."""
import ssl
from urllib.parse import urljoin

from . import evidence
from .scope import normalize_url, origin


def error_kind(exc):
    if isinstance(exc, ssl.SSLCertVerificationError):
        return 'tls_certificate'
    if isinstance(exc, ssl.SSLError):
        return 'tls_protocol'
    if isinstance(exc, TimeoutError):
        return 'timeout'
    return 'connection'


def certificate_blocked(row):
    return row.get('error_kind') == 'tls_certificate' or 'CERTIFICATE_VERIFY_FAILED' in row.get('error', '')


def redundant_alternative(url, explicit_urls, probes):
    """An explicit URL is always tried; transport failures still permit fallback."""
    if url in explicit_urls:
        return False
    scheme, host, port = origin(url)
    return any(origin(row['url'])[1:] == (host, port) and origin(row['url'])[0] != scheme
               and (('status' in row and row['status'] not in (400, 426)) or certificate_blocked(row))
               for row in probes)


def explain(summary):
    if summary.get('dry_run'):
        return []
    rows, seen = [], set()

    def add(code, url, message, action):
        key = (code, url)
        if key not in seen:
            rows.append(dict(code=code, url=evidence.url(url) if url else '', message=message, action=action))
            seen.add(key)

    probes = summary.get('probes', [])
    for row in probes:
        if certificate_blocked(row):
            add('tls_certificate', row['url'], 'HTTPS application coverage is blocked by certificate verification.',
                'Use the hostname matching the certificate and a trusted CA. For a deliberately self-signed lab only, explicitly select --insecure; verification is never disabled automatically.')
        elif row.get('error_kind') == 'tls_protocol' or 'WRONG_VERSION_NUMBER' in row.get('error', ''):
            add('tls_protocol', row['url'], 'The HTTPS handshake failed; this port may use plain HTTP.',
                'Check the observed service and URL scheme. A protocol mismatch is not a vulnerability finding.')
    pages = summary.get('crawl', {}).get('pages', [])
    visited = {p['url'] for p in pages if 'status' in p}
    for row in probes + pages:
        headers = dict((str(k).lower(), v) for k, v in row.get('headers', []))
        location = row.get('location') or headers.get('location')
        if row.get('status') not in (301, 302, 303, 307, 308) or not location:
            continue
        try:
            destination = normalize_url(urljoin(row['url'], location), summary['target'])
        except (ValueError, TypeError):
            add('redirect_scope', row['url'], 'Redirect points outside the single-host scope or to an invalid URL.',
                'Review the Location header and start a separate authorized scan with the intended hostname if appropriate.')
            continue
        if destination not in visited:
            add('redirect_not_crawled', row['url'], 'Redirect destination was not crawled: ' + evidence.url(destination),
                'Check HTTPS certificate errors, crawl limits and redirect exclusions. Only same-origin non-action redirects can be followed; use --crawl-redirects if disabled.')
    if summary.get('active_checks', {}).get('status') == 'no_candidates':
        add('no_get_parameters', '', 'No eligible GET parameters were discovered; parameter injection checks sent no probes.',
            'Review crawl redirects and exclusions, authentication, POST forms and JavaScript-rendered routes. Supply an actual authorized URL with its query parameters when available; do not invent parameters.')
    forms = summary.get('crawl', {}).get('forms', [])
    if any(f.get('reason') for f in forms):
        add('deferred_forms', '', 'Some forms need manual review and were not submitted.',
            'Review the Deferred forms table; POST, password and sensitive-input forms are not GET parameter coverage.')
    if summary.get('external_scanners', {}).get('enabled') is False:
        add('external_disabled', '', 'External web scanners were disabled for this run.',
            'For an authorized numeric-IP target, --external-tools --retain-raw-evidence enables installed external adapters. Check availability with --check; raw evidence can contain sensitive data.')
    return rows
