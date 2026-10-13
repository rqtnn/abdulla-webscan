"""Rqtn Tool Nmap planning and evidence-aware single-IP service inventory."""
import hashlib
import ipaddress
import xml.etree.ElementTree as ET
from pathlib import Path

SERVICE_SCRIPTS = ('ssh2-enum-algos', 'smb2-security-mode')


def command(args, folder):
    argv = ['nmap', '-sS' if getattr(args, 'nmap_scan', 'connect') == 'syn' else '-sT', '-sV', '--version-intensity', str(args.version_intensity),
            '-Pn', '-n', '-T3', '--max-rate', str(args.nmap_rate), '--max-retries', '2',
            '--host-timeout', f'{args.nmap_timeout}s']
    if ':' in args.scan_ip:
        argv.append('-6')
    if getattr(args, 'service_checks', False):
        argv += ['--script', ','.join(SERVICE_SCRIPTS), '--script-timeout', f'{args.network_timeout}s']
    argv += (['-p', '1-65535'] if args.all_ports else
             ['-p', args.ports] if args.ports else ['--top-ports', str(args.top_ports or 1000)])
    return argv + ['-oX', str(folder / 'services.xml'), args.scan_ip]


def selection(args):
    if args.all_ports:
        return 'TCP 1-65535'
    if args.ports:
        return 'TCP ' + args.ports
    return f'Top {args.top_ports or 1000} TCP ports'


def read_xml(path, target, allow_partial=False):
    """Keep complete target-host records from interrupted XML, never infer versions."""
    rows, finished, matched, timed_out, error = {}, {}, False, False, ''
    target = ipaddress.ip_address(target)
    try:
        for _, element in ET.iterparse(path, events=('end',)):
            if element.tag == 'finished':
                finished = dict(element.attrib)
            if element.tag != 'host':
                continue
            addresses = []
            for address in element.findall('address'):
                try:
                    addresses.append(ipaddress.ip_address(address.get('addr', '')))
                except ValueError:
                    pass
            if target not in addresses:
                element.clear()
                continue
            matched = True
            timed_out |= element.get('timedout') == 'true'
            host_scripts = element.findall('hostscript/script')
            for port in element.findall('ports/port'):
                state = port.find('state')
                if port.get('protocol') != 'tcp' or state is None or state.get('state') != 'open':
                    continue
                try:
                    number = int(port.get('portid', '0'))
                except ValueError:
                    continue
                if not 1 <= number <= 65535:
                    continue
                service = port.find('service')
                info = service.attrib if service is not None else {}
                row = dict(port=number, service=info.get('name', 'unknown'),
                           product=info.get('product', ''), version=info.get('version', ''),
                           tunnel=info.get('tunnel', ''))
                for key in ('extrainfo', 'ostype', 'method', 'conf'):
                    if key in info:
                        row[key] = info[key]
                if service is not None:
                    cpes = [c.text for c in service.findall('cpe') if c.text]
                    if cpes:
                        row['cpe'] = cpes
                scripts = port.findall('script') + (host_scripts if number == 445 else [])
                checked = []
                for script in scripts:
                    if script.get('id') not in SERVICE_SCRIPTS:
                        continue
                    checked.append(dict(id=script.get('id'), output=script.get('output', '')[:8192],
                        values=[e.text[:512] for e in script.iter('elem') if e.text][:500]))
                if checked:
                    row['scripts'] = checked
                rows[number] = row
            element.clear()
    except ET.ParseError as exc:
        if not allow_partial:
            raise
        error = str(exc)
    return sorted(rows.values(), key=lambda r: r['port']), dict(
        xml_error=error, target_host_present=matched, host_timed_out=timed_out,
        finished=finished)


def inventory(path, target, job_status):
    """Separate planned, unavailable, partial, and completed empty inventories."""
    details = dict(status=job_status, note='', evidence_file='nmap/services.xml')
    if job_status == 'planned':
        details['note'] = 'Plan only: no port scan or version probes were executed.'
        return [], details
    if not Path(path).is_file():
        details['status'] = 'unavailable'
        details['note'] = 'No Nmap XML produced; review nmap/console.log and tool installation.'
        return [], details
    details['sha256'] = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    rows, parsed = read_xml(path, target, allow_partial=True)
    details.update(parsed)
    if parsed['xml_error'] or parsed['host_timed_out'] or job_status != 'completed' or parsed['finished'].get('exit', 'success') != 'success':
        details['status'] = 'partial'
        details['note'] = 'Incomplete scan: only complete target-host XML records are shown; ports or versions may be missing.'
    elif not parsed['target_host_present']:
        details['status'] = 'inconclusive'
        details['note'] = 'Nmap returned no XML host record for the selected IP; this is not proof of no open ports.'
    else:
        details['status'] = 'completed' if rows else 'completed_no_open_ports'
        details['note'] = ('Open TCP ports observed within the selected port set. Blank versions were not identified.'
                           if rows else 'No open TCP ports reported within the selected port set; other ports were not assessed.')
    return rows, details
