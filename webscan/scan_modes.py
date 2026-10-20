"""Explicit scan plans. Selected tools cannot silently launch unrelated stages."""
import re

EXTERNAL = ('httpx', 'whatweb', 'ffuf', 'gobuster', 'feroxbuster', 'dirsearch', 'nikto', 'nuclei', 'sqlmap', 'wpscan', 'katana', 'dalfox', 'testssl')
TOOLS = ('nmap', *EXTERNAL, 'crawl', 'checks', 'files', 'cors', 'api', 'tls')


def default(args, argv, name, value):
    flag = '--' + name.replace('_', '-')
    if not any(v == flag or v.startswith(flag + '=') for v in argv):
        setattr(args, name, value)


def apply(args, argv):
    if args.scan in ('server', 'estate'):
        default(args, argv, 'nmap_timeout', 3600)
    if getattr(args, 'all_tools', False):
        if args.only:
            raise ValueError('Use --all-tools or --only, not both')
        if args.assessment == 'network':
            raise ValueError('--all-tools requires a web assessment')
        args.external_tools = args.retain_raw_evidence = True
        default(args, argv, 'enum', 'all')
    args.only = list(dict.fromkeys(args.only)) if args.only else None
    chosen = set(args.only or [])
    needs_crawl = bool(chosen & {'crawl', 'checks', 'dalfox'} or 'sqlmap' in chosen and not args.sqlmap_url)
    if needs_crawl and args.no_crawl:
        raise ValueError('Selected tools need crawling; remove --no-crawl or choose different tools')
    if chosen & {'checks', 'cors', 'dalfox'} and args.no_active_checks:
        raise ValueError('Selected checks conflict with --no-active-checks')
    if 'sqlmap' in chosen and args.no_auto_sqli and not args.sqlmap_url:
        raise ValueError('Automatic SQLmap selection conflicts with --no-auto-sqli')
    if chosen == {'tls'} and (args.all_ports or args.top_ports):
        raise ValueError('TLS-only requires explicit --ports or a URL; select nmap and tls for port discovery')
    if chosen & set(args.skip):
        raise ValueError('The same tool cannot be selected with --only and --skip')
    if chosen and args.scan != 'full':
        raise ValueError('Use --only or --scan; do not combine separate scan plans')
    if args.scan in ('ctf', 'deep'):
        args.assessment = 'web'
        args.template_checks = not args.no_active_checks
        args.active_checks = not args.no_active_checks
        args.builtin_sqli = not args.no_active_checks
        args.sensitive_files = args.api_discovery = True
    if args.scan == 'deep':
        for name, value in dict(crawl_pages=300, crawl_depth=5, crawl_timeout=600,
                checks_timeout=300, max_sqli_jobs=30, advanced_timeout=300).items():
            default(args, argv, name, value)
    if args.scan in ('all-ports', 'server'):
        if args.ports or args.top_ports or args.url_port_only or 'nmap' in args.skip:
            raise ValueError('All-port discovery requires Nmap without a restricted port selection')
        args.all_ports = True
        args.assessment = 'full' if args.scan == 'server' else 'web'
        default(args, argv, 'nmap_timeout', 3600)
    elif args.scan == 'web':
        args.assessment = 'web'
        if not any((args.ports, args.all_ports, args.top_ports, args.url_port_only)):
            args.ports = '80,443'
    elif args.scan == 'quick':
        if not any((args.ports, args.all_ports, args.top_ports, args.url_port_only)):
            args.top_ports = 100
        for name, value in dict(version_intensity=2, crawl_pages=20, crawl_depth=2,
                crawl_timeout=60, checks_timeout=60, file_limit=10, max_sqli_jobs=2,
                nmap_timeout=120, tool_timeout=120, advanced_timeout=60).items():
            default(args, argv, name, value)
    elif args.scan == 'port' and not (args.ports or args.url_port_only):
        raise ValueError('--scan port requires --ports or --url-port-only')
    if not chosen:
        return
    args.skip = list(dict.fromkeys(args.skip + [t for t in ('nmap', *EXTERNAL) if t not in chosen]))
    args.enum = 'all' if chosen & {'ffuf', 'gobuster', 'feroxbuster', 'dirsearch'} else 'none'
    args.profile = 'standard'
    args.no_crawl = not needs_crawl
    args.no_auto_sqli = 'sqlmap' not in chosen or bool(args.sqlmap_url)
    args.active_checks = args.builtin_sqli = 'checks' in chosen
    args.no_active_checks = not bool(chosen & {'checks', 'cors', 'dalfox'})
    args.time_sqli = args.time_sqli and 'checks' in chosen
    args.sensitive_files = 'files' in chosen
    args.cors_checks = 'cors' in chosen
    args.api_discovery = 'api' in chosen
    args.contexts = args.contexts if 'api' in chosen else None
    args.idor = args.idor and 'api' in chosen
    args.ssrf_canary = args.ssrf_canary if 'api' in chosen else None
    args.ssrf_metadata = args.ssrf_metadata and 'api' in chosen
    args.sqlmap_url = args.sqlmap_url if 'sqlmap' in chosen else None
    args.sqlmap_param = args.sqlmap_param if 'sqlmap' in chosen else None
    args.service_checks = False
    args.external_tools = bool(chosen & set(EXTERNAL))
    args.assessment = 'network' if chosen <= {'nmap', 'tls'} else ('full' if 'tls' in chosen else 'web')


def plan(args):
    requested = list(args.only or [])
    return dict(mode=args.scan, requested_tools=requested or ['profile:' + args.profile],
                all_tools=getattr(args, 'all_tools', False),
                dependencies=['crawl_for_GET_parameters'] if not args.no_crawl and set(requested) & {'checks', 'sqlmap', 'dalfox'} else [],
                external_raw_output=args.external_tools and args.retain_raw_evidence)


def parse_ports(value):
    """Normalize decimal port inputs for scanner argv, including Arabic digits."""
    value = value.strip().replace('،', ',')
    if not re.fullmatch(r'\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*', value):
        raise ValueError('Use TCP ports such as 80,443,8080 or 1-65535')
    normalized = []
    for part in value.split(','):
        bounds = [int(number) for number in part.split('-')]
        if any(number < 1 or number > 65535 for number in bounds) or bounds[0] > bounds[-1]:
            raise ValueError('Ports must be between 1 and 65535 with ascending ranges')
        normalized.append('-'.join(str(number) for number in bounds))
    return ','.join(normalized)
