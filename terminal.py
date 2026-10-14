"""WS-R terminal presentation; Rich is optional."""
from contextlib import contextmanager
import sys
import time

BANNER = 'WS-R'


class TerminalUI:
    def __init__(self, mode='auto'):
        self.console = None
        if mode == 'plain' or (mode == 'auto' and not sys.stdout.isatty()):
            return
        try:
            from rich.console import Console
            self.console = Console()
        except ImportError:
            if mode == 'rich':
                print('Rich is unavailable; using plain output. Install requirements.txt for Rich.')

    def startup(self, version):
        self.message(f'{BANNER} | {version}')

    def prompt_target(self):
        prompt = 'Target URL/IP (e.g. http://127.0.0.1:3000): '
        return self.console.input(prompt) if self.console else input(prompt)

    def prompt_scan(self):
        from scan_modes import TOOLS, EXTERNAL
        self.message('Choose scan after entering the target:')
        for option in ('1 Full assessment', '2 Web (80/443)', '3 Quick assessment',
                       '4 Nmap only', '5 WhatWeb only', '6 Crawl only',
                       '7 Choose individual tools', '8 Specific port'):
            self.message(option)
        self.message('External tool selection retains raw scanner output. Built-in checks omit bodies by default.')
        def ask(text):
            return self.console.input(text) if self.console else input(text)
        choice = ask('Scan choice [1]: ').strip() or '1'
        if choice.isdecimal():
            choice = str(int(choice))
        if choice in ('1', '2', '3'):
            return {'scan': {'1': 'full', '2': 'web', '3': 'quick'}[choice], 'only': None}
        if choice in ('4', '5', '6'):
            tool = {'4': 'nmap', '5': 'whatweb', '6': 'crawl'}[choice]
            return {'scan': 'full', 'only': [tool], 'retain_raw_evidence': tool in EXTERNAL}
        if choice == '7':
            self.message('Available: ' + ', '.join(TOOLS))
            selected = list(dict.fromkeys(ask('Tools (comma or space separated): ').replace(',', ' ').split()))
            if not selected or any(tool not in TOOLS for tool in selected):
                raise ValueError('Select one or more listed tool names')
            return {'scan': 'full', 'only': selected, 'retain_raw_evidence': bool(set(selected) & set(EXTERNAL))}
        if choice == '8':
            return {'scan': 'port', 'only': None, 'ports': ask('TCP port(s), e.g. 443 or 80,443: ').strip()}
        raise ValueError('Choose a scan number from 1 to 8')

    def whatweb_results(self, summary):
        """Show bounded parsed fingerprints and explicit reasons for absent output."""
        import evidence
        import re
        def text(value):
            return re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', str(value))[:240]
        jobs = [job for job in summary.get('jobs', []) if job.get('tool') == 'whatweb']
        self.message('[WHATWEB] Technology results (fingerprints, not verified vulnerabilities):')
        if not jobs:
            self.message('[WHATWEB] No job started: no responding HTTP(S) URL. Enter the complete URL with its port, e.g. http://192.168.56.101:8080/.')
            return
        rows = [row for row in summary.get('findings', []) if row.get('category') == 'technology'
                and any(item.get('tool') == 'whatweb' for item in row.get('evidence', []))]
        for row in rows[:100]:
            versions = []
            for item in row.get('evidence', []):
                raw = item.get('raw')
                if item.get('tool') == 'whatweb' and isinstance(raw, dict):
                    plugin = raw.get('plugins', {}).get(row.get('check'), {})
                    if isinstance(plugin, dict):
                        values = plugin.get('version', [])
                        versions.extend(values if isinstance(values, list) else [values])
            suffix = ' | version: ' + ', '.join(text(v) for v in versions[:8]) if versions else ''
            self.message('[WHATWEB] ' + text(evidence.url(row['url'])) + ' | ' + text(row['title']) + suffix)
        if len(rows) > 100:
            self.message('[WHATWEB] More technologies are available in report.html.')
        for job in jobs:
            if job.get('status') != 'completed':
                self.message('[WHATWEB] ' + text(job.get('status', 'unknown')) + ': ' + text(job.get('note', '')))
                if 'not installed/on PATH' in job.get('note', ''):
                    self.message('[WHATWEB] Install on Kali/Ubuntu/WSL: sudo apt install whatweb')
                if job.get('status') in ('failed', 'timeout', 'incomplete'):
                    self.message('[WHATWEB] Scanner diagnostics: ' + str(job['folder']) + '/console.log')
        issues = [issue for issue in summary.get('parse_issues', []) if any(issue.get('job') == job.get('name') for job in jobs)]
        if issues:
            self.message('[WHATWEB] Scanner output could not be fully parsed; inspect results.json and console.log in the report directory.')
        if not rows:
            self.message('[WHATWEB] No technology fingerprints parsed. This does not mean the website has no vulnerabilities.')

    def completion(self, statistics, priority):
        self.message('[SUMMARY] Hosts assessed={hosts_assessed} | Hosts reached={hosts_reached} | '
                     'Open TCP ports={open_ports} | Candidate vulnerabilities={vulnerability_candidates} | '
                     'Configuration findings={configuration_findings} | '
                     'Confirmed vulnerabilities={confirmed_vulnerabilities}'.format(**statistics))
        self.message('[PRIORITY] ' + priority + ' (triage priority, not CVSS or confirmed risk)')

    def message(self, message):
        if self.console:
            style = ('red' if message.startswith(('[FAILED]', '[TIMEOUT]')) else
                     'green' if message.startswith('[COMPLETED]') else 'cyan')
            self.console.print(message, style=style, markup=False, highlight=False)
        else:
            print(message, flush=True)

    @contextmanager
    def stage(self, name):
        if not self.console:
            started, last = time.monotonic(), [0.0]
            def update(completed, total):
                now = time.monotonic()
                if now - last[0] >= 2 or completed == total:
                    self.message(f'[PROGRESS] {name}: {completed}/{total}; elapsed {int(now - started)}s')
                    last[0] = now
            self.message('[STAGE] ' + name)
            yield update
            return
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn, TimeElapsedColumn
        with Progress(SpinnerColumn(), TextColumn('{task.description}'), BarColumn(),
                      MofNCompleteColumn(), TimeElapsedColumn(), console=self.console, transient=True) as progress:
            task = progress.add_task(name, total=None)
            yield lambda completed, total: progress.update(task, completed=completed, total=total)

    def services_table(self, services, note=''):
        if note:
            self.message('[NMAP] ' + note)
        if not services:
            return
        columns = ('PORT/STATE', 'SERVICE', 'PRODUCT / VERSION', 'DETECTION')
        rows = [(str(s['port']) + '/tcp open', s['service'],
                 ' '.join(str(s.get(k, '')) for k in ('product', 'version', 'extrainfo')).strip() or 'not identified',
                 s.get('method', 'unspecified')) for s in services]
        if not self.console:
            self.message(' | '.join(columns))
            for row in rows:
                self.message(' | '.join(row))
            return
        from rich.table import Table
        from rich.text import Text
        table = Table(title='Observed open TCP ports and service versions')
        for name in columns:
            table.add_column(name)
        for row in rows:
            table.add_row(*(Text(value) for value in row))
        self.console.print(table)

    def severity_table(self, counts):
        if not self.console:
            self.message('Unvalidated severity groups: ' + ', '.join(f'{name}={counts.get(name, 0)}'
                for name in ('critical', 'high', 'medium', 'low', 'info')))
            return
        from rich.table import Table
        table = Table(title='Findings needing validation')
        table.add_column('Severity')
        table.add_column('Groups', justify='right')
        for name, style in (('critical', 'bold red'), ('high', 'red'), ('medium', 'yellow'), ('low', 'cyan'), ('info', 'white')):
            table.add_row(name.title(), str(counts.get(name, 0)), style=style)
        self.console.print(table)
