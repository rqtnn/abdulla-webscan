"""Rqtn Tool terminal presentation; Rich is optional."""
from contextlib import contextmanager
import sys
import time

BANNER = r'''
 ____    ___  _____  _   _    _____  ___   ___   _
|  _ \  / _ \|_   _|| \ | |  |_   _|/ _ \ / _ \ | |
| |_) || | | | | |  |  \| |    | | | | | | | | || |
|  _ < | |_| | | |  | |\  |    | | | |_| | |_| || |___
|_| \_\ \__\_\ |_|  |_| \_|    |_|  \___/ \___/ |_____|
                    RQTN TOOL
'''


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
                for name in ('critical', 'high', 'medium', 'low')))
            return
        from rich.table import Table
        table = Table(title='Rqtn Tool — findings needing validation')
        table.add_column('Severity')
        table.add_column('Groups', justify='right')
        for name, style in (('critical', 'bold red'), ('high', 'red'), ('medium', 'yellow'), ('low', 'cyan')):
            table.add_row(name.title(), str(counts.get(name, 0)), style=style)
        self.console.print(table)
