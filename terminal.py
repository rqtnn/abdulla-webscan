"""Rqtn Tool terminal presentation; Rich is optional."""
from contextlib import contextmanager
import sys

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
            yield None
            return
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
        with Progress(SpinnerColumn(), TextColumn('{task.description}'), BarColumn(),
                      MofNCompleteColumn(), console=self.console, transient=True) as progress:
            task = progress.add_task(name, total=None)
            yield lambda completed, total: progress.update(task, completed=completed, total=total)

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
