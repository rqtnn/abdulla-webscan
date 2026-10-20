"""Package compatibility, distribution resources and efficient checkpoint contracts."""
import contextlib
import importlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import build_release
from webscan import brand, reporting
from webscan.paths import PROJECT_ROOT
from webscan.storage import atomic_text
from webscan.terminal import TerminalUI


class ArchitectureTests(unittest.TestCase):
    def summary(self):
        return dict(target='127.0.0.1', created='fixture', mode='parallel', jobs=[],
            ports=[], probes=[], outcome='fixture', version=brand.VERSION)

    def test_legacy_imports_are_the_same_modules_not_copies(self):
        for name in ('cli', 'scope', 'crawler', 'checks', 'terminal', 'estate', 'brand', 'findings'):
            self.assertIs(importlib.import_module(name), importlib.import_module('webscan.' + name))

    def test_package_and_both_launchers_agree_from_an_unrelated_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            for launcher in ('twiy.py', 'ws_r.py', 'cli.py'):
                result = subprocess.run([sys.executable, str(PROJECT_ROOT / launcher), '--version'],
                    cwd=tmp, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), brand.VERSION)
        result = subprocess.run([sys.executable, '-m', 'webscan', '--version'],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.stdout.strip(), brand.VERSION)

    def test_globe_brand_compact_and_no_markup_escape_sequences(self):
        for width in (45, 100):
            with contextlib.redirect_stdout(io.StringIO()) as output, \
                    patch('webscan.terminal.shutil.get_terminal_size', return_value=os.terminal_size((width, 24))):
                TerminalUI('plain').startup(brand.VERSION)
            text = output.getvalue()
            self.assertEqual(text.count(brand.NAME), 1)
            self.assertNotIn('\x1b', text)
            self.assertIn('|', text)
            self.assertLessEqual(max(map(len, text.splitlines())), width)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            TerminalUI('plain', theme='plain').startup(brand.VERSION)
        self.assertEqual(len(output.getvalue().splitlines()), 1)

    def test_checkpoints_do_not_parse_logs_and_final_report_contains_latest_evidence(self):
        calls = []
        def collector(root, doc):
            calls.append(len(doc['probes']))
            return [], []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            doc = self.summary()
            for number in range(12):
                doc['probes'].append(dict(url='http://127.0.0.1/' + str(number), status=200))
                reporting.write_checkpoint(root, doc)
            checkpoint = json.loads((root / 'checkpoint.json').read_text())
            self.assertTrue(checkpoint['checkpoint_only'])
            self.assertEqual(checkpoint['probes'][-1]['url'], 'http://127.0.0.1/11')
            self.assertFalse((root / 'report.html').exists())
            self.assertEqual(calls, [])
            reporting.write_reports(root, doc, tools=(), report_script='', collector=collector)
            self.assertEqual(calls, [12])
            self.assertEqual(len(json.loads((root / 'summary.json').read_text())['probes']), 12)
            self.assertIn('parallel', (root / 'report.html').read_text(encoding='utf-8'))

    def test_failed_atomic_replace_retains_previous_checkpoint_and_cleans_temp(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'checkpoint.json'
            atomic_text(target, 'previous')
            with patch('webscan.storage.os.replace', side_effect=OSError('fixture')), self.assertRaises(OSError):
                atomic_text(target, 'new')
            self.assertEqual(target.read_text(), 'previous')
            self.assertEqual([p.name for p in Path(tmp).iterdir()], ['checkpoint.json'])

    def test_release_contains_package_css_and_runs_after_unpacking(self):
        archive = build_release.build()
        with zipfile.ZipFile(archive) as source:
            self.assertIn('ws-r/webscan/cli.py', source.namelist())
            self.assertIn('ws-r/webscan/reporting.py', source.namelist())
            self.assertIn('ws-r/assets/report.css', source.namelist())
            self.assertFalse(any('__pycache__' in n or n.endswith('.pyc') for n in source.namelist()))
            with tempfile.TemporaryDirectory() as tmp:
                source.extractall(tmp)
                result = subprocess.run([sys.executable, str(Path(tmp) / 'ws-r/twiy.py'), '--version'],
                    cwd=tmp, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), brand.VERSION)
