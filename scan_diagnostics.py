"""Compatibility import; implementation lives in webscan.scan_diagnostics."""
import importlib
import sys

_implementation = importlib.import_module("webscan.scan_diagnostics")
sys.modules[__name__] = _implementation
