"""Compatibility import; implementation lives in webscan.checks."""
import importlib
import sys

_implementation = importlib.import_module("webscan.checks")
sys.modules[__name__] = _implementation
