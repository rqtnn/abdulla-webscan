"""Compatibility import; implementation lives in webscan.findings."""
import importlib
import sys

_implementation = importlib.import_module("webscan.findings")
sys.modules[__name__] = _implementation
