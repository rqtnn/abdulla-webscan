"""Compatibility import; implementation lives in webscan.evidence."""
import importlib
import sys

_implementation = importlib.import_module("webscan.evidence")
sys.modules[__name__] = _implementation
