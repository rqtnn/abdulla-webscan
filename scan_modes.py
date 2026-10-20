"""Compatibility import; implementation lives in webscan.scan_modes."""
import importlib
import sys

_implementation = importlib.import_module("webscan.scan_modes")
sys.modules[__name__] = _implementation
