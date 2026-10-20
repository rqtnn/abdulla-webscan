"""Compatibility import; implementation lives in webscan.reliability."""
import importlib
import sys

_implementation = importlib.import_module("webscan.reliability")
sys.modules[__name__] = _implementation
