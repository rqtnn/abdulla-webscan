"""Compatibility import; implementation lives in webscan.transport."""
import importlib
import sys

_implementation = importlib.import_module("webscan.transport")
sys.modules[__name__] = _implementation
