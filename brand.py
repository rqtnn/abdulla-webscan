"""Compatibility import; implementation lives in webscan.brand."""
import importlib
import sys

_implementation = importlib.import_module("webscan.brand")
sys.modules[__name__] = _implementation
