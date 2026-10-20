"""Compatibility import; implementation lives in webscan.scope."""
import importlib
import sys

_implementation = importlib.import_module("webscan.scope")
sys.modules[__name__] = _implementation
