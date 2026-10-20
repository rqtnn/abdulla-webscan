"""Compatibility import; implementation lives in webscan.whatweb_snapshot."""
import importlib
import sys

_implementation = importlib.import_module("webscan.whatweb_snapshot")
sys.modules[__name__] = _implementation
