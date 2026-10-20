"""Compatibility import; implementation lives in webscan.session."""
import importlib
import sys

_implementation = importlib.import_module("webscan.session")
sys.modules[__name__] = _implementation
