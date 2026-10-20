"""Compatibility import; implementation lives in webscan.web_engine."""
import importlib
import sys

_implementation = importlib.import_module("webscan.web_engine")
sys.modules[__name__] = _implementation
