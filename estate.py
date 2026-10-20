"""Compatibility import; implementation lives in webscan.estate."""
import importlib
import sys

_implementation = importlib.import_module("webscan.estate")
sys.modules[__name__] = _implementation
