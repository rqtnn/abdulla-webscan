"""Compatibility import; implementation lives in webscan.technology."""
import importlib
import sys

_implementation = importlib.import_module("webscan.technology")
sys.modules[__name__] = _implementation
