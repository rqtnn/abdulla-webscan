"""Compatibility import; implementation lives in webscan.advanced."""
import importlib
import sys

_implementation = importlib.import_module("webscan.advanced")
sys.modules[__name__] = _implementation
