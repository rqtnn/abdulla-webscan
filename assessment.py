"""Compatibility import; implementation lives in webscan.assessment."""
import importlib
import sys

_implementation = importlib.import_module("webscan.assessment")
sys.modules[__name__] = _implementation
