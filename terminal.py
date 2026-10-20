"""Compatibility import; implementation lives in webscan.terminal."""
import importlib
import sys

_implementation = importlib.import_module("webscan.terminal")
sys.modules[__name__] = _implementation
