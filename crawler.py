"""Compatibility import; implementation lives in webscan.crawler."""
import importlib
import sys

_implementation = importlib.import_module("webscan.crawler")
sys.modules[__name__] = _implementation
