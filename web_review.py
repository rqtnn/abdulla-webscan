"""Compatibility import; implementation lives in webscan.web_review."""
import importlib
import sys

_implementation = importlib.import_module("webscan.web_review")
sys.modules[__name__] = _implementation
