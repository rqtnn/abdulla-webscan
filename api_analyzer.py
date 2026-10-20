"""Compatibility import; implementation lives in webscan.api_analyzer."""
import importlib
import sys

_implementation = importlib.import_module("webscan.api_analyzer")
sys.modules[__name__] = _implementation
