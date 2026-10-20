"""Compatibility import; implementation lives in webscan.run_history."""
import importlib
import sys

_implementation = importlib.import_module("webscan.run_history")
sys.modules[__name__] = _implementation
