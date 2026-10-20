"""Compatibility import; implementation lives in webscan.tool_coverage."""
import importlib
import sys

_implementation = importlib.import_module("webscan.tool_coverage")
sys.modules[__name__] = _implementation
