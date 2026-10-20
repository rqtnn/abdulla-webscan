"""Compatibility import; implementation lives in webscan.wpscan_adapter."""
import importlib
import sys

_implementation = importlib.import_module("webscan.wpscan_adapter")
sys.modules[__name__] = _implementation
