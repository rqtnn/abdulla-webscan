"""Compatibility import; implementation lives in webscan.nmap_scan."""
import importlib
import sys

_implementation = importlib.import_module("webscan.nmap_scan")
sys.modules[__name__] = _implementation
