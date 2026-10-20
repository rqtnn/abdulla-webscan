"""Compatibility import; implementation lives in webscan.jwt_analyzer."""
import importlib
import sys

_implementation = importlib.import_module("webscan.jwt_analyzer")
sys.modules[__name__] = _implementation
