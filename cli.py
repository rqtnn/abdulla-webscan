"""Compatibility import; implementation lives in webscan.cli."""
import importlib
import sys

_implementation = importlib.import_module("webscan.cli")
if __name__ == "__main__":
    raise SystemExit(_implementation.main())
sys.modules[__name__] = _implementation
