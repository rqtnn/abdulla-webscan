"""Adapt only the CLI platform guard for mocked/loopback tests on Windows.

This does not emulate POSIX process groups. Those tests remain POSIX-only.
"""
import os
from unittest.mock import patch
import cli


class PlatformGuard:
    name = 'posix'

    def __getattr__(self, name):
        return getattr(os, name)


def cli_platform(test_case=None):
    guard = patch.object(cli, 'os', PlatformGuard())
    if test_case is not None:
        test_case.addCleanup(guard.stop)
        guard.start()
    return guard
