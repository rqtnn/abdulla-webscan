# Tests

Run from the project root on Kali, Linux, or WSL:

```bash
python3 -m unittest discover -s tests -v
```

Tests use local HTTP servers and simulated scanner results. They do not scan external targets.
Native Windows skips five POSIX-only tests; run on Linux to verify the full suite.
