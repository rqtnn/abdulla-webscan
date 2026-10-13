# Tests

Version 2.2 adds `test_security_regressions.py`: numeric-IP HTTP pinning with
hostname Host/SNI, IPv6 socket selection, safe default evidence, explicit raw
retention, rejected-URL credential/fragment redaction, whole-URL sensitive-query
exclusion, shared discovery pacing, Retry-After cancellation/budgets, API GET
inventory, grouped Dirsearch output, hostname-scanner deferral, and a complete
CLI run against a local HTTP fixture with nonempty safe JSON output.

Validation on 2026-10-13: Python 3.12/Linux, Rich 14.3.4 installed; all 109 tests
passed without skips. `python -m compileall -q .` and `git diff --check` passed.
Existing external-scanner integration tests use local executable fixtures, not
real scanner binaries. TLS identity is verified with mock sockets; HTTP pipeline
integration uses loopback servers. No external target was scanned. CI also tests
Python 3.10; that interpreter was not available for the local run.

Version 2.1 adds single-IP Nmap metadata/CPE parsing, partial XML recovery,
scan selection, plan-only CLI behavior, service/version output, report escaping,
high-impact exposure signatures and masked-value/HTML false-positive controls.

Run from the project root on Kali, Linux, or WSL:

```bash
python3 -m unittest discover -s tests -v
```

Tests use local HTTP servers and simulated scanner results. They do not scan external targets.
Native Windows skips five POSIX-only tests; run on Linux to verify the full suite.

Rqtn Tool 2.0 covers local JavaScript/inline/comment discovery, origin-bound
cookies, explicit zero-candidate status, bounded parallel HTTP workers, shared
pacing, SQL error baseline comparisons and repeated timing pairs, sensitive-file
content signatures with soft-404 controls, security headers, Rich/plain output
and relocated JSON/HTML report evidence links. Existing external scanner adapters,
profile precedence, process orchestration and evidence grouping remain covered.

Install requirements.txt to exercise Rich rendering. Without Rich, its rendering
test is skipped; fallback behavior is still tested. All network tests target local
HTTP fixtures. Deliberately broken database baselines, unstable timing controls,
HTML-escaped reflection and generic HTTP-200 fallbacks must not become positives.
