# Tests

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
