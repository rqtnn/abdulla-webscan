# Rqtn Tool 2.0.0

- Rebranded CLI, ASCII banner, HTTP User-Agent, report headings and documentation.
- Added rqtn.py while preserving webscan.py import/CLI compatibility.
- Added bounded HTTP worker pools and shared cancellable request pacing.
- Centralized URL, origin and redirect scope validation in scope.py.
- Expanded form inventory and static JavaScript/inline/comment route discovery.
- Added explicit SQL error baseline checks, opt-in repeated one-second MySQL
  timing comparisons, and sensitive-file content checks with soft-404 controls.
- Added framing-header analysis alongside CSP, MIME-sniffing and HTTPS HSTS notes.
- Added optional Rich progress/status/severity presentation with plain fallback.
- Added report-file output with relocated evidence links and retained run artifacts.
- Preserved candidate validation labels, raw response evidence and SHA256 hashes.

Verified locally: 84 tests, 79 passed and 5 POSIX-only tests skipped on Windows.
Rich rendering was tested with Rich 14.3.4. Tests use local HTTP servers and
scanner fixtures. Real Linux scanner executables and all POSIX tests still need
verification under Kali/Linux/WSL before claiming deployment readiness.
