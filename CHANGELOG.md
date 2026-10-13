## 3.0.0 — WS-R

- Rename launchers, tests, HTTP identity and documentation; one minimal banner.
- Add quiet rotating diagnostics, CLI exception containment, failed subprocess
  setup records, worker failure handling and recovery-report fallback.
- Add bounded OpenAPI inventory, explicit account/ownership policy comparisons,
  adjacent-ID inventory, owned SSRF canaries and opt-in metadata-root probes.
- Add local JWT structure analysis without storing tokens or personal claims.
- Integrate captured HTTP proof, redacted cURL helpers and advanced inventory
  into the unified JSON/HTML assessment.
- Add regression tests for malformed input, scope, credential isolation,
  incomplete requests, false-positive controls and storage failures.

## 2.4.0

- Print one minimal startup banner and improve interactive IPv6/URL handling.
- Centralize the version and HTTP identity in brand.py.
- Add a unified five-level network/web triage matrix and completion statistics;
  distinguish candidates, configuration observations and confirmed findings.
- Capture actual built-in HTTP request headers with redaction/exactness metadata
  and SHA256; add per-finding HTTP, service and TLS proof to JSON and escaped HTML.
- Add bounded retained-body snippets with hash/path integrity checks and preserve
  scanner-export provenance or explicit missing exchange data.
- Persist discovery evidence separately and preserve offline assessment rebuilds.
- Adapt mocked/loopback CLI tests for Windows without emulating POSIX processes;
  keep Unix permission checks active on Linux and make OpenSSL prerequisites explicit.
- Run CI on Ubuntu and Windows with Python 3.10 and 3.12.
- Normalize report source/destination paths before computing evidence links,
  including Windows short-path aliases.

Local verification: 134 tests discovered, 128 passed, 6 skipped on Windows
(5 POSIX-only tests and the OpenSSL-dependent TLS fixture). No failing runnable
tests. Linux CI is required for process groups and real TLS fixture verification.

## 2.3.0

- Add full/network/web assessment modes and nine service exposure review rules.
- Add opt-in allowlisted SSH algorithm and SMB2 signing negotiation with evidence-backed configuration findings.
- Assess pinned TLS independently of HTTP: verified certificate expiry, chain/hostname errors, negotiated protocol/cipher and certificate digest.
- Preserve network assessment evidence and recommendations in JSON and offline reports.
- Add severity dashboard cards, section navigation and CSP-hashed finding search/filtering.
- Add --http-timeout and enforce absolute HTTP header/body deadlines against trickling peers.
- Preserve responding HTTP services when the body is slow or incomplete; record the coverage warning.
- Show waiting crawler progress and elapsed time in plain/Rich output.
- Add real loopback TLS and slow-peer tests plus network-only/offline/report regressions.

## 2.2.1

- Scan the top 1000 TCP ports for URL targets by default; add explicit --url-port-only.
- Support opt-in Nmap SYN scans with --nmap-scan syn.
- Print HTTP/TLS failures and discovery coverage in the terminal.
- Feed observed web ports into discovery; avoid speculative port probes for an explicit URL when Nmap has no inventory.

## 2.2.0

- Pin built-in HTTP to the selected numeric scan address while preserving Host/SNI.
- Pace initial HTTP discovery with the shared request gate.
- Omit raw bodies by default; redact secret metadata and protect run directories.
- Exclude complete sensitive-query URLs from automatic parameter checks.
- Inventory common API specification paths and scoped OpenAPI/Swagger GET routes.
- Include initial responses in endpoint findings and accept grouped Dirsearch output.
- Make external raw scanner execution explicit, serialize web jobs, and defer hostname jobs with an explanatory coverage gap.
- Add local security regression fixtures; retain raw-evidence compatibility behind opt-in.

# WS-R 2.1.0

- Distinguish dry-run plans from observed Nmap results and scan failures.
- Show open TCP ports, products, versions, extra information and detection method
  in terminal and HTML; retain CPE, confidence and raw XML SHA256 in JSON.
- Add --top-ports for broader URL-target discovery, --version-intensity (default
  7) and --nmap-rate; preserve explicit all-port and single-host scope.
- Recover complete target-host XML records from interrupted output as partial
  evidence, with coverage gaps and exit code 2 rather than a successful empty scan.
- Expand bounded exposure checks for env variants, Git configuration, source
  secrets, SQL row data, SQLite files, private keys and unmasked Actuator secrets.
- Preserve validation labels and raw evidence; suppress HTML fallback and masked
  credential false positives. No automatic access-control or CVE confirmation.

Verified locally: 96 tests, 91 passed and 5 POSIX-only tests skipped on Windows.
New CLI integration tests use a simulated Nmap response or a dry-run and never
scan an external target. Real Nmap/scanner execution still needs Kali/WSL testing.

# WS-R 2.0.0

- Rebranded CLI, ASCII banner, HTTP User-Agent, report headings and documentation.
- Added ws_r.py while preserving cli.py import/CLI compatibility.
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
