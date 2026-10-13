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

# Rqtn Tool 2.1.0

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
