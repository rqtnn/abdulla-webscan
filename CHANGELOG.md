## 4.2.1 — Protocol discovery and empty-result coverage

- Skip redundant generated HTTP/HTTPS alternatives once a port is identified; keep explicit URL
  attempts and fallback after transport failures or protocol/upgrade responses. Classify TLS
  certificate failures separately and never disable verification automatically.
- Follow same-origin non-action redirects by default in CLI crawling, with `--no-crawl-redirects`
  opt-out. Retain request budgets and exclude cross-origin/sensitive/action redirects.
- Explain no GET parameters, blocked TLS, uncrawled redirects, deferred forms and disabled external
  scanners in terminal/HTML/JSON coverage diagnostics, including offline report rebuilds.
- Add loopback end-to-end regressions for canonical redirects, parameter discovery and avoiding
  redundant HTTPS on a responding HTTP port; no supplied public target is contacted in tests.

## 4.2.0 — Technology-driven WordPress follow-up

- Capture passive CMS/runtime hints during existing discovery and crawl requests; scope follow-up
  decisions to the observed HTTP origin and accept parsed WhatWeb WordPress fingerprints.
- Add conditional WPScan after discovery, `--only wpscan`, `--skip wpscan`, dependency diagnostics,
  and a persisted/HTML technology plan explaining disabled, deferred, skipped or completed work.
- Bound the optional adapter with passive plugin/theme detection, `vp,vt` enumeration, one thread,
  request timeouts, throttling, and the existing subprocess cancellation/time limit.
- Parse core/plugin/theme inventory and reported vulnerability/CVE metadata offline. Preserve unknown
  severity and evidence hashes; never infer CVEs from detected versions. Treat WPScan exit 5 as
  completed with matches, while aborted output remains a parsing gap.
- Retain existing numeric-IP/external-raw-evidence rules. API/database availability and incomplete
  technology detection are documented coverage limits.

# 4.1.0 — Pinned WhatWeb and web discovery

- Fix menu 5 silently deferring hostname targets: WhatWeb Ruby plugins analyze locally captured, DNS-pinned HTTP packet files; remap findings to the real URL and state passive-only coverage.
- Bound WhatWeb connection/read timeouts and concurrency; show missing binaries, snapshot failures and incomplete output explicitly.
- Discover robots.txt, sitemap indexes/URLs and JavaScript source-map references under existing scope and crawl budgets. Metadata/technology observations are not vulnerability claims.
- Add report type/severity/text filters and reset in a standalone JavaScript source, embedded into portable HTML reports.
- Add Bash Linux environment bootstrap/check commands; package Bash/JavaScript assets in source releases.
- Accept Arabic tool-list commas and case-insensitive tool names.
- Run a single Linux/Python 3.12 CI job with pip caching and cancellation of superseded runs; retain real Nmap and Ruby WhatWeb loopback tests plus a real hostname/menu-5 regression.
- Re-reviewed official Sn1per web and JavaScript workflows; no upstream source or templates copied.

# 4.0.0 — The World Is Yours

- Linux-only web workflow and Linux CI; new `twiy.py` launcher, historical launcher retained.
- Web-focused default assessment and clearer numbered menu, with CTF preset.
- Selected web ports replace an excluded target URL seed without broadening scope; authenticated origin conflicts remain errors.
- Direct HTTP/HTTPS fallback for custom ports when Nmap is unavailable, bounded to 64 ports.
- Arithmetic-only SSTI checks with random two-probe confirmation and literal controls.
- Evidence-linked CTF web investigation priorities in JSON/HTML, separate from technologies/header notes.
- Rewritten documentation with upstream review, actual integrations and coverage limits.

## 3.2.3 - Runtime and report reliability review

- Fix TLS-only/explicit SQLmap-only isolation and preserve explicit opt-outs.
- Continue web stages after network assessment failures.
- Stop common-port fallback after a completed closed-port inventory.
- Correct crawl-only and incomplete-comparison exit statuses.
- Rebase moved/copied report evidence paths and snapshot comparison baselines.
- Validate imported baseline shapes and normalize duplicate tool names.
- Retry invalid menu inputs and normalize Arabic decimal ports/commas.
- Include the comparison guide in release archives.
- Add regression cases plus real Nmap loopback validation in Linux CI.

## 3.2.2 - All-port discovery and dedicated WhatWeb output

- Make choice 8 scan TCP 1-65535 and assess discovered web services.
- Move manual port selection to choice 9.
- Print dedicated WhatWeb technology/server output instead of a severity table in WhatWeb-only mode.
- Use the documented WhatWeb redirect policy and print missing-binary guidance.
- Preserve explicit Nmap budgets and show incomplete inventory without common-port fallback.

## 3.2.1 - Visible scan menu and WhatWeb results

- Display each menu option on its own line and accept Arabic numerals.
- Show parsed WhatWeb technologies/versions and explicit missing/failed/empty output diagnostics in the terminal.
- Preserve interactive bare IP targets so WhatWeb discovery includes HTTPS on port 443.

## 3.2.0 - Scan selection and history

- Add a post-target terminal menu and CLI-only tool selection with strict stage isolation.
- Add full/web/quick/specific-port plans and preserve explicitly supplied budgets.
- Add same-target baseline comparisons with conservative not-observed labels.
- Export spreadsheet-safe CSV findings from the normalized evidence.
- Preserve external advisory URLs when exporting HTML reports.
- Test isolated Nmap/WhatWeb runs, menu selections, offline comparison and CSV redaction.

## 3.1.1 - Continue checks after crawling

- Make the web profile the default for normal startup; keep explicit standard mode.
- Show route/GET candidate counts and explicit post-crawl stage outcomes.
- Isolate sensitive-file, CORS, crawler, GET, Nuclei setup and API stage errors.
- Handle unreadable stage checkpoints without suppressing subsequent checks.
- Test actual post-crawl SQL error/reflection findings and continuation after faults.

## 3.1.0 - Web findings and reproduction

- Add a web profile with bounded CORS, sensitive-file, API and GET parameter checks.
- Preserve Nuclei CVE classification and references independently of raw evidence.
- Add a final How to exploit section with control/probe GET commands and validation steps.
- Continue sensitive-file checks on other origins after a baseline request fails.
- Recheck cancellation and remaining budgets before crawler/file HTTP requests.
- Add local regression coverage for CVE reports, CORS and partial-origin failures.

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
