# Rqtn Tool

Rqtn Tool 2.2.1 is a modular Python web assessment tool for one authorized lab host.
It discovers web routes, inventories forms, runs bounded preliminary checks and
combines external scanner output into evidence-preserving JSON/HTML reports.
Every finding is marked `needs_validation`; a successful process exit is not
proof of complete coverage or the absence of vulnerabilities.

## URL scan behavior in 2.2.1

Entering an HTTPS URL now selects Nmap's top 1000 TCP ports instead of only 443.
`--url-port-only` preserves the old single-port behavior explicitly. The scanner
still targets one pinned IP. `--nmap-scan syn` uses `-sS` when raw-socket privileges
are available; the default connect scan uses `-sT`. Detected HTTP services on
other ports feed web discovery. A failed HTTP/TLS probe now prints its error and
an explicit coverage explanation instead of looking like an unexplained stop.
If Nmap is skipped or produces no port inventory, the explicit URL is probed
without guessing other ports. Version detection (`-sV`) may take longer than a
plain `nmap -sS`; no identical-port-count guarantee is made across methods.

## Safe defaults in 2.2

Built-in HTTP resolves one IP before the run and connects to that numeric address
through discovery, crawling and GET checks, preserving the hostname in HTTP Host,
TLS SNI and certificate verification. Redirects remain scoped and opt-in.
Discovery probes now share the crawler/checks request gate (`--rate`, `--delay`),
and 429/503 Retry-After responses defer subsequent built-in requests.
OpenAPI/Swagger documents contribute only scoped GET routes without unresolved
path parameters. A bounded inventory tries common API specification paths.
A responding probe appears in findings even when crawling is disabled; this is
an endpoint observation, not a vulnerability. Grouped Dirsearch JSON is supported.

Response bodies are omitted by default. Stored `body_sha256` hashes the saved
placeholder; `response_sha256` hashes the original response used for checks.
Secret-named query parameters, form fields and headers are redacted in metadata
and reports. URLs carrying secret query parameters are excluded from automatic
parameter checks. Run directories are private (0700). Previously saved evidence
is not rewritten or cleaned automatically.

`--retain-raw-evidence` explicitly retains response bodies, which may contain
credentials and personal data. Protect those files. External web scanners require
both `--external-tools` and `--retain-raw-evidence`, and are deferred for hostname
targets because their DNS behavior cannot be pinned reliably across versions.
Use built-in checks for hostname targets. Numeric-IP external web jobs run
sequentially with per-tool pacing; their rate flags are approximate, not a global
network guarantee. Nmap has its separate packet-rate cap. Missing/deferred jobs
remain visible coverage gaps; exit 2 does not mean the report is empty.

```bash
# Built-in checks against an authorized local fixture, without optional scanners
python rqtn.py http://127.0.0.1:8000 --skip nmap --no-auto-sqli
# Explicit raw evidence and external scanners against an authorized numeric-IP lab
python rqtn.py http://127.0.0.1:8000 --external-tools --retain-raw-evidence
```

## Project structure

```text
rqtn-tool/
  rqtn.py          # Branded CLI entry point
  webscan.py       # CLI/orchestration; existing imports remain compatible
  nmap_scan.py     # Single-IP service inventory, versions and XML evidence
  crawler.py       # Concurrent HTML/JavaScript discovery and form inventory
  checks.py        # Reflection, redirects, SQL error/timing and file checks
  transport.py     # Numeric-IP connections preserving Host and TLS identity
  evidence.py      # Safe metadata serialization and explicit raw-body retention
  scope.py         # Single-host normalization, origins, redirects and pacing
  session.py       # Explicit origin-bound Cookie file for built-in requests
  findings.py      # Scanner adapters, deduplication, headers and evidence
  terminal.py      # ASCII banner, optional Rich progress/severity UI
  requirements.txt
  wordlist.txt
  tests/
```

Generic module names are retained for import compatibility. Use `rqtn.py` for
the new CLI; `webscan.py` remains a compatible entry point.

## Install on Kali/Linux

Python 3.10+ is required. Extract the release into a folder called `rqtn-tool`.

```bash
cd rqtn-tool
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python rqtn.py --version
python rqtn.py --check
python -m unittest discover -s tests -v
```

Rich is optional: without it the CLI uses plain text. No aiohttp dependency is
required. Install external scanner executables separately on Kali and put them
on PATH; `--check` lists the exact tools available. The pipeline supports Nmap,
ProjectDiscovery httpx/httpx-toolkit, WhatWeb, ffuf, Gobuster, Feroxbuster,
Dirsearch, Nikto, Nuclei and SQLmap. Missing tools are reported as coverage gaps.
Kali's `httpx-toolkit` is distinct from the Python HTTPX library.

Nuclei requires local YAML templates; `--templates PATH` overrides automatic
legacy/XDG/Kali path discovery. A templates update is a separate preparation step:

```bash
nuclei -ut -ud "$HOME/nuclei-templates"
```

## Run on Windows through WSL

In an administrator PowerShell window, install WSL if needed:

```powershell
wsl --install
```

Restart if requested, open the installed Linux distribution, then follow the
Linux installation steps. If your extracted project is `D:\\Labs\\rqtn-tool`,
its WSL path is `/mnt/d/Labs/rqtn-tool`:

```bash
cd /mnt/d/Labs/rqtn-tool
python3 rqtn.py --check
python3 rqtn.py http://127.0.0.1:3000 --dry-run
```

Make sure the lab is reachable from that Linux environment; VPN/network routes
must be configured there. Native Windows can run unit tests and offline report
rebuilding, but the scanner CLI and subprocess group termination require Linux.

Reference: [Microsoft WSL installation](https://learn.microsoft.com/en-us/windows/wsl/install).

## Basic scans and protocol handling

```bash
# Interactive: a bare entry becomes an HTTP URL.
python rqtn.py

# URL: scan the same host's top 1000 TCP ports by default.
python rqtn.py http://127.0.0.1:3000 --profile lab --output report.html

# Explicit port/path without a scheme: inferred HTTP.
python rqtn.py --target 127.0.0.1:3000/api --output report.json

# Bare IP/hostname on the command line: retain service discovery (top 1000 TCP).
python rqtn.py 192.168.56.101

# All TCP ports on one lab IP; no UDP scan.
python rqtn.py 192.168.56.101 --all-ports --nmap-timeout 3600

# Plan only: no HTTP, DNS resolution or scanner subprocesses.
python rqtn.py http://127.0.0.1:3000 --dry-run
```

Explicit HTTP/HTTPS schemes are preserved; automatic handling infers HTTP rather
than attempting an HTTPS fallback. Lists, ranges/CIDRs and URL credentials are
rejected. Nmap and built-in HTTP use one resolved IP; HTTP retains hostname
Host/SNI. External hostname web scanners are deferred. Scope covers the exact hostname and
responding scheme/port combinations, not subdomains or foreign hosts.

## Enable preliminary checks

### Open ports and service versions (2.1)

`--dry-run` creates a plan only: an empty `ports` list is expected because Nmap
never ran. Remove that flag to collect results. URLs and bare hosts now scan
the top 1000 TCP ports by default. Use `--url-port-only` to restrict Nmap to the
URL port, `--top-ports` for a different count, or `--all-ports` for every TCP port:

```bash
# Broad TCP discovery plus web assessment on this single HTB lab IP.
# Replace the IP with the address currently assigned to your lab instance.
python rqtn.py http://10.129.229.96 --top-ports 1000 \
  --profile lab --crawl-redirects --builtin-sqli --sensitive-files \
  --rate 3 --delay 0.5 --output lab-report.html

# Every TCP port; a larger Nmap time budget is appropriate.
python rqtn.py http://10.129.229.96 --all-ports --nmap-timeout 3600 \
  --version-intensity 7 --profile lab --crawl-redirects \
  --builtin-sqli --sensitive-files --output all-ports.html
```

Only one of `--ports`, `--top-ports`, and `--all-ports` is accepted. Version
intensity is configurable from 0 to 9 (default 7, light 2, exhaustive 9);
higher intensity may identify more services but takes longer. `--nmap-rate`
defaults to 100 packets/sec and is separate from web request pacing.
See [Nmap service detection](https://nmap.org/book/man-version-detection.html).

The CLI and HTML report show observed open TCP ports, service names, products,
versions and extra information. JSON preserves detection method/confidence and
CPE identifiers when Nmap supplies them. A `table` method is a port-number label,
not a fingerprint; a blank version means unidentified, and neither a banner nor
a CPE alone proves a CVE. XML SHA256 and scan selection/status are recorded in
`summary.json` under `nmap`; raw evidence stays in `nmap/services.xml` and
`nmap/console.log`. Interrupted XML can retain complete target-host records,
clearly marked partial. A skipped/failed/planned scan and a completed scan with
no open ports have distinct explanations. No UDP or automatic NSE exploitation
is enabled. Real scanner behavior still needs verification in Kali/WSL.

```bash
python rqtn.py http://127.0.0.1:3000 \
  --profile lab --crawl-redirects --builtin-sqli --sensitive-files \
  --http-workers 4 --rate 5 --delay 0.25 --output report.html
```

For a scan using only the built-in HTTP features:

```bash
python rqtn.py http://127.0.0.1:3000 \
  --enum none --skip nmap httpx whatweb nikto nuclei sqlmap \
  --active-checks --builtin-sqli --sensitive-files --crawl-redirects \
  --http-workers 4 --delay 0.25 --output report.json
```

Time-based preliminary detection is explicit and optional:

```bash
python rqtn.py http://127.0.0.1:3000 --profile lab --time-sqli --output report.json
```

### crawler.py

The crawler uses a bounded ThreadPoolExecutor. Route parsing, deduplication and
report writes stay in the coordinating thread; workers perform HTTP GETs.
The Python API defaults to one worker for compatibility; CLI `--http-workers`
defaults to four and permits at most eight.

It extracts anchor/iframe links, external `script src`, quoted root-relative and
relative JavaScript routes, inline-script/comment hints, and candidate script
directories. It does not evaluate JavaScript or reconstruct dynamic URLs.
Forms retain action, method, enctype, input controls and GET field values.
Password control values are redacted in the inventory. POST, file/password,
select/textarea and sensitive-token forms are inventoried for manual review,
not automatically submitted. GET candidates preserve named submit dispatch.

```python
state = crawl(seeds, target, folder, stop, workers=4,
              rate=5, delay=0.25, follow_redirects=True)
```

All requests share page/depth/time budgets, with bounded bodies (256 KiB).
Response hashes and redacted discovery `url/source/kind` are saved in `crawl/`.
Body files contain placeholders unless `retain_raw=True` / `--retain-raw-evidence`
is explicitly supplied.
Redirects are opt-in and revalidated before fetching; foreign origins,
action-like URLs and loops cannot expand the allowed scope.

### checks.py

- **Reflected XSS candidate:** compare a control with an inert custom HTML tag.
  Literal unescaped reflection is reported; script execution and exploitability
  are not established. No JavaScript executes.
- **External redirect candidate:** use an `rqtn.invalid` sentinel for known
  redirect parameters. Never connect to the destination.
- **SQL error candidate:** `--builtin-sqli` appends a quote and looks for new
  MySQL/PostgreSQL/SQLite/MSSQL/Oracle error signatures absent from the control.
  Pre-existing database errors do not establish injection.
- **Timing anomaly:** `--time-sqli` uses a one-second MySQL `SLEEP(1)` expression
  and two fresh control/probe pairs. Checks run with one worker; pacing wait is
  excluded from HTTP elapsed time. Stable controls and repeated differences
  >=0.8 seconds are required. Network/server jitter may still produce false
  positives; other DBMS dialects and injection contexts are not covered.
- **Sensitive files:** `--sensitive-files` uses `wordlist.txt`, a random
  nonexistent-path control per origin, and content signatures for Git HEAD,
  environment configuration, SQL dumps, ZIP backups and PHP source backups.
  Version 2.1 also recognizes Git configuration, environment variants, SQLite
  database files, private keys and Actuator JSON with unmasked secret-like
  values. Content indicating row data or secret exposure is prioritized as a
  high-severity candidate; schema-only dumps and generic metadata remain medium.
  Masked/placeholding values and HTML fallback pages do not establish secret
  exposure. Titles omit secret values; raw response evidence can contain them.
  HTTP 200 or a filename alone does not produce a finding. `--file-limit`
  bounds URLs across origins; redirects are not followed for these probes.

Checks preserve redacted request URLs and status/headers, response hashes and
timing samples; raw bodies require explicit opt-in.
All matches remain candidates. Limits, errors, truncation and zero-candidate
runs are reported explicitly. SQLmap detection remains available as a separate,
bounded external stage; no database dumping or server commands are enabled.

### scope.py

`scoped_link` centralizes exact-host, responding-origin and action-path checks.
`RequestGate` reserves request start slots across threads with cancellable
waits. Built-in stages share one gate. Start spacing is
`max(1 / rate, delay)`, so adding workers does not multiply built-in traffic.
The rate controls request starts, not response duration or packet bandwidth.

`--delay` applies to built-in stages. External executables use their existing
per-tool `--rate`/pause settings and individual timeout flags. External jobs are
serialized by the CLI, including when legacy `--mode parallel` is supplied.
`--http-workers` controls built-in requests.

### session.py

For an existing lab session, put one ASCII Cookie header value in `cookie.txt`,
for example `session=VALUE; security=low` (without the `Cookie:` prefix).

```bash
chmod 600 cookie.txt
python rqtn.py http://127.0.0.1:3000 --profile lab --cookie-file cookie.txt
```

The cookie is sent only to the target URL's exact scheme/host/port and only by
built-in requests. It is not copied to command arguments or report metadata.
Response evidence can still contain sensitive information; keep it local.
There is no automatic login, cookie renewal or CSRF refresh. External base
scanners remain unauthenticated; automatic SQLmap and discovered-route Nuclei
are deferred for cookie-enabled scans (`requires_authenticated_scanner`).

### findings.py and reporting

Scanner adapters preserve original file paths, record positions and SHA256.
Inline raw records are omitted from default CLI reports; retained metadata
records are redacted. Deduplication keeps distinct checks, queries, statuses and origins.
Security headers are evaluated on successful HTML responses: CSP,
X-Content-Type-Options, HTTPS-only HSTS, and X-Frame-Options when CSP
`frame-ancestors` is absent. Missing headers are configuration notes, not
proof of an exploitable vulnerability.

`--output results` retains the existing per-run directory layout.
`--output report.json` or `--output report.html` exports that report and keeps
both canonical formats plus evidence in a uniquely named run under
`report.evidence/`. Exported HTML links point to that evidence directory;
exported JSON includes `evidence_directory`. Keep the report and evidence
directory together when transferring them.

The HTML escapes untrusted content and disables scripts with a restrictive CSP.
Rich provides colored status messages, stage progress bars and a severity table
for Critical/High/Medium/Low groups. Use `--ui rich` or `--ui plain`; auto mode
uses Rich only in a terminal when installed. Progress describes completed work
against a budget, not a guarantee of complete site coverage.

```bash
python rqtn.py --report-only results/HOST_TIMESTAMP_ID --output rebuilt.html
```

Offline rebuilding performs no network/scanner requests and preserves the
original scan version. Rebuilding cannot add evidence missing from the scan.

## Tests and verification

```bash
python -m unittest discover -s tests -v
```

Tests use local HTTP servers and simulated scanner output, never external lab
targets. They cover scope enforcement, TLS Host/SNI, bounded concurrency,
shared pacing, form/JS extraction, reflection controls, SQL baseline and repeated
timing comparisons, soft-404/file signatures, redacted session inventory,
evidence hashes, Rich/plain output and relocated JSON/HTML evidence links.

Five existing POSIX-specific tests are skipped on native Windows; run the full
suite in Kali/Linux/WSL to verify process-group and executable CLI behavior.
A Windows test run does not establish compatibility of installed Linux scanner
versions. Check each tool's console log after a real lab run.

## Detection limits

Rqtn Tool is an assessment aid, not a replacement for authenticated browser
testing. It does not automatically confirm IDOR, business-logic flaws, stored/DOM
XSS, arbitrary POST workflows or privilege escalation. Changing an object ID and
viewing another record is evidence to investigate, not proof that the session
has changed role. API routes requiring unusual headers/bodies and dynamically
generated JavaScript routes may remain undiscovered. Zero findings means only
that these checks did not establish candidates within their coverage.

Implementation references: [Python ThreadPoolExecutor](https://docs.python.org/3/library/concurrent.futures.html#threadpoolexecutor),
[Rich progress](https://rich.readthedocs.io/en/stable/progress.html),
[MySQL SLEEP](https://dev.mysql.com/doc/refman/8.4/en/miscellaneous-functions.html#function_sleep).
