## Scan selection and history (3.2.0)

Run `python ws_r.py` in a terminal, enter the target, then choose a scan:

1. Full assessment
2. Web assessment on ports 80/443
3. Quick assessment (top 100 ports, light service probes and smaller web budgets)
4. Nmap only (no HTTP discovery, crawling, TLS or other scanners)
5. WhatWeb only (HTTP reachability discovery plus WhatWeb, no Nmap or crawler)
6. Crawl only
7. Individual tools (comma or space separated)
8. Specific TCP port(s)

Use `--menu` to request the menu explicitly or `--no-menu` for scripted runs.
When stdin/stdout are not terminals, the CLI remains noninteractive. Selecting an
external tool in the menu explicitly retains its raw scanner output; the menu
labels this before selection. Built-in checks omit response bodies by default.
Missing executables are reported as skipped, not replaced with a different scanner.
The existing numeric-IP restriction on external scanners remains in force.

```bash
python ws_r.py 192.168.56.101 --only nmap
python ws_r.py http://192.168.56.101:8080/ --only whatweb --retain-raw-evidence
python ws_r.py 192.168.56.101 --only nmap whatweb --retain-raw-evidence
python ws_r.py https://your-authorized-site.example --only crawl
python ws_r.py 192.168.56.101 --scan quick
python ws_r.py 192.168.56.101 --scan port --ports 443
python ws_r.py http://192.168.56.101:8080/ --only checks
```

`--only checks` and `--only sqlmap` retain crawling as a declared dependency to
find eligible GET parameters. Other built-in stages and unselected scanners are
disabled. A web scanner still requires HTTP discovery to find responding URLs.
Quick-mode defaults do not override explicit budgets/port selections.

Each report directory now includes `findings.csv`. Spreadsheet formula prefixes
are escaped, query secrets are redacted, and CVE advisory links remain valid when
HTML reports are exported to another folder.

```bash
# Compare a new same-host run with a previous report directory or summary.json
python ws_r.py 192.168.56.101 --compare results/PREVIOUS_RUN
# Rebuild and compare offline without scanning anything
python ws_r.py --report-only results/CURRENT_RUN --compare results/PREVIOUS_RUN
```

Comparisons appear in HTML/JSON and `comparison.json`: new findings, severity/status
changes, findings not observed this time, and port inventory differences. Missing
observations are not labeled fixed; different tool selections, timeouts, port
scope and account contexts can change coverage. Review the scan plan and gaps.

See [Sn1per comparison](SN1PER_COMPARISON.md) for the source-backed design comparison.

## Pipeline continuation (3.1.1)

Normal startup now uses `--profile web` by default. The previous default profile
only crawled unless parameter checks were explicitly enabled, so a run could end
immediately after discovery. Use `--profile standard` for the previous passive
behavior. The default enables bounded GET reflection/redirect/database-error
checks, CORS, sensitive files and API inventory, even without external scanners.

After crawling, `[POST-CRAWL]` shows eligible and excluded GET parameters.
`[GET CHECKS]`, `[NUCLEI]`, `[SQLMAP]` and `[ADVANCED]` state what ran or why a
stage was skipped. An application with no eligible GET query parameters produces
`no_candidates`, not injection coverage; CORS/file/API checks are independent.
A stage failure is recorded as incomplete coverage and does not suppress the
remaining independent stages. Cancellation still stops the scan.

```bash
git pull --ff-only origin main
python ws_r.py https://your-authorized-site.example --assessment web
```

External scanner restrictions from 3.1.0 still apply. This update does not silently
enable absent scanners, raw response retention or external scans for hostnames.

## Web vulnerability review (3.1.0)

For an authorized web application, enable the built-in web profile:

```bash
git pull --ff-only
python ws_r.py https://your-authorized-site.example --profile web --assessment web
```

The web profile enables sensitive-file content checks with nonexistent-path controls,
two-origin credentialed CORS comparisons, OpenAPI inventory, inert HTML reflection,
external redirect comparisons, and quote/database-error checks on discovered GET
parameters. Requests remain bounded and pinned to the selected target IP. Use
`--http-timeout 5 --checks-timeout 120 --crawl-timeout 120` to tune budgets.
`--no-active-checks` disables parameter probes and CORS; sensitive-file and API GET
inventory remain enabled. This profile does not enable SSRF metadata probes,
response data extraction, or time-based SQLi.

The final **How to exploit** report section includes captured control/probe URLs,
redacted cURL GET helpers, validation steps, and CVE advisory links when Nuclei
reports a CVE. Template classification (CWE/CVSS) is retained in JSON as
scanner-reported metadata; it is not a verified application severity. CVE matches
must be checked against the deployed product, version and advisory prerequisites.
No CVE is guessed from a banner. Custom application flaws often have no CVE.
POST/multi-step templates still need their original scanner evidence for reproduction.

External scanners keep their existing restrictions: `--external-tools
--retain-raw-evidence` requires a numeric IP target. For hostname targets, built-in
web checks run but external Nuclei is deferred because DNS pinning is not guaranteed.
Consequently, the hostname profile does **not** claim comprehensive CVE coverage.
Missing tools, partial jobs and failed controls are recorded as coverage gaps.

# WS-R

WS-R 3.0.0 combines single-host TCP/service inventory, HTML/JavaScript discovery,
bounded GET checks and scanner adapters into evidence-preserving JSON/HTML reports.
Use it only for authorized labs. Startup prints `WS-R | 3.0.0` once.

Findings remain **needs_validation**. The tool does not automatically extract
databases, run shells, forge tokens, submit POST forms or change application state.
A completed scan does not prove complete coverage or absence of vulnerabilities.

## Kali / WSL installation

Use Python 3.10+ inside Linux. On Windows, open a Kali/Ubuntu WSL terminal and
extract the archive into `~/ws-r`. Native Windows supports tests and offline
reports; the scanning CLI requires Linux/WSL. Connect your lab VPN in the same
environment and verify reachability before scanning remote lab machines.

```bash
cd ~/ws-r
sudo apt update
sudo apt install python3 python3-venv nmap
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python ws_r.py --check
python ws_r.py --help
```

Rich is optional (`--ui plain`). Bounded thread pools use separate HTTP
connections and a shared, cancellable rate/delay gate with Retry-After backoff.

```bash
# Interactive target prompt; HTTP(S), hostname, IPv4 or IPv6 accepted
python ws_r.py

# Plan only: no DNS, HTTP or subprocess execution
python ws_r.py http://127.0.0.1:3000 --dry-run --output plan.html

# Built-in web checks plus API inventory
python ws_r.py http://127.0.0.1:3000 --assessment web --skip nmap \
  --api-discovery --active-checks --builtin-sqli --sensitive-files \
  --delay 0.2 --http-workers 4 --output report.html

# Top 1000 TCP ports by default, with service versions; all ports is optional
python ws_r.py 192.168.56.101 --assessment network --output network.json
python ws_r.py 192.168.56.101 --all-ports --nmap-timeout 3600 --output full.html

# Offline report rebuilding also works on Windows
python ws_r.py --report-only results/HOST_TIMESTAMP_ID --output rebuilt.html
```

`--output report.json` / `report.html` exports that report with a sibling evidence
directory. A directory output creates a timestamped run with both formats.
`--http-timeout` bounds each request; stages also have absolute budgets. Keep
evidence alongside HTML links. External tools are optional and require
`--external-tools --retain-raw-evidence`, numeric IP targets and separate rate caps.

## API and access-control assessment

`--api-discovery` probes five common Swagger/OpenAPI JSON paths. It inventories
methods, path parameters, declared security and administrative hints, with at most
200 routes/document. Remote servers/references and action-like paths are excluded.
It never executes discovered POST/DELETE operations. Documentation exposure is
Info; route names or missing security declarations do not prove broken access control.

Copy `contexts.example.json` to `contexts.local.json` and configure 2..8 named
accounts with separate cookie/bearer files and up to 32 explicit resource policies.
Cookie files contain one Cookie header value; bearer files contain one token
without the `Bearer ` prefix. Credentials remain bound to the target URL's exact
scheme/host/port. No automatic login, refresh or session validity check is performed.

```bash
cp contexts.example.json contexts.local.json
# Edit policies and create your separate lab account cookie files first
chmod 600 contexts.local.json *.cookie
python ws_r.py http://127.0.0.1:3000 --assessment web --skip nmap \
  --contexts contexts.local.json --idor --api-discovery \
  --advanced-timeout 120 --show-helpers --output accounts.html
```

Each policy's `allow` list names the accounts expected to access its exact URL.
This expresses horizontal object ownership or vertical role boundaries. Each
context gets two GET requests per resource; stable identical successful responses
under allowed and disallowed contexts produce a candidate. Login pages, invalid
sessions or public content can still cause false positives: verify protected data
and account validity manually. Roles and comparisons are retained in the matrix.

`--idor` inventories adjacent values for existing ID-like GET parameters.
`--idor-value VALUE` supplies up to four explicit string alternatives. Missing or
nonnumeric identifiers are skipped without alternatives. Response differences
without declared ownership remain inventory, not IDOR findings. A policy can name
the alternate object's exact URL and expected owner.

## SSRF and JWT

```bash
# Use a canary you control; correlate target-side requests in its server logs
python ws_r.py http://127.0.0.1:3000 --assessment web --skip nmap \
  --ssrf-canary http://YOUR_LAB_CANARY/wsr-unique-marker --output canary.json

# Explicit lab-only metadata ROOT probes, never credential endpoints
python ws_r.py http://127.0.0.1:3000 --assessment web --skip nmap \
  --ssrf-metadata --output metadata.html
```

SSRF probes replace existing URL-like GET parameters from discovery. The scanner
connects only to the scoped target; injected destinations are inputs to that lab
application. URL reflection or HTTP 200 alone never confirms SSRF. Canary log
correlation is manual; there is no external callback service. Metadata testing
uses only `http://169.254.169.254/`, never credential/token/user-data paths. New
metadata-shaped responses are candidates. No filter-bypass tricks are included.

JWTs encountered in crawl/advanced response bodies receive bounded local analysis.
Invalid JSON/base64, missing signatures and invalid claim types return structured
results. Reports retain token SHA256, algorithm and issue labels, not tokens or
personal claims. Unsigned tokens do not establish server acceptance. Signatures
are not verified; cookies, headers and JavaScript runtime state are outside this
JWT discovery coverage.

## Evidence, reliability and limits

Findings include artifact digest, record index and observed request/response or
Nmap/TLS service proof. HTTP requests explicitly mark credential redaction and
truncation. Response bodies are omitted by default; `--retain-raw-evidence` enables
stored bodies and hash-verified snippets. Protect retained evidence. Imported
scanner exchanges retain provenance; missing exchanges are never fabricated.

Critical/High/Medium/Low/Info matrix and statistics distinguish hosts
assessed/reached, open ports, candidate/configuration/informational groups and
coverage gaps. Priority 0..4 is ordinal triage, **not CVSS**. No finding becomes
confirmed automatically. API routes and context/JWT inventory appear in both reports.

`--show-helpers` prints shell-quoted redacted GET cURL commands for advanced
candidates. JSON/HTML also carry helpers. They omit account credentials, never
follow redirects or execute automatically; apply the intended context yourself.

`--log-file ws-r.log` writes quiet rotating diagnostics (1 MiB, two backups),
without exception messages, credentials, bodies or local variables. Worker/network
failures create incomplete results. CLI errors return 2 without tracebacks;
interrupts return 130. Invalid arguments use argparse usage messages. Final report
failure attempts `recovery.json`; existing evidence remains available. Unwritable
storage cannot guarantee recovery, and zero failures in every runtime environment
cannot be guaranteed. Logs and context files are excluded from releases.

SQLi error/reflection/timing checks are preliminary. `--time-sqli` is an explicit,
serialized one-second MySQL timing anomaly check. SQLmap performs detection only.
No timing anomaly alone proves injection. The crawler inventories GET/POST forms
and static JS routes but never executes a browser or submits POST forms.

## Architecture and tests

```text
ws-r/
  ws_r.py, cli.py              launcher and orchestration
  brand.py, terminal.py        identity and Rich/plain UI
  crawler.py, checks.py        discovery and bounded preliminary web checks
  api_analyzer.py              OpenAPI inventory
  advanced.py                  contexts, IDOR inventory, SSRF and helpers
  jwt_analyzer.py              defensive local token structure parser
  reliability.py              quiet rotating diagnostics
  nmap_scan.py, assessment.py  port/service/TLS inventory and unified matrix
  scope.py, session.py         target boundaries and origin-bound credentials
  transport.py                IP pinning, TLS/Host identity and deadlines
  evidence.py, findings.py     redacted PoC, adapters and deduplication
  tests/                      unit and isolated loopback integration tests
```

```bash
python -m compileall -q .
python -m unittest discover -s tests -v
python build_release.py
```

CI covers Ubuntu/Windows and Python 3.10/3.12. Windows skips POSIX-only executable
and process-group tests; certificate fixtures require the OpenSSL command. Tests
never target public sites. The repository URL remains unchanged for existing
users; source archives extract into the newly named `ws-r` directory.
