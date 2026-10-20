# Web tool review — The World Is Yours 4.0

Reviewed upstream documentation on 2026-10-15. These are independently implemented workflow ideas and existing executable adapters; no upstream source code is copied.

| Upstream | Useful capability | Integration in this project |
| --- | --- | --- |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Template matchers, HTTP evidence, CVE metadata | Existing optional adapter, scoped templates, findings and references; matches require validation |
| [SQLmap](https://github.com/sqlmapproject/sqlmap) | Parameter-specific SQL injection testing | Existing optional GET detection adapter and explicit URL/parameter selection; database/OS takeover is not launched |
| [Feroxbuster](https://github.com/epi052/feroxbuster) | Recursive content discovery | Existing optional adapter and consolidated endpoint observations |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP metadata and technology discovery | Existing optional adapter; built-in bounded pinned HTTP probes work without it |
| [Katana](https://github.com/projectdiscovery/katana) | Crawl, form and JavaScript endpoint discovery | Built-in crawler already covers links/forms/static JavaScript references; Katana/headless execution is not integrated |
| [Tplmap](https://github.com/epinna/tplmap) | Server-side template injection investigation | New independent arithmetic-only detection using two random products, literal-expression controls and reflection rejection; not an adapter or engine fingerprint |
| [Commix](https://github.com/commixproject/commix) | OS command injection investigation | Reviewed for impact classification. No Commix execution adapter or automatic shell workflow is included |

## Workflow

1. Select the lab host and web port scope. Nmap provides service discovery, rather than SSH/SMB auditing in the default workflow.
2. Probe HTTP/HTTPS and show explicit errors, missing executables and time limits.
3. Crawl links/forms and discover paths, exposed configuration, APIs and input parameters.
4. Run selected built-in or optional external web checks. CTF mode adds arithmetic SSTI probes.
5. Read web investigation priorities, recorded controls/probes, manual reproduction and remediation. A lead is not proof of server access.

The default never runs shell commands on the target or extracts its database. XSS reflection is not established XSS. SQLi, SSTI and template CVE matches each require independent validation. Exact coverage depends on chosen tools and templates; file-upload exploitation, authenticated business flows and blind command injection are not comprehensively tested.

## 4.1 additions

The Sn1per web/JavaScript workflow review led to scoped robots, sitemap-index and source-map-reference inventory. WhatWeb's native HTTP packet-file support (see [official Target implementation](https://github.com/urbanadventurer/WhatWeb/blob/master/lib/target.rb)) enables passive Ruby plugins without a second hostname resolution. It does not provide URL/DNS/TLS plugin coverage. Bash setup and JavaScript report filters have no effect on scan scope or vulnerability confirmation.

## WPScan (4.2.0)

Optional Ruby adapter, detected by `--check`. Automatic selection needs an observed WordPress hint;
explicit `--only wpscan` is also supported. It runs after bounded discovery with passive component
checks and explicit `vp,vt` enumeration, no user/password enumeration. External evidence and numeric-IP
rules apply. Results include informational component inventory and supplied vulnerability metadata;
WPScan API/local database configuration controls enrichment. Review `technology-plan.json` and task
status for coverage. The executable is optional and adapter tests use a process fixture; a real WPScan
installation is required to assess version-specific CLI behavior.
# Complementary engines in 4.3.0

Install scanner binaries separately from their official projects, place them on PATH,
then run `python3 twiy.py --check`. TWIY never downloads or executes installers.
The `testssl` adapter accepts either `testssl.sh` or `testssl` on PATH.

For a numeric-IP lab target, enable installed adapters with:

```bash
python3 twiy.py http://192.0.2.10 --scan web --external-tools --retain-raw-evidence --no-menu
```

Select complementary engines independently:

```bash
python3 twiy.py http://192.0.2.10 --only katana dalfox --retain-raw-evidence --no-auto-sqli --no-menu
python3 twiy.py https://192.0.2.10 --only testssl --retain-raw-evidence --no-menu
python3 twiy.py http://192.0.2.10 --only katana dalfox --dry-run --no-menu
```

These example addresses are documentation placeholders; replace them with your authorized lab.
`--only` enables the selected external adapters. Dalfox depends on the built-in
crawler for GET parameter selection. Katana output, when selected alongside it,
feeds that same selection stage. SQLmap opt-out does not disable Dalfox.
An absent, unsupported or failing scanner is reported explicitly; it is never
counted as a clean vulnerability scan.

| Engine | Scheduled command contract | Scope and limits |
| --- | --- | --- |
| [Katana](https://github.com/projectdiscovery/katana) | `katana -config engine.yaml -u URL -jc -dr -cs EXACT_ORIGIN -cos ACTION_REGEX -d DEPTH -ct SECONDS -c 1 -p 1 -rl RATE -retry 0 -duc -j -or -ob -o results.jsonl` | JavaScript parsing, exact origin scope, no redirects, process/crawl time limits. No headless browser, form autofill, model download or secret validation. Scoped GET exports are capped at `--crawl-pages` before feeding the crawler. |
| [Dalfox](https://github.com/hahwul/dalfox) | `dalfox --config engine.json scan URL --param NAME:query --method GET --skip-discovery --skip-mining --skip-reflection-header --skip-reflection-cookie --skip-reflection-path --skip-waf-probe --waf-bypass off --workers 1 --rate-limit RATE --max-payloads-per-param 100 --insecure=false --format json -o results.json` | Dalfox v3 CLI only. Selected GET parameters, path scope, request and process timeouts. No blind/OAST, stored XSS, remote payload lists or automatic bypass. `--no-active-checks` disables injection. |
| [testssl.sh](https://github.com/testssl/testssl.sh) | `testssl.sh --protocols --nodns none --ip IP --warnings batch --color 0 --socket-timeout SECONDS --openssl-timeout SECONDS --jsonfile results.json HTTPS_URL` | HTTPS origins only. Protocol negotiation, not the full vulnerability suite. TLS/QUIC negotiation can use TCP/UDP on the scheduled port. Parent process timeout applies; HTTP `--rate` does not cap TLS handshakes. |

The actual full argv is saved in each job's `command.txt`. Locally installed CLI
help must advertise the required flags before a job starts. User-global Katana
and Dalfox scan profiles are replaced with generated empty profiles so they cannot
silently add credentials, callbacks, proxies or unrelated scan features.

**TLS behavior:** upstream Katana's standard transport bypasses certificate
verification. HTTPS Katana jobs are deferred unless you explicitly pass
`--insecure`; the built-in verified crawler remains available. Dalfox also defaults
to insecure TLS upstream, so this adapter explicitly passes `--insecure=false`
unless you requested `--insecure`. testssl intentionally negotiates TLS to assess
protocol support; it does not grant a certificate an application trust decision.

Reports retain scanner provenance, artifact SHA256, Dalfox detection tier and
confidence. A Dalfox `R` record means reflection only and is excluded from web
vulnerability leads. `V`/`A` records remain candidates needing manual validation.
Dalfox exit 1 means findings, not process failure; `meta.incomplete` and testssl
WARN/FATAL records are coverage gaps. Partial findings remain reviewable.

Validation uses controlled scanner executables and exported result fixtures,
including full Katana → GET selection → Dalfox orchestration, timeout and failure
handling. This does not certify every release of the three upstream binaries.
