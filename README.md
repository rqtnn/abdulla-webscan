# The World Is Yours

Linux web vulnerability assessment for CTF labs and authorized single-host targets. Version **4.3.0**.

Enter one IP, hostname or URL, select a web scan, and follow the evidence in the HTML report. The default workflow focuses on web applications; Nmap discovers services that may host HTTP/HTTPS. It does not automatically gain a shell or claim server access.

## Repository layout

| Location | Contents |
| --- | --- |
| `twiy.py`, `ws_r.py` | Current and compatible launchers |
| Root Python modules | Scanner, discovery and report implementation |
| `docs/` | Tool integration notes and Sn1per comparison |
| `assets/` | Embedded HTML report JavaScript |
| `wordlists/` | Default discovery wordlist |
| `examples/` | Account-context configuration example |
| `scripts/` | Linux setup and diagnostics |
| `tests/` | Python and JavaScript tests |
| `.github/workflows/` | Linux CI |
| `releases/`, `results/` | Generated archives and scan output (ignored by Git) |

Start commands remain unchanged. Use `examples/contexts.example.json` as a
configuration reference and `--wordlist /path/to/list.txt` for a custom wordlist.

## Start on Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
sudo apt install nmap whatweb
python3 twiy.py --check
python3 twiy.py
```

`ws_r.py` remains a compatible launcher. Only Linux is supported and tested. `bash scripts/setup-linux.sh` creates the virtual environment and checks scanner dependencies; `bash scripts/setup-linux.sh --check` repeats diagnostics without installing anything. Other scanners are optional: missing tools appear explicitly in task results. Python's `httpx` library is not the ProjectDiscovery executable.

## Scan menu

1. Web vulnerability assessment
2. Web on ports 80/443
3. Quick web assessment
4. Discover web services (Nmap only)
5. WhatWeb technologies only
6. Crawl only
7. Choose individual tools
8. Discover all TCP ports, then assess HTTP/HTTPS services
9. Web on custom ports: any port 1–65535, lists or ranges
10. CTF web checks, including arithmetic SSTI comparisons
11. Deep web assessment: up to 300 crawl requests, depth 5, 600 seconds of crawling,
    30 GET parameter candidates and 300 seconds of built-in input checks. Explicit
    CLI limits override these defaults; rate limits and origin scope still apply.
12. All applicable tools with the deep plan (retains raw scanner evidence).

```bash
# Deep assessment of an authorized lab, with installed external scanners
python3 twiy.py http://LAB_IP:8080 --scan deep --external-tools --retain-raw-evidence --no-menu
```

Run `python3 twiy.py --check` first: the deep plan does not install missing binaries
or Nuclei templates. Use the lab's actual URL, port and application path. Add
`--insecure` only for a deliberately self-signed lab. An IP hosting several virtual
sites may require the intended hostname; an IP alone cannot identify every site.

OpenAPI/Swagger discovery now inventories primitive GET query parameters from
path and operation declarations, so API-only inputs reach built-in checks and
enabled external adapters. Values are synthetic (`wsr`, `1`, `true`); schema
credentials/examples, unresolved references, path templates and POST operations
are not used. A seeded input may fail application validation; discovery does not
prove the endpoint was fully tested. Named HTML submit buttons are preserved in
GET form candidates so handlers gated by `submit=...` can be reached.

Ports are editable, not fixed examples. Enter `8080`, `22,8080,8443` or `8000-8100`. Arabic digits and Arabic commas are accepted. If selected ports exclude the target URL port, the scanner uses the same host on the selected ports and drops the old URL path/query. It never adds the excluded port back. Cookie/account contexts require a matching origin instead.

To run every installed applicable adapter instead of the default built-in-only
workflow, choose menu **12** or use:

```bash
python3 twiy.py --check
python3 twiy.py http://LAB_IP:PORT --scan deep --all-tools --no-menu
```

`--all-tools` enables external scanners, raw evidence and all four directory
engines (ffuf, Gobuster, Feroxbuster, Dirsearch). Explicit `--skip`, `--enum`,
`--no-auto-sqli` and `--no-active-checks` still apply. It does not install binaries
or templates. WPScan needs WordPress evidence; SQLmap/Dalfox need eligible GET
inputs; testssl needs HTTPS. Hostname pinning and unsupported CLI/TLS restrictions
remain visible, with the exact reason in **Tool coverage**. Retained raw evidence
can contain response data and should be protected.

The terminal preflight lists missing/incompatible binaries. The final terminal,
HTML report and `summary.json` now include every adapter, job counts, parsed
observations and parsing gaps. `completed_no_matches` only describes executed
checks; missing, disabled, inapplicable and inconclusive checks are distinct.
Dalfox reflection/informational tiers remain observations and do not increase
the vulnerability candidate count.

## Common commands

```bash
# CTF web assessment; GET inputs, SQL errors, arithmetic templates, files, CORS and APIs
python3 twiy.py http://192.168.56.101:8080 --scan ctf

# Custom web ports, regardless of the URL's original default port
python3 twiy.py https://192.168.56.101 --scan port --ports 80,8080,8443

# All TCP ports to discover web services on unusual ports (can take up to an hour)
python3 twiy.py 192.168.56.101 --scan all-ports

# Exactly one tool, without running the entire pipeline
python3 twiy.py http://192.168.56.101:8080 --only whatweb --retain-raw-evidence
python3 twiy.py http://192.168.56.101:8080 --only checks --template-checks

# Enable installed external web scanners and their raw evidence in a numeric-IP lab
python3 twiy.py 192.168.56.101 --scan ctf --external-tools --retain-raw-evidence

# Offline report rebuild and same-target comparison
python3 twiy.py --report-only results/RUN_DIRECTORY
python3 twiy.py 192.168.56.101 --compare results/PREVIOUS_RUN
```

## Troubleshoot empty results and HTTP/TLS messages

- Discovery skips a generated opposite-protocol URL after a successful response identifies a port,
  reducing `https://HOST:80` wrong-version errors. Certificate verification failure identifies TLS
  but blocks application coverage; it does not cause an automatic retry with verification disabled.
  Explicit URLs are always attempted; timeouts, handshake failures and HTTP 400/426 still permit
  protocol fallback.
- CLI crawling follows safe same-origin redirects by default, so a `/directory` → `/directory/`
  normalization no longer hides its links/forms. Redirects to another host, scheme or port remain
  deferred even when another origin was already selected. All hops use existing rate/page/depth/time
  budgets and origin-bound credentials. `crawler.crawl()` retains its direct-call opt-in default.
- `no_candidates` means no eligible GET inputs were found and no parameter probes ran. Routes are
  not parameters. POST/password forms, authentication and JavaScript-rendered routes may need manual
  investigation; an empty candidate list does not establish safety.
- The terminal and HTML report now show coverage diagnostics with next steps for TLS verification,
  redirects not crawled, deferred forms, absent GET inputs and disabled external scanners. Offline
  report rebuilds preserve these explanations. External tools remain explicit opt-in and need their
  binaries installed: check with `python3 twiy.py --check`, then use
  `--external-tools --retain-raw-evidence` on an authorized numeric-IP target if desired.

For `CERTIFICATE_VERIFY_FAILED`, use the hostname that matches the certificate and ensure its CA is
trusted. Only if an authorized lab deliberately uses a self-signed certificate should you explicitly
select `--insecure`; this does not repair the certificate. A `301` is a redirect, not a failed scanner
or evidence of a vulnerability. Review its `Location` and the coverage diagnostics.

## Technology-driven follow-up

Discovery and crawl responses now retain small passive technology hints from generator metadata,
explicit technology headers and same-origin WordPress assets. Parsed WhatWeb fingerprints also feed
an origin-scoped follow-up plan. Hints are observations, not proof of a product/version or vulnerability;
unknown technology never suppresses the existing general checks.

`technology-plan.json` and the HTML report explain the WPScan decision for each responding URL.
With external scanners enabled, WPScan runs after discovery only when WordPress evidence exists.
`--only wpscan` explicitly requests it even without a passive hint; WPScan still performs its own
WordPress checks. `--skip wpscan` disables it. Hostnames retain the existing external-adapter
restriction because WPScan cannot use the built-in DNS-pinned HTTP transport.

```bash
# Install optional WPScan on Kali, then check availability
sudo apt install wpscan
python3 twiy.py --check

# Automatic WordPress follow-up when evidence is observed
python3 twiy.py http://192.168.56.101 --external-tools --retain-raw-evidence

# WPScan only, with the existing external scanner evidence policy
python3 twiy.py http://192.168.56.101 --only wpscan --retain-raw-evidence
```

The adapter uses passive core/plugin/theme detection, explicit `vp,vt` enumeration, one thread,
request timeouts, throttling and the existing process time budget. It does not request user enumeration
or password attacks. WPScan exit code 5 means vulnerability matches were reported and is treated as
completed; aborted/malformed output remains a coverage gap. Component inventory is informational;
reported vulnerabilities require validation and retain unknown severity rather than an invented score.
Only supplied CVE metadata is imported. Vulnerability enrichment needs a WPScan API token or supported
local database configured in WPScan itself; this adapter does not provision credentials. Empty or
unavailable vulnerability data does not establish safety. Updates are separate (`wpscan --update`);
scans use `--no-update` for predictable runs. See the
[official WPScan documentation](https://github.com/wpscanteam/wpscan/wiki/WPScan-User-Documentation).

## Read the results

- **CTF web investigation priorities**: execution-related candidates first, then database, file/configuration and authorization leads. These are evidence-linked leads, not confirmed exploit chains.
- **Findings and evidence**: baseline/probe requests, status, signatures, source tool and remediation. Missing security headers and technology observations are separate from vulnerability candidates.
- **How to exploit / CVE**: recorded GET reproduction helpers and manual validation steps. CVEs come from scanner metadata, never guessed from a version banner.
- **Coverage and tasks**: missing binaries, failures, timeouts and excluded parameters. An empty report does not establish that a target is secure.
- HTML, JSON and CSV files are saved in the run directory. Redaction is enabled by default; external raw evidence requires explicit opt-in.

CTF arithmetic probes support `{{...}}` and `${...}`. Two independently generated products must appear inside unique delimiters; literal reflection, static numbers, truncated responses and failed controls do not count. This does not identify every template engine or prove OS execution.

Crawling now seeds `/robots.txt` and `/sitemap.xml` on each selected origin, follows concrete same-origin sitemap entries/indexes, and inventories JavaScript source-map references. All use the existing page/depth/time/rate budgets; wildcard robots rules, action paths, foreign origins and static source maps are not requested. Use `--no-web-metadata` to disable metadata seeds. Advertised/disallowed paths are discovery leads, never vulnerability findings by themselves.

Built-in requests stay on one host and pin DNS resolution. Discovery and active checks do not follow redirects; CLI crawling follows same-origin, non-action redirects within the existing budgets by default. Use `--no-crawl-redirects` to inventory them without following. Cross-host, scheme/port changes and sensitive/action redirects remain deferred. WhatWeb selected via menu **5** also works for hostnames: the pinned HTTP transport saves a bounded HTTP packet, and WhatWeb's Ruby passive plugins analyze that local file. The original hostname/URL, Host header and TLS identity are preserved, and fingerprints are mapped back to that URL. Snapshot mode covers headers/body only, not URL/DNS/TLS plugins. Truncated or encoded packets are explicitly incomplete rather than treated as successful scans. Other external adapters remain opt-in for numeric IP targets. Use `--insecure` only when your lab deliberately uses a self-signed certificate. `--no-active-checks` disables input and CORS probes; `--profile standard` selects a lighter baseline. See `python3 twiy.py --help` for budgets and account-scoped options.

[Reviewed tools and integration details](docs/WEB_TOOLS.md) · [Earlier Sn1per comparison](docs/SN1PER_COMPARISON.md) · [Change history](CHANGELOG.md)

## Tests and releases

```bash
python3 -m unittest discover -s tests -v
node --test tests/report.test.cjs
bash -n scripts/setup-linux.sh
python3 build_release.py
```

CI uses one Linux job with Python 3.12, including loopback integration for installed Nmap and WhatWeb. JavaScript filters are tested with Node, Bash setup is syntax-checked, and superseded CI runs are cancelled. Tests use isolated local fixtures, not public targets. Python 3.10 remains the source syntax minimum but is no longer in the CI matrix. Source archives retain the historical `ws-r/` directory layout and include both launchers.

## Languages and review workflow

Python coordinates bounded requests and evidence. Ruby WhatWeb provides the established passive plugin engine. Go-based Nuclei/httpx and Rust-based Feroxbuster remain optional external scanners. Bash handles Linux setup, and the separately maintained `assets/report.js` filters HTML observations by type, severity and literal text, with a reset button. Reports embed that JavaScript and remain portable/offline; Node is required only for its developer tests.
## 4.3 complementary web engines

Katana JavaScript discovery, Dalfox v3 GET XSS assessment and testssl.sh TLS
protocol checks now join the existing Nuclei, SQLmap, WPScan, WhatWeb and directory
adapters. Discovery exports feed scoped GET selection; scanner failures and
partial results remain visible. See [commands and TLS behavior](docs/WEB_TOOLS.md) and
the [12-project upstream review](docs/SN1PER_COMPARISON.md).

```bash
python3 twiy.py --check
python3 twiy.py http://192.0.2.10 --scan web --external-tools --retain-raw-evidence --no-menu
python3 twiy.py http://192.0.2.10 --only katana dalfox --retain-raw-evidence --no-menu
```

Replace the documentation IP with your authorized numeric-IP lab target.
External binaries must be installed separately. Katana on HTTPS requires explicit
`--insecure` because upstream does not verify certificates. Unsupported CLI
versions are skipped with a reason. These integrations expand coverage; no
benchmark establishing superiority over Sn1per has been performed.
