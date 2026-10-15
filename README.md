# The World Is Yours

Linux web vulnerability assessment for CTF labs and authorized single-host targets. Version **4.1.0**.

Enter one IP, hostname or URL, select a web scan, and follow the evidence in the HTML report. The default workflow focuses on web applications; Nmap discovers services that may host HTTP/HTTPS. It does not automatically gain a shell or claim server access.

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

Ports are editable, not fixed examples. Enter `8080`, `22,8080,8443` or `8000-8100`. Arabic digits and Arabic commas are accepted. If selected ports exclude the target URL port, the scanner uses the same host on the selected ports and drops the old URL path/query. It never adds the excluded port back. Cookie/account contexts require a matching origin instead.

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

## Read the results

- **CTF web investigation priorities**: execution-related candidates first, then database, file/configuration and authorization leads. These are evidence-linked leads, not confirmed exploit chains.
- **Findings and evidence**: baseline/probe requests, status, signatures, source tool and remediation. Missing security headers and technology observations are separate from vulnerability candidates.
- **How to exploit / CVE**: recorded GET reproduction helpers and manual validation steps. CVEs come from scanner metadata, never guessed from a version banner.
- **Coverage and tasks**: missing binaries, failures, timeouts and excluded parameters. An empty report does not establish that a target is secure.
- HTML, JSON and CSV files are saved in the run directory. Redaction is enabled by default; external raw evidence requires explicit opt-in.

CTF arithmetic probes support `{{...}}` and `${...}`. Two independently generated products must appear inside unique delimiters; literal reflection, static numbers, truncated responses and failed controls do not count. This does not identify every template engine or prove OS execution.

Crawling now seeds `/robots.txt` and `/sitemap.xml` on each selected origin, follows concrete same-origin sitemap entries/indexes, and inventories JavaScript source-map references. All use the existing page/depth/time/rate budgets; wildcard robots rules, action paths, foreign origins and static source maps are not requested. Use `--no-web-metadata` to disable metadata seeds. Advertised/disallowed paths are discovery leads, never vulnerability findings by themselves.

Built-in requests stay on one host, pin DNS resolution and do not follow redirects. WhatWeb selected via menu **5** also works for hostnames: the pinned HTTP transport saves a bounded HTTP packet, and WhatWeb's Ruby passive plugins analyze that local file. The original hostname/URL, Host header and TLS identity are preserved, and fingerprints are mapped back to that URL. Snapshot mode covers headers/body only, not URL/DNS/TLS plugins. Truncated or encoded packets are explicitly incomplete rather than treated as successful scans. Other external adapters remain opt-in for numeric IP targets. Use `--insecure` only when your lab deliberately uses a self-signed certificate. `--no-active-checks` disables input and CORS probes; `--profile standard` selects a lighter baseline. See `python3 twiy.py --help` for budgets and account-scoped options.

[Reviewed tools and integration details](WEB_TOOLS.md) · [Earlier Sn1per comparison](SN1PER_COMPARISON.md) · [Change history](CHANGELOG.md)

## Tests and releases

```bash
python3 -m unittest discover -s tests -v
node --test tests/report.test.cjs
bash -n scripts/setup-linux.sh
python3 build_release.py
```

CI uses one Linux job with Python 3.12, including loopback integration for installed Nmap and WhatWeb. JavaScript filters are tested with Node, Bash setup is syntax-checked, and superseded CI runs are cancelled. Tests use isolated local fixtures, not public targets. Python 3.10 remains the source syntax minimum but is no longer in the CI matrix. Source archives retain the historical `ws-r/` directory layout and include both launchers.

## Languages and review workflow

Python coordinates bounded requests and evidence. Ruby WhatWeb provides the established passive plugin engine. Go-based Nuclei/httpx and Rust-based Feroxbuster remain optional external scanners. Bash handles Linux setup, and the separately maintained `report.js` filters HTML observations by type, severity and literal text, with a reset button. Reports embed that JavaScript and remain portable/offline; Node is required only for its developer tests.
