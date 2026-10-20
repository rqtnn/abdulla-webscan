# Sn1per and WS-R

Research source: [official 1N3/Sn1per repository](https://github.com/1N3/Sn1per),
reviewed on 2026-10-14. The README mixes Community and paid Professional/Enterprise
capabilities; advertised integration counts are not independent validation.
No Sn1per code, exploit library or templates were copied into WS-R.

| Area | Sn1per documentation | WS-R 3.2.0 |
| --- | --- | --- |
| Scan modes | Normal, web, specific port, full-port and mass modes | Full, web, quick, specific port and isolated tool plans |
| Tool control | Configurable third-party integrations | Post-target menu, `--only`, explicit disabled stages and dependency records |
| Target scope | Single hosts, host files and subnet modes | Existing one-host/IP boundary retained |
| Fingerprinting | Multiple external reconnaissance/fingerprinting integrations | WhatWeb/httpx selection and existing metadata adapters |
| Reporting | Workspace/host reports; CSV/Excel/PDF advertised for Professional | Evidence-linked HTML/JSON, CVE/manual verification, CSV added |
| Repeated assessment | Continuous surface comparisons advertised | Same-target offline comparison added; missing findings are not called fixed |
| Commercial integrations | Nessus, OpenVAS/GVM, Burp and others listed | Existing scanner adapters; no claim that commercial integrations were added |
| Exploitation | Automated exploitation and brute-force features advertised | Bounded detection/control requests; manual verification guides preserved |

## Implemented from the comparison

- Explicit scan selection after entering a target, including Nmap-only and WhatWeb-only.
- Quick budgets and single-port plans using the existing bounded scanner engine.
- Run comparison of finding identity, severity/status and port inventory.
- CSV export for review in spreadsheets, with formula injection protection.

## Practical boundaries

WhatWeb-only still needs HTTP reachability discovery; it does not run Nmap,
crawling or vulnerability probes. Nmap-only makes no HTTP requests.
GET checks and automatic SQLmap require crawling as an explicit dependency.
Explicit SQLmap-only GET targets do not require discovery.
External scanners require installed executables and raw-evidence opt-in. Remote adapters retain numeric-IP restrictions; the 4.1 WhatWeb snapshot exception is described below. No external target was scanned during
development; automated scanner fixtures and isolated loopback tests validate
orchestration rather than every installed third-party version.

## 4.1 web review (2026-10-15)

Reviewed [`modes/normal_webporthttp.sh`](https://github.com/1N3/Sn1per/blob/master/modes/normal_webporthttp.sh), [`modes/javascript-analysis.sh`](https://github.com/1N3/Sn1per/blob/master/modes/javascript-analysis.sh) and [`modes/webscan.sh`](https://github.com/1N3/Sn1per/blob/master/modes/webscan.sh). Adopted independent implementations of robots-path inventory and JavaScript asset/route investigation, plus bounded sitemap-index traversal. Existing Nuclei, Nikto and SQLmap adapters remain the vulnerability scanner integrations. Third-party archives, mass scanning, paid scanner APIs and automated exploitation were not added.

WhatWeb hostname handling now uses native HTTP packet-file input from the pinned transport. Numeric-IP runs retain direct WhatWeb behavior; other external scanners keep their numeric-IP restriction. Bash setup reduces dependency mistakes; JavaScript report category filters separate vulnerability candidates from technologies, endpoints and configuration notes. Neither a robots exclusion nor a version banner is treated as a confirmed vulnerability.
# 4.3 upstream research and integration review — 2026-10-19

This is a focused review of 12 relevant upstream projects, not an exhaustive
search of every GitHub repository. Sources below are official repositories and
documentation. Selection favors complementary coverage, machine-readable
evidence and controls that fit TWIY's one-host workflow. No upstream code or
payload library was copied. No comparative vulnerability-detection benchmark
was run, so this release does not claim to outperform Sn1per.

| Upstream reviewed | Useful capability | TWIY decision |
| --- | --- | --- |
| [Sn1per](https://github.com/1N3/Sn1per), including [web mode](https://github.com/1N3/Sn1per/blob/master/modes/web.sh) and [webscan](https://github.com/1N3/Sn1per/blob/master/modes/webscan.sh) | Orchestrating multiple reconnaissance and web scanners | Improve independent pipeline stages and evidence; Community source and paid product claims are distinct. |
| [Katana](https://github.com/projectdiscovery/katana), [HTTP transport source](https://github.com/projectdiscovery/katana/blob/dev/pkg/engine/common/http.go) | Crawling and JavaScript URL extraction | Added bounded standard-mode adapter. TLS-bypass default requires explicit insecure opt-in for HTTPS. |
| [Dalfox](https://github.com/hahwul/dalfox), [CLI reference](https://github.com/hahwul/dalfox/blob/main/docs/content/reference/cli.md), [output](https://github.com/hahwul/dalfox/blob/main/docs/content/guide/output.md) | Dedicated reflected/DOM XSS assessment, evidence tiers | Added v3 adapter with selected GET input, bounded payload budget and incomplete-coverage handling. Older Go/v2 CLI is not assumed compatible. |
| [testssl.sh](https://github.com/testssl/testssl.sh), [manual](https://github.com/testssl/testssl.sh/blob/3.3dev/doc/testssl.1.md) | TLS protocol configuration evidence | Added protocol-only JSON adapter; full intrusive vulnerability suite is not scheduled. |
| [Arjun](https://github.com/s0md3v/Arjun), [requester](https://github.com/s0md3v/Arjun/blob/master/arjun/core/requester.py), [utils](https://github.com/s0md3v/Arjun/blob/master/arjun/core/utils.py) | Hidden parameter discovery | Deferred: reviewed requester disables TLS validation; stability probes try alternative schemes. Its default large dictionary and special parameters also need a separate bounded integration design. |
| [WAFW00F](https://github.com/EnableSecurity/wafw00f) | WAF fingerprinting | Deferred: fingerprinting is useful context, but detection alone does not improve vulnerability validation; reviewed CLI lacks a comparable request-rate control. No bypass automation added. |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Template-based checks, CVE metadata | Existing adapter retained; discovered routes continue to feed local HTTP templates with OAST and automatic updates disabled. Template matches require validation. |
| [ffuf](https://github.com/ffuf/ffuf) | Directory/content discovery | Existing rate-limited JSON adapter retained. Additional directory engines are alternatives rather than evidence of stronger detection by count. |
| [XSStrike](https://github.com/s0md3v/XSStrike) | XSS analysis and payload generation | Deferred in this release to avoid two overlapping XSS engines before Dalfox integration has real-binary lab coverage. |
| [Jaeles](https://github.com/jaeles-project/jaeles) | Signature-driven web checks | Deferred: overlaps Nuclei; adding another signature library requires explicit template provenance and execution controls. |
| [OWASP ZAP](https://github.com/zaproxy/zaproxy) | Browser/proxy sessions and active scanning | Deferred: needs a separately managed daemon, authenticated-session handling and explicit API/context lifecycle. |
| [OWASP WSTG](https://github.com/OWASP/wstg) | Structured web-testing methodology | Used as a coverage reference, not an executable scanner; business logic and authorization still require application-specific review. |

The practical improvement is a connected discovery-to-assessment workflow:
installed fingerprint/directory engines → Katana → built-in crawl and GET
selection → control checks, Dalfox, Nuclei and SQLmap → evidence-linked reports.
WPScan remains technology-driven. testssl protocol checks are a separate HTTPS
branch. Tool selection, raw-evidence policy, origin filtering, timeouts and
explicit failure status apply throughout.

For a defensible comparison with Sn1per, run both tools against the same local
ground-truth lab set with pinned tool/template versions and equal time budgets;
measure validated true positives, false positives, discovered routes/parameters,
completion rate and time. This release's fixture tests verify integration
behavior; they are not that detection benchmark.
