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
