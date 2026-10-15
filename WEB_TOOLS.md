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


## WPScan and adaptive planning (4.2)

Reviewed the [official WPScan documentation](https://github.com/wpscanteam/wpscan/wiki/WPScan-User-Documentation), upstream CLI/enumeration/exit-code implementations, [ffuf extensions](https://github.com/ffuf/ffuf/wiki/Input-methods) and [Dirsearch wordlists](https://github.com/maurosoria/dirsearch/blob/master/docs/wordlists.md). WPScan uses explicit popular-plugin/theme enumeration with passive detection, one worker, throttling, request/process deadlines and no in-scan updates. No API token is stored in command lines or reports. `--only wpscan` still requires WordPress evidence; it never forces detection. The adapter inherits numeric-IP and raw-evidence restrictions; API/database availability limits advisory coverage.

The default plan fingerprints HTTP headers, generator tags and same-origin asset structure, optionally enriches them with WhatWeb, maps routes, then runs follow-up tools. Enabled directory adapters receive stack-specific extensions, including `--force-extensions` for Dirsearch's plain wordlist. Python/Ruby/Node indicators guide manual review; no language-specific exploit is inferred or executed. All observations require validation.
