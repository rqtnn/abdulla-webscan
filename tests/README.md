# Linux tests

Run `python3 -m unittest discover -s tests -v` from the repository root.
CI runs on Ubuntu with Python 3.12 (one job, pip cache, superseded runs cancelled). Nmap and WhatWeb are installed for real loopback integration; other adapters use controlled fake executables and exported fixture formats. No public targets are scanned.

`test_twiy.py` checks the 4.0 web default, CTF menu, custom port override, authenticated origin conflict, arithmetic SSTI positive/negative controls and evidence-based web priorities. Existing suites cover crawler limits, SQL error/timing controls, sensitive-file signatures, API/account comparisons, TLS, DNS pinning, redaction, offline reports, failure continuation and subprocess cancellation.

Some older test helper names and fixture paths retain historical names. Windows/macOS are not supported or exercised by CI.

`test_web_expansion.py` covers real menu choice 5 on an unresolved hostname pinned to loopback, original Host preservation, snapshot attribution/failures, sitemap indexes and robots/JavaScript discovery scope. The real binary case runs in Linux CI. `node --test tests/report.test.cjs` checks combined report filters and reset; `bash -n scripts/setup-linux.sh` checks the Linux bootstrap. Tests do not install scanners themselves.
`test_web_engine.py` exercises Katana/Dalfox/testssl command contracts, isolated
selection, exact-origin input/output filtering, secret/action exclusions,
Dalfox exit 1 and incomplete metadata, TLS warning interpretation, process
timeouts, and controlled Katana → crawl → Dalfox orchestration with SQLmap disabled.
These use fake executables and upstream-shaped JSON exports, not real scanner binaries.
