# Linux tests

Run `python3 -m unittest discover -s tests -v` from the repository root.
CI runs on Ubuntu with Python 3.10 and 3.12. Nmap and WhatWeb are installed for real loopback integration; other adapters use controlled fake executables and exported fixture formats. No public targets are scanned.

`test_twiy.py` checks the 4.0 web default, CTF menu, custom port override, authenticated origin conflict, arithmetic SSTI positive/negative controls and evidence-based web priorities. Existing suites cover crawler limits, SQL error/timing controls, sensitive-file signatures, API/account comparisons, TLS, DNS pinning, redaction, offline reports, failure continuation and subprocess cancellation.

Some older test helper names and fixture paths retain historical names. Windows/macOS are not supported or exercised by CI.
