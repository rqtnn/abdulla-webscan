# The World Is Yours

Linux web vulnerability assessment for CTF labs and authorized single-host targets. Version **4.3.0**.

Enter one IP, hostname or URL, select a scan, and review the evidence in the HTML report. Built-in checks use bounded requests; external scanner integrations are optional and report missing dependencies explicitly.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
sudo apt install nmap whatweb
python3 twiy.py --check
python3 twiy.py
```

Linux only. `ws_r.py` remains a compatible launcher. Alternatively, run `bash scripts/setup-linux.sh` to create the Python environment and check dependencies. It does not install external scanners.

## Documentation

- [Scan modes, commands and troubleshooting](docs/USAGE.md)
- [External tool integrations](docs/WEB_TOOLS.md)
- [Change history](docs/CHANGELOG.md)
- [Tests and local fixtures](tests/README.md)
- [Account-context example](examples/contexts.example.json)

## Repository layout

| Location | Purpose |
| --- | --- |
| `twiy.py`, `ws_r.py` | Current and compatible launchers |
| Root Python modules | Scanner, discovery, evidence and reporting |
| `docs/` | Usage, integration notes and change history |
| `assets/` | Embedded report JavaScript |
| `wordlists/` | Default discovery wordlist |
| `examples/` | Sample configuration |
| `scripts/` | Linux setup and diagnostics |
| `tests/` | Python and JavaScript regression tests |
| `.github/workflows/` | Linux CI |
| `build_release.py` | Source archive builder |

Generated `results/`, `releases/`, logs and caches are ignored by Git.

## Development checks

```bash
python3 -m unittest discover -s tests -v
node --test tests/report.test.cjs
bash -n scripts/setup-linux.sh
python3 build_release.py
```

Tests use isolated local fixtures. Real Nmap and WhatWeb integration tests require those binaries; other external adapters use controlled fixtures. An empty scan report does not establish that a target is secure: review tool coverage, errors and excluded inputs.
