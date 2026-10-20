# Engine layout and compatibility

```text
twiy.py / ws_r.py / python -m webscan
                       |
                  webscan.cli
                 /     |      \
        scan_modes   estate   scheduler
                       |          |
             pinned host scans  process_runner
                       |          |
            discovery / crawl / tool adapters
                       |
                  reporting
                 /         \
       atomic checkpoint   final evidence aggregation
                           HTML / JSON / CSV
```

`webscan/cli.py` owns user input, plan validation and dependency-stage orchestration.
`process_runner.py` owns subprocess groups, timeouts, cancellation and command/output evidence.
It takes a notification callback instead of importing a CLI-global UI. `scheduler.py` owns
independent batch execution and input-order results; dependency stages are still ordered.
`reporting.py` owns aggregation and presentation; it does not schedule scans or own terminal state.
`storage.py` writes atomic UTF-8 checkpoints beside their final destination. Resource paths are
centralized in `paths.py`; assets and default wordlists resolve from the distribution root.

The existing specialized modules retain their responsibilities inside the package: scope and
transport pin connections, crawler inventories pages/inputs, checks perform bounded comparisons,
adapters prepare and parse external tools, and findings/assessment build evidence-linked observations.
The estate controller still isolates hostname/address scans in separate processes, retaining their
Host/SNI and existing per-host budgets. This refactor does not broaden scan scope or change default
probe payloads, authentication propagation, DNS restrictions or vulnerability-validation claims.

## Compatibility aliases

Root modules such as `cli.py`, `scope.py` and `terminal.py` forward to the actual package module
object. They do not copy globals or maintain duplicate implementations. Existing imports and patches
therefore still refer to the same objects. Public launchers remain in the root, and the source ZIP
retains its historical `ws-r/` directory. The package and root aliases must be distributed together.
This is a source distribution; installation as an independently relocated wheel is not provided.

## Discovery and reporting

Previously each HTTP discovery response triggered complete result aggregation, scanner-file reads,
CSV export and HTML rendering. Discovery now writes `checkpoint.json` atomically, with an explicit
live/incomplete marker. Network-stage and final reports still use full aggregation. Normal completion,
cancellation and handled errors retain the existing final-report path. A forcefully killed process may
leave only earlier reports and the last checkpoint; that checkpoint must not be treated as a completed
assessment. Existing reports are not re-rendered after every discovery response.

The `performance` metadata records discovery checkpoint and full-render counts. The standalone
benchmark compares both reporting strategies using local synthetic observations and verifies equal
final statistics. It sends no network requests and imposes no timing threshold on correctness tests.
Use a controlled lab and identical scan budgets to measure actual end-to-end scan performance.

## Verification

```bash
python3 -m unittest discover -s tests -v
node --test tests/report.test.cjs
bash -n scripts/setup-linux.sh
python3 benchmarks/report_checkpoints.py --probes 40 --repeats 3
python3 build_release.py
```

Architecture tests cover alias identity, both launchers and package entry, resource lookup from another
working directory, compact/literal ASCII output, final evidence after live checkpoints, atomic-write
failure recovery, and running the extracted release. Existing scope, redaction, cancellation, HTTP
and external-adapter regressions remain part of the full Linux test suite.
