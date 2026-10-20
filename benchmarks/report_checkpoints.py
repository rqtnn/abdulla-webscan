"""Offline comparison of old per-probe reports and new discovery checkpoints.

This measures report I/O/aggregation only, not scanning throughput or Sn1per.
Run: python benchmarks/report_checkpoints.py --probes 40 --repeats 3
"""
import argparse
import copy
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from webscan import reporting


def trial(probes, checkpoint):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        summary = dict(target='127.0.0.1', created='benchmark', mode='sequential',
            outcome='Offline report benchmark', jobs=[], ports=[], probes=[])
        started = time.perf_counter()
        for index in range(probes):
            summary['probes'].append(dict(url='http://127.0.0.1/' + str(index), status=200))
            if checkpoint:
                reporting.write_checkpoint(root, summary)
            else:
                reporting.write_reports(root, summary, tools=(), report_script='')
        if checkpoint:
            reporting.write_reports(root, summary, tools=(), report_script='')
        elapsed = time.perf_counter() - started
        return elapsed, copy.deepcopy(summary['statistics'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probes', type=int, default=40)
    parser.add_argument('--repeats', type=int, default=3)
    args = parser.parse_args()
    if not (1 <= args.probes <= 500 and 1 <= args.repeats <= 10):
        parser.error('Use probes 1..500 and repeats 1..10')
    before, after = [], []
    for repeat in range(args.repeats):
        measurements = {}
        for mode in ((False, True) if repeat % 2 == 0 else (True, False)):
            measurements[mode] = trial(args.probes, mode)
        assert measurements[False][1] == measurements[True][1], 'Final assessment statistics changed'
        before.append(measurements[False][0])
        after.append(measurements[True][0])
    old, new = statistics.median(before), statistics.median(after)
    print(json.dumps(dict(scope='offline reporting only', probes=args.probes, repeats=args.repeats,
        old_full_renders=args.probes, new_full_renders=1, before_seconds=round(old, 4),
        after_seconds=round(new, 4), ratio=round(old / new, 2), statistics_equal=True), indent=2))


if __name__ == '__main__':
    main()
