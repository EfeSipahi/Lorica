"""Merge the attack value sources into one deduplicated file.

The key is the exact value string. The first occurrence is kept (sources in the order
below) and meta.sources lists every source that had it. A value labeled 1 in one place and
0 in another is excluded and listed in the manifest. Types are not balanced here.

Usage: python scripts/merge_attack_values.py
"""

import argparse
import collections
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Output, read_jsonl  # noqa: E402

SOURCES = ['openappsec-malicious', 'modsec-learn', 'httpparams', 'gotestwaf']
NAME = 'attack-values'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--root', default='data/processed')
    args = parser.parse_args(argv)
    inputs = [os.path.join(args.root, s, 'values.jsonl.gz') for s in SOURCES]
    kept, labels, sources = {}, collections.defaultdict(set), collections.defaultdict(list)
    for path in inputs:
        for record in read_jsonl(path):
            value = record['value']
            labels[value].add(record['label'])
            if record['source'] not in sources[value]:
                sources[value].append(record['source'])
            kept.setdefault(value, record)
    conflicts = sorted(v for v, ls in labels.items() if len(ls) > 1)
    per_source = collections.Counter()
    notes = ['exact-string deduplication; first source in order '
             + ', '.join(SOURCES) + ' wins']
    with Output(NAME, 'values.jsonl.gz', __file__, inputs, args.root, notes) as out:
        out.read(sum(len(s) for s in sources.values()))
        lengths = []
        for value, record in kept.items():
            if value in conflicts:
                out.skip('label_conflict')
                continue
            record = dict(record, meta=dict(record['meta'], sources=sources[value]))
            per_source[record['source']] += 1
            lengths.append(len(value))
            out.write(record)
        out.extra = dict(
            kept_per_first_source=dict(per_source),
            duplicates_removed=sum(len(s) for s in sources.values()) - len(kept),
            label_conflicts=conflicts[:200],
            value_length=dict(median=statistics.median(lengths) if lengths else 0,
                              p95=sorted(lengths)[int(0.95 * (len(lengths) - 1))]
                              if lengths else 0, max=max(lengths, default=0)))


if __name__ == '__main__':
    main()
