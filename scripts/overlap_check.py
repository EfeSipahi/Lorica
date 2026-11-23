"""Find training data that also appears in the test sets converted so far (CSIC, ECML).

Two checks:
- attack values: a merged attack value equal to any value extracted from a test request
  (decoded once, same rules as the model) is excluded;
- normal requests: an open-appsec request with the same method, target and body as a test
  request is excluded.

Nothing is deleted. The excluded ids are written to data/processed/overlap/excluded.jsonl.gz
and later steps skip them.

Usage: python scripts/overlap_check.py
"""

import argparse
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Output, read_jsonl  # noqa: E402
from extract_values import extract  # noqa: E402

TEST_SETS = ['csic-2010', 'ecml-pkdd-2007']
NAME = 'overlap'


def request_key(request):
    return (request['method'], request['request_target'], request['body'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--root', default='data/processed')
    args = parser.parse_args(argv)
    test_paths = [os.path.join(args.root, t, 'requests.jsonl.gz') for t in TEST_SETS]
    attack_path = os.path.join(args.root, 'attack-values', 'values.jsonl.gz')
    legit_path = os.path.join(args.root, 'openappsec-legit', 'requests.jsonl.gz')
    test_values, test_requests = collections.defaultdict(set), collections.defaultdict(set)
    for name, path in zip(TEST_SETS, test_paths):
        for request in read_jsonl(path):
            test_requests[request_key(request)].add(name)
            for value in extract(request):
                test_values[value['value']].add(name)
    by_reason = collections.Counter()
    examples = collections.defaultdict(list)
    notes = ['ids listed here are excluded from training; source files are not changed']
    with Output(NAME, 'excluded.jsonl.gz', __file__, [attack_path, legit_path] + test_paths,
                args.root, notes) as out:
        for record in read_jsonl(attack_path):
            out.read()
            if record['value'] in test_values:
                hit = sorted(test_values[record['value']])
                reason = 'attack_value_in_' + '+'.join(hit)
                by_reason[reason] += 1
                if len(examples[reason]) < 10:
                    examples[reason].append(record['value'][:200])
                out.write(dict(id=record['value_id'], kind='attack-value', reason=reason,
                               label=None))
        for request in read_jsonl(legit_path):
            out.read()
            if request_key(request) in test_requests:
                reason = 'legit_request_in_' + '+'.join(sorted(test_requests[request_key(request)]))
                by_reason[reason] += 1
                out.write(dict(id=request['sample_id'], kind='request', reason=reason,
                               label=None))
        out.extra = dict(excluded_by_reason=dict(by_reason), examples=dict(examples))
    print(dict(by_reason))


if __name__ == '__main__':
    main()
