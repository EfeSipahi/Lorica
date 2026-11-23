"""Run every phase 2 step in order and print a short summary from the manifests.

Usage (from the project root): python scripts/prepare_data.py [--only NAME ...]
"""

import argparse
import importlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

STEPS = [
    ('openappsec-legit', 'convert_openappsec_legit'),
    ('openappsec-malicious', 'convert_openappsec_malicious'),
    ('modsec-learn', 'convert_modsec_learn'),
    ('httpparams', 'convert_httpparams'),
    ('gotestwaf', 'convert_gotestwaf'),
    ('csic-2010', 'convert_csic'),
    ('ecml-pkdd-2007', 'convert_ecml'),
    ('attack-values', 'merge_attack_values'),
    ('overlap', 'overlap_check'),
]


def summary(root, name):
    with open(os.path.join(root, name, 'manifest.json'), encoding='utf-8') as f:
        m = json.load(f)
    keys = ('counts', 'skipped', 'labels', 'attack_types', 'notes', 'exact_duplicates',
            'duplicates_removed', 'kept_per_first_source', 'value_length',
            'excluded_by_reason', 'shape')
    return {k: m[k] for k in keys if k in m and m[k]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--only', nargs='*', help='run only these steps')
    parser.add_argument('--root', default='data/processed')
    args = parser.parse_args(argv)
    for name, module in STEPS:
        if args.only and name not in args.only:
            continue
        start = time.time()
        print(f'\n== {name}', flush=True)
        importlib.import_module(module).main(['--root', args.root])
        print(f'({time.time() - start:.0f} s)')
        print(json.dumps(summary(args.root, name), indent=1, ensure_ascii=False))


if __name__ == '__main__':
    main()
