"""Convert modsec-learn SQLi strings to attack value records.

Each file is a JSON array of 'p=<form-encoded payload>' strings; the payload is
form-decoded once. Every value is SQL injection.

Usage: python scripts/convert_modsec_learn.py
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Output, find_files, value_record  # noqa: E402
from extract_values import percent_decode  # noqa: E402

ROOT = 'data/raw/modsec-learn-dataset'
NAME = 'modsec-learn'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--raw', default=ROOT)
    parser.add_argument('--root', default='data/processed')
    args = parser.parse_args(argv)
    files = find_files(args.raw, 'sqli_parsed.json')
    notes = ['form-decoded once after removing the p= wrapper']
    with Output(NAME, 'values.jsonl.gz', __file__, files, args.root, notes) as out:
        for path in files:
            part = os.path.basename(os.path.dirname(path))
            with open(path, encoding='utf-8') as f:
                entries = json.load(f)
            for index, text in enumerate(entries):
                out.read()
                if not isinstance(text, str) or not text.startswith('p=') or '&' in text:
                    out.skip('unexpected_shape')
                    continue
                value, flags = percent_decode(text[2:], plus_is_space=True)
                if value.strip() == '':
                    out.skip('empty')
                    continue
                out.write(value_record(
                    f'{NAME}:{part}:{index}', NAME, os.path.relpath(path, args.raw), value, 1,
                    'sqli', meta=dict(source_type=part, decode_flags=sorted(flags))))


if __name__ == '__main__':
    main()
