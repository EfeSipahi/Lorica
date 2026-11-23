"""Convert HttpParams attack rows to attack value records.

Only 'anom' rows are kept. The 'norm' rows were copied from CSIC, which is a test set, so
they are dropped. A few cmdi rows in the source have a second CSV row merged into the
payload; those are skipped and counted. Payloads are stored as they are (not encoded).

Usage: python scripts/convert_httpparams.py
"""

import argparse
import csv
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Output, find_files, value_record  # noqa: E402

ROOT = 'data/raw/httpparams'
NAME = 'httpparams'
MERGED_ROW = re.compile(r'",\d+,[a-z-]+,(?:anom|norm)\b')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--raw', default=ROOT)
    parser.add_argument('--root', default='data/processed')
    args = parser.parse_args(argv)
    path = find_files(args.raw, 'payload_full.csv')[0]
    notes = ['norm rows dropped: copied from CSIC (a test set)',
             'rows with a second CSV row merged into the payload are skipped']
    with Output(NAME, 'values.jsonl.gz', __file__, [path], args.root, notes) as out, \
            open(path, encoding='utf-8', newline='') as f:
        for line_no, row in enumerate(csv.DictReader(f), start=2):
            out.read()
            if row['label'] != 'anom':
                out.skip('norm_row_from_csic')
                continue
            payload = row['payload']
            if MERGED_ROW.search(payload):
                out.skip('merged_csv_row')
                continue
            if payload == '':
                out.skip('empty')
                continue
            out.write(value_record(f'{NAME}:payload_full.csv:{line_no}', NAME,
                                   'payload_full.csv', payload, 1, row['attack_type'],
                                   meta=dict(source_type=row['attack_type'])))


if __name__ == '__main__':
    main()
