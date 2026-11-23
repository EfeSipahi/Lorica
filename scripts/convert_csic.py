"""Convert CSIC 2010 (all three files) to request records. Test set only.

A request starts with a line 'METHOD http://... HTTP/1.1'; headers end at the first blank
line; the body is the line right after it (empty for GET). Absolute targets are reduced to
path and query, with the original in meta. Files are read as Latin-1, which maps every
byte to one character; percent-escapes inside values are decoded later.

Usage: python scripts/convert_csic.py
"""

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Output, find_files, request_record  # noqa: E402
from convert_openappsec_legit import relative_target  # noqa: E402

ROOT = 'data/raw/csic-2010'
NAME = 'csic-2010'
FILES = {'normalTrafficTraining.txt': 0, 'normalTrafficTest.txt': 0,
         'anomalousTrafficTest.txt': 1}
REQUEST_LINE = re.compile(r'^([A-Z]+) (http://\S+) (HTTP/\d\.\d)$')


def split_requests(lines):
    """Yield lists of lines, one list per request."""
    current = None
    for line in lines:
        line = line.rstrip('\r\n')
        if REQUEST_LINE.match(line):
            if current is not None:
                yield current
            current = [line]
        elif current is not None:
            current.append(line)
    if current is not None:
        yield current


def parse_request(lines):
    method, url, version = REQUEST_LINE.match(lines[0]).groups()
    headers, i = [], 1
    while i < len(lines) and lines[i] != '':
        name, _, value = lines[i].partition(': ')
        headers.append([name, value])
        i += 1
    body = lines[i + 1] if i + 1 < len(lines) else ''
    return method, url, version, headers, body


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--raw', default=ROOT)
    parser.add_argument('--root', default='data/processed')
    args = parser.parse_args(argv)
    paths = {name: find_files(args.raw, name)[0] for name in FILES}
    notes = ['read as Latin-1; values are percent-encoded Latin-1 (Jam%F3n)',
             'all three files are test data; normalTrafficTraining is kept for the phase 5 '
             'diagnostic run only']
    with Output(NAME, 'requests.jsonl.gz', __file__, list(paths.values()), args.root,
                notes) as out:
        for name, label in FILES.items():
            with open(paths[name], encoding='latin-1', newline='') as f:
                for index, lines in enumerate(split_requests(f)):
                    out.read()
                    method, url, version, headers, body = parse_request(lines)
                    target, _ = relative_target(url)
                    out.write(request_record(
                        sample_id=f'{NAME}:{name}:{index}', source=NAME, method=method,
                        request_target=target, http_version=version, headers=headers,
                        body=body, label=label, label_name='anomalous' if label else 'normal',
                        meta=dict(file=name, original_target=url)))


if __name__ == '__main__':
    main()
