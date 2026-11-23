"""Convert open-appsec malicious requests to attack value records.

Each file is one JSON array: the first half are GET /?p=<payload>, the second half the same
payloads as POST bodies p=<payload>, in the same order. One value is kept per pair after
checking both copies match. The payload is form-decoded once.

Usage: python scripts/convert_openappsec_malicious.py
"""

import argparse
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Output, value_record  # noqa: E402
from extract_values import percent_decode  # noqa: E402

ZIP = 'data/raw/open-appsec/malicious.zip'
NAME = 'openappsec-malicious'
TYPES = {'cmdexe': 'cmdi', 'log4shell': 'log4shell', 'shellshock': 'cmdi', 'sqli': 'sqli',
         'traversal': 'path-traversal', 'xss': 'xss', 'xxe': 'xxe'}


def payload_of(text):
    """The raw form-encoded payload after 'p=', or None if the text has another shape."""
    if not text.startswith('p=') or '&' in text:
        return None
    return text[2:]


def pairs(records):
    half = len(records) // 2
    if len(records) % 2 or any(r.get('method') != 'GET' for r in records[:half]) \
            or any(r.get('method') != 'POST' for r in records[half:]):
        raise ValueError('file is not GET half then POST half')
    return zip(records[:half], records[half:])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--zip', default=ZIP)
    parser.add_argument('--root', default='data/processed')
    args = parser.parse_args(argv)
    notes = ['one value per GET/POST pair; form-decoded once (+ is a space)',
             'shellshock is typed cmdi; meta.source_type keeps the file name']
    with zipfile.ZipFile(args.zip) as archive, \
            Output(NAME, 'values.jsonl.gz', __file__, [args.zip], args.root, notes) as out:
        for filename in sorted(n for n in archive.namelist() if n.endswith('.json')):
            stem = os.path.basename(filename)[:-len('.json')]
            records = json.loads(archive.read(filename).decode('utf-8'))
            for index, (get, post) in enumerate(pairs(records)):
                out.read(2)
                query = get['url'][2:] if get['url'].startswith('/?') else ''
                raw = payload_of(query)
                if raw is None or raw != payload_of(post.get('data') or ''):
                    out.skip('pair_mismatch_or_shape')
                    continue
                value, flags = percent_decode(raw, plus_is_space=True)
                if value == '':
                    out.skip('empty')
                    continue
                out.write(value_record(
                    f'{NAME}:{stem}:{index}', NAME, filename, value, 1, TYPES[stem],
                    meta=dict(source_type=stem, decode_flags=sorted(flags))))


if __name__ == '__main__':
    main()
