"""Convert GoTestWAF test cases to value records.

Attack payloads get label 1; false-pos/texts.yml gives benign texts with label 0.
Three files use \\' inside double-quoted strings, which Go's YAML reader accepts and
PyYAML does not; for a file that fails to parse, \\' is replaced by ' and the replacement is
counted. The community-<N>kb-* files (payloads padded with kilobytes of filler to test WAF
size limits) are skipped. Payloads are stored as written; encoder and placeholder go in meta.

Usage: python scripts/convert_gotestwaf.py
"""

import argparse
import os
import re
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Output, value_record  # noqa: E402

ROOT = 'data/raw/gotestwaf'
NAME = 'gotestwaf'
PADDING_FILE = re.compile(r'community-\d+kb-')
TYPES = {
    'sql injection': 'sqli', 'xss': 'xss', 'rce': 'cmdi', 'shell': 'cmdi', 'xxe': 'xxe',
    'lfi': 'path-traversal', 'path traversal': 'path-traversal',
    'community-lfi-multipart': 'path-traversal', 'crlf injection': 'crlf',
    'ldap injection': 'ldapi', 'nosql injection': 'nosqli', 'ss injection': 'ssi',
    'sst injection': 'ssti', 'mail injection': 'other', 'graphql': 'other', 'grpc': 'other',
    'rest non-crud': 'other', 'useragent': 'other', 'rawrequest test': 'cmdi',
}


def load(path):
    """Parse one YAML file; returns (data, number of \\' replacements made)."""
    with open(path, encoding='utf-8') as f:
        text = f.read()
    try:
        return yaml.safe_load(text), 0
    except yaml.YAMLError:
        count = text.count("\\'")
        return yaml.safe_load(text.replace("\\'", "'")), count


def placeholders(data):
    names = []
    for item in data.get('placeholder') or []:
        names.extend(item.keys() if isinstance(item, dict) else [item])
    return names


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--raw', default=ROOT)
    parser.add_argument('--root', default='data/processed')
    args = parser.parse_args(argv)
    files = sorted(os.path.join(d, f) for d, _, fs in os.walk(args.raw) for f in fs
                   if f.endswith(('.yml', '.yaml')))
    notes = []
    with Output(NAME, 'values.jsonl.gz', __file__, files, args.root, notes) as out:
        for path in files:
            rel = os.path.relpath(path, args.raw).replace(os.sep, '/')
            if PADDING_FILE.search(os.path.basename(path)):
                out.skip('padding_file', len((load(path)[0] or {}).get('payload') or []))
                continue
            data, fixed = load(path)
            if fixed:
                out.notes.append(f"{rel}: replaced {fixed} \\' with ' to parse")
            benign = rel.startswith('false-pos/')
            source_type = data.get('type')
            attack_type = None if benign else TYPES.get(str(source_type).lower())
            if not benign and attack_type is None:
                attack_type = 'other'
                out.notes.append(f'{rel}: unknown type {source_type!r} mapped to other')
            places = placeholders(data)
            for index, payload in enumerate(data.get('payload') or []):
                out.read()
                if payload is None or str(payload) == '':
                    out.skip('empty')
                    continue
                meta = dict(source_type=source_type, encoder=data.get('encoder') or [],
                            placeholder=places)
                if 'RawRequest' in places:
                    meta['raw_request'] = True
                out.write(value_record(
                    f'{NAME}:{rel}:{index}', NAME, rel, str(payload), 0 if benign else 1,
                    attack_type, meta=meta))


if __name__ == '__main__':
    main()
