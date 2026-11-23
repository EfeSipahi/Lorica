"""Convert ECML/PKDD 2007 to request records, with attack positions. Test set only.

Each attackIntervall is mapped to a span in the request record's own text
(meta.attack_spans, [part, start, end) with 0-based end-exclusive offsets, the same form
scripts/extract_values.py uses). 'uri' and 'query' without numbers mean the whole part.
Out-of-context attacks count as attacks; meta.in_context keeps the flag.

Usage: python scripts/convert_ecml.py
"""

import argparse
import io
import os
import sys
import xml.etree.ElementTree as ET
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Output, find_files, request_record  # noqa: E402

ROOT = 'data/raw/ecml-pkdd-2007'
NAME = 'ecml-pkdd-2007'
TYPES = {'XSS': 'xss', 'SqlInjection': 'sqli', 'LdapInjection': 'ldapi',
         'XPathInjection': 'xpathi', 'OsCommanding': 'cmdi',
         'PathTransversal': 'path-traversal', 'SSI': 'ssi'}
CONTEXT = ('os', 'webserver', 'runningLdap', 'runningSqlDb', 'runningXpath')


def local(tag):
    return tag.rsplit('}', 1)[-1]


def child_text(element, name):
    for child in element.iter():
        if local(child.tag) == name:
            return child.text or ''
    return None


def interval_span(interval, uri, query):
    """Map one attackIntervall text to [part, start, end) in the request record."""
    if interval == 'uri':
        return ['target', 0, len(uri)]
    if interval == 'query':
        return ['target', len(uri) + 1, len(uri) + 1 + len(query)]
    where, numbers = interval.rsplit(':', 1)
    lo, hi = (int(x) for x in numbers.split('-'))
    if where == 'query':
        return ['target', len(uri) + lo, len(uri) + 1 + hi]
    if where == 'body':
        return ['body', lo - 1, hi]
    if where.startswith('headers:'):
        return ['header:' + where.split(':', 1)[1], lo - 1, hi]
    raise ValueError(interval)


def parse_sample(element):
    kind = child_text(element, 'type')
    uri = child_text(element, 'uri') or ''
    query = child_text(element, 'query') or ''
    headers = []
    for line in (child_text(element, 'headers') or '').splitlines():
        if ': ' in line:
            headers.append(line.split(': ', 1))
    intervals = [(c.text or '').strip() for c in element.iter()
                 if local(c.tag) == 'attackIntervall']
    label = int(kind != 'Valid')
    meta = dict(in_context=(child_text(element, 'inContext') or '').strip().upper() == 'TRUE',
                attack_intervals=intervals,
                attack_spans=[interval_span(i, uri, query) for i in intervals],
                context={k: (child_text(element, k) or '').strip() for k in CONTEXT})
    return request_record(
        sample_id=f'{NAME}:{element.get("id")}', source=NAME,
        method=(child_text(element, 'method') or '').strip(),
        request_target=uri + ('?' + query if query else ''),
        http_version=(child_text(element, 'protocol') or '').strip() or None,
        headers=headers, body=child_text(element, 'body') or '', label=label,
        label_name=kind, attack_types=[TYPES[kind]] if label else [], meta=meta)


def samples(path):
    with zipfile.ZipFile(path) as archive:
        name = next(n for n in archive.namelist() if n.endswith('.xml'))
        with archive.open(name) as raw:
            for _, element in ET.iterparse(io.BufferedReader(raw), events=('end',)):
                if local(element.tag) == 'sample':
                    yield element
                    element.clear()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--raw', default=ROOT)
    parser.add_argument('--root', default='data/processed')
    args = parser.parse_args(argv)
    path = find_files(args.raw, 'learning_dataset_xml.zip')[0]
    notes = ['meta.attack_spans: [part, start, end), 0-based, end-exclusive, into the record',
             'out-of-context attacks are labeled 1; meta.in_context keeps the flag']
    with Output(NAME, 'requests.jsonl.gz', __file__, [path], args.root, notes) as out:
        for element in samples(path):
            out.read()
            try:
                out.write(parse_sample(element))
            except (KeyError, ValueError):
                out.skip('unparsed_sample')


if __name__ == '__main__':
    main()
