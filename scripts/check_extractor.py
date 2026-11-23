"""End-of-phase-1 check for scripts/extract_values.py on real data.

1. open-appsec legitimate: about 1,000 requests read straight from the zip, spread over
   small site files.
2. CSIC 2010: the 1,000 requests already parsed in archive/data/http-mini (read only).
3. ECML/PKDD 2007: every attack's attackIntervall is mapped to a span and compared with
   the extracted values.

For 1 and 2, every value that has a span must have raw == the text at that span. For 3,
each numeric interval should equal exactly one value's span. The script prints counts and
exits with status 1 if any span check fails. It writes nothing.

Usage (from the project root):
    python scripts/check_extractor.py [--openappsec N] [--ecml-limit N]
"""

import argparse
import collections
import io
import json
import os
import sys
import xml.etree.ElementTree as ET
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from extract_values import extract, header_scored, part_text  # noqa: E402

OPENAPPSEC_ZIP = 'data/raw/open-appsec/legitimate.zip'
CSIC_MINI = 'archive/data/http-mini/requests.jsonl'
ECML_ZIP_NAME = 'learning_dataset_xml.zip'
ECML_DIR = 'data/raw/ecml-pkdd-2007'


def check_spans(request, values, problems):
    for value in values:
        if value['span'] is None:
            continue
        part, start, end = value['span']
        if part_text(request, part)[start:end] != value['raw']:
            problems.append((request.get('sample_id'), value['location'], value['name']))


def report(title, stats, problems, requests):
    print(f'\n== {title}')
    print(f'requests: {requests}, values: {stats["values"]}, '
          f'values per request: {stats["values"] / max(requests, 1):.1f}')
    print('by location:', {k[9:]: v for k, v in sorted(stats.items())
                           if k.startswith('location_')})
    print('body kinds:', {k[5:]: v for k, v in sorted(stats.items()) if k.startswith('body_')})
    print('flags:', dict(sorted(stats['flags'].items())) if stats['flags'] else {})
    print('empty values skipped:', stats['skipped_empty'])
    print('span mismatches:', len(problems), problems[:5])


def run_requests(title, requests):
    stats, problems, count = collections.Counter(), [], 0
    stats['flags'] = collections.Counter()
    for request in requests:
        values = extract(request, stats)
        stats['flags'].update(f for v in values for f in v['flags'])
        check_spans(request, values, problems)
        count += 1
    report(title, stats, problems, count)
    return problems


def openappsec_requests(limit):
    with zipfile.ZipFile(OPENAPPSEC_ZIP) as archive:
        files = sorted((i for i in archive.infolist()
                        if i.filename.endswith('.json') and i.file_size < 20_000_000),
                       key=lambda i: i.filename)
        step = max(1, len(files) // 40)
        chosen = files[::step][:40]
        per_file = max(1, limit // len(chosen))
        produced = 0
        for info in chosen:
            records = json.loads(archive.read(info).decode('utf-8'))
            for i, record in enumerate(records[:per_file]):
                if produced >= limit:
                    return
                headers = record.get('headers') or {}
                yield dict(sample_id=f'openappsec-legit:{info.filename}:{i}',
                           method=record.get('method'), request_target=record.get('url') or '',
                           headers=[[k, str(v)] for k, v in headers.items()],
                           body=record.get('data') or '', label=0)
                produced += 1


def csic_requests():
    with open(CSIC_MINI, encoding='utf-8') as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def find_ecml_zip():
    for root, _, files in os.walk(ECML_DIR):
        if ECML_ZIP_NAME in files:
            return os.path.join(root, ECML_ZIP_NAME)
    raise FileNotFoundError(ECML_ZIP_NAME)


def local(tag):
    return tag.rsplit('}', 1)[-1]


def child_text(element, name):
    for child in element.iter():
        if local(child.tag) == name:
            return child.text or ''
    return None


def ecml_samples(limit):
    with zipfile.ZipFile(find_ecml_zip()) as archive:
        name = next(n for n in archive.namelist() if n.endswith('.xml'))
        with archive.open(name) as raw:
            count = 0
            for _, element in ET.iterparse(io.BufferedReader(raw), events=('end',)):
                if local(element.tag) != 'sample':
                    continue
                kind = child_text(element, 'type')
                intervals = [(c.text or '').strip() for c in element.iter()
                             if local(c.tag) == 'attackIntervall']
                uri = child_text(element, 'uri') or ''
                query = child_text(element, 'query') or ''
                headers = []
                for line in (child_text(element, 'headers') or '').splitlines():
                    if ': ' in line:
                        hname, hvalue = line.split(': ', 1)
                        headers.append([hname, hvalue])
                request = dict(sample_id=f'ecml:{element.get("id")}',
                               method=(child_text(element, 'method') or '').strip(),
                               request_target=uri + ('?' + query if query else ''),
                               headers=headers, body=child_text(element, 'body') or '',
                               label=int(kind != 'Valid'))
                element.clear()
                if kind != 'Valid':
                    yield request, uri, query, intervals
                    count += 1
                    if limit and count >= limit:
                        return


def interval_span(interval, uri, query):
    """Map one attackIntervall text to [part, start, end) or a whole-part span."""
    if interval == 'uri':
        return ['target', 0, len(uri)], True
    if interval == 'query':
        return ['target', len(uri) + 1, len(uri) + 1 + len(query)], True
    where, numbers = interval.rsplit(':', 1)
    lo, hi = (int(x) for x in numbers.split('-'))
    if where == 'query':
        offset = len(uri) + 1
        return ['target', offset + lo - 1, offset + hi], False
    if where == 'body':
        return ['body', lo - 1, hi], False
    if where.startswith('headers:'):
        return ['header:' + where.split(':', 1)[1], lo - 1, hi], False
    raise ValueError(interval)


def run_ecml(limit):
    counts = collections.Counter()
    unscored = collections.Counter()
    problems = []
    for request, uri, query, intervals in ecml_samples(limit):
        values = extract(request)
        check_spans(request, values, problems)
        counts['attacks'] += 1
        for interval in intervals:
            try:
                span, whole = interval_span(interval, uri, query)
            except ValueError:
                counts['interval_unparsed'] += 1
                continue
            if whole:
                overlap = [v for v in values if v['span'] and v['span'][0] == span[0]
                           and v['span'][1] < span[2] and v['span'][2] > span[1]]
                counts['whole_part_with_values' if overlap else 'whole_part_no_value'] += 1
                continue
            exact = [v for v in values if v['span'] == span]
            if len(exact) == 1:
                counts['exact_one_value'] += 1
            elif exact:
                counts['exact_several_values'] += 1
            elif span[0].startswith('header:') and span[0] != 'header:Cookie' \
                    and not header_scored(span[0][7:]):
                counts['in_unscored_header'] += 1
                unscored[span[0][7:]] += 1
            else:
                counts['no_matching_value'] += 1
                if len(problems) < 5:
                    print('  no match:', request['sample_id'], interval)
    print('\n== ECML/PKDD attackIntervall mapping')
    print(dict(sorted(counts.items())))
    print('attacks in unscored headers, by header:', dict(unscored.most_common()))
    print('span mismatches:', len(problems), problems[:5])
    return problems, counts['no_matching_value'] + counts['exact_several_values']


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--openappsec', type=int, default=1000)
    parser.add_argument('--ecml-limit', type=int, default=0, help='0 = all attacks')
    args = parser.parse_args(argv)
    failures = len(run_requests('open-appsec legitimate', openappsec_requests(args.openappsec)))
    failures += len(run_requests('CSIC 2010 (archive/data/http-mini)', csic_requests()))
    ecml_problems, unmatched = run_ecml(args.ecml_limit)
    failures += len(ecml_problems)
    print('\nRESULT:', 'PASS' if failures == 0 else f'FAIL ({failures} span mismatches)',
          f'| ECML intervals without exactly one value: {unmatched}')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
