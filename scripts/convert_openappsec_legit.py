"""Convert part of open-appsec legitimate traffic to request records (label 0).

Sites are sampled at random with a fixed seed from the site files under --max-mb
megabytes, so each file can be parsed whole. Each request's group is its site.

Usage: python scripts/convert_openappsec_legit.py [--sites 150] [--seed 2026] [--max-mb 50]
"""

import argparse
import collections
import hashlib
import json
import os
import random
import sys
import zipfile
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Output, request_record  # noqa: E402

ZIP = 'data/raw/open-appsec/legitimate.zip'
NAME = 'openappsec-legit'


def relative_target(url):
    """Path plus query of a URL; absolute URLs are reduced to their path and query."""
    if url.startswith(('http://', 'https://')):
        parts = urlsplit(url)
        return (parts.path or '/') + ('?' + parts.query if parts.query else ''), True
    return url, False


def convert_record(record, site, index):
    target, was_absolute = relative_target(record.get('url') or '')
    body = record.get('data')
    if body is None:
        body = ''
    elif not isinstance(body, str):
        body = json.dumps(body, ensure_ascii=False)
    headers = record.get('headers') or {}
    meta = {'original_target': record.get('url')} if was_absolute else {}
    return request_record(
        sample_id=f'{NAME}:{site}:{index}', source=NAME, group=site,
        method=record.get('method'), request_target=target,
        headers=list(headers.items()), body=body, label=0, label_name='normal', meta=meta)


def choose_sites(archive, count, seed, max_bytes):
    eligible = sorted(i.filename for i in archive.infolist()
                      if i.filename.endswith('.json') and i.file_size < max_bytes)
    chosen = sorted(random.Random(seed).sample(eligible, min(count, len(eligible))))
    return eligible, chosen


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--sites', type=int, default=150)
    parser.add_argument('--seed', type=int, default=2026)
    parser.add_argument('--max-mb', type=int, default=50)
    parser.add_argument('--zip', default=ZIP)
    parser.add_argument('--root', default='data/processed')
    args = parser.parse_args(argv)
    per_site = {}
    seen = set()
    duplicates = 0
    kinds = collections.Counter()
    with zipfile.ZipFile(args.zip) as archive:
        eligible, chosen = choose_sites(archive, args.sites, args.seed, args.max_mb * 1_000_000)
        notes = [f'{len(chosen)} of {len(eligible)} site files under {args.max_mb} MB, '
                 f'random.Random({args.seed}).sample; duplicates are counted, not removed']
        with Output(NAME, 'requests.jsonl.gz', __file__, [args.zip], args.root, notes) as out:
            for filename in chosen:
                site = os.path.basename(filename)[:-len('.json')]
                records = json.loads(archive.read(filename).decode('utf-8'))
                out.read(len(records))
                per_site[site] = 0
                for index, record in enumerate(records):
                    try:
                        request = convert_record(record, site, index)
                    except ValueError:
                        out.skip('malformed')
                        continue
                    key = hashlib.sha1(json.dumps(
                        [request['method'], request['request_target'], request['body'],
                         request['headers']]).encode()).digest()
                    duplicates += key in seen
                    seen.add(key)
                    kinds['with_query'] += '?' in request['request_target']
                    kinds['with_body'] += request['body'] != ''
                    kinds['absolute_url'] += bool(request['meta'])
                    out.write(request)
                    per_site[site] += 1
                del records
            out.extra = dict(sites=per_site, exact_duplicates=duplicates, shape=dict(kinds))
    print(json.dumps(dict(sites=len(per_site), requests=sum(per_site.values()),
                          exact_duplicates=duplicates), indent=2))


if __name__ == '__main__':
    main()
