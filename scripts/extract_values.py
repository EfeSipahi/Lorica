"""Split HTTP requests into the values the model scores.

A request record (common format: method, request_target, headers, body) becomes a list of
value records. Each value is decoded once, the way the server decodes it; its raw text and
its position in the request are kept, so labels that point at raw positions or names
(ECML/PKDD intervals, ModSecurity variables) can be mapped onto values later.

Usage:
    python scripts/extract_values.py IN.jsonl[.gz] OUT.jsonl[.gz]

Standard library only.
"""

import argparse
import collections
import gzip
import json
import re
import sys

# Headers that carry protocol data, not application input. Every other header is scored.
# Cookie is split into its own values. Names are compared in lower case.
PROTOCOL_HEADERS = {
    'host', 'content-length', 'content-type', 'connection', 'cache-control', 'pragma',
    'upgrade-insecure-requests', 'origin', 'cookie',
}
PROTOCOL_PREFIXES = ('accept', 'sec-', 'if-')

ESCAPE_RUN = re.compile(r'(?:%[0-9A-Fa-f]{2})+')
INVALID_ESCAPE = re.compile(r'%(?![0-9A-Fa-f]{2})')
BOUNDARY = re.compile(r'boundary=(?:"([^"]+)"|([^;\s]+))', re.IGNORECASE)
DISPOSITION_PARAM = re.compile(r';\s*([A-Za-z*]+)="([^"]*)"')
FORM_TOKEN = re.compile(r'[^=&\s]+=[^\s]*')


def percent_decode(text, plus_is_space=False):
    """Decode %XX escapes once. Returns (decoded, flags).

    Each run of escapes is read as UTF-8; a run that is not valid UTF-8 is read as Latin-1
    and flagged. Literal characters are never re-encoded, so text read as Latin-1 upstream
    (CSIC) stays intact. Invalid escapes such as %zz stay as they are and are flagged.
    """
    flags = set()
    if plus_is_space:
        text = text.replace('+', ' ')
    if INVALID_ESCAPE.search(text):
        flags.add('invalid-escape')

    def run(match):
        data = bytes.fromhex(match.group(0).replace('%', ''))
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            flags.add('latin1')
            return data.decode('latin-1')

    return ESCAPE_RUN.sub(run, text), flags


def header_scored(name):
    low = name.lower()
    return low not in PROTOCOL_HEADERS and not low.startswith(PROTOCOL_PREFIXES)


def header_values(headers, wanted):
    return [value for name, value in headers if name.lower() == wanted]


def split_tokens(text, separator):
    """Yield (token, start) for each non-empty token, with its offset in text."""
    start = 0
    for token in text.split(separator):
        if token:
            yield token, start
        start += len(token) + 1


def sniff_body(body, headers):
    """Return the body kind: none, form, json, multipart or raw (plus a flag or None)."""
    if body == '':
        return 'none', None
    content_types = ' '.join(header_values(headers, 'content-type')).lower()
    if 'multipart/form-data' in content_types and multipart_boundary(body, headers):
        return 'multipart', None
    stripped = body.strip()
    if stripped[:1] in '{[':
        try:
            json.loads(stripped)
            return 'json', None
        except ValueError:
            return 'raw', 'invalid-json'
    if 'application/x-www-form-urlencoded' in content_types:
        return 'form', None
    tokens = [t for t in stripped.split('&') if t]
    if tokens and all(FORM_TOKEN.fullmatch(t) for t in tokens):
        return 'form', None
    return 'raw', None


def multipart_boundary(body, headers):
    for value in header_values(headers, 'content-type'):
        match = BOUNDARY.search(value)
        if match:
            boundary = match.group(1) or match.group(2)
            if '--' + boundary in body:
                return boundary
    return None


class Extractor:
    def __init__(self, request):
        self.request = request
        self.values = []
        self.stats = collections.Counter()

    def add(self, location, name, raw, span, decoded=None, flags=()):
        value = raw if decoded is None else decoded
        if value == '':
            self.stats['skipped_empty'] += 1
            return
        self.values.append(dict(
            sample_id=self.request.get('sample_id'),
            value_index=len(self.values),
            location=location,
            name=name,
            value=value,
            raw=raw,
            span=span,
            flags=sorted(flags),
        ))

    def pairs(self, text, part, offset, location, separator='&', plus_is_space=True):
        """Split name=value pairs; spans point at the value's raw text."""
        bare_location = 'query-bare' if location == 'query' else location
        for token, start in split_tokens(text, separator):
            start += offset
            if location == 'cookie':
                stripped = token.lstrip()
                start += len(token) - len(stripped)
                token = stripped.rstrip()
            if '=' in token:
                name, raw = token.split('=', 1)
                value_start = start + len(name) + 1
                decoded_name, _ = percent_decode(name, plus_is_space)
                decoded, flags = percent_decode(raw, plus_is_space)
                self.add(location, decoded_name, raw, [part, value_start, value_start + len(raw)],
                         decoded, flags)
            else:
                decoded, flags = percent_decode(token, plus_is_space)
                self.add(bare_location, None, token, [part, start, start + len(token)], decoded,
                         flags | ({'bare'} if location != 'query' else set()))

    def target(self):
        target = self.request.get('request_target') or ''
        qpos = target.find('?')
        path = target if qpos < 0 else target[:qpos]
        decoded, flags = percent_decode(path)
        self.add('path', None, path, ['target', 0, len(path)], decoded, flags)
        if qpos >= 0:
            self.pairs(target[qpos + 1:], 'target', qpos + 1, 'query')

    def body(self):
        body = self.request.get('body') or ''
        headers = self.request.get('headers') or []
        kind, flag = sniff_body(body, headers)
        self.stats['body_' + kind] += 1
        if kind == 'form':
            self.pairs(body, 'body', 0, 'body-form')
        elif kind == 'json':
            self.json_leaves(json.loads(body.strip()), '')
        elif kind == 'multipart':
            self.multipart(body, multipart_boundary(body, headers))
        elif kind == 'raw':
            self.add('body-raw', None, body, ['body', 0, len(body)],
                     flags={flag} if flag else ())

    def json_leaves(self, node, path):
        if isinstance(node, dict):
            for key, child in node.items():
                self.json_leaves(child, f'{path}.{key}' if path else str(key))
        elif isinstance(node, list):
            for i, child in enumerate(node):
                self.json_leaves(child, f'{path}[{i}]')
        elif node is None:
            self.stats['skipped_empty'] += 1
        else:
            text = node if isinstance(node, str) else json.dumps(node)
            # No raw text or span for JSON leaves in v1 (see docs/roadmap.md, phase 1).
            self.add('body-json', path or None, None, None, decoded=text)

    def multipart(self, body, boundary):
        delimiter = '--' + boundary
        pos = body.find(delimiter)
        while pos >= 0:
            start = pos + len(delimiter)
            if body.startswith('--', start):
                break  # closing delimiter
            nxt = body.find(delimiter, start)
            end = len(body) if nxt < 0 else nxt
            self.multipart_part(body, start, end)
            pos = nxt

    def multipart_part(self, body, start, end):
        part = body[start:end]
        split = re.search(r'\r?\n\r?\n', part)
        if not split:
            return
        head = part[:split.start()]
        params = {}
        for line in re.split(r'\r?\n', head):
            if line.lower().startswith('content-disposition:'):
                params = {k.lower(): v for k, v in DISPOSITION_PARAM.findall(line)}
        name = params.get('name')
        if 'filename' in params:
            filename = params['filename']
            at = body.find('filename="', start, start + split.start()) + len('filename="')
            self.add('body-multipart', name, filename, ['body', at, at + len(filename)],
                     flags={'filename'})
            return
        content_start = start + split.end()
        content = body[content_start:end]
        trimmed = re.sub(r'\r?\n$', '', content)
        self.add('body-multipart', name, trimmed,
                 ['body', content_start, content_start + len(trimmed)])

    def header_fields(self):
        headers = self.request.get('headers') or []
        for name, value in headers:
            if name.lower() == 'cookie':
                self.pairs(value, f'header:{name}', 0, 'cookie', separator=';')
        for name, value in headers:
            if header_scored(name):
                self.add('header', name, value, [f'header:{name}', 0, len(value)])

    def run(self):
        self.target()
        self.body()
        self.header_fields()
        return self.values


def extract(request, stats=None):
    """Return the value records of one request record. Adds counts to stats if given."""
    extractor = Extractor(request)
    values = extractor.run()
    if stats is not None:
        stats.update(extractor.stats)
        stats['requests'] += 1
        stats['values'] += len(values)
        stats.update('location_' + v['location'] for v in values)
    return values


def part_text(request, part):
    """The text a span's part refers to."""
    if part == 'target':
        return request.get('request_target') or ''
    if part == 'body':
        return request.get('body') or ''
    name = part.split(':', 1)[1]
    for header, value in request.get('headers') or []:
        if header == name:
            return value
    raise KeyError(part)


def open_text(path, mode):
    if str(path).endswith('.gz'):
        return gzip.open(path, mode + 't', encoding='utf-8')
    return open(path, mode, encoding='utf-8')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('input', help='requests.jsonl or requests.jsonl.gz')
    parser.add_argument('output', help='values.jsonl or values.jsonl.gz')
    args = parser.parse_args(argv)
    stats = collections.Counter()
    with open_text(args.input, 'r') as src, open_text(args.output, 'w') as dst:
        for line in src:
            if not line.strip():
                continue
            request = json.loads(line)
            for value in extract(request, stats):
                value.update(label=None, label_source='request-only', attack_type=None,
                             request_label=request.get('label'))
                dst.write(json.dumps(value, ensure_ascii=False) + '\n')
    json.dump(dict(sorted(stats.items())), sys.stdout, indent=2)
    print()


if __name__ == '__main__':
    main()
