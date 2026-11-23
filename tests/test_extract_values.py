import collections
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from extract_values import extract, main, part_text, percent_decode, sniff_body  # noqa: E402


def request(target='/', body='', headers=(), method='GET', sample_id='t:1'):
    return dict(sample_id=sample_id, method=method, request_target=target,
                headers=[list(h) for h in headers], body=body, label=0)


def by_location(values, location):
    return [v for v in values if v['location'] == location]


class DecodingTests(unittest.TestCase):
    def test_once_only(self):
        self.assertEqual(percent_decode('%2527')[0], '%27')

    def test_plus_rule(self):
        self.assertEqual(percent_decode('a+b', plus_is_space=True)[0], 'a b')
        self.assertEqual(percent_decode('a+b')[0], 'a+b')

    def test_utf8_and_latin1_fallback(self):
        self.assertEqual(percent_decode('%C3%A9'), ('é', set()))
        self.assertEqual(percent_decode('arca%EDsta'), ('arcaísta', {'latin1'}))

    def test_literal_non_ascii_kept(self):
        self.assertEqual(percent_decode('Jamón%20x')[0], 'Jamón x')

    def test_invalid_escape_kept_and_flagged(self):
        self.assertEqual(percent_decode('100%zz%'), ('100%zz%', {'invalid-escape'}))


class TargetTests(unittest.TestCase):
    def test_path_is_one_value_without_plus_rule(self):
        values = extract(request('/a/../b+c/%2e%2e/etc'))
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0]['location'], 'path')
        self.assertEqual(values[0]['value'], '/a/../b+c/../etc')
        self.assertEqual(values[0]['span'], ['target', 0, 20])

    def test_query_pairs_repeated_and_spans(self):
        req = request('/s?q=a+b&q=%27x&n=')
        values = by_location(extract(req), 'query')
        self.assertEqual([(v['name'], v['value']) for v in values], [('q', 'a b'), ('q', "'x")])
        for v in values:
            _, start, end = v['span']
            self.assertEqual(req['request_target'][start:end], v['raw'])

    def test_empty_values_counted_not_kept(self):
        stats = collections.Counter()
        values = extract(request('/s?n=&m=1&&'), stats)
        self.assertEqual([v['name'] for v in by_location(values, 'query')], ['m'])
        self.assertEqual(stats['skipped_empty'], 1)

    def test_bare_query_token(self):
        values = by_location(extract(request('/?<script>alert(1)</script>&a=1')), 'query-bare')
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0]['value'], '<script>alert(1)</script>')
        self.assertIsNone(values[0]['name'])

    def test_whole_query_bare(self):
        values = extract(request('/scripts/..%c0%2f../winnt/system32/cmd.exe?/c+dir'))
        self.assertEqual(values[1]['location'], 'query-bare')
        self.assertEqual(values[1]['value'], '/c dir')
        self.assertEqual(values[1]['span'], ['target', 43, 49])


class BodyTests(unittest.TestCase):
    def test_form_body(self):
        req = request('/login', 'user=ali&pass=a%26b+c', method='POST',
                      headers=[('Content-Type', 'application/x-www-form-urlencoded')])
        values = by_location(extract(req), 'body-form')
        self.assertEqual([(v['name'], v['value']) for v in values],
                         [('user', 'ali'), ('pass', 'a&b c')])
        self.assertEqual(req['body'][values[1]['span'][1]:values[1]['span'][2]], 'a%26b+c')

    def test_form_sniffed_without_content_type(self):
        self.assertEqual(sniff_body('a=1&b=2', [])[0], 'form')

    def test_json_sent_as_text_plain(self):
        req = request('/api', '{"user": {"tags": ["x", 2, null]}, "ok": true, "s": ""}',
                      method='POST', headers=[('Content-Type', 'text/plain;charset=UTF-8')])
        stats = collections.Counter()
        values = by_location(extract(req, stats), 'body-json')
        self.assertEqual([(v['name'], v['value']) for v in values],
                         [('user.tags[0]', 'x'), ('user.tags[1]', '2'), ('ok', 'true')])
        self.assertIsNone(values[0]['span'])
        self.assertEqual(stats['skipped_empty'], 2)

    def test_root_array_json(self):
        values = extract(request('/', '[{"a": "b"}]', method='POST'))
        self.assertEqual(values[1]['name'], '[0].a')

    def test_broken_json_is_raw(self):
        values = extract(request('/', '{"a": ', method='POST'))
        self.assertEqual(values[1]['location'], 'body-raw')
        self.assertEqual(values[1]['flags'], ['invalid-json'])

    def test_xml_is_raw_and_not_decoded(self):
        body = '<?xml version="1.0"?><a>%41</a>'
        values = extract(request('/', body, method='POST',
                                 headers=[('Content-Type', 'application/xml')]))
        self.assertEqual(values[1]['location'], 'body-raw')
        self.assertEqual(values[1]['value'], body)

    def test_multipart_fields_and_filename(self):
        body = ('--XyZ\r\nContent-Disposition: form-data; name="title"\r\n\r\nhello world\r\n'
                '--XyZ\r\nContent-Disposition: form-data; name="file"; filename="../../a.php"\r\n'
                'Content-Type: application/octet-stream\r\n\r\n<?php system($_GET[c]); ?>\r\n'
                '--XyZ--\r\n')
        req = request('/up', body, method='POST',
                      headers=[('Content-Type', 'multipart/form-data; boundary=XyZ')])
        values = by_location(extract(req), 'body-multipart')
        self.assertEqual([(v['name'], v['value'], v['flags']) for v in values],
                         [('title', 'hello world', []), ('file', '../../a.php', ['filename'])])
        for v in values:
            self.assertEqual(body[v['span'][1]:v['span'][2]], v['raw'])


class HeaderTests(unittest.TestCase):
    def test_cookies_split_and_spans(self):
        cookie = 'a=1; itrbi=%27+or+1%3D1; flag'
        req = request(headers=[('Cookie', cookie)])
        values = by_location(extract(req), 'cookie')
        self.assertEqual([(v['name'], v['value']) for v in values],
                         [('a', '1'), ('itrbi', "' or 1=1"), (None, 'flag')])
        for v in values:
            self.assertEqual(part_text(req, v['span'][0])[v['span'][1]:v['span'][2]], v['raw'])

    def test_scored_headers(self):
        req = request(headers=[('Host', 'x'), ('User-Agent', '() { :; }; echo'),
                               ('Accept-Encoding', 'gzip'), ('Sec-Fetch-Mode', 'cors'),
                               ('Referer', 'http://a/?q=%27'), ('X-Api-Version', '${jndi:x}'),
                               ('If-None-Match', 'abc'), ('Origin', 'http://a')])
        values = by_location(extract(req), 'header')
        self.assertEqual([v['name'] for v in values], ['User-Agent', 'Referer', 'X-Api-Version'])
        self.assertEqual(values[1]['value'], 'http://a/?q=%27')  # headers are not decoded


class EcmlShapeTests(unittest.TestCase):
    """ECML/PKDD marks one value with 1-based inclusive offsets into the raw part."""

    def test_query_interval_is_one_value(self):
        query = 'ab=xy&ts2=%3C%21--%23exec+cmd%3D%22ls%22--%3E&z=1'
        req = request('/p.jsp?' + query)
        lo, hi = query.index('%3C') + 1, query.index('&z') - 1 + 1
        start = len('/p.jsp?') + lo - 1
        matches = [v for v in extract(req) if v['span'] == ['target', start, start + hi - lo + 1]]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['name'], 'ts2')


class CommandLineTests(unittest.TestCase):
    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = os.path.join(tmp, 'r.jsonl'), os.path.join(tmp, 'v.jsonl.gz')
            with open(src, 'w', encoding='utf-8') as f:
                f.write(json.dumps(request('/a?b=c')) + '\n')
            stdout = sys.stdout
            sys.stdout = open(os.devnull, 'w')
            try:
                main([src, dst])
            finally:
                sys.stdout.close()
                sys.stdout = stdout
            import gzip
            with gzip.open(dst, 'rt', encoding='utf-8') as f:
                rows = [json.loads(line) for line in f]
        self.assertEqual([r['location'] for r in rows], ['path', 'query'])
        self.assertEqual(rows[1]['label_source'], 'request-only')
        self.assertEqual(rows[1]['request_label'], 0)


if __name__ == '__main__':
    unittest.main()
