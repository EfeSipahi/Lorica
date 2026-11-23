"""Converters, merge and overlap check, run on small hand-made copies of each raw format."""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

import convert_csic  # noqa: E402
import convert_ecml  # noqa: E402
import convert_gotestwaf  # noqa: E402
import convert_httpparams  # noqa: E402
import convert_modsec_learn  # noqa: E402
import convert_openappsec_legit  # noqa: E402
import convert_openappsec_malicious  # noqa: E402
import merge_attack_values  # noqa: E402
import overlap_check  # noqa: E402
from common import read_jsonl, request_record, value_record  # noqa: E402
from extract_values import extract  # noqa: E402

CSIC_TEXT = (
    'GET http://localhost:8080/tienda1/a.jsp?id=2&nombre=Jam%F3n HTTP/1.1\n'
    'User-Agent: Mozilla/5.0\nHost: localhost:8080\nCookie: JSESSIONID=AB\n'
    'Connection: close\n\n\n'
    'POST http://localhost:8080/tienda1/a.jsp HTTP/1.1\n'
    'User-Agent: Mozilla/5.0\nContent-Type: application/x-www-form-urlencoded\n'
    'Content-Length: 21\n\nid=2&cantidad=%27+or\n\n\n'
)

ECML_XML = '''<?xml version="1.0"?><dataset>
<sample id="1"><reqContext><os>UNIX</os><webserver>APACHE</webserver></reqContext>
<class><type>Valid</type><inContext>TRUE</inContext></class>
<request><method>GET</method><protocol>HTTP/1.1</protocol><uri><![CDATA[/a]]></uri>
<query><![CDATA[b=1]]></query><headers><![CDATA[Host: x
User-Agent: y]]></headers><body></body></request></sample>
<sample id="2"><class><type>SqlInjection</type><inContext>TRUE</inContext>
<attackIntervall>query:7-17</attackIntervall></class>
<request><method>GET</method><uri><![CDATA[/a]]></uri>
<query><![CDATA[b=1&c=%27or+1%3D1&d=2]]></query><headers><![CDATA[Host: x]]></headers>
<body></body></request></sample>
<sample id="3"><class><type>OsCommanding</type><inContext>FALSE</inContext>
<attackIntervall>uri</attackIntervall><attackIntervall>query</attackIntervall></class>
<request><method>GET</method><uri><![CDATA[/scripts/cmd.exe]]></uri>
<query><![CDATA[/c+dir]]></query><headers></headers><body></body></request></sample>
</dataset>'''


def quiet(function, *args):
    with contextlib.redirect_stdout(io.StringIO()):
        return function(*args)


class ConverterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.raw = os.path.join(self.tmp.name, 'raw')
        self.out = os.path.join(self.tmp.name, 'processed')
        os.makedirs(self.raw)

    def tearDown(self):
        self.tmp.cleanup()

    def path(self, *parts):
        path = os.path.join(self.raw, *parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return path

    def rows(self, name, data_file):
        return list(read_jsonl(os.path.join(self.out, name, data_file)))

    def manifest(self, name):
        with open(os.path.join(self.out, name, 'manifest.json'), encoding='utf-8') as f:
            return json.load(f)

    def test_openappsec_legit(self):
        zpath = self.path('legitimate.zip')
        with zipfile.ZipFile(zpath, 'w') as z:
            for site in ('a', 'b', 'c'):
                z.writestr(f'legitimate/{site}.json', json.dumps([
                    {'method': 'get', 'url': '/x?q=1', 'headers': {'Host': site},
                     'data': ''},
                    {'method': 'POST', 'url': 'https://h/y', 'headers': {},
                     'data': {'k': 1}}]))
        quiet(convert_openappsec_legit.main,
              ['--zip', zpath, '--root', self.out, '--sites', '2', '--seed', '1'])
        rows = self.rows('openappsec-legit', 'requests.jsonl.gz')
        self.assertEqual(len(rows), 4)
        self.assertEqual(len({r['group'] for r in rows}), 2)
        self.assertEqual(rows[0]['method'], 'GET')
        self.assertEqual(rows[1]['request_target'], '/y')
        self.assertEqual(rows[1]['body'], '{"k": 1}')
        self.assertEqual(self.manifest('openappsec-legit')['counts'], {'read': 4, 'written': 4})

    def test_openappsec_malicious_pairs(self):
        zpath = self.path('malicious.zip')
        records = [
            {'method': 'GET', 'url': '/?p=%27+or+1%3D1', 'headers': {}, 'data': ''},
            {'method': 'GET', 'url': '/?p=abc', 'headers': {}, 'data': ''},
            {'method': 'POST', 'url': '/', 'headers': {}, 'data': 'p=%27+or+1%3D1'},
            {'method': 'POST', 'url': '/', 'headers': {}, 'data': 'p=xyz'},
        ]
        with zipfile.ZipFile(zpath, 'w') as z:
            z.writestr('Malicious/sqli.json', json.dumps(records))
        convert_openappsec_malicious.main(['--zip', zpath, '--root', self.out])
        rows = self.rows('openappsec-malicious', 'values.jsonl.gz')
        self.assertEqual([(r['value'], r['attack_type']) for r in rows], [("' or 1=1", 'sqli')])
        self.assertEqual(self.manifest('openappsec-malicious')['skipped'],
                         {'pair_mismatch_or_shape': 1})

    def test_modsec_learn(self):
        with open(self.path('sqlmap', 'sqli_parsed.json'), 'w') as f:
            json.dump(['p=%27+or+1%3D1', 'p=', 'q=1'], f)
        convert_modsec_learn.main(['--raw', self.raw, '--root', self.out])
        rows = self.rows('modsec-learn', 'values.jsonl.gz')
        self.assertEqual([r['value'] for r in rows], ["' or 1=1"])

    def test_httpparams(self):
        with open(self.path('payload_full.csv'), 'w', newline='') as f:
            f.write('"payload","length","attack_type","label"\r\n'
                    '"campello, el","12","norm","norm"\r\n'
                    '"-5"" union select 1--","20","sqli","anom"\r\n'
                    '"+|+dir+c:"",10,cmdi,anom $+|+dir+c:""","35","cmdi","anom"\r\n')
        convert_httpparams.main(['--raw', self.raw, '--root', self.out])
        rows = self.rows('httpparams', 'values.jsonl.gz')
        self.assertEqual([r['value'] for r in rows], ['-5" union select 1--'])
        self.assertEqual(self.manifest('httpparams')['skipped'],
                         {'merged_csv_row': 1, 'norm_row_from_csic': 1})

    def test_gotestwaf(self):
        with open(self.path('owasp', 'xss-scripting.yml'), 'w') as f:
            f.write('payload:\n  - "<b>x</b>"\n  - "\\\'-alert(1)//"\nencoder:\n  - URL\n'
                    'placeholder:\n  - URLParam\ntype: XSS\n')
        with open(self.path('false-pos', 'texts.yml'), 'w') as f:
            f.write('payload:\n  - union was a great select\nencoder:\n  - URL\n'
                    'placeholder:\n  - HTMLForm\n')
        with open(self.path('community', 'community-8kb-xss.yml'), 'w') as f:
            f.write('payload:\n  - "AAAA"\nencoder:\n  - URL\nplaceholder:\n  - URLParam\n'
                    'type: 8KB XSS\n')
        with open(self.path('community', 'community-rce-rawrequests.yml'), 'w') as f:
            f.write('payload:\n  - "cmd=cat /etc/passwd"\nencoder:\n  - Plain\nplaceholder:\n'
                    '  - RawRequest:\n      method: "POST"\n      body: "{{payload}}"\n'
                    'type: "RawRequest test"\n')
        convert_gotestwaf.main(['--raw', self.raw, '--root', self.out])
        rows = {r['value']: r for r in self.rows('gotestwaf', 'values.jsonl.gz')}
        self.assertEqual(rows["'-alert(1)//"]['attack_type'], 'xss')
        self.assertEqual(rows['union was a great select']['label'], 0)
        self.assertTrue(rows['cmd=cat /etc/passwd']['meta']['raw_request'])
        self.assertNotIn('AAAA', rows)
        manifest = self.manifest('gotestwaf')
        self.assertEqual(manifest['skipped'], {'padding_file': 1})
        self.assertTrue(any('xss-scripting.yml' in n for n in manifest['notes']))

    def test_csic(self):
        for name in convert_csic.FILES:
            with open(self.path(name), 'w', encoding='latin-1') as f:
                f.write(CSIC_TEXT)
        convert_csic.main(['--raw', self.raw, '--root', self.out])
        rows = self.rows('csic-2010', 'requests.jsonl.gz')
        self.assertEqual(len(rows), 6)
        get, post = rows[4], rows[5]
        self.assertEqual((get['label'], get['request_target'], get['body']),
                         (1, '/tienda1/a.jsp?id=2&nombre=Jam%F3n', ''))
        self.assertEqual(post['body'], 'id=2&cantidad=%27+or')
        self.assertEqual(post['headers'][1], ['Content-Type', 'application/x-www-form-urlencoded'])
        self.assertEqual(extract(get)[2]['value'], 'Jamón')

    def test_ecml_spans_hit_one_value(self):
        with zipfile.ZipFile(self.path('x', 'learning_dataset_xml.zip'), 'w') as z:
            z.writestr('learning_dataset.xml', ECML_XML)
        convert_ecml.main(['--raw', self.raw, '--root', self.out])
        rows = self.rows('ecml-pkdd-2007', 'requests.jsonl.gz')
        self.assertEqual([r['label'] for r in rows], [0, 1, 1])
        self.assertEqual(rows[1]['attack_types'], ['sqli'])
        span = rows[1]['meta']['attack_spans'][0]
        hits = [v for v in extract(rows[1]) if v['span'] == span]
        self.assertEqual([(v['name'], v['value']) for v in hits], [('c', "'or 1=1")])
        self.assertEqual(rows[2]['meta']['attack_spans'], [['target', 0, 16],
                                                           ['target', 17, 23]])
        self.assertFalse(rows[2]['meta']['in_context'])


class MergeAndOverlapTests(unittest.TestCase):
    def test_merge_then_overlap(self):
        with tempfile.TemporaryDirectory() as root:
            def write(name, data_file, records):
                os.makedirs(os.path.join(root, name))
                import gzip
                with gzip.open(os.path.join(root, name, data_file), 'wt') as f:
                    for r in records:
                        f.write(json.dumps(r) + '\n')

            write('openappsec-malicious', 'values.jsonl.gz', [
                value_record('a:1', 'openappsec-malicious', 'f', "' or 1=1", 1, 'sqli'),
                value_record('a:2', 'openappsec-malicious', 'f', 'select x', 1, 'sqli')])
            write('modsec-learn', 'values.jsonl.gz', [
                value_record('m:1', 'modsec-learn', 'f', "' or 1=1", 1, 'sqli')])
            write('httpparams', 'values.jsonl.gz', [])
            write('gotestwaf', 'values.jsonl.gz', [
                value_record('g:1', 'gotestwaf', 'f', 'select x', 0, None),
                value_record('g:2', 'gotestwaf', 'f', '<b>', 1, 'xss')])
            quiet(merge_attack_values.main, ['--root', root])
            merged = list(read_jsonl(os.path.join(root, 'attack-values', 'values.jsonl.gz')))
            self.assertEqual([(r['value'], r['meta']['sources']) for r in merged],
                             [("' or 1=1", ['openappsec-malicious', 'modsec-learn']),
                              ('<b>', ['gotestwaf'])])
            legit = request_record('l:1', 'openappsec-legit', 'GET', '/a?q=1', [], '', 0,
                                   'normal')
            write('openappsec-legit', 'requests.jsonl.gz', [legit])
            write('csic-2010', 'requests.jsonl.gz', [
                request_record('c:1', 'csic-2010', 'GET', "/t?x=%27+or+1%3D1", [], '', 1, 'a')])
            write('ecml-pkdd-2007', 'requests.jsonl.gz', [
                request_record('e:1', 'ecml', 'GET', '/a?q=1', [], '', 0, 'Valid')])
            quiet(overlap_check.main, ['--root', root])
            excluded = list(read_jsonl(os.path.join(root, 'overlap', 'excluded.jsonl.gz')))
            self.assertEqual([(e['id'], e['reason']) for e in excluded],
                             [('a:1', 'attack_value_in_csic-2010'),
                              ('l:1', 'legit_request_in_ecml-pkdd-2007')])


if __name__ == '__main__':
    unittest.main()
