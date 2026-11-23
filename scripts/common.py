"""Shared helpers for the converters: record builders, JSONL writers and manifests.

Every converter writes one folder under data/processed/<name>/ holding a data file
(requests.jsonl.gz or values.jsonl.gz) and manifest.json. Data files are git-ignored;
manifests may be committed. Standard library only.
"""

import collections
import datetime
import gzip
import hashlib
import json
import os

PROCESSED = 'data/processed'

ATTACK_TYPES = {
    'sqli', 'nosqli', 'xss', 'cmdi', 'path-traversal', 'ssti', 'ssi', 'xxe', 'ldapi',
    'xpathi', 'crlf', 'log4shell', 'ssrf', 'open-redirect', 'other',
}


def sha256_file(path, chunk=1 << 20):
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(chunk), b''):
            digest.update(block)
    return digest.hexdigest()


def request_record(sample_id, source, method, request_target, headers, body, label,
                   label_name, group=None, http_version=None, attack_types=(), meta=None):
    """A request record in the common format. Raises ValueError on a malformed record."""
    if label not in (0, 1):
        raise ValueError(f'{sample_id}: label must be 0 or 1')
    if not isinstance(request_target, str):
        raise ValueError(f'{sample_id}: request_target must be a string')
    for t in attack_types:
        if t not in ATTACK_TYPES:
            raise ValueError(f'{sample_id}: unknown attack type {t!r}')
    return dict(
        sample_id=sample_id, source=source, group=group, method=(method or '').upper(),
        request_target=request_target, http_version=http_version,
        headers=[[str(n), str(v)] for n, v in headers], body=body or '', label=label,
        label_name=label_name, attack_types=list(attack_types), meta=meta or {},
    )


def value_record(value_id, source, source_file, value, label, attack_type, meta=None):
    """A value record (a payload with no request around it)."""
    if label not in (0, 1, None):
        raise ValueError(f'{value_id}: label must be 0, 1 or None')
    if attack_type is not None and attack_type not in ATTACK_TYPES:
        raise ValueError(f'{value_id}: unknown attack type {attack_type!r}')
    if label == 1 and attack_type is None:
        raise ValueError(f'{value_id}: an attack value needs an attack type')
    return dict(value_id=value_id, source=source, source_file=source_file, value=value,
                label=label, attack_type=attack_type, meta=meta or {})


class Output:
    """Writes one output folder: a gzipped JSONL data file plus manifest.json.

    Use as a context manager. Count skips with skip(reason); the manifest is written on a
    clean exit only, so a failed run never leaves a manifest that looks complete.
    """

    def __init__(self, name, data_file, script, inputs, root=PROCESSED, notes=None):
        self.folder = os.path.join(root, name)
        self.data_path = os.path.join(self.folder, data_file)
        self.script = script
        self.inputs = list(inputs)
        self.notes = list(notes or [])
        self.counts = collections.Counter()
        self.skipped = collections.Counter()
        self.labels = collections.Counter()
        self.types = collections.Counter()
        self.extra = {}

    def __enter__(self):
        os.makedirs(self.folder, exist_ok=True)
        self.tmp_path = self.data_path + '.partial'
        self.file = gzip.open(self.tmp_path, 'wt', encoding='utf-8')
        return self

    def write(self, record):
        self.file.write(json.dumps(record, ensure_ascii=False) + '\n')
        self.counts['written'] += 1
        self.labels[str(record.get('label'))] += 1
        types = record.get('attack_types') or ([record['attack_type']]
                                               if record.get('attack_type') else [])
        self.types.update(types)

    def read(self, n=1):
        self.counts['read'] += n

    def skip(self, reason, n=1):
        self.skipped[reason] += n

    def __exit__(self, exc_type, exc, tb):
        self.file.close()
        if exc_type is not None:
            return False
        os.replace(self.tmp_path, self.data_path)
        manifest = dict(
            script=self.script,
            script_sha256=sha256_file(self.script),
            inputs=[dict(path=p, bytes=os.path.getsize(p), sha256=sha256_file(p))
                    for p in self.inputs],
            output=os.path.basename(self.data_path),
            counts=dict(self.counts),
            skipped=dict(sorted(self.skipped.items())),
            labels=dict(sorted(self.labels.items())),
            attack_types=dict(sorted(self.types.items())),
            notes=self.notes,
            created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
            **self.extra,
        )
        with open(os.path.join(self.folder, 'manifest.json'), 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
            f.write('\n')
        return False


def find_files(root, name):
    """All paths under root whose file name is name, sorted. Raises if there are none."""
    found = sorted(os.path.join(d, f) for d, _, files in os.walk(root) for f in files
                   if f == name)
    if not found:
        raise FileNotFoundError(f'{name} not found under {root}')
    return found


def read_jsonl(path):
    opener = gzip.open if str(path).endswith('.gz') else open
    with opener(path, 'rt', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                yield json.loads(line)
