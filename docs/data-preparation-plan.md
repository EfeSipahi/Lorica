# Data preparation plan: one common format

Goal: convert every dataset in `data/raw/` into the record types defined in
[common-format.md](common-format.md), and split every request into the fields that the
application reads. Later steps (injecting attacks, feature extraction, training,
cross-dataset testing) then read one format instead of thirteen.

Training data comes first, as the project brief assigns it: open-appsec normal requests and
the six attack-value sources. Test sets follow in step 8.

This plan makes data decisions only. It does not choose the model, its features, its
hyperparameters, its threshold, the train/test split or which fields the model uses.

## Rules

- `data/raw/` is never modified.
- A converter changes the format only. Dropping, deduplicating and relabeling happen in their
  own steps, and each of those reports what it removed and why.
- Every output folder holds a `manifest.json`: script name and hash, input files and their
  hashes, records read, written and skipped (with reasons), and counts per label and type.
- New behaviour goes in new scripts. Recorded experiments in `archive/` depend on the hashes of
  `extract_features.py` and the training scripts, so those are not edited.
- Outputs go under `data/processed/common/` and are git-ignored, because of size and because
  several sources have no license. Manifests are committed, so anyone can check that their
  rebuilt files match.
- Scripts must also run on a small machine: 7 GB RAM, 4 cores, about 16 GB free disk. Large
  inputs are streamed, never loaded whole.

## Steps

| # | Step | Output | Status |
|---|---|---|---|
| 1 | Define the common format | `docs/common-format.md` | Done |
| 2 | Shared helpers: record builders, validator, manifest writer, `.gitignore` rules, tests | `scripts/common_format.py`, `tests/test_common_format.py` | |
| 3 | Convert open-appsec legitimate (normal requests) | `common/openappsec-legit-v1/` | |
| 4 | Split request records into field records. Run it on open-appsec first, then on each test set after step 8 | `common/<source>-fields-v1/` | |
| 5 | Convert the attack-value sources, one at a time (5a–5f below) | `common/<source>-v1/` | |
| 6 | Merge attack values: exact deduplication across sources, label conflicts, counts | `common/attack-values-v1/` | |
| 7 | Hand review: random sample per source and type; fix mappings; label the two unlabeled SecLists files | review notes in `docs/` | |
| 8 | Convert test sets to the request format: CSIC, SR-BH (+ X-WAD), ECML/PKDD, ModSec-WP, ATRDF, 30-day ModSecurity logs | `common/<source>-v1/` | |
| 9 | Overlap check: remove training values, requests and fields that also appear in any test set | report + filtered files | |

Folder paths in the table are relative to `data/processed/`.

## What each step has to handle

### Step 3: open-appsec legitimate

- 692 JSON files, one per site, about 1.04M requests, 7.3 GB unpacked. The largest file is
  734 MB, so the JSON array is read incrementally, straight from the zip.
- Each record is `{method, url, headers, data}`. `url` becomes `request_target` (checked to be
  relative), the `headers` object becomes a list of pairs, `data` becomes `body`.
- `group` is the file name without `.json` (one site per file). Label 0.
- Output is gzip-compressed JSONL.
- The manifest reports per-site counts, methods, how many requests have a query or body, body
  kinds (empty, form, JSON, other) and the exact-duplicate count. Duplicates are counted, not
  removed.

### Step 4: split requests into fields

The field format, the list of locations and the decoding rules are in
[common-format.md](common-format.md#field-records). Decisions taken on 24 November 2026:

- The request record stays as it is. Field records are a separate output, so the split rules
  can change without converting the raw data again, and the injection step still has the full
  request.
- One field for each input the application reads: the path, each query parameter, each form
  parameter, each JSON leaf value, each cookie pair and each header.
- The path is one field. It is not split at `/`, because `../../etc/passwd` must stay together.
- The Referer is parsed like a request URL: its host, its path and each of its query
  parameters become separate fields. A Referer that is not a URL (`' OR 1=1--`) becomes one
  field.
- A URL inside a parameter value (`redirect_to=https://site.com/?a=1`) stays one field.
- Every header becomes a field, `Host` included. Which header fields the model uses is a
  training decision. Two options are planned for comparison:
  - Option A: only `User-Agent`, `Referer` and `Cookie`, as in the project brief.
  - Option B: all headers except fixed browser headers (`Host`, `Content-Length`,
    `Connection`, `Accept`, `Accept-Encoding`, `Accept-Language`, `sec-ch-*`, `sec-fetch-*`, …).
- Each value is decoded one time, as a server does. Repeated decoding, and counting the
  layers, belong to feature extraction.
- Parameter, cookie and header names are kept for reports. They are never model inputs.
- Field labels: 0 for every field of a normal request; 1 for an injected field; `null` when the
  source does not show where the attack is.
- Empty values are skipped and counted.
- Size: about 1.04M open-appsec requests with 10–20 headers each give roughly 20 million field
  records. Output is gzip-compressed. Duplicates (the same `User-Agent` in many requests) are
  counted here and handled when training data is sampled.

Known limits of field-level detection. These go into the final report:

- A format error with no attack text (letters in a phone-number field, as in some CSIC
  "anomalous" requests) cannot be seen without the parameter name.
- An attack split across two or more fields can look normal in each field.
- Each field is one more chance for a false alarm. With 0.1% false alarms per field, a
  request with 20 fields has about 2%. The threshold is therefore set per request.
- Attacks inside names (NoSQL `user[$ne]=1`, a JSON key `$ne`) are not seen while names are
  not model inputs. The splitter keeps the names, so a later experiment can test this.

### Step 5: attack values

| Step | Source | Records | What to handle |
|---|---|---|---|
| 5a | open-appsec malicious | 73,924 | Each payload is sent twice, as `GET /?p=…` and as a POST body `p=…`. Keep one value per pair after checking both copies match. Form-decode once (`+` is a space). Type from file name: cmdexe, log4shell, shellshock, sqli, traversal, xss, xxe |
| 5b | modsec-learn | 19,623 | Every value is `p=<form-encoded>`; form-decode once. All SQLi |
| 5c | HttpParams | 31,067 rows | Keep the 11,763 `anom` rows (sqli 10,852, xss 532, path-traversal 290, cmdi 89). Drop the 19,304 `norm` rows: they were copied from CSIC, which is a test set |
| 5d | GoTestWAF | ~170 payloads + 47 benign texts | YAML. `false-pos/texts.yml` gives label 0. Three files (`owasp-api/rest.yml`, `owasp-api/soap.yml`, `owasp/xss-scripting.yml`) fail strict YAML parsing on `\'`; fix with one documented replacement and count it. Keep `encoder` and `placeholder` in `meta`. Flag the `RawRequest` cases, which hold whole `name=value` bodies |
| 5e | SecLists | ~70 files | One value per line, type from folder or file name. `big-list-of-naughty-strings.txt` and `fuzz-Bo0oM.txt` get `label: null` until step 7. Lists of bare file paths (`LFI-etc-files-of-all-linux-packages.txt`, `Windows-Paths.txt`) are flagged for review: a path is only an attack in the right parameter |
| 5f | PayloadsAllTheThings | ~37k lines | v1 reads only the `Intruder/` and `Intruders/` lists. The `.md` code blocks are skipped because they mix payloads with shell commands, code and prose. `dotdotpwn.txt` alone has 21,144 lines |

Line-based sources (SecLists, PayloadsAllTheThings) keep each line as it is, apart from the
line ending. Empty lines are skipped and counted. Lines starting with `#` are kept, since `#`
is part of many payloads; step 7 checks for real comment lines.

### Step 6: merge

- Deduplication key: the exact `value` string. The first occurrence is kept and every source
  that had it is listed in `meta.sources`.
- A value labeled 0 in one source and 1 in another is excluded and listed in the report.
- The report shows counts per type and per source, and the value-length distribution.
- Path traversal will dominate (dotdotpwn 21k, open-appsec traversal 14k). Type balance is
  handled when training data is sampled, not here.

### Step 8: test sets

Order: CSIC (the parser exists), SR-BH, ECML/PKDD, ModSec-WP (needs `openpyxl`), ATRDF (needs
`7z`, installed), 30-day ModSecurity logs. The field mappings are in
[the research report](../reports/HTTP%20request%20datasets%20for%20IDS.md), section "Most
conversions take one script".

After each conversion, run the step 4 splitter on it. Where the source shows the attack
position (ECML/PKDD `attackIntervall`, the ModSecurity logs' `found within ARGS:…`), set the
matching field's label to 1.

### Step 9: overlap check

Needs step 8. Hash every training value, request and field, look each one up in every test
set, and remove matches from training. HttpParams is the main suspect because it was built
partly from CSIC.

## After this plan

Injecting attack values into fields of normal requests, selecting the header fields (option A
or B above), feature extraction and training. See the project brief and the research report.
