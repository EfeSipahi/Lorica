# Data preparation plan: one common format

Goal: convert every dataset in `data/raw/` into one of the two record types defined in
[common-format.md](common-format.md). Later steps (splitting requests into values, injecting
attacks, training, cross-dataset testing) then read one format instead of thirteen.

Training data comes first, as the project brief assigns it: open-appsec normal requests and
the six attack-value sources. Test sets follow in step 7.

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
- Scripts must run on this machine: 7 GB RAM, 4 cores, about 16 GB free disk. Large inputs
  are streamed, never loaded whole.

## Steps

| # | Step | Output | Status |
|---|---|---|---|
| 1 | Define the common format | `docs/common-format.md` | Done, waiting for review |
| 2 | Shared helpers: record builders, validator, manifest writer, `.gitignore` rules, tests | `scripts/common_format.py`, `tests/test_common_format.py` | |
| 3 | Convert open-appsec legitimate (normal requests) | `common/openappsec-legit-v1/` | |
| 4 | Convert the attack-value sources, one at a time (4a–4f below) | `common/<source>-v1/` | |
| 5 | Merge attack values: exact deduplication across sources, label conflicts, counts | `common/attack-values-v1/` | |
| 6 | Hand review: random sample per source and type; fix mappings; label the two unlabeled SecLists files | review notes in `docs/` | |
| 7 | Convert test sets to the request format: CSIC, SR-BH (+ X-WAD), ECML/PKDD, ModSec-WP, ATRDF, 30-day ModSecurity logs | `common/<source>-v1/` | |
| 8 | Overlap check: remove training values and requests that also appear in any test set | report + filtered files | |

Folder paths in the table are relative to `data/processed/`.

## What each conversion has to handle

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

### Step 4: attack values

| Step | Source | Records | What to handle |
|---|---|---|---|
| 4a | open-appsec malicious | 73,924 | Each payload is sent twice, as `GET /?p=…` and as a POST body `p=…`. Keep one value per pair after checking both copies match. Form-decode once (`+` is a space). Type from file name: cmdexe, log4shell, shellshock, sqli, traversal, xss, xxe |
| 4b | modsec-learn | 19,623 | Every value is `p=<form-encoded>`; form-decode once. All SQLi |
| 4c | HttpParams | 31,067 rows | Keep the 11,763 `anom` rows (sqli 10,852, xss 532, path-traversal 290, cmdi 89). Drop the 19,304 `norm` rows: they were copied from CSIC, which is a test set |
| 4d | GoTestWAF | ~170 payloads + 47 benign texts | YAML. `false-pos/texts.yml` gives label 0. Three files (`owasp-api/rest.yml`, `owasp-api/soap.yml`, `owasp/xss-scripting.yml`) fail strict YAML parsing on `\'`; fix with one documented replacement and count it. Keep `encoder` and `placeholder` in `meta`. Flag the `RawRequest` cases, which hold whole `name=value` bodies |
| 4e | SecLists | ~70 files | One value per line, type from folder or file name. `big-list-of-naughty-strings.txt` and `fuzz-Bo0oM.txt` get `label: null` until step 6. Lists of bare file paths (`LFI-etc-files-of-all-linux-packages.txt`, `Windows-Paths.txt`) are flagged for review: a path is only an attack in the right parameter |
| 4f | PayloadsAllTheThings | ~37k lines | v1 reads only the `Intruder/` and `Intruders/` lists. The `.md` code blocks are skipped because they mix payloads with shell commands, code and prose. `dotdotpwn.txt` alone has 21,144 lines |

Line-based sources (SecLists, PayloadsAllTheThings) keep each line as it is, apart from the
line ending. Empty lines are skipped and counted. Lines starting with `#` are kept, since `#`
is part of many payloads; step 6 checks for real comment lines.

### Step 5: merge

- Deduplication key: the exact `value` string. The first occurrence is kept and every source
  that had it is listed in `meta.sources`.
- A value labeled 0 in one source and 1 in another is excluded and listed in the report.
- The report shows counts per type and per source, and the value-length distribution.
- Path traversal will dominate (dotdotpwn 21k, open-appsec traversal 14k). Type balance is
  handled when training data is sampled, not here.

### Step 7: test sets

Order: CSIC (the parser exists), SR-BH, ECML/PKDD, ModSec-WP (needs `openpyxl`), ATRDF (needs
`7z`, installed), 30-day ModSecurity logs. The field mappings are in
[the research report](../reports/HTTP%20request%20datasets%20for%20IDS.md), section "Most
conversions take one script".

### Step 8: overlap check

Needs step 7. Hash every training value and request, look each one up in every test set, and
remove matches from training. HttpParams is the main suspect because it was built partly from
CSIC.

## After this plan

Splitting requests into values, injecting attack values into normal requests, and training.
See the project brief and the research report.
