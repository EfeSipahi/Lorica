# Common format

Every dataset is converted into one of two record types:

- **Request records**: full HTTP requests. Used for open-appsec normal traffic and for every
  test set.
- **Value records**: single strings with no request around them. Used for the attack-payload
  lists (and the few benign "looks like an attack" texts).

There are two types because the payload lists have no request to put them in. Placing them
inside real requests is the injection step, which comes later and is kept separate from
conversion.

A third type, **field records**, is made from request records by the splitter. Each field is
one input of a request (one parameter, one cookie, one header, …).

All types are JSON Lines: one JSON object per line, UTF-8, keys in the order shown below.

## Request records

File: `requests.jsonl`, or `requests.jsonl.gz` for large sources. Field names match
`archive/data/http-mini/requests.jsonl`, so the old extractor (`archive/scripts/extract_features.py`) can also read the new files.

| Field            | Type                    | Meaning                                                                                                                        |
| ---------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `sample_id`      | string                  | `<source>:<file>:<index>`, unique and stable across reruns                                                                     |
| `source`         | string                  | Dataset key, e.g. `openappsec-legit`                                                                                           |
| `group`          | string or null          | Unit that must stay on one side of any split. open-appsec: the site file. Other sources: `null` until a grouping step fills it |
| `method`         | string                  | Upper case                                                                                                                     |
| `request_target` | string                  | Path plus `?query`, no scheme or host. Not percent-decoded                                                                     |
| `http_version`   | string or null          | `null` when the source does not record it                                                                                      |
| `headers`        | list of `[name, value]` | Original order and case; repeated headers kept; may be empty                                                                   |
| `body`           | string                  | As sent, not decoded; `""` when there is none                                                                                  |
| `label`          | 0 or 1                  | 0 normal, 1 attack or anomalous                                                                                                |
| `label_name`     | string                  | The source's own label word (`normal`, `anomalous`, `attack`, a CAPEC name, …)                                                 |
| `attack_types`   | list of strings         | From the vocabulary below; empty for normal requests                                                                           |
| `meta`           | object                  | Source-specific extras (original absolute URL, CAPEC vector, X-WAD flag, …). Never a model input                               |

Notes:

- Absolute targets (CSIC's `http://localhost:8080/...`) are reduced to path and query; the
  original goes in `meta.original_target`.
- Text that is not valid UTF-8 (CSIC) is read as Latin-1, which maps every byte to one
  character and can be reversed. The manifest records which decoding was used.
- Network, timing, session and response fields (IPs, ports, timestamps, status codes) are not
  kept. The model only sees requests.

## Value records

File: `values.jsonl`.

| Field | Type | Meaning |
|---|---|---|
| `value_id` | string | `<source>:<file>:<index>`, unique and stable |
| `source` | string | Dataset key, e.g. `gotestwaf` |
| `source_file` | string | Path inside the dataset folder |
| `value` | string | The payload as it would reach the application, that is after the server's own single URL or form decoding |
| `label` | 1, 0 or null | 1 attack, 0 benign, `null` not yet labeled by hand (never used for training) |
| `attack_type` | string or null | From the vocabulary below; `null` for benign values |
| `meta` | object | The source's own type name, GoTestWAF encoders and placeholders, review flags, … |

Notes:

- Sources that ship values wrapped for transport (`p=%27%20OR...` in open-appsec and
  modsec-learn) are unwrapped and form-decoded exactly once. Payloads that are encoded twice
  on purpose therefore keep their second layer.
- Sources that ship plain strings (HttpParams, GoTestWAF, SecLists, PayloadsAllTheThings) are
  stored as they are, without their line endings.
- Empty values are skipped and counted.

## Field records

File: `fields.jsonl.gz`, in its own folder `<source>-fields-v1/`. The splitter (step 4 of the
[plan](data-preparation-plan.md)) makes them from request records. The model will give a score
to each field; the score of a request is its highest field score.

| Field | Type | Meaning |
|---|---|---|
| `field_id` | string | `<sample_id>#<n>`; `n` is the position of the field in the request, from 0 |
| `sample_id` | string | The request record the field comes from |
| `source` | string | Copied from the request |
| `group` | string or null | Copied from the request |
| `location` | string | Where the field is in the request (table below) |
| `name` | string or null | Parameter, cookie or header name, or the JSON key path. `null` where the location has no name. For reports only, never a model input |
| `raw` | string | The text as it is in the request |
| `value` | string | `raw` after one decode, as a server does it (table below) |
| `label` | 1, 0 or null | 1 attack, 0 normal, `null` not known |
| `request_label` | 0 or 1 | Copy of the request's `label` |
| `meta` | object | Decode notes, e.g. `meta.encoding` when Latin-1 was used |

### Locations

| Location | One field for | Decoding |
|---|---|---|
| `path` | The full path of the request target. Not split at `/`, so `../../etc/passwd` stays together | Percent-decode one time (`+` stays `+`) |
| `query` | Each query parameter | Form-decode one time (`+` is a space) |
| `body-form` | Each parameter of a form body | Form-decode one time |
| `body-json` | Each leaf value of a JSON body; `name` is the key path, e.g. `user.tags[0]` | JSON parse; numbers and booleans as their JSON text |
| `body-raw` | The full body of any other type (multipart, XML, plain text) | None |
| `cookie` | Each `name=value` pair of the `Cookie` header | Percent-decode one time |
| `header` | Each header except `Cookie` and `Referer`, `Host` included | None |
| `referer-host` | The host of a Referer URL | None |
| `referer-path` | The path of a Referer URL | Percent-decode one time |
| `referer-query` | Each query parameter of a Referer URL | Form-decode one time |
| `referer` | The full Referer value when it is not a URL, e.g. `' OR 1=1--` | None |

Rules:

- The body type comes from `Content-Type`. When `Content-Type` is missing, the splitter tries
  JSON, then the form format, and otherwise uses `body-raw`.
- Every header becomes a field. Which header fields the model uses is decided in training,
  not here.
- A URL inside a parameter value (`redirect_to=https://site.com/?a=1`) is one field. It is not
  split again.
- Each occurrence of a repeated header or parameter is its own field. Two Referer headers are
  split separately.
- Empty values are skipped and counted in the manifest. An empty value cannot hold an attack.
- Decoded bytes that are not valid UTF-8 are read as Latin-1, and `meta.encoding` records it.
- Further decoding (repeated URL decoding, HTML entities, …) belongs to feature extraction,
  which also counts the layers.

### Field labels

| Request | `label` of its fields |
|---|---|
| Normal request (label 0) | 0 for every field |
| Normal request with an injected attack value | 1 for the injected field, 0 for the others |
| Attack request; the source does not show the attack position (CSIC, SR-BH, ModSec-WP, ATRDF) | `null` for every field |
| Attack request; the source shows the position (ECML/PKDD `attackIntervall`, ModSecurity logs `found within ARGS:…`) | 1 for the matching field, `null` for the others |

### Example

The request target `/wp-login.php?redirect_to=%2Fwp-admin%2F&id=1&name=efe` gives four
fields: the path and three query parameters. The `redirect_to` field, from an attack request
in a source that does not show the attack position:

```json
{"field_id": "srbh-2020:data_capec_multilabel.csv:48213#1", "sample_id": "srbh-2020:data_capec_multilabel.csv:48213", "source": "srbh-2020", "group": null, "location": "query", "name": "redirect_to", "raw": "%2Fwp-admin%2F", "value": "/wp-admin/", "label": null, "request_label": 1, "meta": {}}
```

## Attack types

The model does not predict the type. Types are used only to report detection rate per attack
type. The list is kept short; each source's own type name stays in `meta.source_type`.

| Type | Covers |
|---|---|
| `sqli` | SQL injection |
| `nosqli` | NoSQL injection |
| `xss` | Cross-site scripting |
| `cmdi` | OS command and server-side code execution, including Shellshock |
| `path-traversal` | Directory traversal and local file inclusion |
| `ssti` | Server-side template injection |
| `ssi` | Server-side includes |
| `xxe` | XML external entities and other XML injection |
| `ldapi` | LDAP injection |
| `xpathi` | XPath injection |
| `crlf` | CRLF and header injection |
| `log4shell` | JNDI lookups (`${jndi:...}`) |
| `ssrf` | Server-side request forgery |
| `open-redirect` | Open redirect |
| `other` | Anything else (mail injection, format strings, API-specific cases) |

## Files in each output folder

```text
data/processed/common/<source>-v1/
├── requests.jsonl(.gz)  or  values.jsonl
└── manifest.json

data/processed/common/<source>-fields-v1/
├── fields.jsonl.gz
└── manifest.json
```

The manifest of a fields folder also counts fields per location and the empty values that were
skipped.

`manifest.json` holds:

- `script`, `script_sha256`: the converter that produced the folder
- `inputs`: each input file with its size and SHA-256
- `counts`: records read, written, and skipped by reason
- `labels`, `attack_types`: counts of the written records
- `decoding`: how text was decoded
- `notes`: anything a reader of the data must know (e.g. the GoTestWAF YAML fix)
- `created_at`

The data files are git-ignored; `manifest.json` is committed.
