# TUNA branch roadmap

23 November 2026

TUNA builds a working per-value model end to end first, on a few sources, then adds data and
improves the model. The group plan prepared all 13 datasets before any model. TUNA reaches a first
scored test set in phase 4 instead of after 8 data steps. Nothing is committed or pushed without
the owner's word.

## Keep or change

Most of the value extraction design (Claude Doc "Value extraction and per-value labels") carries
over, because it rests on facts checked in the data. What changes is the order of work and the
size of the first data set.

| Topic | From the group docs | TUNA |
|---|---|---|
| What a value is | Section 1 table, names not scored, the agreed header list | Keep |
| Decoding | Decode once, extra passes at feature time | Keep |
| Value record | Section 3 fields | Keep, minus `meta` fields no script reads yet |
| Test labels | ECML intervals, CRS matches when visible, request level elsewhere | Keep |
| Injection and swap control | Sections 5 and 6 | Keep, plus an artifact probe (phase 3) |
| Split rules | Site and payload groups never cross splits | Keep |
| Overlap check | Step 8, after all test sets | Move earlier: run it on each source as it is added |
| Data preparation | All 13 datasets converted, then reviewed, before any model | Start with 5 attack sources and part of open-appsec; add the rest after a baseline exists |
| Hand review | Step 6, before training | Only for sources added in phase 7 (SecLists, PayloadsAllTheThings) |
| Manifests | Full manifest per source | Keep, shorter: script hash, input hashes, counts |
| Metric | F1 | Detection rate at a 1% request-level false-alarm rate; F1 and ROC AUC beside it |
| ATRDF, Fwaf | In the plan | ATRDF at the end of phase 5; Fwaf dropped |

## Decisions

- Main metric: detection rate at a 1% request-level false-alarm rate.
- The archive experiment is not used for comparison.
- Cookies are scored; training samples them down so they do not swamp other values.
- CSIC stays a test set. One diagnostic run in phase 5 adds CSIC's normal training file to
  training, to tell domain shift apart from a weak model.
- This file is the branch's plan.

## Roadmap

Each phase ends with a check, and the next phase starts after the owner has seen it.

| # | Phase | Output | Done when |
|---|---|---|---|
| 0 | Branch setup | `scripts/`, `tests/` on TUNA; this file as `docs/roadmap.md` | Folders exist; `archive/` untouched |
| 1 | Value extractor | `scripts/extract_values.py` + tests built from hand-made requests and real ECML samples | Tests pass; on 1,000 open-appsec and 1,000 CSIC requests, every value's `raw` equals its `span` slice |
| 2 | First data | Converters for open-appsec legitimate (about 150 sites to start), open-appsec malicious, modsec-learn, HttpParams attacks, GoTestWAF; test converters for CSIC and ECML; dedup and overlap check against those two test sets | Manifests written; counts per source and type reported; overlaps removed and listed |
| 3 | Injection and swap set | `scripts/inject.py`: attack and swap requests, split by site and payload group | Artifact probe: a model that sees only non-content features (value length, location, encoding style, slot added) cannot tell swapped requests from untouched ones (ROC AUC under 0.6) |
| 4 | Baseline model | Character 1-5 grams with hashing, plus location, into a linear model (SGD logistic regression); request score = highest value score | Scores on CSIC (request level) and ECML (value level), plus the swap gap |
| 5 | Full test suite | Converters and labels for the 30-day ModSecurity logs, ModSec-WP, SR-BH (original and X-WAD labels), then ATRDF | One report: detection at 1% false alarms per test set, per attack type and per location; plus the CSIC diagnostic run |
| 6 | Better models | Hand features (special characters, entropy, decode depth) with HistGradientBoosting; a small character CNN only if CPU time allows | Beats the baseline on validation; test sets used once per model, never for tuning |
| 7 | More attack data | SecLists and PayloadsAllTheThings with hand review of a sample per type; retrain the best model | Per-type detection does not drop on any test set |
| 8 | Write-up | Results report in `docs/` | Owner approves it |

Machine: 7 GB RAM, 4 cores. Everything streams; phase 2 uses about 15% of open-appsec so a full
run stays under an hour (estimate).
