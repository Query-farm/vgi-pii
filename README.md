<p align="center">
  <img src="https://raw.githubusercontent.com/Query-farm/vgi/main/docs/vgi-logo.png" alt="Vector Gateway Interface (VGI)" width="320">
</p>

<p align="center"><em>A <a href="https://query.farm">Query.Farm</a> VGI worker for DuckDB.</em></p>

# vgi-pii

[![CI](https://github.com/Query-farm/vgi-pii/actions/workflows/ci.yml/badge.svg)](https://github.com/Query-farm/vgi-pii/actions/workflows/ci.yml)

A [VGI](https://query.farm) worker that brings **PII detection and redaction**
into DuckDB/SQL. It finds and removes personally-identifiable information —
names, emails, phone numbers, credit cards, SSNs, locations, and more — from
free text, as plain SQL functions, backed by
[Microsoft Presidio](https://microsoft.github.io/presidio/) (analyzer +
anonymizer) and a pinned [spaCy](https://spacy.io/) model.

```sql
INSTALL vgi FROM community; LOAD vgi;
ATTACH 'pii' (TYPE vgi, LOCATION 'uv run pii_worker.py');

SELECT pii.has_pii('Call John Smith at john@example.com');     -- true
SELECT pii.redact('Call John Smith at john@example.com');      -- 'Call <PERSON> at <EMAIL_ADDRESS>'
SELECT pii.anonymize('Call John Smith at john@example.com');   -- 'Call **** at ****************'
SELECT pii.pii_types('Call John Smith at john@example.com');   -- ['EMAIL_ADDRESS', 'PERSON']
SELECT * FROM pii.detect_pii('Call John Smith at john@example.com');
SELECT * FROM pii.supported_entities() ORDER BY entity_type;
```

The Presidio analyzer is wired to the **`en_core_web_sm`** spaCy pipeline
(~12 MB, MIT), pinned as a wheel dependency. Everything runs **offline** — no
network calls at query time — and the model loads **once per worker process**
and is amortised over every row of every query.

## Scalars (per-row) vs. table functions

The split follows what the VGI SDK allows for each function shape:

* **Scalars** take **positional** arguments only and resolve overloads by
  *arity* (DuckDB's `name := value` syntax is a table-function/macro feature, not
  a scalar one). Every per-row answer is a **scalar**, so it works inline in any
  projection or predicate. The optional `language` argument is an extra
  positional **arity overload**:

  ```sql
  SELECT has_pii(body)             FROM messages;   -- language defaults to 'en'
  SELECT has_pii(body, 'en')       FROM messages;   -- explicit language
  SELECT id, redact(body)          FROM messages;
  SELECT body, anonymize(body)     FROM messages;
  SELECT pii_types(body)           FROM messages;   -- VARCHAR[]
  ```

* **Table functions** return *many* rows and **do** take `name := value` args:
  `detect_pii(text, language := 'en', score_threshold := 0.5)` (one row per
  detected entity) and `supported_entities(language := 'en')` (discovery).

  ```sql
  SELECT * FROM pii.detect_pii('Email john@example.com', score_threshold := 0.8);
  SELECT * FROM pii.supported_entities() ORDER BY entity_type;
  ```

**NULL semantics.** A NULL (or empty / whitespace-only) input yields NULL output
for every scalar, and **no rows** for `detect_pii`. Text with no detected PII is
returned **unchanged** by `redact` / `anonymize`. Nothing raises on odd input —
detection of a problematic row degrades to "no PII" rather than crashing the
worker.

## Function catalog

| Function | Form | Signature | Returns |
| --- | --- | --- | --- |
| `has_pii` | scalar | `(text[, language])` | `BOOLEAN` (NULL if no text) |
| `redact` | scalar | `(text[, language])` | `VARCHAR` — entities → `<TYPE>` tags |
| `anonymize` | scalar | `(text[, language])` | `VARCHAR` — entities → `*` mask |
| `pii_types` | scalar | `(text[, language])` | `VARCHAR[]` — distinct entity types, sorted |
| `detect_pii` | table | `(text, language := 'en', score_threshold := 0.5)` | `(entity_type VARCHAR, text VARCHAR, start INT, end_pos INT, score DOUBLE)` |
| `supported_entities` | table | `(language := 'en')` | `(entity_type VARCHAR)` |

The `language` default is `'en'`. `detect_pii.score_threshold` (and the
threshold used by all scalars) defaults to `0.5` — detections below that
confidence are dropped.

### Detection

Presidio combines a spaCy NER model with a battery of pattern/context
recognizers (email, phone, credit card, IBAN, SSN, URL, IP, crypto, dates, …).
`detect_pii` returns one row per detected entity with its character offsets
(`start` inclusive, `end_pos` exclusive — `end_pos` is suffixed because `end` is
a SQL keyword) and confidence `score`. Use `supported_entities()` to discover
every type the analyzer can return.

### Redaction vs. anonymization

`redact` and `anonymize` are two **distinct anonymizer operators** over the same
detections:

* `redact` uses Presidio's default *replace* operator, swapping each entity for
  a `<ENTITY_TYPE>` tag (`<PERSON>`, `<EMAIL_ADDRESS>`, …) — readable, preserves
  *what kind* of value was there.
* `anonymize` uses the *mask* operator, overwriting every character of each
  entity with `*` — preserves nothing about the value.

```sql
SELECT id,
       redact(body)     AS tagged,
       anonymize(body)  AS masked
FROM   messages
WHERE  has_pii(body);
```

## Dependencies & licensing

This worker is **MIT**. Native / model dependencies:

| Component | License | Notes |
| --- | --- | --- |
| `vgi-pii` (this worker) | **MIT** | This repository's own code. |
| [`presidio-analyzer`](https://pypi.org/project/presidio-analyzer/) | **MIT** | PII detection. |
| [`presidio-anonymizer`](https://pypi.org/project/presidio-anonymizer/) | **MIT** | Redaction / masking operators. |
| [`spaCy`](https://spacy.io/) | **MIT** | NLP runtime. |
| [`en_core_web_sm`](https://github.com/explosion/spacy-models) | **MIT** | The pinned English spaCy pipeline (model weights). |
| [`vgi-python`](https://github.com/Query-farm/vgi-python) | Query Farm Source-Available | The VGI SDK. |

> **spaCy model licensing.** The pinned `en_core_web_sm` model is **MIT**. Other
> spaCy models vary — many `_sm`/`_lg` English models are MIT, while some
> non-English pipelines are **CC-BY-SA** (their training corpora carry that
> license). If you swap the pinned model (see `engine.SPACY_MODEL`), check that
> model's license for your use.

Detection is only as complete as Presidio's recognizers + the spaCy model;
consult the [Presidio docs](https://microsoft.github.io/presidio/) for the
supported-entity matrix and accuracy caveats. PII detection is **probabilistic**
— treat it as a strong filter, not a guarantee of complete removal.

## Local development

```sh
uv sync --all-extras     # .venv with vgi-python + presidio + spaCy + en_core_web_sm + dev tools
make test                # pytest (unit + integration) + SQL end-to-end
make test-unit           # pytest only
make test-sql            # DuckDB sqllogictest files via haybarn-unittest
uv run ruff check .      # lint
uv run mypy vgi_pii/
```

`tests/test_engine.py` covers the pure Presidio logic (multiple PII types, none,
empty, NULL, unicode, very long text, threshold behaviour); `tests/test_tables.py`
drives `detect_pii` / `supported_entities` through the real bind→init→process
lifecycle in-process; `tests/test_scalars.py` spawns `pii_worker.py` over the VGI
client/RPC stack exactly as DuckDB would after `ATTACH`. The `test/sql/*.test`
files are DuckDB sqllogictest cases run by
[`haybarn-unittest`](https://pypi.org/project/haybarn-unittest/)
(`uv tool install haybarn-unittest`) against a real `ATTACH` + `SELECT`.

## Layout

```
pii_worker.py            entry point; assembles the `pii` catalog (inline uv script metadata); warms Presidio at startup
Makefile                 test / test-unit / test-sql / lint targets
vgi_pii/
  engine.py              pure Presidio lifecycle + logic (analyzer/anonymizer cached per-process; no Arrow/VGI)
  scalars.py             per-row scalars (arity overloads for the optional `language`)
  tables.py              table functions: detect_pii, supported_entities
  schema_utils.py        Arrow field/comment helper
tests/
  harness.py             in-process bind→init→process driver
  test_engine.py         pure-logic unit + edge tests
  test_tables.py         table-function integration tests
  test_scalars.py        per-row scalar overloads via vgi.client.Client
test/sql/
  *.test                 DuckDB sqllogictest end-to-end cases (haybarn-unittest)
```

---

## Authorship & License

Written by [Query.Farm](https://query.farm).

Copyright 2026 Query Farm LLC - https://query.farm

