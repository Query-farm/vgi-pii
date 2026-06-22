# CLAUDE.md — vgi-pii

Contributor/agent notes. User-facing docs live in `README.md`; this is the
"how it's built and where the sharp edges are" companion.

## What this is

A [VGI](https://query.farm) worker that detects **and** redacts PII in free text
— person names, emails, phones, credit cards, SSNs, locations, URLs, … — as
DuckDB scalar functions plus two table functions, backed by
[Microsoft Presidio](https://microsoft.github.io/presidio/) (analyzer +
anonymizer, both MIT) and a pinned `en_core_web_sm` spaCy model (MIT).
`pii_worker.py` assembles every function into one `pii` catalog (single `main`
schema) over stdio, and **warms the Presidio engine at startup**. Sibling
style/tooling to `vgi-conform` / `vgi-calendar` / `vgi-nlp`.

## Layout

```
pii_worker.py      repo-root stdio entry point; PEP 723 inline deps; warms Presidio in run(); main()
vgi_pii/
  engine.py        pure Presidio lifecycle + logic; analyzer/anonymizer cached per-process; no Arrow/VGI; unit-testable
  scalars.py       per-row scalars (arity overload for the optional `language`)
  tables.py        table functions: detect_pii, supported_entities
  schema_utils.py  pa.Field comment / column-doc helper
tests/             pytest: test_engine (pure), test_tables (in-proc), test_scalars (Client RPC)
test/sql/*.test    haybarn-unittest sqllogictest — authoritative E2E
Makefile           test / test-unit / test-sql / lint
```

To add a function: implement the logic in `engine.py` (pure, total — never raises
on garbage; returns `None`/`[]` for "no PII"), wrap it as a scalar or table
function in the matching module, register it in `pii_worker.py`'s catalog lists.

## Scalars vs table functions — THE core convention (read first)

The VGI SDK makes **scalar functions positional-only**: `name := value` named
args are rejected for scalars and only work on table functions. This drives the
function-shape split:

- **Per-row functions are scalars with arity overloads** (`has_pii`, `redact`,
  `anonymize`, `pii_types`). The optional `language` argument is a second
  `ScalarFunction` subclass sharing the `Meta.name`: `redact(text)` (language
  `'en'`) / `redact(text, language)`. Don't build the overload classes from a
  factory: a nested `class Meta:` body can't reference an enclosing-scope
  variable, so each overload is written out explicitly.
- **Set-returning functions are table functions** and *do* take `name := value`:
  `detect_pii(text, language := 'en', score_threshold := 0.5)` and
  `supported_entities(language := 'en')`.
- **`pii_types` returns a `VARCHAR[]`** — a LIST return **requires** an explicit
  `Returns(arrow_type=pa.list_(pa.string()))` or the SDK raises at
  class-definition time.

## Sharp edges (learned the hard way)

1. **Pin the spaCy model; do NOT let Presidio pick.** With no explicit NLP
   config, `AnalyzerEngine()` defaults to `en_core_web_lg` (~400 MB) and tries to
   **download** it on first use. `engine._analyzer()` wires an
   `NlpEngineProvider` to `en_core_web_sm` (~12 MB, installed as a wheel via the
   pyproject `[tool.uv.sources]` + PEP 723 header) so the worker is hermetic and
   light. Change the model in one place: `engine.SPACY_MODEL`.
2. **Warm the engine once, at spawn.** Building the analyzer loads spaCy (~1-2 s),
   lazily. `PiiWorker.run()` calls `engine.warm_up()` before serving so the first
   query of every ATTACH isn't slow — otherwise a worker-pool teardown SIGTERM
   mid-first-query can record a spurious E2E failure. It only fills caches; never
   changes an output; best-effort (never fatal).
3. **`haybarn-unittest` skips `require vgi`.** Under haybarn the extension is not
   autoloaded for `require`, so a `.test` using `require vgi` is silently SKIPPED.
   Every `.test` here uses explicit `statement ok` / `LOAD vgi;` instead.
4. **`UNNEST` only in a FROM subquery under haybarn's DuckDB.** `SELECT
   UNNEST(...)` in a bare projection raises *"UNNEST not supported here"*; wrap it
   as `FROM (SELECT UNNEST(pii_types(...)) AS t)`. See `test/sql/detect.test`.
5. **`end` is a SQL keyword** — `detect_pii`'s exclusive end offset column is
   named **`end_pos`**, not `end`.
6. **PERSON detection depends on the model.** With the small `en_core_web_sm`
   pipeline a bare first name ("John") is often *not* tagged PERSON; a full name
   ("John Smith") reliably is. Fixtures and doc examples use "John Smith" so
   assertions are deterministic. The default `score_threshold` is `0.5`, so
   low-confidence guesses (e.g. a bare `212-555-1234` at ~0.4) are dropped.
7. **NULL vs no-PII vs unchanged.** NULL/empty text → NULL (scalars) / no rows
   (`detect_pii`). Text with **no** detected PII → `redact`/`anonymize` return it
   **unchanged** (not NULL); `has_pii` → `false`; `pii_types` → empty list `[]`.
8. **Never crash a row.** `engine` catches per-call exceptions and degrades to
   "no PII" / unchanged text, so an odd input can't take down the worker.
9. **The unit suite can pass while the RPC path is broken.** `test_engine.py`
   calls pure functions directly; only `test_scalars.py` (real `vgi.client.Client`
   subprocess) and `test/sql/*.test` (real `ATTACH`+`SELECT`) exercise the wire.
   **Run the SQL suite** — it's authoritative.

## Python pin

spaCy ships **cp313** wheels but not cp314 yet, so `.python-version` pins `3.13`
(committed). Without it `uv sync` may pick 3.14 and fail to resolve spaCy.

## Licensing

This worker is **MIT**. Presidio (analyzer + anonymizer), spaCy, and the pinned
`en_core_web_sm` model are all **MIT**. Other spaCy models vary — some
non-English pipelines are **CC-BY-SA**; check before swapping the model. See the
README licensing table.

## Testing

```sh
uv run pytest -q              # unit: pure engine + in-proc tables + Client RPC scalars
make test-sql                 # E2E: haybarn-unittest over test/sql/*  (authoritative)
make test                     # both
uv run ruff check . && uv run mypy vgi_pii/
```

`make test-sql` sets `VGI_PII_WORKER="uv run --python 3.13 pii_worker.py"`, puts
`~/.local/bin` on PATH, and runs `haybarn-unittest --test-dir . "test/sql/*"`.
Install the runner once with `uv tool install haybarn-unittest`. CI
(`.github/workflows/ci.yml`) runs unit + lint + a gated `e2e` job. If `make
test-sql` shows an *intermittent* failure, re-run 2–3× — a loaded host can kill a
worker; only a consistent failure is real.
