# Inspect PII spans before interpreting redaction

[Open the executed notebook](01_thresholds_spans_and_redaction.ipynb).

[![Open in Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Query-farm/vgi-pii/blob/main/notebooks/01_thresholds_spans_and_redaction.ipynb)

The notebook chooses a contact-category review scope from the worker’s reference
catalog, detects overlapping spans in invented English prose, counts their union
in SQL and compares a configurable detection threshold with fixed-threshold
redaction scalars. Its two SVG charts show span boundaries and cutoff sensitivity.

In Colab choose **Runtime → Run all**. Shared setup installs only the base package,
retaining compatible preloaded pandas, Matplotlib and kernel libraries. Inference
runs locally in a separate Python 3.13 worker environment. No API key, real personal
record, worker checkout or SQL engine build is needed. If an earlier setup damaged
the kernel dependencies, save work, choose **Runtime → Disconnect and delete runtime**,
reconnect and run the updated notebook.

## Run locally

From this directory, with [uv](https://docs.astral.sh/uv/) installed:

```sh
uv sync --locked
uv run --locked vgi-notebooks --timeout 300
uv run --locked vgi-notebooks --timeout 300 --parameters '{"SCORE_THRESHOLD":0.9}' --output-dir artifacts/threshold-09
```

The worker release is **v0.4.0** and the required English model is
**en_core_web_sm 3.8.0**. The release lists that model only in its development
extra, so the visible `uvx` command supplies this one model wheel explicitly;
there are no transitive dependency overrides. Initial downloads need network access;
subsequent text analysis is local. These packages belong to the worker process,
not the notebook kernel. Model/version changes can alter detections, boundaries
and scores: rerun both default and experiment when upgrading.

The local notebook lock adds the `[runner]` extra of
[vgi-example-notebooks v0.3.4](https://github.com/Query-farm/vgi-example-notebooks), while
Colab uses only its base package. The shared package owns the
[standard](https://github.com/Query-farm/vgi-example-notebooks/blob/v0.3.4/docs/standard.md),
runner, canonical branding and SVG presentation. Defaults are saved only after
successful execution; overrides require a separate destination. Native SVG output
is accompanied by content-addressed `charts/` image links for GitHub. Review PNGs,
logs and experiment copies are ignored. No copied standard or custom runner remains.

Optional kernel registration:

```sh
uv run --locked python -m ipykernel install --user --name pii-examples --display-name 'Python (PII examples)'
```

## Analytical choices and limits

`entity_types` and `supported_entities(language := 'en')` establish that the
installed recognizers support PERSON, EMAIL_ADDRESS, PHONE_NUMBER and URL. The
detailed span analysis uses that contact-category intersection. The scalar examples
continue to use all default recognizers. Catalog support means a recognizer exists;
it does not guarantee that it will find every instance.

All input text is invented. The [provenance record](fixtures/provenance.json) retains
its hash and purpose; a notebook assertion verifies the visible SQL literal against
that hash without requiring the companion text file. There are no observed capture
timestamps, service calls or real personal records. SQL materializes each worker
response before DataFrame display, so captures cannot repeat worker calls.

Offsets are zero-based characters with exclusive end positions. SQL expands each
interval and counts distinct character positions, avoiding double-counting nested
URL/email findings. Recognizer scores are not calibrated probabilities. Filtering
a materialized candidate set creates the cutoff curve; an independent worker call
verifies the selected threshold. Returned labels and boundaries are model outputs,
not truth labels or a measured detection accuracy.

Change only `SCORE_THRESHOLD` from **0.5 to 0.9**, then restart and run all. Compare
retained spans and unique character coverage. The per-row `has_pii`, `pii_types`,
`redact` and `anonymize` functions keep their fixed 0.5 cutoff, so their outputs
should remain unchanged. A stricter detector review cutoff is not a stricter redactor.
The function called `anonymize` masks accepted spans; retained structure and length
mean its name does not establish irreversible anonymity.

NULL/empty inputs produce NULL scalar outputs; a clean synthetic control is returned
unchanged. For arbitrary text, unchanged output can mean no accepted finding **or**
an analyzer error: this worker catches errors and degrades to empty detections or
unchanged text. The positive synthetic example catches a failed model startup but
does not certify other inputs. Shared SQL setup starts with an empty temporary
secret directory and persistent secrets disabled.

## Coverage and verification

[coverage.json](coverage.json) maps all **seven named public SQL surfaces** to
visible executed queries, results, interpretation and hash-bound execution receipts.
Full native function/table/view exports are retained under `coverage/`; overloaded
scalar signatures count once. Both v0.4.0 and the current public source baseline
have six function names plus the `entity_types` table. No object is excluded.
Current interface compatibility is reviewed separately from release execution.

The saved default and detached threshold-0.9 experiment pass **14 SQL checks**
plus the provenance hash assertion. The detached run starts with an empty worker
uv cache and only the notebook file: no helper, fixture or source checkout is
needed. Raising the cutoff selects **4→1 spans** and covers **50→16 of 121
characters**; the fixed-threshold scalar outputs and catalog scope are byte-identical.
All four chart previews were inspected. Three runner guards and an invalid-threshold
check preserve the default and reject invalid input before worker attachment.

A fresh Python 3.12 kernel preloads pandas 2.2.3, Matplotlib 3.10.0, IPython 8.30.0,
ipykernel 6.17.1 and jupyter-client 7.4.9 before the base-only bootstrap. The complete
notebook executes, retains those versions and passes `pip check`; the local runner
package is not installed in that kernel. A hosted Colab UI session has not been
manually exercised.

Source checks pass 42 pytest tests, 70 SQL assertions across four cases, Ruff,
formatting, mypy and CI-isolated pydoclint. Executed metadata validation reports
100/100, assurance L2 and zero findings. Worker code and root dependencies remain
unchanged. The current public baseline is
`b74d21e37ac8953d1a897af7b9f36e6b67a8a142`; its post-release changes add metadata
examples and documentation, while the actual named SQL catalog matches v0.4.0.
