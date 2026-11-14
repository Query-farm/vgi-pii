# PII SQL notebooks

[What does a stricter PII threshold actually remove?](01_thresholds_spans_and_redaction.ipynb) inspects overlapping detection spans, computes distinct character coverage in SQL, and distinguishes a configurable detector threshold from the worker's fixed-threshold redaction scalars.

## Run from this directory

Install [uv](https://docs.astral.sh/uv/) and Git. The notebook environment uses Python 3.13 or 3.14; the separate worker explicitly uses Python 3.13 for its spaCy dependencies. First use needs network access to install dependencies, the published Haybarn/VGI extension, the pinned Git revision and the English model wheel. Inference is local. Copying this entire directory is sufficient; no worker checkout or local build is needed.

```bash
uv sync --frozen
uv run --frozen python execute.py
```

Visible SQL launches the exact Git revision `1536e17f93fc19576c52f2f6f126ae7a80c569d2` with `uvx`, SDK 0.51.0 / RPC 0.53.1, Presidio analyzer/anonymizer 2.2.366, spaCy 3.8.18 and the explicit `en_core_web_sm` 3.8.0 wheel. These pins match the tested worker lock. The wheel is supplied explicitly because the source package lists the model in its development extra. The notebook environment independently pins Haybarn 2.0.0rc11. After changing any worker, model or engine pin, rerun both the default and the experiment.

For interactive use, register this environment and select it in Jupyter:

```bash
uv run --frozen python -m ipykernel install --user --name vgi-pii-notebooks --display-name 'Python (vgi-pii notebooks)'
```

Restart and run all after editing `SCORE_THRESHOLD`. Setup, plotting, interpretation source and cleanup are folded; parameters and SQL remain visible. The runner uses a temporary kernel and this directory as cwd. It saves only after success, rejects unknown parameters, and requires a separate destination for overrides.

## One focused experiment

```bash
uv run --frozen python execute.py --parameters '{"SCORE_THRESHOLD":0.9}' --output-dir validation/threshold-09
```

The default threshold is 0.5. Raising it to 0.9 reduces the selected detections and their unique coverage. It does not configure the per-row `redact`, `anonymize`, `has_pii` or `pii_types` functions: their threshold remains 0.5. Compare the detector outputs and the unchanged tagged/masked scalar outputs, then restore 0.5.

The input is entirely synthetic English prose with invented names and contacts; [provenance](fixtures/provenance.json) records its byte hash and purpose. There are no real personal records, observed event timestamps, or service calls. The committed text asset is checked against the visible SQL literal.

## Interpretation and checks

Offsets are zero-based characters with an exclusive end. SQL expands intervals and counts distinct character positions, avoiding double-counting nested findings. Recognizer scores are not calibrated probabilities. The sensitivity curve filters a single materialized candidate response; a separate actual worker call verifies the selected cutoff. Entity labels and span boundaries are model outputs, not ground truth. A masked result can retain structure and length and does not prove irreversible anonymity.

Twelve SQL invariants cover offsets, catalog membership, score filtering, coverage, monotonicity and scalar NULL/control behavior. The text-provenance check is separate. The known positive example helps catch a failed model startup, but this worker can degrade analyzer errors to unchanged text or empty detections. An unchanged result must not be interpreted as a guarantee that text contains no PII.

Source validation: 42 pytest tests; 70 stdio, 78 HTTP and 70 Unix SQL assertions; Ruff/format, mypy, isolated pydoclint, and metadata quality 100/L2 with zero findings. The saved default outputs are embedded in the notebook. Review charts, logs and experiment copies are ignored under `validation/`; the runner copies fixtures, assets and runtime companions with experiments. [STANDARD.md](STANDARD.md) records presentation conventions.
