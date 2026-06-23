# CI: the vgi-pii worker integration suite

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs the unit tests
and this repo's sqllogictest suite (`test/sql/*.test`) against the vgi-pii
VGI worker through the **real DuckDB `vgi` extension** on every push / PR.

## How it works (no C++ build)

Rather than building the vgi DuckDB extension from source, CI drives a
**prebuilt** standalone `haybarn-unittest` (the DuckDB/Haybarn sqllogictest
runner, published in Haybarn's releases) and installs the **signed** `vgi`
extension from the Haybarn community channel:

1. **Install the worker** — `uv sync --frozen` into a venv. `pii_worker.py`
   is a self-contained PEP 723 stdio worker the extension can spawn via
   `uv run pii_worker.py`; its inline deps pin the spaCy `en_core_web_sm`
   model wheel (~12 MB, MIT) that Presidio's analyzer is wired to, so no model
   is downloaded at the worker's first use. The workflow additionally runs
   `python -m spacy download en_core_web_sm` before the suite so the model is
   resolvable regardless of how the subprocess env is provisioned.
2. **Download the runner** — the matching `haybarn_unittest-*` asset per
   platform from the latest Haybarn release.
3. **Preprocess** — the standalone runner links none of the extensions the
   tests gate on, so [`preprocess-require.awk`](preprocess-require.awk) rewrites
   each `require <ext>` into an explicit signed `INSTALL <ext> FROM
   {community,core}; LOAD <ext>;`. These tests skip `require vgi` (haybarn
   silently SKIPs it) and `LOAD vgi;` directly, so the awk also injects an
   `INSTALL vgi FROM community;` right before each bare `LOAD vgi;`. `require-env`
   and everything else pass through untouched.
4. **Run** — [`run-integration.sh`](run-integration.sh) stages the preprocessed
   tree, points `VGI_PII_WORKER` at `uv run pii_worker.py`, warms the
   extension cache once, then runs the suite in a single `haybarn-unittest`
   invocation. Any failed assertion exits non-zero and fails the job.

## Run it locally

```bash
uv sync --python 3.13                       # install the worker + deps (model via dev extra)
# point HAYBARN_UNITTEST at a haybarn-unittest binary (or a local DuckDB
# `unittest` built with the vgi extension), and the worker at the stdio command:
HAYBARN_UNITTEST=/path/to/haybarn-unittest \
VGI_PII_WORKER="uv run --python 3.13 pii_worker.py" \
  ci/run-integration.sh
```

Or use the Makefile target `make test-sql`, which installs `haybarn-unittest`
as a uv tool and points the worker at `uv run --python 3.13 pii_worker.py`.
