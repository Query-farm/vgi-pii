# Changelog

## 0.5.0 (2026-11-25)

- Speaks VGI protocol 3.4: require vgi-python `>=0.55.2,<0.56`; uv.lock re-locked. This release
  needs Haybarn 2.0.1 (or stock DuckDB 2.0 with `INSTALL vgi FROM query_farm`): Haybarn 2.0.0
  loads a 3.3 `vgi` extension that cannot attach it.
- SQL tests run on haybarn-unittest 2.0.1rc3.
- `serve` extra is `vgi-python[http,oauth]`; the Docker image installs it, so the image runs in
  Orchard hosted mode (`VGI_ORCHARD_HOSTED=1` with VGI_JWT_ISSUER, VGI_JWT_AUDIENCE,
  VGI_JWT_JWKS_URI and VGI_SIGNING_KEY). The HEALTHCHECK uses `HEAD /health`, which stays
  anonymous in hosted mode.

## 0.4.3 (2026-11-16)

- Bump vgi-python to 0.52.2.
- Requires Python 3.14 (CI, Docker image and tooling moved to 3.14).

## 0.4.2 — 2026-11-15

### Fixed

- The worker now detects PII when installed the way the README says
  (`uvx --from git+https://github.com/Query-farm/vgi-pii@<tag> vgi-pii-worker`).
  The `en_core_web_sm` spaCy model was pinned through `[tool.uv.sources]`, which
  `uvx --from git+...` and pip ignore, so the model was never installed. Presidio
  then tried to download it at runtime: the worker either exited during ATTACH
  (no pip or uv on PATH) or returned no entity types and detected nothing. The
  model is now a direct-URL `[project]` dependency, so every installer picks it up.
- If the model is missing anyway, detection raises a `ModelNotInstalledError`
  that says how to install it, instead of silently returning empty results.
  The worker never downloads a model at runtime.

## 0.4.1

Earlier releases are listed on the GitHub releases page.
