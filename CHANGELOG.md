# Changelog

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
