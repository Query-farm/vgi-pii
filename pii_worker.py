# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "vgi-python[http]>=0.16.0",
#     "presidio-analyzer>=2.2",
#     "presidio-anonymizer>=2.2",
#     "spacy>=3.7",
#     "en-core-web-sm",
# ]
#
# [tool.uv.sources]
# en-core-web-sm = { url = "https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl" }
# ///
"""Repo-root PEP 723 shim for the vgi-pii worker.

The worker catalog, :class:`PiiWorker`, and :func:`main` live in the
wheel-importable :mod:`vgi_pii.worker` module (so the built wheel contains the
worker and the installed ``vgi-pii-worker`` console script / ``vgi-serve`` can
launch it). This file stays at the repo root purely as a PEP 723 script so
``uv run pii_worker.py`` keeps resolving the inline dependencies (including the
pinned ``en_core_web_sm`` spaCy model wheel) and spawning the worker over stdio
exactly as DuckDB drives it after ``ATTACH`` -- unchanged for the Makefile,
``ci/run-integration.sh``, and the test suite.

Usage:
    uv run pii_worker.py                 # serve over stdio (DuckDB subprocess)

    INSTALL vgi FROM community; LOAD vgi;
    ATTACH 'pii' (TYPE vgi, LOCATION 'uv run pii_worker.py');
"""

from __future__ import annotations

from vgi_pii.worker import PiiWorker, main

__all__ = ["PiiWorker", "main"]


if __name__ == "__main__":
    main()
