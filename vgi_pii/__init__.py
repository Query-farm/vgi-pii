"""Detect + redact PII in text as a VGI worker, via Microsoft Presidio.

The implementation is split so each concern stays focused:

- ``engine``  -- the pure Presidio lifecycle + logic (build the analyzer /
  anonymizer once and cache them for the process; ``detect`` / ``has_pii`` /
  ``redact`` / ``anonymize`` / ``pii_types`` / ``supported_entities``). No Arrow
  or VGI dependency, directly unit-testable.
- ``scalars`` -- per-row VGI scalar functions (positional-only; the optional
  trailing ``language`` argument is exposed as an arity overload).
- ``tables``  -- set-returning functions: ``detect_pii`` (one row per entity)
  and ``supported_entities`` (discovery).

``pii_worker.py`` at the repo root assembles these into the ``pii`` catalog and
runs the worker over stdio (or HTTP), warming the Presidio engine at startup.
"""

from __future__ import annotations

__version__ = "0.1.0"
