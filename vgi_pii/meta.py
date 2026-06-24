"""Shared per-object discovery/description metadata for the pii worker.

The ``vgi-lint-check`` strict profile (0.26.0) expects a consistent set of
tags on **every** function and table so agents and humans can discover,
understand, and run each object. This module centralises those tags so each
scalar/table only declares its own content once.

Tags emitted on each object (with the rule that gates them):

- ``vgi.title`` (VGI124)       -- human-friendly display name. It must not
  normalize-equal the machine name (lowercase + strip non-alphanumerics), so we
  always carry an extra descriptive word.
- ``vgi.doc_llm`` (VGI112)     -- a Markdown narrative aimed at an LLM/agent:
  what the object does, when to use it, inputs/outputs, key behaviours and edge
  cases.
- ``vgi.doc_md`` (VGI113)      -- a Markdown narrative aimed at human docs:
  overview, usage, and notes. Distinct content from ``vgi.doc_llm``.
- ``vgi.keywords`` (VGI126)    -- comma-separated search terms / synonyms.
- ``vgi.source_url`` (VGI128)  -- link to the implementing source file.

``source_url(path)`` builds the canonical GitHub blob URL (pinned to ``main``)
for a file under the repository root.
"""

from __future__ import annotations

# Base GitHub blob URL for source files in this repo (pinned to ``main``).
_SOURCE_BASE = "https://github.com/Query-farm/vgi-pii/blob/main"


def source_url(relative_path: str) -> str:
    """Build the canonical ``vgi.source_url`` for a repo-relative source file.

    Args:
        relative_path: Path to the file relative to the repository root, e.g.
            ``"vgi_pii/scalars.py"``.

    Returns:
        The GitHub blob URL for that file, pinned to ``main``.
    """
    return f"{_SOURCE_BASE}/{relative_path}"


def object_tags(
    *,
    title: str,
    doc_llm: str,
    doc_md: str,
    keywords: str,
    relative_path: str,
) -> dict[str, str]:
    """Build the five standard per-object discovery/description tags.

    Args:
        title: Human-friendly display name (``vgi.title``).
        doc_llm: Markdown narrative for an LLM/agent audience (``vgi.doc_llm``).
        doc_md: Markdown narrative for human docs (``vgi.doc_md``).
        keywords: Comma-separated search terms/synonyms (``vgi.keywords``).
        relative_path: Implementing file relative to the repo root, used to build
            ``vgi.source_url``.

    Returns:
        A dict of the five tag keys to their values, ready to merge into a
        function's ``Meta.tags``.
    """
    return {
        "vgi.title": title,
        "vgi.doc_llm": doc_llm,
        "vgi.doc_md": doc_md,
        "vgi.keywords": keywords,
        "vgi.source_url": source_url(relative_path),
    }
