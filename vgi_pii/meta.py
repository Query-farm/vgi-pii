"""Shared per-object discovery/description metadata for the pii worker.

The ``vgi-lint-check`` strict profile expects a consistent set of tags on
**every** function and table so agents and humans can discover, understand, and
run each object. This module centralises those tags so each scalar/table only
declares its own content once.

Tags emitted on each object (with the rule that gates them):

- ``vgi.title`` (VGI124)       -- human-friendly display name. It must not
  normalize-equal the machine name (lowercase + strip non-alphanumerics), so we
  always carry an extra descriptive word.
- ``vgi.doc_llm`` (VGI112)     -- a Markdown narrative aimed at an LLM/agent:
  what the object does, when to use it, inputs/outputs, key behaviours and edge
  cases.
- ``vgi.doc_md`` (VGI113)      -- a Markdown narrative aimed at human docs:
  overview, usage, and notes. Distinct content from ``vgi.doc_llm``.
- ``vgi.keywords`` (VGI126/VGI138) -- search terms / synonyms, serialized as a
  JSON array of strings (``["a", "b"]``), never a comma-separated string.

``vgi.source_url`` is intentionally **not** set per object (VGI139): the
source link belongs only on the catalog object.
"""

from __future__ import annotations

import json
from collections.abc import Sequence


def keywords_json(keywords: Sequence[str]) -> str:
    """Serialize keywords as a JSON array of strings (``vgi.keywords``).

    VGI138 requires ``vgi.keywords`` to be a JSON array like ``["a", "b"]`` and
    rejects a comma-separated string.

    Args:
        keywords: Individual search terms / synonyms for the object.

    Returns:
        The keywords encoded as a JSON array-of-strings literal.
    """
    return json.dumps(list(keywords))


def object_tags(
    *,
    title: str,
    doc_llm: str,
    doc_md: str,
    keywords: Sequence[str],
    category: str,
) -> dict[str, str]:
    """Build the standard per-object discovery/description tags.

    Args:
        title: Human-friendly display name (``vgi.title``).
        doc_llm: Markdown narrative for an LLM/agent audience (``vgi.doc_llm``).
        doc_md: Markdown narrative for human docs (``vgi.doc_md``).
        keywords: Search terms/synonyms; serialized to a JSON array string for
            ``vgi.keywords`` (VGI138).
        category: The object's primary ``vgi.category`` -- the name of one entry
            in the schema's ``vgi.categories`` registry (VGI409/VGI411/VGI413).

    Returns:
        A dict of the tag keys to their values, ready to merge into a function's
        ``Meta.tags``.
    """
    return {
        "vgi.title": title,
        "vgi.doc_llm": doc_llm,
        "vgi.doc_md": doc_md,
        "vgi.keywords": keywords_json(keywords),
        "vgi.category": category,
    }
