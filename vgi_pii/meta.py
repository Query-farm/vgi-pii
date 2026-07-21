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
from collections.abc import Mapping, Sequence


def example_queries_json(examples: Sequence[Mapping[str, str]]) -> str:
    """Serialize described example queries for the ``vgi.example_queries`` tag.

    VGI515 requires every function- and schema-level example to carry a
    non-empty human-readable description, and the native
    ``duckdb_functions().examples`` carrier (populated from ``Meta.examples``)
    drops descriptions. Emitting the same queries through ``vgi.example_queries``
    as a JSON list of ``{"description", "sql"}`` objects preserves them; the
    linter unions the two carriers deduped by SQL, keeping the described copy.

    Args:
        examples: Ordered ``{"description": ..., "sql": ...}`` mappings; for a
            function with arity overloads, aggregate every overload's examples
            here (they share one function name in the catalog).

    Returns:
        The examples encoded as a JSON array-of-objects literal.
    """
    return json.dumps([{"description": e["description"], "sql": e["sql"]} for e in examples])


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
    examples: Sequence[Mapping[str, str]] | None = None,
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
        examples: Optional described example queries; serialized to
            ``vgi.example_queries`` (VGI515) so every example keeps its
            description. Aggregate arity-overload examples under the one function
            name.

    Returns:
        A dict of the tag keys to their values, ready to merge into a function's
        ``Meta.tags``.
    """
    tags = {
        "vgi.title": title,
        "vgi.doc_llm": doc_llm,
        "vgi.doc_md": doc_md,
        "vgi.keywords": keywords_json(keywords),
        "vgi.category": category,
    }
    if examples is not None:
        tags["vgi.example_queries"] = example_queries_json(examples)
    return tags
