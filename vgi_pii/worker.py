# Copyright 2026 Query Farm LLC - https://query.farm

"""VGI worker exposing PII detection + redaction (Microsoft Presidio) to SQL.

Assembles the scalar and table functions in :mod:`vgi_pii` into a single ``pii``
catalog and runs the worker over stdio (DuckDB subprocess) or HTTP. It detects
and redacts personally-identifiable information in text using
`Microsoft Presidio <https://microsoft.github.io/presidio/>`_ (analyzer +
anonymizer) backed by the pinned ``en_core_web_sm`` spaCy model.

This module is wheel-importable (it lives inside the ``vgi_pii`` package), so it
backs both the installed ``vgi-pii-worker`` console script and
``vgi-serve vgi_pii.worker:PiiWorker --http``. The repo-root ``pii_worker.py`` is
a thin PEP 723 shim that re-exports :class:`PiiWorker` and :func:`main` so
``uv run pii_worker.py`` keeps working unchanged.

Usage:
    vgi-pii-worker                       # serve over stdio (DuckDB subprocess)
    uv run pii_worker.py                 # same, via the PEP 723 shim

    INSTALL vgi FROM community; LOAD vgi;
    ATTACH 'pii' (TYPE vgi, LOCATION 'vgi-pii-worker');

    SELECT pii.main.has_pii('Call John Smith at john@example.com');        -- true
    SELECT pii.main.redact('Call John Smith at john@example.com');         -- 'Call <PERSON> at <EMAIL_ADDRESS>'
    SELECT pii.main.anonymize('Call John Smith at john@example.com');      -- 'Call **** at ****************'
    SELECT pii.main.pii_types('Call John Smith at john@example.com');      -- ['EMAIL_ADDRESS', 'PERSON']
    SELECT * FROM pii.main.detect_pii('Call John Smith at john@example.com');
    SELECT * FROM pii.main.supported_entities() ORDER BY entity_type;
"""

from __future__ import annotations

import json
from typing import Any

from vgi import Worker
from vgi.catalog import Catalog, Schema

from vgi_pii import engine
from vgi_pii.scalars import SCALAR_FUNCTIONS
from vgi_pii.tables import DISCOVERY_TABLES, TABLE_FUNCTIONS

_CATALOG_DESCRIPTION_LLM = (
    "Detect and redact personally-identifiable information (PII) in free text directly in SQL, "
    "backed by Microsoft Presidio (analyzer + anonymizer) and a spaCy NLP model. Find whether "
    "text contains PII (has_pii), list the distinct entity types present (pii_types), replace each "
    "entity with its type tag (redact, e.g. '<PERSON>'), mask each entity's characters (anonymize), "
    "enumerate every detected entity with offsets and confidence (detect_pii), and discover the "
    "entity types the analyzer supports (supported_entities). Detected types include PERSON, "
    "EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, US_SSN, LOCATION, URL, IP_ADDRESS and more. Use for "
    "privacy scrubbing, data-loss-prevention checks, and PII auditing of text columns."
)

_CATALOG_DESCRIPTION_MD = (
    "# PII Detection & Redaction in SQL\n\n"
    "![Microsoft Presidio logo](https://raw.githubusercontent.com/microsoft/presidio/main/docs/assets/dps-icon.svg)\n\n"
    "**Find, redact, and anonymize personally-identifiable information (PII) in free text "
    "directly from DuckDB SQL** — person names, email addresses, phone numbers, credit-card "
    "numbers, US SSNs, locations, URLs, IP addresses and more — powered by "
    "[Microsoft Presidio](https://microsoft.github.io/presidio/).\n\n"
    "This extension brings privacy scrubbing, data-loss-prevention (DLP) checks, and PII "
    "auditing to your data warehouse without exporting a single row to an external service. "
    "It is built for data engineers, privacy and security teams, and analysts who need to "
    "sanitize logs, user-generated content, support transcripts, and other text columns "
    "before sharing, training, or archiving them. Every function runs in-process over Apache "
    "Arrow, so detection happens right next to your data and PII never leaves your "
    "environment.\n\n"
    "Detection is powered by [Microsoft Presidio](https://github.com/microsoft/presidio) "
    "(its analyzer and anonymizer engines) backed by a [spaCy](https://spacy.io/) "
    "named-entity-recognition pipeline using the pinned `en_core_web_sm` model from the "
    "[spaCy models](https://github.com/explosion/spacy-models) collection. Presidio combines "
    "this NLP model with pattern recognizers and checksum validation (for example, Luhn "
    "validation of credit-card numbers) to flag a broad catalog of entity types, each with a "
    "confidence score and character offsets you can inspect or threshold.\n\n"
    "## What you can do\n\n"
    "Two complementary capabilities are grouped in the `main` schema. *Detection* answers "
    "whether text holds sensitive data, which categories it holds, and exactly where each "
    "value sits (with a confidence score you can threshold). *Redaction* rewrites the text so "
    "the sensitive values are gone -- either labelled by the kind of value that was there, or "
    "masked so even the shape is hidden. Detection powers filtering, alerting, and auditing; "
    "redaction powers safe sharing, export, and archival. Every operation accepts an optional "
    "ISO language argument (defaulting to English) and treats NULL or blank input gracefully.\n\n"
    "```sql\n"
    "SELECT pii.main.redact('Call John Smith at john@example.com');\n"
    "-- 'Call <PERSON> at <EMAIL_ADDRESS>'\n"
    "```\n\n"
    "Learn more from the [Presidio documentation](https://microsoft.github.io/presidio/), the "
    "[Presidio source repository](https://github.com/microsoft/presidio), and the "
    "[spaCy NLP library](https://github.com/explosion/spaCy)."
)

_MAIN_DESCRIPTION_LLM = (
    "## main\n\n"
    "The main schema groups every PII capability in the pii catalog. Reach for it whenever you "
    "need to find, scrub, or audit personally-identifiable information in a text column. Two "
    "kinds of work live here.\n\n"
    "- **Detection** tells you about the PII in a value without changing it: whether any is "
    "present (a boolean predicate for filtering), which distinct entity types occur (as a "
    "sorted array), the full per-occurrence detail (one row per entity with its type, character "
    "offsets, and confidence score you can threshold), and which entity types the analyzer is "
    "able to recognise at all.\n"
    "- **Redaction** rewrites the text so the sensitive values are removed -- either replaced "
    "by a tag naming the kind of value that was there, or masked character-for-character so "
    "even the shape is hidden.\n\n"
    "The per-row operations are scalars usable inline in any projection or predicate; the "
    "per-occurrence and discovery operations are table functions. Every operation takes an "
    "optional ISO language argument (defaulting to English). Detection is powered by Microsoft "
    "Presidio with a spaCy NLP model; NULL or blank input is handled gracefully (NULL or no "
    "rows). Detection tags a broad set of entity types (PERSON, EMAIL_ADDRESS, PHONE_NUMBER, "
    "CREDIT_CARD, US_SSN, LOCATION, URL, IP_ADDRESS, and more), each with a confidence score you "
    "can raise via the `score_threshold` argument to trade recall for precision."
)

_MAIN_DESCRIPTION_MD = (
    "# main\n\n"
    "PII detection and redaction over free text, exposed as DuckDB scalar and table "
    "functions.\n\n"
    "## Detection vs. redaction\n\n"
    "The schema offers two complementary kinds of operation. **Detection** inspects text "
    "without changing it -- flag whether any PII is present, summarise which entity types "
    "occur, enumerate each occurrence with its character offsets and confidence score, and "
    "introspect which entity types the analyzer can recognise. **Redaction** rewrites text so "
    "the sensitive values are removed -- either tagged by the kind of value or masked so even "
    "its shape is hidden.\n\n"
    "## Notes\n\n"
    "Per-row operations are scalars (usable inline in any projection or predicate) and take an "
    "optional trailing `language`; the per-occurrence and discovery operations are table "
    "functions that accept named arguments (`language :=`, `score_threshold :=`). Raise "
    "`score_threshold` on the table functions to keep only high-confidence detections, and pass "
    "`language` to scan non-English text. Powered by "
    "[Microsoft Presidio](https://microsoft.github.io/presidio/)."
)

# Schema-level examples must be a described JSON list (VGI515): each entry pairs
# a human-readable description with a runnable, catalog-qualified query. Projected
# columns (never bare SELECT *) keep them readable and VGI514-clean.
_MAIN_EXAMPLE_QUERIES = json.dumps(
    [
        {
            "description": "Flag whether text contains any PII (a boolean predicate for filtering).",
            "sql": "SELECT pii.main.has_pii('Call John Smith at john@example.com')",
        },
        {
            "description": "Replace each PII entity with a <TYPE> tag naming its kind.",
            "sql": "SELECT pii.main.redact('Call John Smith at john@example.com')",
        },
        {
            "description": "Mask each PII entity's characters with '*'.",
            "sql": "SELECT pii.main.anonymize('Call John Smith at john@example.com')",
        },
        {
            "description": "List the distinct PII entity types present in text.",
            "sql": "SELECT pii.main.pii_types('Call John Smith at john@example.com')",
        },
        {
            "description": "Enumerate every detected PII entity with its offsets and confidence.",
            "sql": (
                "SELECT entity_type, text, start, end_pos, score "
                "FROM pii.main.detect_pii('Call John Smith at john@example.com') ORDER BY start"
            ),
        },
        {
            "description": "Discover which entity types the analyzer can detect.",
            "sql": "SELECT entity_type FROM pii.main.supported_entities() ORDER BY entity_type",
        },
    ]
)

# vgi.keywords must be a JSON array of strings (VGI138), not a comma-separated
# string; serialized below via json.dumps.
_CATALOG_KEYWORDS = [
    "pii",
    "personally identifiable information",
    "redaction",
    "anonymization",
    "privacy",
    "presidio",
    "data loss prevention",
    "dlp",
    "sensitive data",
    "person",
    "email",
    "phone",
    "credit card",
    "ssn",
    "location",
    "ip address",
    "url",
    "text scrubbing",
    "masking",
]

_MAIN_KEYWORDS = [
    "pii",
    "detect",
    "redact",
    "anonymize",
    "mask",
    "entity types",
    "has_pii",
    "pii_types",
    "detect_pii",
    "supported_entities",
    "privacy",
    "presidio",
    "sensitive data",
]

# Category navigation registry for the `main` schema (VGI413). Ordered JSON
# array of {"name","description"}; every function carries a matching
# `vgi.category` (set in vgi_pii.scalars / vgi_pii.tables).
_MAIN_CATEGORIES = [
    {
        "name": "detection",
        "description": (
            "Inspect text for PII without changing it: test for presence, list the distinct "
            "entity types, or enumerate every occurrence with its offsets and confidence."
        ),
    },
    {
        "name": "redaction",
        "description": (
            "Rewrite text to remove PII by replacing each detected entity with a type tag or masking its characters."
        ),
    },
    {
        "name": "discovery",
        "description": "Introspect which PII entity types the analyzer is able to detect.",
    },
]

# Grader suite for `vgi-lint simulate` / VGI152 & VGI920. Each task's
# reference_sql and the analyst's answer run against the *same* live worker, so a
# task passes when the analyst discovers and calls the right function -- not on
# any absolute Presidio output. success_criteria is an LLM-judge fallback;
# ignore_column_names avoids penalising harmless output-column naming, and
# unordered relaxes row order where the prompt doesn't fix it.
_AGENT_TEST_TASKS = [
    {
        "name": "detect-pii-presence",
        "prompt": (
            "Does the text 'Contact Jane Doe at jane@example.com' contain any "
            "personally-identifiable information? Return a single boolean value."
        ),
        "reference_sql": "SELECT pii.main.has_pii('Contact Jane Doe at jane@example.com')",
        "success_criteria": (
            "Returns a single boolean value that is true, obtained by calling the worker's "
            "PII-presence predicate on the given text."
        ),
        "ignore_column_names": True,
    },
    {
        "name": "list-pii-types",
        "prompt": ("List the distinct PII entity types present in the text 'Contact Jane Doe at jane@example.com'."),
        "reference_sql": "SELECT pii.main.pii_types('Contact Jane Doe at jane@example.com')",
        "success_criteria": (
            "Returns the sorted array of distinct PII entity types (such as EMAIL_ADDRESS and "
            "PERSON) present in the text."
        ),
        "ignore_column_names": True,
    },
    {
        "name": "redact-with-type-tags",
        "prompt": (
            "Produce a copy of the text 'Email jane@example.com now' in which every PII value "
            "is replaced by a tag naming its entity type (for example <EMAIL_ADDRESS>)."
        ),
        "reference_sql": "SELECT pii.main.redact('Email jane@example.com now')",
        "success_criteria": (
            "Returns the input text with each detected PII entity replaced by a <TYPE> tag naming its entity type."
        ),
        "ignore_column_names": True,
    },
    {
        "name": "mask-pii-characters",
        "prompt": (
            "Produce a copy of the text 'Email jane@example.com now' in which every PII value's "
            "characters are masked with asterisks."
        ),
        "reference_sql": "SELECT pii.main.anonymize('Email jane@example.com now')",
        "success_criteria": (
            "Returns the input text with each detected PII entity's characters overwritten by '*' asterisks."
        ),
        "ignore_column_names": True,
    },
    {
        "name": "per-entity-detail",
        "prompt": (
            "For the text 'Contact Jane Doe at jane@example.com', return one row per detected "
            "PII entity showing the entity type and the matched substring."
        ),
        "reference_sql": (
            "SELECT entity_type, text FROM "
            "pii.main.detect_pii('Contact Jane Doe at jane@example.com') ORDER BY entity_type, text"
        ),
        "success_criteria": (
            "Returns one row per detected PII entity, each showing the entity type and the "
            "matched substring from the input text."
        ),
        "unordered": True,
        "ignore_column_names": True,
    },
    {
        "name": "count-supported-entity-types",
        "prompt": "How many distinct PII entity types can this worker's analyzer detect?",
        "reference_sql": "SELECT count(*) FROM pii.main.supported_entities()",
        "success_criteria": (
            "Returns the number of distinct PII entity types the analyzer supports, obtained "
            "from the worker's supported-entities discovery function."
        ),
        "ignore_column_names": True,
    },
    {
        "name": "recognizes-credit-card",
        "prompt": (
            "Does this worker's list of recognizable PII entity types include credit-card "
            "numbers (the CREDIT_CARD type)? Return a single boolean value."
        ),
        "reference_sql": ("SELECT count(*) > 0 FROM pii.main.entity_types WHERE entity_type = 'CREDIT_CARD'"),
        "success_criteria": (
            "Returns a single boolean that is true, determined by looking up CREDIT_CARD in the "
            "worker's browsable table of recognizable entity types."
        ),
        "ignore_column_names": True,
    },
]

_CATALOG_TAGS = {
    "vgi.title": "PII Detection & Redaction",
    "vgi.keywords": json.dumps(_CATALOG_KEYWORDS),
    "vgi.doc_llm": _CATALOG_DESCRIPTION_LLM,
    "vgi.doc_md": _CATALOG_DESCRIPTION_MD,
    "vgi.author": "Query.Farm",
    "vgi.copyright": "Copyright 2026 Query Farm LLC - https://query.farm",
    "vgi.license": "MIT",
    "vgi.support_contact": "https://github.com/Query-farm/vgi-pii/issues",
    "vgi.support_policy_url": "https://github.com/Query-farm/vgi-pii/blob/main/README.md",
    "vgi.agent_test_tasks": json.dumps(_AGENT_TEST_TASKS),
}

_PII_CATALOG = Catalog(
    name="pii",
    default_schema="main",
    comment="PII detection + redaction for SQL, powered by Microsoft Presidio",
    source_url="https://github.com/Query-farm/vgi-pii",
    tags=_CATALOG_TAGS,
    schemas=[
        Schema(
            name="main",
            comment="Detect, list, redact, and anonymize PII entities in free text",
            tags={
                "vgi.title": "PII Functions — main",
                "vgi.keywords": json.dumps(_MAIN_KEYWORDS),
                "vgi.doc_llm": _MAIN_DESCRIPTION_LLM,
                "vgi.doc_md": _MAIN_DESCRIPTION_MD,
                "vgi.example_queries": _MAIN_EXAMPLE_QUERIES,
                "vgi.categories": json.dumps(_MAIN_CATEGORIES),
                # VGI123 classifying tags — BARE keys (not vgi.-namespaced).
                "domain": "security",
                "category": "parsing",
                "topic": "pii-detection-and-redaction",
            },
            functions=[*SCALAR_FUNCTIONS, *TABLE_FUNCTIONS],
            tables=list(DISCOVERY_TABLES),
        ),
    ],
)


class PiiWorker(Worker):
    """Worker process hosting the ``pii`` catalog."""

    catalog = _PII_CATALOG

    def run(self, otel_config: Any = None) -> None:
        """Warm the Presidio engine + spaCy model once, then serve.

        Building Presidio's ``AnalyzerEngine`` loads a spaCy model (~1-2 s); it
        is lazy by default, so without this the first query of every ATTACH pays
        that cost inline -- a window in which a worker-pool teardown SIGTERM (or a
        heavily-loaded host) can kill the run mid-assertion and record a spurious
        E2E failure. Warming at spawn moves the one-time cost ahead of any query,
        keeping the SQL suite deterministic without changing any output.
        Best-effort; never fatal.
        """
        engine.warm_up()
        super().run(otel_config=otel_config)


def main() -> None:
    """Run the pii worker process (stdio or, via flags, HTTP)."""
    PiiWorker.main()


if __name__ == "__main__":
    main()
