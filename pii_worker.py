# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "vgi-python[http]>=0.8.5",
#     "presidio-analyzer>=2.2",
#     "presidio-anonymizer>=2.2",
#     "spacy>=3.7",
#     "en-core-web-sm",
# ]
#
# [tool.uv.sources]
# en-core-web-sm = { url = "https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl" }
# ///
"""VGI worker exposing PII detection + redaction (Microsoft Presidio) to SQL.

Assembles the scalar and table functions in ``vgi_pii`` into a single ``pii``
catalog and runs the worker over stdio (DuckDB subprocess) or HTTP. It detects
and redacts personally-identifiable information in text using
`Microsoft Presidio <https://microsoft.github.io/presidio/>`_ (analyzer +
anonymizer) backed by the pinned ``en_core_web_sm`` spaCy model.

Usage:
    uv run pii_worker.py                 # serve over stdio (DuckDB subprocess)

    INSTALL vgi FROM community; LOAD vgi;
    ATTACH 'pii' (TYPE vgi, LOCATION 'uv run pii_worker.py');

    SELECT pii.has_pii('Call John Smith at john@example.com');        -- true
    SELECT pii.redact('Call John Smith at john@example.com');         -- 'Call <PERSON> at <EMAIL_ADDRESS>'
    SELECT pii.anonymize('Call John Smith at john@example.com');      -- 'Call **** at ****************'
    SELECT pii.pii_types('Call John Smith at john@example.com');      -- ['EMAIL_ADDRESS', 'PERSON']
    SELECT * FROM pii.detect_pii('Call John Smith at john@example.com');
    SELECT * FROM pii.supported_entities() ORDER BY entity_type;
"""

from __future__ import annotations

import json
from typing import Any

from vgi import Worker
from vgi.catalog import Catalog, Schema

from vgi_pii import engine
from vgi_pii.scalars import SCALAR_FUNCTIONS
from vgi_pii.tables import TABLE_FUNCTIONS

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
    "## SQL functions\n\n"
    "The catalog exposes four scalar functions and two table functions in the `main` schema. "
    "Use `has_pii(text)` as a boolean predicate to filter or flag rows that contain sensitive "
    "data, and `pii_types(text)` to get the sorted `VARCHAR[]` of distinct entity types "
    "present. Use `redact(text)` to replace each detected entity with a `<TYPE>` tag (for "
    "example `<PERSON>`, `<EMAIL_ADDRESS>`) and `anonymize(text)` to mask each entity's "
    "characters with `*`. For full visibility, the `detect_pii(text)` table function returns "
    "one row per entity with its type, start/end offsets and confidence score (with an "
    "optional `score_threshold`), and `supported_entities()` lists every entity type the "
    "analyzer can detect. All scalars accept an optional ISO `language` argument (defaulting "
    "to `'en'`), and NULL or blank input is handled gracefully.\n\n"
    "```sql\n"
    "SELECT pii.redact('Call John Smith at john@example.com');\n"
    "-- 'Call <PERSON> at <EMAIL_ADDRESS>'\n"
    "SELECT * FROM pii.detect_pii('Call John Smith at john@example.com') ORDER BY start;\n"
    "```\n\n"
    "Learn more from the [Presidio documentation](https://microsoft.github.io/presidio/), the "
    "[Presidio source repository](https://github.com/microsoft/presidio), and the "
    "[spaCy NLP library](https://github.com/explosion/spaCy)."
)

_MAIN_DESCRIPTION_LLM = (
    "## main\n\n"
    "The `main` schema groups every PII function in the `pii` catalog. Reach for it whenever "
    "you need to find, scrub, or audit personally-identifiable information in a text column.\n\n"
    "- **Scalars (one value per row):** `has_pii` (boolean predicate), `pii_types` (sorted "
    "`VARCHAR[]` of distinct entity types), `redact` (replace each entity with a `<TYPE>` tag), "
    "and `anonymize` (mask each entity's characters with `*`). Each takes an optional ISO "
    "`language` argument (defaults to `'en'`).\n"
    "- **Table functions (one row per result):** `detect_pii` (one row per entity, with offsets "
    "and confidence; supports `score_threshold`) and `supported_entities` (the entity types the "
    "analyzer can detect).\n\n"
    "All detection is powered by Microsoft Presidio with the `en_core_web_sm` spaCy model; "
    "NULL/blank input is handled gracefully (NULL or no rows)."
)

_MAIN_DESCRIPTION_MD = (
    "# main\n\n"
    "PII detection and redaction over free text, exposed as DuckDB scalar and table "
    "functions.\n\n"
    "## Functions\n\n"
    "| function | kind | purpose |\n"
    "|---|---|---|\n"
    "| `has_pii` | scalar | `true` if any PII is present |\n"
    "| `pii_types` | scalar | distinct entity types as `VARCHAR[]` |\n"
    "| `redact` | scalar | replace entities with `<TYPE>` tags |\n"
    "| `anonymize` | scalar | mask entity characters with `*` |\n"
    "| `detect_pii` | table | one row per entity with offsets and score |\n"
    "| `supported_entities` | table | the entity types the analyzer detects |\n\n"
    "## Notes\n\n"
    "Scalars take an optional `language`; table functions accept named arguments "
    "(`language :=`, `score_threshold :=`). Powered by "
    "[Microsoft Presidio](https://microsoft.github.io/presidio/)."
)

_MAIN_EXAMPLE_QUERIES = (
    "SELECT pii.main.has_pii('Call John Smith at john@example.com');\n"
    "SELECT pii.main.redact('Call John Smith at john@example.com');\n"
    "SELECT pii.main.anonymize('Call John Smith at john@example.com');\n"
    "SELECT pii.main.pii_types('Call John Smith at john@example.com');\n"
    "SELECT * FROM pii.main.detect_pii('Call John Smith at john@example.com') ORDER BY start;\n"
    "SELECT * FROM pii.main.supported_entities() ORDER BY entity_type;"
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
                # VGI123 classifying tags — BARE keys (not vgi.-namespaced).
                "domain": "security",
                "category": "parsing",
                "topic": "pii-detection-and-redaction",
            },
            functions=[*SCALAR_FUNCTIONS, *TABLE_FUNCTIONS],
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
