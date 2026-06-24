# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "vgi-python[http]>=0.8.4",
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
    "# pii\n\n"
    "Detect and redact PII in free text (person names, emails, phone numbers, credit cards, SSNs, "
    "locations, URLs, IP addresses, …) directly in SQL, powered by "
    "[Microsoft Presidio](https://microsoft.github.io/presidio/).\n\n"
    "**Scalars:** `has_pii`, `pii_types`, `redact`, `anonymize`.\n\n"
    "**Table functions:** `detect_pii`, `supported_entities`."
)

_MAIN_DESCRIPTION_LLM = (
    "PII detection and redaction functions over free text: has_pii, pii_types, redact, anonymize "
    "(per-row scalars) plus detect_pii and supported_entities (table functions)."
)

_MAIN_DESCRIPTION_MD = (
    "PII detection and redaction functions powered by Microsoft Presidio: `has_pii`, `pii_types`, "
    "`redact`, `anonymize`, `detect_pii`, `supported_entities`."
)

_CATALOG_TAGS = {
    "vgi.description_llm": _CATALOG_DESCRIPTION_LLM,
    "vgi.description_md": _CATALOG_DESCRIPTION_MD,
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
                "vgi.description_llm": _MAIN_DESCRIPTION_LLM,
                "vgi.description_md": _MAIN_DESCRIPTION_MD,
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
