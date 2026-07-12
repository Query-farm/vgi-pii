"""Set-returning PII table functions for DuckDB.

These expand to **many rows**, so they are exposed as **table functions** -- the
form that accepts DuckDB ``name := value`` arguments (``language``,
``score_threshold``). The per-row, single-value PII functions (``has_pii``,
``redact``, ``anonymize``, ``pii_types``) are *scalars* and live in
:mod:`vgi_pii.scalars`.

    SELECT * FROM pii.main.detect_pii('Call John Smith at john@example.com');
    SELECT * FROM pii.main.detect_pii('...', language := 'en', score_threshold := 0.8);
    SELECT * FROM pii.main.supported_entities() ORDER BY entity_type;
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Annotated, ClassVar

import pyarrow as pa
from vgi.arguments import Arg
from vgi.catalog import Table
from vgi.metadata import FunctionExample
from vgi.table_function import (
    BindParams,
    ProcessParams,
    TableCardinality,
    TableFunctionGenerator,
    bind_fixed_schema,
    init_single_worker,
)
from vgi_rpc.rpc import OutputCollector

from . import engine
from .meta import keywords_json, object_tags
from .schema_utils import field

_LANGUAGE = Arg[str]("language", default="en", doc="ISO language code (e.g. 'en').")
_SCORE_THRESHOLD = Arg[float](
    "score_threshold",
    default=engine.DEFAULT_SCORE_THRESHOLD,
    arrow_type=pa.float64(),
    doc="Minimum detection confidence in [0, 1] (default 0.5).",
)

# Guaranteed-runnable, catalog-qualified examples (VGI509). Each ``sql`` is
# self-contained and re-runnable against an attached ``pii`` worker. We omit
# ``expected_result`` deliberately -- the linter only needs each query to execute
# cleanly, and exact detection output can vary with the spaCy model version.
_EXECUTABLE_EXAMPLES = json.dumps(
    [
        {
            "description": "Detect whether text contains any PII.",
            "sql": "SELECT pii.main.has_pii('Call John Smith at john@example.com') AS has_pii",
        },
        {
            "description": "Tag-redact each PII entity with its <TYPE> label.",
            "sql": "SELECT pii.main.redact('Call John Smith at john@example.com') AS redacted",
        },
        {
            "description": "Mask each PII entity's characters with '*'.",
            "sql": "SELECT pii.main.anonymize('Call John Smith at john@example.com') AS masked",
        },
        {
            "description": "List the distinct PII entity types present in text.",
            "sql": "SELECT pii.main.pii_types('Call John Smith at john@example.com') AS types",
        },
        {
            "description": "Expand text into one row per detected PII entity.",
            "sql": (
                "SELECT entity_type, text, start, end_pos "
                "FROM pii.main.detect_pii('Call John Smith at john@example.com') "
                "ORDER BY start"
            ),
        },
        {
            "description": "Count how many PII entity types the analyzer supports.",
            "sql": "SELECT count(*) AS n FROM pii.main.supported_entities()",
        },
    ]
)


@dataclass(kw_only=True)
class _DetectPiiArgs:
    """``detect_pii(text, language := ..., score_threshold := ...)``."""

    text: Annotated[str, Arg(0, arrow_type=pa.string(), doc="Text to scan for PII.")]
    language: Annotated[str, _LANGUAGE]
    score_threshold: Annotated[float, _SCORE_THRESHOLD]


_DETECT_PII_SCHEMA = pa.schema(
    [
        field("entity_type", pa.string(), "Detected PII entity type, e.g. 'PERSON'.", nullable=False),
        field("text", pa.string(), "The matched substring.", nullable=False),
        field("start", pa.int32(), "Start character offset (inclusive).", nullable=False),
        field("end_pos", pa.int32(), "End character offset (exclusive).", nullable=False),
        field("score", pa.float64(), "Detection confidence in [0, 1].", nullable=False),
    ]
)


@init_single_worker
@bind_fixed_schema
class DetectPiiFunction(TableFunctionGenerator[_DetectPiiArgs]):
    """One row per detected PII entity in ``text``.

    Columns: ``entity_type``, ``text`` (the matched substring), ``start`` /
    ``end_pos`` (character offsets; ``end_pos`` is exclusive -- named with a
    ``_pos`` suffix because ``end`` is a SQL keyword), and ``score``. NULL/empty
    text yields no rows.
    """

    FIXED_SCHEMA: ClassVar[pa.Schema] = _DETECT_PII_SCHEMA

    class Meta:
        """Function metadata."""

        name = "detect_pii"
        description = "One row per detected PII entity (entity_type, text, start, end_pos, score)"
        categories = ["pii", "detect"]
        tags = {
            **object_tags(
                title="Detect PII Entities Table",
                doc_llm=(
                    "## detect_pii\n\n"
                    "A table function that returns **one row per detected PII entity** in the "
                    "input text, with the matched substring, its character offsets, the entity "
                    "type, and the detection confidence. Use it when you need the full, "
                    "per-occurrence detail -- e.g. to highlight spans, build a redaction map, or "
                    "audit exactly what was found and where.\n\n"
                    "- **Arguments:** `text` (positional `VARCHAR`); optional named "
                    "`language := 'en'` and `score_threshold := 0.5` (minimum confidence in "
                    "`[0, 1]`).\n"
                    "- **Returns:** rows of `(entity_type, text, start, end_pos, score)`. "
                    "`end_pos` is exclusive (named with a `_pos` suffix because `end` is a SQL "
                    "keyword).\n"
                    "- **Edge cases:** `NULL`, empty, or whitespace-only text yields **no rows**; "
                    "raising `score_threshold` drops low-confidence guesses.\n\n"
                    "For a per-row boolean or a list of types, use the `has_pii` / `pii_types` "
                    "scalars instead. Backed by Microsoft Presidio."
                ),
                doc_md=(
                    "# detect_pii\n\n"
                    "Expand text into one row per detected PII entity, with offsets and "
                    "confidence.\n\n"
                    "## Signature\n\n"
                    "`detect_pii(text[, language := 'en'][, score_threshold := 0.5])` — the "
                    "single positional `text` argument is required; `language` and "
                    "`score_threshold` are optional named arguments.\n\n"
                    "## Result columns\n\n"
                    "Each row is `(entity_type, text, start, end_pos, score)`: the entity type, "
                    "the matched substring, its inclusive start and exclusive end character "
                    "offsets, and the detection confidence in `[0, 1]`.\n\n"
                    "## Notes\n\n"
                    "`end_pos` is the exclusive end offset (the column is named `end_pos` because "
                    "`end` is a SQL keyword). NULL/blank text returns no rows. Raise "
                    "`score_threshold` to keep only high-confidence detections. See this "
                    "function's example queries for runnable demonstrations."
                ),
                keywords=[
                    "pii",
                    "detect_pii",
                    "entities",
                    "spans",
                    "offsets",
                    "score",
                    "confidence",
                    "table function",
                    "person",
                    "email",
                    "audit",
                    "privacy",
                ],
                category="detection",
            ),
            "vgi.result_columns_schema": json.dumps(
                [
                    {
                        "name": "entity_type",
                        "type": "VARCHAR",
                        "description": "Detected PII entity type, e.g. PERSON, EMAIL_ADDRESS.",
                    },
                    {
                        "name": "text",
                        "type": "VARCHAR",
                        "description": "The matched substring from the input text.",
                    },
                    {
                        "name": "start",
                        "type": "INTEGER",
                        "description": "Start character offset of the match (inclusive).",
                    },
                    {
                        "name": "end_pos",
                        "type": "INTEGER",
                        "description": "End character offset of the match (exclusive).",
                    },
                    {
                        "name": "score",
                        "type": "DOUBLE",
                        "description": "Detection confidence in the range [0, 1].",
                    },
                ]
            ),
            "vgi.executable_examples": _EXECUTABLE_EXAMPLES,
        }
        examples = [
            FunctionExample(
                sql=(
                    "SELECT entity_type, text, start, end_pos, score "
                    "FROM pii.main.detect_pii('Call John Smith at john@example.com') "
                    "ORDER BY start"
                ),
                description="List every PII entity found in the text, ordered by position",
            ),
            FunctionExample(
                sql=(
                    "SELECT entity_type, text FROM "
                    "pii.main.detect_pii('Email john@example.com', score_threshold := 0.8)"
                ),
                description="Only high-confidence detections",
            ),
        ]

    @classmethod
    def cardinality(cls, params: BindParams[_DetectPiiArgs]) -> TableCardinality:
        """Estimated and maximum row count for the planner."""
        return TableCardinality(estimate=4, max=None)

    @classmethod
    def process(cls, params: ProcessParams[_DetectPiiArgs], state: None, out: OutputCollector) -> None:
        """Emit the output rows produced by this invocation."""
        a = params.args
        entities = engine.detect(a.text, a.language, a.score_threshold)
        out.emit(
            pa.RecordBatch.from_pydict(
                {
                    "entity_type": [e.entity_type for e in entities],
                    "text": [e.text for e in entities],
                    "start": [e.start for e in entities],
                    "end_pos": [e.end for e in entities],
                    "score": [e.score for e in entities],
                },
                schema=params.output_schema,
            )
        )
        out.finish()


@dataclass(kw_only=True)
class _SupportedEntitiesArgs:
    """``supported_entities(language := ...)``."""

    language: Annotated[str, _LANGUAGE]


_SUPPORTED_ENTITIES_SCHEMA = pa.schema(
    [field("entity_type", pa.string(), "An entity type the analyzer can detect.", nullable=False)]
)


@init_single_worker
@bind_fixed_schema
class SupportedEntitiesFunction(TableFunctionGenerator[_SupportedEntitiesArgs]):
    """Every entity type the analyzer can detect for a language, one per row."""

    FIXED_SCHEMA: ClassVar[pa.Schema] = _SUPPORTED_ENTITIES_SCHEMA

    class Meta:
        """Function metadata."""

        name = "supported_entities"
        description = "Every PII entity type the analyzer can detect (PERSON, EMAIL_ADDRESS, ...)"
        categories = ["pii", "detect"]
        tags = {
            **object_tags(
                title="Supported PII Entity Types",
                doc_llm=(
                    "## supported_entities\n\n"
                    "A discovery table function that lists **every PII entity type the analyzer "
                    "can detect** for a language, one type per row. Use it to learn what "
                    "`detect_pii` / `pii_types` might return -- e.g. to validate a filter, build a "
                    "UI picker, or document coverage.\n\n"
                    "- **Arguments:** optional named `language := 'en'`.\n"
                    "- **Returns:** rows of a single column `entity_type` (e.g. `PERSON`, "
                    "`EMAIL_ADDRESS`, `PHONE_NUMBER`, `CREDIT_CARD`, `US_SSN`, `LOCATION`, `URL`, "
                    "`IP_ADDRESS`).\n"
                    "- **Edge cases:** an unsupported language yields the recognizers available "
                    "for that configuration (possibly empty).\n\n"
                    "Backed by Microsoft Presidio's registered recognizers."
                ),
                doc_md=(
                    "# supported_entities\n\n"
                    "List every PII entity type the analyzer can detect, one per row.\n\n"
                    "## Signature\n\n"
                    "`supported_entities([language := 'en'])` — takes only the optional named "
                    "`language` argument and returns a single `entity_type` column.\n\n"
                    "## Notes\n\n"
                    "Pass `language := '...'` to inspect the recognizers configured for another "
                    "language. The returned names are exactly the values that "
                    "`detect_pii.entity_type` and `pii_types` can produce -- use this table to "
                    "validate a filter or build a picker. See this function's example queries for "
                    "runnable demonstrations."
                ),
                keywords=[
                    "pii",
                    "supported_entities",
                    "entity types",
                    "recognizers",
                    "discovery",
                    "catalog",
                    "coverage",
                    "person",
                    "email",
                    "privacy",
                ],
                category="discovery",
            ),
            "vgi.result_columns_schema": json.dumps(
                [
                    {
                        "name": "entity_type",
                        "type": "VARCHAR",
                        "description": "An entity type the analyzer can detect, e.g. PERSON.",
                    },
                ]
            ),
        }
        examples = [
            FunctionExample(
                sql=(
                    "SELECT entity_type FROM pii.main.supported_entities() "
                    "WHERE entity_type LIKE '%CARD%' ORDER BY entity_type"
                ),
                description="Which detectable entity types relate to payment cards",
            ),
            FunctionExample(
                sql="SELECT count(*) FROM pii.main.supported_entities()",
                description="How many entity types are supported",
            ),
        ]

    @classmethod
    def cardinality(cls, params: BindParams[_SupportedEntitiesArgs]) -> TableCardinality:
        """Estimated and maximum row count for the planner."""
        return TableCardinality(estimate=25, max=200)

    @classmethod
    def process(cls, params: ProcessParams[_SupportedEntitiesArgs], state: None, out: OutputCollector) -> None:
        """Emit the output rows produced by this invocation."""
        rows = engine.supported_entities(params.args.language)
        out.emit(pa.RecordBatch.from_pydict({"entity_type": rows}, schema=params.output_schema))
        out.finish()


TABLE_FUNCTIONS: list[type] = [
    DetectPiiFunction,
    SupportedEntitiesFunction,
]


# ===========================================================================
# entity_types -- a browsable discovery *table* (VGI146)
# ===========================================================================
#
# A worker that exposes only table functions forces an agent to guess arguments
# before it can see any data. Exposing the analyzer's recognizable entity types
# as a plain, argument-free *table* (backed by the existing
# ``SupportedEntitiesFunction`` generator, scanned with its default language) lets
# an agent browse the worker's vocabulary with a bare ``SELECT ... FROM`` -- no
# arguments to guess, no credentials, no network. Mirrors the discovery-table
# idiom used by the sibling ``vgi-conform`` worker.

_ENTITY_TYPES_DOC_LLM = (
    "## entity_types\n\n"
    "A browsable discovery **table** listing every PII entity type this worker's analyzer "
    "can recognise (for the default English configuration), one type per row. Read it with a "
    "plain `SELECT` -- no arguments required -- to learn the exact vocabulary that "
    "`detect_pii.entity_type` and `pii_types` can produce, e.g. to validate a filter, build a "
    "picker, or document coverage.\n\n"
    "- **Columns:** a single `entity_type` `VARCHAR` (e.g. `PERSON`, `EMAIL_ADDRESS`, "
    "`PHONE_NUMBER`, `CREDIT_CARD`, `US_SSN`, `LOCATION`, `URL`, `IP_ADDRESS`).\n"
    "- **Rows:** one per recognisable entity type; `entity_type` is the table's primary key.\n\n"
    "For the recognizers of a *non-default* language, call the `supported_entities(language := ...)` "
    "table function instead. Backed by Microsoft Presidio's registered recognizers."
)

_ENTITY_TYPES_DOC_MD = (
    "# entity_types\n\n"
    "A browsable table of every PII entity type the analyzer can recognise for the default "
    "English configuration, one per row.\n\n"
    "## Columns\n\n"
    "- `entity_type` (`VARCHAR`, primary key) -- a recognizable entity type such as `PERSON`, "
    "`EMAIL_ADDRESS`, or `CREDIT_CARD`.\n\n"
    "## Notes\n\n"
    "These are exactly the values `detect_pii` and `pii_types` can return. This table uses the "
    "default (English) recognizer set; for another language use the "
    "`supported_entities(language := ...)` table function. See this table's example queries for "
    "runnable demonstrations."
)

ENTITY_TYPES_TABLE = Table(
    name="entity_types",
    function=SupportedEntitiesFunction,
    comment="Every PII entity type the analyzer can recognise (default English), one per row.",
    primary_key=(("entity_type",),),
    not_null=("entity_type",),
    column_comments={
        "entity_type": "A PII entity type the analyzer can detect, e.g. PERSON, EMAIL_ADDRESS.",
    },
    tags={
        "vgi.title": "Recognizable PII Entity Types",
        "vgi.doc_llm": _ENTITY_TYPES_DOC_LLM,
        "vgi.doc_md": _ENTITY_TYPES_DOC_MD,
        "vgi.keywords": keywords_json(
            [
                "pii",
                "entity types",
                "entity_types",
                "recognizers",
                "discovery",
                "vocabulary",
                "catalog",
                "coverage",
                "person",
                "email",
                "credit card",
            ]
        ),
        "vgi.category": "discovery",
        "domain": "security",
        "vgi.example_queries": json.dumps(
            [
                {
                    "description": "Count how many PII entity types the analyzer recognises.",
                    "sql": "SELECT count(*) AS n FROM pii.main.entity_types",
                },
                {
                    "description": "Check whether the analyzer recognises credit-card numbers.",
                    "sql": (
                        "SELECT count(*) > 0 AS detects_cards "
                        "FROM pii.main.entity_types WHERE entity_type = 'CREDIT_CARD'"
                    ),
                },
            ]
        ),
    },
)


DISCOVERY_TABLES: list[Table] = [
    ENTITY_TYPES_TABLE,
]
