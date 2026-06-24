"""Set-returning PII table functions for DuckDB.

These expand to **many rows**, so they are exposed as **table functions** -- the
form that accepts DuckDB ``name := value`` arguments (``language``,
``score_threshold``). The per-row, single-value PII functions (``has_pii``,
``redact``, ``anonymize``, ``pii_types``) are *scalars* and live in
:mod:`vgi_pii.scalars`.

    SELECT * FROM pii.detect_pii('Call John Smith at john@example.com');
    SELECT * FROM pii.detect_pii('...', language := 'en', score_threshold := 0.8);
    SELECT * FROM pii.supported_entities() ORDER BY entity_type;
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Annotated, ClassVar

import pyarrow as pa
from vgi.arguments import Arg
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
from .meta import object_tags
from .schema_utils import field

_TABLES_SOURCE = "vgi_pii/tables.py"

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
            "sql": "SELECT pii.has_pii('Call John Smith at john@example.com') AS has_pii",
        },
        {
            "description": "Tag-redact each PII entity with its <TYPE> label.",
            "sql": "SELECT pii.redact('Call John Smith at john@example.com') AS redacted",
        },
        {
            "description": "Mask each PII entity's characters with '*'.",
            "sql": "SELECT pii.anonymize('Call John Smith at john@example.com') AS masked",
        },
        {
            "description": "List the distinct PII entity types present in text.",
            "sql": "SELECT pii.pii_types('Call John Smith at john@example.com') AS types",
        },
        {
            "description": "Expand text into one row per detected PII entity.",
            "sql": (
                "SELECT entity_type, text, start, end_pos "
                "FROM pii.detect_pii('Call John Smith at john@example.com') "
                "ORDER BY start"
            ),
        },
        {
            "description": "Count how many PII entity types the analyzer supports.",
            "sql": "SELECT count(*) AS n FROM pii.supported_entities()",
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
                    "## Usage\n\n"
                    "```sql\n"
                    "SELECT * FROM pii.detect_pii('Call John Smith at john@example.com');\n"
                    "SELECT entity_type, text\n"
                    "FROM pii.detect_pii('Email john@example.com', score_threshold := 0.8);\n"
                    "```\n\n"
                    "## Notes\n\n"
                    "`end_pos` is the exclusive end offset (the column is named `end_pos` because "
                    "`end` is a SQL keyword). NULL/blank text returns no rows. Use the optional "
                    "`language` and `score_threshold` named arguments to tune detection."
                ),
                keywords=(
                    "pii, detect_pii, entities, spans, offsets, score, confidence, table function, "
                    "person, email, audit, privacy"
                ),
                relative_path=_TABLES_SOURCE,
            ),
            "vgi.result_columns_md": (
                "| column | type | description |\n"
                "|---|---|---|\n"
                "| `entity_type` | VARCHAR | Detected PII entity type, e.g. `PERSON`, `EMAIL_ADDRESS`. |\n"
                "| `text` | VARCHAR | The matched substring from the input. |\n"
                "| `start` | INTEGER | Start character offset (inclusive). |\n"
                "| `end_pos` | INTEGER | End character offset (exclusive). |\n"
                "| `score` | DOUBLE | Detection confidence in `[0, 1]`. |"
            ),
            "vgi.executable_examples": _EXECUTABLE_EXAMPLES,
        }
        examples = [
            FunctionExample(
                sql="SELECT * FROM pii.detect_pii('Call John Smith at john@example.com')",
                description="List every PII entity found in the text",
            ),
            FunctionExample(
                sql=("SELECT entity_type, text FROM pii.detect_pii('Email john@example.com', score_threshold := 0.8)"),
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
                    "## Usage\n\n"
                    "```sql\n"
                    "SELECT * FROM pii.supported_entities() ORDER BY entity_type;\n"
                    "SELECT count(*) FROM pii.supported_entities();\n"
                    "```\n\n"
                    "## Notes\n\n"
                    "Pass `language := '...'` to inspect the recognizers configured for another "
                    "language. The returned names are exactly the values `detect_pii.entity_type` "
                    "and `pii_types` can produce."
                ),
                keywords=(
                    "pii, supported_entities, entity types, recognizers, discovery, catalog, "
                    "coverage, person, email, privacy"
                ),
                relative_path=_TABLES_SOURCE,
            ),
            "vgi.result_columns_md": (
                "| column | type | description |\n"
                "|---|---|---|\n"
                "| `entity_type` | VARCHAR | An entity type the analyzer can detect, e.g. `PERSON`. |"
            ),
        }
        examples = [
            FunctionExample(
                sql="SELECT * FROM pii.supported_entities() ORDER BY entity_type",
                description="List every detectable PII entity type",
            ),
            FunctionExample(
                sql="SELECT count(*) FROM pii.supported_entities()",
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
