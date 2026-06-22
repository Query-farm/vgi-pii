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
from .schema_utils import field

_LANGUAGE = Arg[str]("language", default="en", doc="ISO language code (e.g. 'en').")
_SCORE_THRESHOLD = Arg[float](
    "score_threshold",
    default=engine.DEFAULT_SCORE_THRESHOLD,
    arrow_type=pa.float64(),
    doc="Minimum detection confidence in [0, 1] (default 0.5).",
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
        name = "detect_pii"
        description = "One row per detected PII entity (entity_type, text, start, end_pos, score)"
        categories = ["pii", "detect"]
        examples = [
            FunctionExample(
                sql="SELECT * FROM pii.detect_pii('Call John Smith at john@example.com')",
                description="List every PII entity found in the text",
            ),
            FunctionExample(
                sql=(
                    "SELECT entity_type, text FROM "
                    "pii.detect_pii('Email john@example.com', score_threshold := 0.8)"
                ),
                description="Only high-confidence detections",
            ),
        ]

    @classmethod
    def cardinality(cls, params: BindParams[_DetectPiiArgs]) -> TableCardinality:
        return TableCardinality(estimate=4, max=None)

    @classmethod
    def process(cls, params: ProcessParams[_DetectPiiArgs], state: None, out: OutputCollector) -> None:
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
        name = "supported_entities"
        description = "Every PII entity type the analyzer can detect (PERSON, EMAIL_ADDRESS, ...)"
        categories = ["pii", "detect"]
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
        return TableCardinality(estimate=25, max=200)

    @classmethod
    def process(
        cls, params: ProcessParams[_SupportedEntitiesArgs], state: None, out: OutputCollector
    ) -> None:
        rows = engine.supported_entities(params.args.language)
        out.emit(pa.RecordBatch.from_pydict({"entity_type": rows}, schema=params.output_schema))
        out.finish()


TABLE_FUNCTIONS: list[type] = [
    DetectPiiFunction,
    SupportedEntitiesFunction,
]
