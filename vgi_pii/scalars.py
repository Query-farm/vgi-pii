"""Per-row scalar PII functions.

Every function here is a true DuckDB **scalar** -- one value (per row) in, one
value out -- so it can be used inline in any projection or predicate:

    SELECT has_pii(body)                      FROM messages;
    SELECT id, redact(body)                   FROM messages;
    SELECT anonymize(body)                    FROM messages;
    SELECT pii_types(body)                    FROM messages;

A note on argument syntax
-------------------------
VGI / DuckDB *scalar* functions take **positional** arguments and resolve
overloads by *arity* (the ``name := value`` named-argument syntax is a property
of table functions and macros, not scalars). The optional ``language`` argument
therefore cannot be a Python-style default on a single class; instead it is
exposed as its own arity overload that shares the function ``name`` -- the same
idiom the sibling ``vgi-conform`` worker uses for its optional ``region`` /
``country`` arguments. So, e.g.:

    redact(text)            -- language defaults to 'en'
    redact(text, language)  -- explicit language

NULL semantics: a NULL (or empty/whitespace-only) input row yields NULL output
for every scalar here. ``pii_types`` returns a ``VARCHAR[]`` (note the explicit
``Returns(arrow_type=...)`` -- the SDK requires it for LIST returns).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

import pyarrow as pa
from vgi.arguments import ConstParam, Param, Returns
from vgi.metadata import FunctionExample
from vgi.scalar_function import ScalarFunction

from . import engine

_DEFAULT_LANGUAGE = "en"


# ---------------------------------------------------------------------------
# Small mapping helpers: apply a pure ``str -> X`` function across an array,
# passing NULL straight through.
# ---------------------------------------------------------------------------


def _map_bool(arr: pa.StringArray, fn: Callable[[str], bool | None]) -> pa.BooleanArray:
    out = [None if x is None else fn(x) for x in arr.to_pylist()]
    return pa.array(out, type=pa.bool_())


def _map_str(arr: pa.StringArray, fn: Callable[[str], str | None]) -> pa.StringArray:
    out = [None if x is None else fn(x) for x in arr.to_pylist()]
    return pa.array(out, type=pa.string())


def _map_list(arr: pa.StringArray, fn: Callable[[str], list[str] | None]) -> pa.ListArray:
    out = [None if x is None else fn(x) for x in arr.to_pylist()]
    return pa.array(out, type=pa.list_(pa.string()))


# ===========================================================================
# has_pii
# ===========================================================================


class HasPiiFunction(ScalarFunction):
    """``has_pii(text)`` -- True if any PII entity is detected (language 'en')."""

    class Meta:
        name = "has_pii"
        description = "True if any PII entity is detected in text (language defaults to 'en')"
        categories = ["pii", "detect"]
        examples = [
            FunctionExample(
                sql="SELECT pii.has_pii('Call John Smith at john@example.com')",
                description="Detect whether text contains PII",
            ),
        ]

    @classmethod
    def compute(
        cls, text: Annotated[pa.StringArray, Param(doc="Text to scan for PII.")]
    ) -> Annotated[pa.BooleanArray, Returns()]:
        return _map_bool(text, lambda x: engine.has_pii(x, _DEFAULT_LANGUAGE))


class HasPiiLanguageFunction(ScalarFunction):
    """``has_pii(text, language)`` -- True if any PII entity is detected."""

    class Meta:
        name = "has_pii"
        description = "True if any PII entity is detected in text, in a given language"
        categories = ["pii", "detect"]
        examples = [
            FunctionExample(
                sql="SELECT pii.has_pii('Call John Smith at john@example.com', 'en')",
                description="Detect PII with an explicit language",
            ),
        ]

    @classmethod
    def compute(
        cls,
        text: Annotated[pa.StringArray, Param(doc="Text to scan for PII.")],
        language: Annotated[str, ConstParam("ISO language code, e.g. 'en'.")],
    ) -> Annotated[pa.BooleanArray, Returns()]:
        return _map_bool(text, lambda x: engine.has_pii(x, language))


# ===========================================================================
# redact -- replace each entity with its <TYPE> tag
# ===========================================================================


class RedactFunction(ScalarFunction):
    """``redact(text)`` -- replace each entity with its ``<TYPE>`` tag."""

    class Meta:
        name = "redact"
        description = "Replace each PII entity with its type tag, e.g. '<PERSON>' (language 'en')"
        categories = ["pii", "redact"]
        examples = [
            FunctionExample(
                sql="SELECT pii.redact('Call John Smith at john@example.com')",
                description="Tag-redact PII (-> 'Call <PERSON> at <EMAIL_ADDRESS>')",
            ),
        ]

    @classmethod
    def compute(
        cls, text: Annotated[pa.StringArray, Param(doc="Text to redact.")]
    ) -> Annotated[pa.StringArray, Returns()]:
        return _map_str(text, lambda x: engine.redact(x, _DEFAULT_LANGUAGE))


class RedactLanguageFunction(ScalarFunction):
    """``redact(text, language)`` -- tag-redact in a given language."""

    class Meta:
        name = "redact"
        description = "Replace each PII entity with its type tag, in a given language"
        categories = ["pii", "redact"]
        examples = [
            FunctionExample(
                sql="SELECT pii.redact('Call John Smith at john@example.com', 'en')",
                description="Tag-redact PII with an explicit language",
            ),
        ]

    @classmethod
    def compute(
        cls,
        text: Annotated[pa.StringArray, Param(doc="Text to redact.")],
        language: Annotated[str, ConstParam("ISO language code, e.g. 'en'.")],
    ) -> Annotated[pa.StringArray, Returns()]:
        return _map_str(text, lambda x: engine.redact(x, language))


# ===========================================================================
# anonymize -- replace each entity's characters with a '*' mask
# ===========================================================================


class AnonymizeFunction(ScalarFunction):
    """``anonymize(text)`` -- mask each entity's characters with ``*``."""

    class Meta:
        name = "anonymize"
        description = "Replace each PII entity's characters with a '*' mask (language 'en')"
        categories = ["pii", "redact"]
        examples = [
            FunctionExample(
                sql="SELECT pii.anonymize('Call John Smith at john@example.com')",
                description="Mask PII (-> 'Call **** at ****************')",
            ),
        ]

    @classmethod
    def compute(
        cls, text: Annotated[pa.StringArray, Param(doc="Text to anonymize.")]
    ) -> Annotated[pa.StringArray, Returns()]:
        return _map_str(text, lambda x: engine.anonymize(x, _DEFAULT_LANGUAGE))


class AnonymizeLanguageFunction(ScalarFunction):
    """``anonymize(text, language)`` -- mask each entity in a given language."""

    class Meta:
        name = "anonymize"
        description = "Replace each PII entity's characters with a '*' mask, in a given language"
        categories = ["pii", "redact"]
        examples = [
            FunctionExample(
                sql="SELECT pii.anonymize('Call John Smith at john@example.com', 'en')",
                description="Mask PII with an explicit language",
            ),
        ]

    @classmethod
    def compute(
        cls,
        text: Annotated[pa.StringArray, Param(doc="Text to anonymize.")],
        language: Annotated[str, ConstParam("ISO language code, e.g. 'en'.")],
    ) -> Annotated[pa.StringArray, Returns()]:
        return _map_str(text, lambda x: engine.anonymize(x, language))


# ===========================================================================
# pii_types -- distinct entity types present (LIST return)
# ===========================================================================


class PiiTypesFunction(ScalarFunction):
    """``pii_types(text)`` -- distinct entity types present, as ``VARCHAR[]``."""

    class Meta:
        name = "pii_types"
        description = "Distinct PII entity types present in text, as a sorted VARCHAR[] (language 'en')"
        categories = ["pii", "detect"]
        examples = [
            FunctionExample(
                sql="SELECT pii.pii_types('Call John Smith at john@example.com')",
                description="The distinct PII types in text (-> ['EMAIL_ADDRESS', 'PERSON'])",
            ),
        ]

    @classmethod
    def compute(
        cls, text: Annotated[pa.StringArray, Param(doc="Text to scan for PII types.")]
    ) -> Annotated[pa.ListArray, Returns(arrow_type=pa.list_(pa.string()))]:
        return _map_list(text, lambda x: engine.pii_types(x, _DEFAULT_LANGUAGE))


class PiiTypesLanguageFunction(ScalarFunction):
    """``pii_types(text, language)`` -- distinct entity types in a language."""

    class Meta:
        name = "pii_types"
        description = "Distinct PII entity types present in text, in a given language, as VARCHAR[]"
        categories = ["pii", "detect"]
        examples = [
            FunctionExample(
                sql="SELECT pii.pii_types('Call John Smith at john@example.com', 'en')",
                description="The distinct PII types in text, explicit language",
            ),
        ]

    @classmethod
    def compute(
        cls,
        text: Annotated[pa.StringArray, Param(doc="Text to scan for PII types.")],
        language: Annotated[str, ConstParam("ISO language code, e.g. 'en'.")],
    ) -> Annotated[pa.ListArray, Returns(arrow_type=pa.list_(pa.string()))]:
        return _map_list(text, lambda x: engine.pii_types(x, language))


SCALAR_FUNCTIONS: list[type] = [
    HasPiiFunction,
    HasPiiLanguageFunction,
    RedactFunction,
    RedactLanguageFunction,
    AnonymizeFunction,
    AnonymizeLanguageFunction,
    PiiTypesFunction,
    PiiTypesLanguageFunction,
]
