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
from .meta import object_tags

_DEFAULT_LANGUAGE = "en"

# Per-object discovery/description tags, shared by both arity overloads of each
# scalar (the no-language and explicit-language forms share a function name, so
# both must carry identical object-level metadata).
_HAS_PII_TAGS = object_tags(
    title="Detect PII Presence",
    doc_llm=(
        "## has_pii\n\n"
        "Return `true` when the input text contains **any** personally-identifiable "
        "information (PII) entity, otherwise `false`. Use it as a fast boolean predicate "
        "to flag or filter rows that need privacy handling, before deciding to redact or "
        "anonymize them.\n\n"
        "- **Input:** a `VARCHAR` of free text; an optional second argument is the ISO "
        "language code (defaults to `'en'`).\n"
        "- **Output:** `BOOLEAN` -- `true` if at least one entity (PERSON, EMAIL_ADDRESS, "
        "PHONE_NUMBER, CREDIT_CARD, US_SSN, LOCATION, URL, IP_ADDRESS, ...) is detected.\n"
        "- **Edge cases:** `NULL`, empty, or whitespace-only input returns `NULL`.\n\n"
        "Backed by Microsoft Presidio (analyzer) with the `en_core_web_sm` spaCy model."
    ),
    doc_md=(
        "# has_pii\n\n"
        "A scalar predicate that answers a single question: *does this text contain PII?* "
        "Call it inline in a projection to tag rows, or in a `WHERE` clause to keep only "
        "the rows that need privacy handling before they are shared, exported, or archived.\n\n"
        "## Behaviour\n\n"
        "- Returns `true` as soon as any entity (a person name, email, phone number, credit "
        "card, US SSN, location, URL, IP address, ...) is detected, otherwise `false`.\n"
        "- Pass an explicit ISO language as the optional second argument "
        "(`has_pii(text, 'en')`) to scan non-English text.\n"
        "- `NULL`, empty, or whitespace-only input yields `NULL` rather than `false`.\n\n"
        "See this function's example queries for a runnable demonstration."
    ),
    keywords=[
        "pii",
        "has_pii",
        "detect",
        "contains pii",
        "sensitive data",
        "privacy",
        "dlp",
        "predicate",
        "boolean",
    ],
    category="detection",
)

_REDACT_TAGS = object_tags(
    title="Redact PII With Type Tags",
    doc_llm=(
        "## redact\n\n"
        "Return the input text with every detected PII span replaced by a tag naming its "
        "entity type, e.g. `<PERSON>` or `<EMAIL_ADDRESS>`. Use it when you want a "
        "human-readable, *self-documenting* scrub that preserves which kind of value was "
        "removed (useful for audit, debugging, and downstream classification).\n\n"
        "- **Input:** a `VARCHAR` of free text; an optional second argument is the ISO "
        "language code (defaults to `'en'`).\n"
        "- **Output:** `VARCHAR` -- the same text with each entity replaced by `<TYPE>`.\n"
        "- **Example:** `'Call John Smith at john@example.com'` -> "
        "`'Call <PERSON> at <EMAIL_ADDRESS>'`.\n"
        "- **Edge cases:** `NULL`, empty, or whitespace-only input returns `NULL`; text "
        "with no PII is returned unchanged.\n\n"
        "Contrast with `anonymize`, which masks characters (`****`) instead of labelling "
        "them. Backed by Microsoft Presidio (analyzer + anonymizer)."
    ),
    doc_md=(
        "# redact\n\n"
        "Replace each PII entity in text with a tag that names its type, leaving the "
        "surrounding text intact.\n\n"
        "## Usage\n\n"
        "```sql\n"
        "SELECT pii.main.redact('Call John Smith at john@example.com');\n"
        "-- 'Call <PERSON> at <EMAIL_ADDRESS>'\n"
        "```\n\n"
        "## Notes\n\n"
        "Use `redact` when you want to know *what kind* of value was removed; use "
        "`anonymize` when you want the value's shape hidden behind a `*` mask. Accepts an "
        "explicit language as the second argument. NULL/blank input yields NULL."
    ),
    keywords=[
        "pii",
        "redact",
        "mask",
        "replace",
        "scrub",
        "type tag",
        "person",
        "email",
        "privacy",
        "sanitize",
    ],
    category="redaction",
)

_ANONYMIZE_TAGS = object_tags(
    title="Anonymize PII With Character Mask",
    doc_llm=(
        "## anonymize\n\n"
        "Return the input text with every detected PII span overwritten character-for-"
        "character by a `*` mask, so the value is hidden but its length/position is "
        "preserved. Use it for display or export where the *shape* of the data can remain "
        "but the value must not.\n\n"
        "- **Input:** a `VARCHAR` of free text; an optional second argument is the ISO "
        "language code (defaults to `'en'`).\n"
        "- **Output:** `VARCHAR` -- the same text with each entity replaced by `*` characters.\n"
        "- **Example:** `'Call John Smith at john@example.com'` -> "
        "`'Call **** at ****************'`.\n"
        "- **Edge cases:** `NULL`, empty, or whitespace-only input returns `NULL`; text "
        "with no PII is returned unchanged.\n\n"
        "Contrast with `redact`, which labels each entity with a `<TYPE>` tag. Backed by "
        "Microsoft Presidio (analyzer + anonymizer)."
    ),
    doc_md=(
        "# anonymize\n\n"
        "Mask each PII entity in text with `*` characters, hiding the value while keeping "
        "the rest of the text readable.\n\n"
        "## Usage\n\n"
        "```sql\n"
        "SELECT pii.main.anonymize('Call John Smith at john@example.com');\n"
        "-- 'Call **** at ****************'\n"
        "```\n\n"
        "## Notes\n\n"
        "Choose `anonymize` over `redact` when the type label `<PERSON>` would itself leak "
        "structure you want hidden. Accepts an explicit language as the second argument. "
        "NULL/blank input yields NULL."
    ),
    keywords=[
        "pii",
        "anonymize",
        "mask",
        "asterisk",
        "obfuscate",
        "hide",
        "scrub",
        "privacy",
        "sanitize",
        "redact",
    ],
    category="redaction",
)

_PII_TYPES_TAGS = object_tags(
    title="List Distinct PII Types",
    doc_llm=(
        "## pii_types\n\n"
        "Return the **distinct** PII entity types present in the input text as a sorted "
        "`VARCHAR[]`. Use it to summarise what categories of sensitive data a value "
        "contains -- e.g. to drive routing, alerting, or per-type handling -- without "
        "needing the per-span detail of `detect_pii`.\n\n"
        "- **Input:** a `VARCHAR` of free text; an optional second argument is the ISO "
        "language code (defaults to `'en'`).\n"
        "- **Output:** `VARCHAR[]` -- the sorted, de-duplicated set of detected entity "
        "type names, e.g. `['EMAIL_ADDRESS', 'PERSON']`.\n"
        "- **Edge cases:** `NULL`, empty, or whitespace-only input returns `NULL`; text "
        "with no PII returns an empty list.\n\n"
        "For one row per occurrence (with offsets and confidence) use the `detect_pii` "
        "table function instead. Backed by Microsoft Presidio."
    ),
    doc_md=(
        "# pii_types\n\n"
        "Return the set of PII entity types found in text, sorted and de-duplicated, as a "
        "`VARCHAR[]`.\n\n"
        "## Usage\n\n"
        "```sql\n"
        "SELECT pii.main.pii_types('Call John Smith at john@example.com');\n"
        "-- ['EMAIL_ADDRESS', 'PERSON']\n"
        "```\n\n"
        "## Notes\n\n"
        "This is a compact summary; for per-occurrence detail (matched text, offsets, "
        "confidence) use `detect_pii`. Accepts an explicit language as the second "
        "argument. NULL/blank input yields NULL; PII-free text yields an empty list."
    ),
    keywords=[
        "pii",
        "pii_types",
        "entity types",
        "categories",
        "list",
        "distinct",
        "classify",
        "privacy",
        "summary",
    ],
    category="detection",
)


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
        """Function metadata."""

        name = "has_pii"
        description = "True if any PII entity is detected in text (language defaults to 'en')"
        categories = ["pii", "detect"]
        tags = _HAS_PII_TAGS
        examples = [
            FunctionExample(
                sql="SELECT pii.main.has_pii('Call John Smith at john@example.com')",
                description="Detect whether text contains PII",
            ),
        ]

    @classmethod
    def compute(
        cls, text: Annotated[pa.StringArray, Param(doc="Text to scan for PII.")]
    ) -> Annotated[pa.BooleanArray, Returns()]:
        """Map each input row to its output value."""
        return _map_bool(text, lambda x: engine.has_pii(x, _DEFAULT_LANGUAGE))


class HasPiiLanguageFunction(ScalarFunction):
    """``has_pii(text, language)`` -- True if any PII entity is detected."""

    class Meta:
        """Function metadata."""

        name = "has_pii"
        description = "True if any PII entity is detected in text, in a given language"
        categories = ["pii", "detect"]
        tags = _HAS_PII_TAGS
        examples = [
            FunctionExample(
                sql="SELECT pii.main.has_pii('Call John Smith at john@example.com', 'en')",
                description="Detect PII with an explicit language",
            ),
        ]

    @classmethod
    def compute(
        cls,
        text: Annotated[pa.StringArray, Param(doc="Text to scan for PII.")],
        language: Annotated[str, ConstParam("ISO language code, e.g. 'en'.")],
    ) -> Annotated[pa.BooleanArray, Returns()]:
        """Map each input row to its output value."""
        return _map_bool(text, lambda x: engine.has_pii(x, language))


# ===========================================================================
# redact -- replace each entity with its <TYPE> tag
# ===========================================================================


class RedactFunction(ScalarFunction):
    """``redact(text)`` -- replace each entity with its ``<TYPE>`` tag."""

    class Meta:
        """Function metadata."""

        name = "redact"
        description = "Replace each PII entity with its type tag, e.g. '<PERSON>' (language 'en')"
        categories = ["pii", "redact"]
        tags = _REDACT_TAGS
        examples = [
            FunctionExample(
                sql="SELECT pii.main.redact('Call John Smith at john@example.com')",
                description="Tag-redact PII (-> 'Call <PERSON> at <EMAIL_ADDRESS>')",
            ),
        ]

    @classmethod
    def compute(
        cls, text: Annotated[pa.StringArray, Param(doc="Text to redact.")]
    ) -> Annotated[pa.StringArray, Returns()]:
        """Map each input row to its output value."""
        return _map_str(text, lambda x: engine.redact(x, _DEFAULT_LANGUAGE))


class RedactLanguageFunction(ScalarFunction):
    """``redact(text, language)`` -- tag-redact in a given language."""

    class Meta:
        """Function metadata."""

        name = "redact"
        description = "Replace each PII entity with its type tag, in a given language"
        categories = ["pii", "redact"]
        tags = _REDACT_TAGS
        examples = [
            FunctionExample(
                sql="SELECT pii.main.redact('Call John Smith at john@example.com', 'en')",
                description="Tag-redact PII with an explicit language",
            ),
        ]

    @classmethod
    def compute(
        cls,
        text: Annotated[pa.StringArray, Param(doc="Text to redact.")],
        language: Annotated[str, ConstParam("ISO language code, e.g. 'en'.")],
    ) -> Annotated[pa.StringArray, Returns()]:
        """Map each input row to its output value."""
        return _map_str(text, lambda x: engine.redact(x, language))


# ===========================================================================
# anonymize -- replace each entity's characters with a '*' mask
# ===========================================================================


class AnonymizeFunction(ScalarFunction):
    """``anonymize(text)`` -- mask each entity's characters with ``*``."""

    class Meta:
        """Function metadata."""

        name = "anonymize"
        description = "Replace each PII entity's characters with a '*' mask (language 'en')"
        categories = ["pii", "redact"]
        tags = _ANONYMIZE_TAGS
        examples = [
            FunctionExample(
                sql="SELECT pii.main.anonymize('Call John Smith at john@example.com')",
                description="Mask PII (-> 'Call **** at ****************')",
            ),
        ]

    @classmethod
    def compute(
        cls, text: Annotated[pa.StringArray, Param(doc="Text to anonymize.")]
    ) -> Annotated[pa.StringArray, Returns()]:
        """Map each input row to its output value."""
        return _map_str(text, lambda x: engine.anonymize(x, _DEFAULT_LANGUAGE))


class AnonymizeLanguageFunction(ScalarFunction):
    """``anonymize(text, language)`` -- mask each entity in a given language."""

    class Meta:
        """Function metadata."""

        name = "anonymize"
        description = "Replace each PII entity's characters with a '*' mask, in a given language"
        categories = ["pii", "redact"]
        tags = _ANONYMIZE_TAGS
        examples = [
            FunctionExample(
                sql="SELECT pii.main.anonymize('Call John Smith at john@example.com', 'en')",
                description="Mask PII with an explicit language",
            ),
        ]

    @classmethod
    def compute(
        cls,
        text: Annotated[pa.StringArray, Param(doc="Text to anonymize.")],
        language: Annotated[str, ConstParam("ISO language code, e.g. 'en'.")],
    ) -> Annotated[pa.StringArray, Returns()]:
        """Map each input row to its output value."""
        return _map_str(text, lambda x: engine.anonymize(x, language))


# ===========================================================================
# pii_types -- distinct entity types present (LIST return)
# ===========================================================================


class PiiTypesFunction(ScalarFunction):
    """``pii_types(text)`` -- distinct entity types present, as ``VARCHAR[]``."""

    class Meta:
        """Function metadata."""

        name = "pii_types"
        description = "Distinct PII entity types present in text, as a sorted VARCHAR[] (language 'en')"
        categories = ["pii", "detect"]
        tags = _PII_TYPES_TAGS
        examples = [
            FunctionExample(
                sql="SELECT pii.main.pii_types('Call John Smith at john@example.com')",
                description="The distinct PII types in text (-> ['EMAIL_ADDRESS', 'PERSON'])",
            ),
        ]

    @classmethod
    def compute(
        cls, text: Annotated[pa.StringArray, Param(doc="Text to scan for PII types.")]
    ) -> Annotated[pa.ListArray, Returns(arrow_type=pa.list_(pa.string()))]:
        """Map each input row to its output value."""
        return _map_list(text, lambda x: engine.pii_types(x, _DEFAULT_LANGUAGE))


class PiiTypesLanguageFunction(ScalarFunction):
    """``pii_types(text, language)`` -- distinct entity types in a language."""

    class Meta:
        """Function metadata."""

        name = "pii_types"
        description = "Distinct PII entity types present in text, in a given language, as VARCHAR[]"
        categories = ["pii", "detect"]
        tags = _PII_TYPES_TAGS
        examples = [
            FunctionExample(
                sql="SELECT pii.main.pii_types('Call John Smith at john@example.com', 'en')",
                description="The distinct PII types in text, explicit language",
            ),
        ]

    @classmethod
    def compute(
        cls,
        text: Annotated[pa.StringArray, Param(doc="Text to scan for PII types.")],
        language: Annotated[str, ConstParam("ISO language code, e.g. 'en'.")],
    ) -> Annotated[pa.ListArray, Returns(arrow_type=pa.list_(pa.string()))]:
        """Map each input row to its output value."""
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
