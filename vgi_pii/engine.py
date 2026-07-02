"""Presidio engine lifecycle + pure PII logic: load once, cache for the process.

VGI keeps the worker process alive across queries, so the expensive thing a
PII worker does -- building Presidio's ``AnalyzerEngine`` (which loads a spaCy
model, ~1-2 s) -- happens **once** and is amortised over every row of every
query. This module owns that caching: the scalar/table functions only ask for
"analyze / redact / mask this text" and get an answer back.

Pinned model
------------
The analyzer is wired to the **``en_core_web_sm``** spaCy pipeline explicitly
(via :class:`~presidio_analyzer.nlp_engine.NlpEngineProvider`). Without an
explicit NLP config Presidio defaults to ``en_core_web_lg`` (~400 MB) and will
try to *download* it on first use -- a slow, network-dependent surprise. Pinning
the small model (~12 MB, installed as a wheel dependency) keeps the worker
hermetic, light, and deterministic.

Everything here is pure (no Arrow / VGI types) and directly unit-testable. All
functions are **total**: NULL/empty text yields an empty result / ``None`` and
no input ever raises out of this module.
"""

from __future__ import annotations

import threading
from functools import lru_cache
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:  # pragma: no cover - typing only
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine

# The single spaCy pipeline this worker pins. Small (~12 MB), MIT, fast.
SPACY_MODEL = "en_core_web_sm"

# Default analyzer detection threshold (Presidio's own default is 0.0, which
# surfaces low-confidence guesses; 0.5 is a sensible, documented default that
# matches the table function's ``score_threshold`` default).
DEFAULT_SCORE_THRESHOLD = 0.5

# Tag operator wraps each entity as ``<ENTITY_TYPE>`` (Presidio's default
# "replace" behaviour). Mask operator overwrites every char of each entity with
# a single masking character.
_MASK_CHAR = "*"

_lock = threading.Lock()


class Entity(NamedTuple):
    """One detected PII span: ``(entity_type, text, start, end, score)``.

    ``start``/``end`` are character offsets into the original text (``end`` is
    exclusive, matching Presidio / Python slicing); ``text`` is the matched
    substring; ``score`` is the detection confidence in ``[0, 1]``.
    """

    entity_type: str
    text: str
    start: int
    end: int
    score: float


# ---------------------------------------------------------------------------
# Engine construction (cached, thread-safe)
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _analyzer() -> AnalyzerEngine:
    """The Presidio ``AnalyzerEngine``, built once with the pinned spaCy model."""
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    provider = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": SPACY_MODEL}],
        }
    )
    nlp_engine = provider.create_engine()
    return AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])


@lru_cache(maxsize=1)
def _anonymizer() -> AnonymizerEngine:
    """The Presidio ``AnonymizerEngine``, built once (stateless, but cached)."""
    from presidio_anonymizer import AnonymizerEngine

    # AnonymizerEngine() takes no required args; presidio is untyped so mypy
    # cannot see the no-arg constructor and flags it as an untyped call.
    return AnonymizerEngine()  # type: ignore[no-untyped-call]


def analyzer() -> AnalyzerEngine:
    """Thread-safe accessor for the cached analyzer (serialises first build)."""
    with _lock:
        return _analyzer()


def anonymizer() -> AnonymizerEngine:
    """Thread-safe accessor for the cached anonymizer."""
    with _lock:
        return _anonymizer()


def warm_up() -> None:
    """Build the analyzer + anonymizer eagerly at worker startup.

    Everything here is lazy by design, so the *first* query of every ATTACH
    otherwise pays the Presidio/spaCy build cost (~1-2 s) inline. Under the
    end-to-end SQL suite that load happens while the runner is mid-assertion on
    the first file -- a long window in which a worker-pool teardown SIGTERM (or a
    heavily-loaded host) can kill the run and record a spurious failure, making
    the suite flaky even though every output is deterministic.

    Warming here moves that one-time cost to process spawn, before any query is
    issued. It only populates the existing caches -- it never changes an output.
    Best-effort: a missing model is not fatal here (the relevant function will
    raise its own actionable error if actually invoked).

    Beyond building the engines, it runs one throwaway analyze+anonymize on a
    sample string. Presidio loads its recognizer registry and spaCy inference
    graph lazily on the *first* ``analyze`` call (several seconds), not when the
    engine object is constructed; exercising that path once here keeps the first
    real query fast instead of paying ~10-20 s inline.
    """
    try:
        analyzer()
        anonymizer()
        # Trigger the lazy recognizer/NLP-inference path once so the first real
        # query is warm. Output is discarded; failures are non-fatal.
        _anonymize("Warm up john@example.com", "en", DEFAULT_SCORE_THRESHOLD, operators=None)
    except Exception:  # pragma: no cover - best-effort warmup
        pass


# ---------------------------------------------------------------------------
# Pure logic -- one text in, an answer out. NULL/empty -> empty/None.
# ---------------------------------------------------------------------------


def _has_text(text: str | None) -> bool:
    return bool(text and text.strip())


def detect(
    text: str | None,
    language: str = "en",
    score_threshold: float = DEFAULT_SCORE_THRESHOLD,
) -> list[Entity]:
    """All PII entities in ``text`` at/above ``score_threshold``.

    Returns ``[]`` for NULL/empty text. Never raises: any analyzer error for an
    odd input degrades to an empty result so the worker can't crash on a row.
    Results are returned in a deterministic order (by start, then entity type).
    """
    if not _has_text(text):
        return []
    assert text is not None  # for type-checkers; guarded by _has_text
    try:
        results = analyzer().analyze(text=text, language=language, score_threshold=score_threshold)
    except Exception:
        return []
    entities = [
        Entity(
            entity_type=r.entity_type,
            text=text[r.start : r.end],
            start=r.start,
            end=r.end,
            score=float(r.score),
        )
        for r in results
    ]
    entities.sort(key=lambda e: (e.start, e.entity_type, e.end))
    return entities


def has_pii(
    text: str | None,
    language: str = "en",
    score_threshold: float = DEFAULT_SCORE_THRESHOLD,
) -> bool | None:
    """``True`` if any PII entity is detected; ``None`` for NULL/empty text."""
    if not _has_text(text):
        return None
    return len(detect(text, language, score_threshold)) > 0


def pii_types(
    text: str | None,
    language: str = "en",
    score_threshold: float = DEFAULT_SCORE_THRESHOLD,
) -> list[str] | None:
    """Distinct entity types present, sorted; ``None`` for NULL/empty text."""
    if not _has_text(text):
        return None
    return sorted({e.entity_type for e in detect(text, language, score_threshold)})


def _anonymize(
    text: str | None,
    language: str,
    score_threshold: float,
    operators: dict[str, Any] | None,
) -> str | None:
    """Shared anonymize path for :func:`redact` / :func:`anonymize`."""
    if not _has_text(text):
        return None
    assert text is not None
    try:
        results = analyzer().analyze(text=text, language=language, score_threshold=score_threshold)
        if not results:
            return text
        # Presidio re-exports RecognizerResult under two module paths that mypy
        # sees as distinct; analyzer results are exactly what anonymize expects.
        return (
            anonymizer()
            .anonymize(
                text=text,
                analyzer_results=results,  # type: ignore[arg-type]
                operators=operators,
            )
            .text
        )
    except Exception:
        # Never crash a row: fall back to returning the text unchanged.
        return text


def redact(
    text: str | None,
    language: str = "en",
    score_threshold: float = DEFAULT_SCORE_THRESHOLD,
) -> str | None:
    """Replace each entity with its type tag, e.g. ``<PERSON>``/``<EMAIL_ADDRESS>``.

    Uses Presidio's default ("replace") operator. ``None`` for NULL/empty text;
    text with no detected PII is returned unchanged.
    """
    return _anonymize(text, language, score_threshold, operators=None)


def anonymize(
    text: str | None,
    language: str = "en",
    score_threshold: float = DEFAULT_SCORE_THRESHOLD,
) -> str | None:
    """Replace each entity's characters with a ``*`` mask (a distinct operator).

    ``None`` for NULL/empty text; text with no detected PII is returned
    unchanged.
    """
    from presidio_anonymizer.entities import OperatorConfig

    operators = {
        "DEFAULT": OperatorConfig(
            "mask",
            {"masking_char": _MASK_CHAR, "chars_to_mask": 1_000_000, "from_end": False},
        )
    }
    return _anonymize(text, language, score_threshold, operators=operators)


def supported_entities(language: str = "en") -> list[str]:
    """Every entity type the analyzer can detect for ``language``, sorted."""
    try:
        return sorted(analyzer().get_supported_entities(language=language))
    except Exception:
        return []
