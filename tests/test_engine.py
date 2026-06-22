"""Unit tests for the pure Presidio logic in ``vgi_pii.engine``.

These call the engine functions directly (no Arrow / VGI / subprocess), so they
exercise detection, redaction, masking, type listing, threshold behaviour, and a
strong battery of edge cases (multiple PII types, none, empty, NULL, unicode,
very long text). The analyzer/anonymizer build once and are cached, so the
first test pays the model-load cost and the rest are fast.
"""

from __future__ import annotations

from vgi_pii import engine

# A fixture sentence with several distinct PII types well above threshold.
MULTI = "Call John Smith at john@example.com about account 4095-2609-9393-4932."


class TestHasPii:
    def test_true_when_present(self) -> None:
        assert engine.has_pii(MULTI) is True

    def test_false_when_absent(self) -> None:
        assert engine.has_pii("the quick brown fox jumps") is False

    def test_null_and_empty(self) -> None:
        assert engine.has_pii(None) is None
        assert engine.has_pii("") is None
        assert engine.has_pii("   \t\n  ") is None


class TestPiiTypes:
    def test_multiple_types_sorted_distinct(self) -> None:
        types = engine.pii_types(MULTI)
        assert types is not None
        assert types == sorted(types)
        assert len(types) == len(set(types))
        assert "PERSON" in types
        assert "EMAIL_ADDRESS" in types
        assert "CREDIT_CARD" in types

    def test_none_for_clean_text(self) -> None:
        assert engine.pii_types("nothing to see here") == []

    def test_null(self) -> None:
        assert engine.pii_types(None) is None


class TestRedact:
    def test_tags_entities(self) -> None:
        out = engine.redact("Call John Smith at john@example.com")
        assert out is not None
        assert "<PERSON>" in out
        assert "<EMAIL_ADDRESS>" in out
        assert "john@example.com" not in out

    def test_clean_text_unchanged(self) -> None:
        assert engine.redact("the cat sat on the mat") == "the cat sat on the mat"

    def test_null_and_empty(self) -> None:
        assert engine.redact(None) is None
        assert engine.redact("") is None


class TestAnonymize:
    def test_masks_entities(self) -> None:
        out = engine.anonymize("Email john@example.com")
        assert out is not None
        assert "*" in out
        assert "john@example.com" not in out
        # No type tags leak from the mask operator.
        assert "<EMAIL_ADDRESS>" not in out

    def test_distinct_from_redact(self) -> None:
        text = "Call John at john@example.com"
        assert engine.anonymize(text) != engine.redact(text)

    def test_null(self) -> None:
        assert engine.anonymize(None) is None


class TestDetect:
    def test_rows_and_offsets(self) -> None:
        ents = engine.detect("Email john@example.com")
        assert ents
        email = next(e for e in ents if e.entity_type == "EMAIL_ADDRESS")
        # Offsets must slice back to the matched substring.
        assert "Email john@example.com"[email.start : email.end] == email.text
        assert email.text == "john@example.com"
        assert 0.0 <= email.score <= 1.0

    def test_sorted_by_start(self) -> None:
        ents = engine.detect(MULTI)
        starts = [e.start for e in ents]
        assert starts == sorted(starts)

    def test_empty_and_null(self) -> None:
        assert engine.detect(None) == []
        assert engine.detect("") == []
        assert engine.detect("plain words only") == []


class TestThreshold:
    def test_higher_threshold_drops_low_confidence(self) -> None:
        # A bare URL-ish token scores modestly; a high threshold prunes it.
        text = "Visit example.com for details"
        low = engine.detect(text, score_threshold=0.0)
        high = engine.detect(text, score_threshold=0.95)
        assert len(high) <= len(low)

    def test_threshold_monotonic_on_multi(self) -> None:
        assert len(engine.detect(MULTI, score_threshold=0.95)) <= len(
            engine.detect(MULTI, score_threshold=0.1)
        )


class TestSupportedEntities:
    def test_nonempty_sorted(self) -> None:
        ents = engine.supported_entities()
        assert len(ents) > 5
        assert ents == sorted(ents)
        assert "EMAIL_ADDRESS" in ents
        assert "PERSON" in ents


class TestEdgeCases:
    def test_unicode(self) -> None:
        # Accented names / IDNs must not crash and should still redact.
        out = engine.redact("Contact José at jose@example.com")
        assert out is not None
        assert "jose@example.com" not in out

    def test_very_long_text(self) -> None:
        big = ("My email is a@b.com. " * 2000) + "End."
        assert engine.has_pii(big) is True
        red = engine.redact(big)
        assert red is not None
        assert "a@b.com" not in red

    def test_no_crash_on_odd_input(self) -> None:
        for s in ["\x00\x01\x02", "🙂🎉", "a" * 10000, "...,,,;;;"]:
            # None of these should raise; result is bool/str/None as appropriate.
            assert engine.has_pii(s) in (True, False)
            assert engine.redact(s) is not None
