"""Integration tests for the pii table functions.

Drives ``detect_pii`` and ``supported_entities`` through the real
bind -> init -> process lifecycle in-process (no worker subprocess). The per-row
functions are *scalars* and are covered in ``test_scalars.py``.
"""

from __future__ import annotations

import pyarrow as pa

from vgi_pii.tables import DetectPiiFunction, SupportedEntitiesFunction

from .harness import invoke_table_function


class TestDetectPii:
    def test_columns_and_rows(self) -> None:
        table = invoke_table_function(
            DetectPiiFunction,
            positional=(pa.scalar("Call John Smith at john@example.com"),),
        )
        assert table.column_names == ["entity_type", "text", "start", "end_pos", "score"]
        types = table.column("entity_type").to_pylist()
        assert "PERSON" in types
        assert "EMAIL_ADDRESS" in types

    def test_offsets_and_score(self) -> None:
        text = "Email john@example.com"
        table = invoke_table_function(DetectPiiFunction, positional=(pa.scalar(text),))
        rows = table.to_pylist()
        email = next(r for r in rows if r["entity_type"] == "EMAIL_ADDRESS")
        assert text[email["start"] : email["end_pos"]] == email["text"]
        assert 0.0 <= email["score"] <= 1.0

    def test_empty_text_no_rows(self) -> None:
        table = invoke_table_function(DetectPiiFunction, positional=(pa.scalar(""),))
        assert table.num_rows == 0

    def test_clean_text_no_rows(self) -> None:
        table = invoke_table_function(DetectPiiFunction, positional=(pa.scalar("the quick brown fox"),))
        assert table.num_rows == 0

    def test_high_threshold_prunes(self) -> None:
        text = "Visit example.com today"
        low = invoke_table_function(
            DetectPiiFunction,
            positional=(pa.scalar(text),),
            named={"score_threshold": pa.scalar(0.0, type=pa.float64())},
        )
        high = invoke_table_function(
            DetectPiiFunction,
            positional=(pa.scalar(text),),
            named={"score_threshold": pa.scalar(0.95, type=pa.float64())},
        )
        assert high.num_rows <= low.num_rows


class TestSupportedEntities:
    def test_columns_and_nonempty(self) -> None:
        table = invoke_table_function(SupportedEntitiesFunction)
        assert table.column_names == ["entity_type"]
        assert table.num_rows > 5

    def test_known_entities_present(self) -> None:
        table = invoke_table_function(SupportedEntitiesFunction)
        ents = table.column("entity_type").to_pylist()
        assert "EMAIL_ADDRESS" in ents
        assert "PERSON" in ents
