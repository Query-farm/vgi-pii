"""End-to-end tests for the per-row scalar pii functions.

These spawn ``pii_worker.py`` as a subprocess via ``vgi.client.Client`` and call
each scalar exactly as DuckDB would after ``ATTACH``, exercising the arity
overloads (``has_pii(text)`` / ``has_pii(text, language)`` and the like). The
``text`` column travels in the input batch (a ``Param``); only the constant
``language`` argument goes in ``positional``.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pyarrow as pa
import pytest
from vgi import Arguments
from vgi.client import Client

_WORKER = str(Path(__file__).resolve().parent.parent / "pii_worker.py")


@pytest.fixture(scope="module")
def client() -> Iterator[Client]:
    # Current interpreter (deps already installed) + worker_limit=1 so output
    # order matches input order for deterministic per-row assertions.
    with Client(f"{sys.executable} {_WORKER}", worker_limit=1) as c:
        yield c


def _scalar(client: Client, name: str, values: list, *, positional: list[pa.Scalar] | None = None) -> list:
    batch = pa.RecordBatch.from_pydict({"t": pa.array(values, type=pa.string())})
    results = list(
        client.scalar_function(
            function_name=name,
            input=iter([batch]),
            arguments=Arguments(positional=positional or []),
        )
    )
    return results[0]["result"].to_pylist()


class TestHasPii:
    def test_detect(self, client: Client) -> None:
        out = _scalar(client, "has_pii", ["Call John at john@example.com", "the cat sat", None])
        assert out == [True, False, None]

    def test_language_overload(self, client: Client) -> None:
        out = _scalar(client, "has_pii", ["Email a@b.com"], positional=[pa.scalar("en")])
        assert out == [True]


class TestRedact:
    def test_tags(self, client: Client) -> None:
        out = _scalar(client, "redact", ["Call John Smith at john@example.com"])[0]
        assert "<PERSON>" in out
        assert "<EMAIL_ADDRESS>" in out
        assert "john@example.com" not in out

    def test_null_and_clean(self, client: Client) -> None:
        assert _scalar(client, "redact", [None]) == [None]
        assert _scalar(client, "redact", ["just words"]) == ["just words"]

    def test_language_overload(self, client: Client) -> None:
        out = _scalar(client, "redact", ["Email john@example.com"], positional=[pa.scalar("en")])[0]
        assert "<EMAIL_ADDRESS>" in out


class TestAnonymize:
    def test_masks(self, client: Client) -> None:
        out = _scalar(client, "anonymize", ["Email john@example.com"])[0]
        assert "*" in out
        assert "john@example.com" not in out
        assert "<EMAIL_ADDRESS>" not in out

    def test_null(self, client: Client) -> None:
        assert _scalar(client, "anonymize", [None]) == [None]


class TestPiiTypes:
    def test_distinct_sorted_list(self, client: Client) -> None:
        out = _scalar(client, "pii_types", ["Call John Smith at john@example.com"])[0]
        assert isinstance(out, list)
        assert out == sorted(out)
        assert "PERSON" in out
        assert "EMAIL_ADDRESS" in out

    def test_null_and_clean(self, client: Client) -> None:
        assert _scalar(client, "pii_types", [None]) == [None]
        assert _scalar(client, "pii_types", ["nothing here"]) == [[]]

    def test_language_overload(self, client: Client) -> None:
        out = _scalar(client, "pii_types", ["Email a@b.com"], positional=[pa.scalar("en")])[0]
        assert "EMAIL_ADDRESS" in out
