"""The documented outputs in scalar example descriptions match the engine.

Descriptions such as ``Mask PII (-> 'Call ********** at ****************')``
state the exact result of their example query; this keeps those claims honest
(they once said ``'Call **** at ...'`` and ``['EMAIL_ADDRESS', 'PERSON']``, but
the mask is per character and the email's domain is also detected as ``URL``).
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from vgi_pii import engine
from vgi_pii.scalars import SCALAR_FUNCTIONS

_CLAIM = re.compile(r"\(-> (.+)\)\.?$")
_CALL = re.compile(r"^SELECT pii\.main\.(\w+)\('([^']*)'\)$")


def _claims() -> list[tuple[str, str, str]]:
    out = []
    for fn in SCALAR_FUNCTIONS:
        for ex in fn.Meta.examples:
            claim, call = _CLAIM.search(ex.description), _CALL.match(ex.sql)
            if claim and call:
                out.append((call.group(1), call.group(2), claim.group(1)))
    return out


def test_claims_found() -> None:
    assert {name for name, _, _ in _claims()} >= {"redact", "anonymize", "pii_types"}


@pytest.mark.parametrize(("name", "text", "claim"), _claims())
def test_documented_output_matches(name: str, text: str, claim: str) -> None:
    result: Any = getattr(engine, name)(text)
    assert repr(result) == claim
