"""Section 7 leak 10: glc.db.log_call() validated nothing, so any
in-process caller could write an arbitrary token count into the cost
ledger invariant 8's budget checks are computed from."""

from __future__ import annotations

import pytest

import glc.db as db


def test_log_call_accepts_plausible_token_counts():
    db.log_call(provider="gemini", model="x", input_tokens=1000, output_tokens=500, status="ok")
    rows = db.recent(limit=1)
    assert rows[0]["input_tokens"] == 1000


def test_log_call_rejects_absurd_token_count():
    with pytest.raises(ValueError, match="plausible range"):
        db.log_call(provider="gemini", model="x", input_tokens=999_999_999, agent="victim", status="ok")


def test_log_call_rejects_negative_token_count():
    with pytest.raises(ValueError, match="plausible range"):
        db.log_call(provider="gemini", model="x", input_tokens=-5, status="ok")
