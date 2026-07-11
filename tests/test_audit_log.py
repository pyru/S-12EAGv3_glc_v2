"""Append-only audit log — write correctness, restart survival,
no-update/no-delete surface."""

from __future__ import annotations

import sqlite3

import pytest

from glc.audit import store
from glc.audit.store import AuditStore, _resolve_path, append, init_store, query, schema_version


def test_init_then_append():
    init_store()
    rid = append(
        channel="telegram",
        channel_user_id="42",
        trust_level="owner_paired",
        event_type="inbound_message",
        session_id="s1",
        params={"text": "hi"},
    )
    assert rid > 0
    rows = query(limit=5)
    assert len(rows) == 1
    assert rows[0]["channel"] == "telegram"
    assert rows[0]["event_type"] == "inbound_message"


def test_write_survives_restart(monkeypatch, tmp_path):
    init_store()
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="boot")
    store._singleton = None  # simulate process restart
    rows = query(limit=10)
    assert len(rows) == 1


def test_store_exposes_no_update_or_delete():
    s = AuditStore()
    assert not hasattr(s, "update")
    assert not hasattr(s, "delete")
    public = [n for n in dir(s) if not n.startswith("_")]
    assert "append" in public
    assert len([n for n in public if n in ("update", "delete", "modify")]) == 0


def test_delete_from_audit_log_is_blocked_at_the_db_layer():
    """Section 7 leak 2: sqlite3.connect(...).execute("DELETE FROM
    audit_log") from any in-process code — not just glc.audit.store's
    own API. The append-only guarantee must hold at the database layer,
    not only because glc's Python wrapper doesn't expose a delete()."""
    init_store()
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="probe")
    assert len(query(limit=10)) == 1

    conn = sqlite3.connect(_resolve_path())
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("DELETE FROM audit_log")
        conn.commit()
    conn.close()

    assert len(query(limit=10)) == 1


def test_update_of_audit_log_is_blocked_at_the_db_layer():
    init_store()
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="probe")

    conn = sqlite3.connect(_resolve_path())
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("UPDATE audit_log SET event_type='tampered'")
        conn.commit()
    conn.close()

    assert query(limit=10)[0]["event_type"] == "probe"


def test_schema_version_is_one():
    init_store()
    assert schema_version() == 1


def test_query_filters_by_session_and_channel():
    init_store()
    append(
        channel="discord", channel_user_id="1", trust_level="owner_paired", event_type="x", session_id="s-A"
    )
    append(
        channel="telegram", channel_user_id="1", trust_level="owner_paired", event_type="x", session_id="s-B"
    )
    rows = query(session_id="s-A")
    assert len(rows) == 1
    assert rows[0]["channel"] == "discord"
    rows = query(channel="telegram")
    assert len(rows) == 1


def test_jsonifies_complex_params():
    init_store()
    append(
        channel="x",
        channel_user_id="1",
        trust_level="owner_paired",
        event_type="x",
        params={"nested": {"k": [1, 2, 3]}},
    )
    rows = query(limit=1)
    assert "nested" in rows[0]["params_json"]
