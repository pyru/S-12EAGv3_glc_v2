"""Data-plane auth, rate limiting, and budget enforcement.

Covers Section 6 findings A1/A2 (no auth), C5 (no rate limit or budget),
and invariant 4's scoped-credential mechanism.
"""

from __future__ import annotations


def test_chat_without_credential_is_401(app_client):
    r = app_client.post("/v1/chat", json={"prompt": "hi"})
    assert r.status_code == 401


def test_credential_wrong_tool_is_rejected(app_client, data_plane_headers):
    import glc.security.credentials as creds

    token = creds.mint("test", tool="not_data_plane")
    r = app_client.post("/v1/chat", json={"prompt": "hi"}, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403


def test_credential_is_single_use(app_client, data_plane_headers):
    headers = data_plane_headers()
    r1 = app_client.get("/v1/status", headers=headers)
    r2 = app_client.get("/v1/status", headers=headers)
    assert r1.status_code == 200
    assert r2.status_code == 403


def test_mint_credential_requires_bootstrap_key(app_client):
    r = app_client.post("/v1/internal/credential", headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 403
    r = app_client.post("/v1/internal/credential")
    assert r.status_code == 401


def test_data_plane_rate_limit_trips(app_client, data_plane_headers):
    # default messages_per_minute is 30 (glc/channels.yaml defaults);
    # the 31st read in the same minute must be rejected.
    last = None
    for _ in range(31):
        last = app_client.get("/v1/status", headers=data_plane_headers())
    assert last.status_code == 429


def test_data_plane_budget_exhausted_returns_402(app_client, data_plane_headers, monkeypatch):
    import glc.db as db

    monkeypatch.setenv("GLC_DAILY_TOKEN_BUDGET", "1000")
    db.log_call(provider="gemini", model="x", input_tokens=900, output_tokens=200, status="ok")
    r = app_client.post("/v1/chat", json={"prompt": "hi"}, headers=data_plane_headers())
    assert r.status_code == 402
