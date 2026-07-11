"""WS /v1/channels/{name} — Section 6/7 findings C2/leak 9 (cross-channel
envelope spoofing) and C3 (auth token in the query string)."""

from __future__ import annotations

import json
from datetime import datetime, timezone


def _envelope(channel: str, user_id: str = "u1", text: str = "hi") -> dict:
    return {
        "channel": channel,
        "channel_user_id": user_id,
        "user_handle": "u",
        "text": text,
        "trust_level": "untrusted",
        "arrived_at": datetime.now(timezone.utc).isoformat(),
    }


def test_channel_mismatch_is_rejected(app_client, install_token):
    from glc.security.pairing import get_pairing_store

    get_pairing_store().force_pair_owner("webui", "u1", user_handle="u")
    with app_client.websocket_connect(
        "/v1/channels/webui", headers={"Authorization": f"Bearer {install_token}"}
    ) as ws:
        ws.send_text(json.dumps(_envelope("whatsapp", "u1")))
        try:
            ws.receive_text()
            raised = False
        except Exception:
            raised = True
    assert raised, "server must close the socket on a channel/route mismatch, not just error and continue"


def test_matching_channel_is_accepted(app_client, install_token):
    from glc.security.pairing import get_pairing_store

    get_pairing_store().force_pair_owner("webui", "u1", user_handle="u")
    with app_client.websocket_connect(
        "/v1/channels/webui", headers={"Authorization": f"Bearer {install_token}"}
    ) as ws:
        ws.send_text(json.dumps(_envelope("webui", "u1")))
        reply = json.loads(ws.receive_text())
    assert "error" not in reply


def test_query_string_token_is_no_longer_accepted(app_client, install_token):
    connected = True
    try:
        with app_client.websocket_connect(f"/v1/channels/webui?token={install_token}"):
            pass
    except Exception:
        connected = False
    assert not connected, "a query-string token must not authenticate the connection anymore"


def test_header_token_still_works(app_client, install_token):
    from glc.security.pairing import get_pairing_store

    get_pairing_store().force_pair_owner("webui", "u1", user_handle="u")
    with app_client.websocket_connect(
        "/v1/channels/webui", headers={"Authorization": f"Bearer {install_token}"}
    ) as ws:
        ws.send_text(json.dumps(_envelope("webui")))
        reply = json.loads(ws.receive_text())
    assert "error" not in reply
