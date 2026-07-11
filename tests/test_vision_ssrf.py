"""SSRF via /v1/vision's image-url resolver — Section 6 finding C1.

_assert_public_host is exercised directly (pure, no network needed for
literal IPs); the end-to-end /v1/chat path is exercised through a
message containing an image_url block, which is enough to prove the
host check runs before any HTTP fetch is attempted.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from glc.routes.chat import _assert_public_host


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",  # loopback
        "169.254.169.254",  # cloud metadata / link-local
        "10.0.0.5",  # RFC1918 private
        "192.168.1.1",  # RFC1918 private
        "172.16.0.1",  # RFC1918 private
        "0.0.0.0",  # unspecified
        "::1",  # loopback v6
        "fe80::1",  # link-local v6
    ],
)
def test_private_and_link_local_hosts_rejected(host):
    with pytest.raises(HTTPException) as exc:
        _assert_public_host(host)
    assert exc.value.status_code == 400


def test_public_host_accepted():
    # A literal public IP resolves with no network call and must pass.
    _assert_public_host("8.8.8.8")


def test_vision_rejects_private_image_url(app_client, data_plane_headers):
    r = app_client.post(
        "/v1/chat",
        json={
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "describe"},
                        {"type": "image_url", "image_url": {"url": "http://169.254.169.254/latest/meta-data/"}},
                    ],
                }
            ]
        },
        headers=data_plane_headers(),
    )
    assert r.status_code == 400
    assert "non-public address" in r.json()["detail"]
