"""Section 6 finding C4: the data plane must not return raw upstream
error detail (provider hostnames, auth failure text) to an untrusted
caller — full detail still gets logged server-side, keyed by an
incident id."""

from __future__ import annotations

import logging

from glc.security.errors import safe_detail, safe_http_error


def test_safe_detail_hides_raw_exception_text():
    exc = Exception("gemini HTTP 400: API key not valid — generativelanguage.googleapis.com")
    detail = safe_detail("provider gemini", exc)
    assert "googleapis.com" not in detail
    assert "API key not valid" not in detail
    assert "incident" in detail


def test_safe_detail_logs_full_detail(caplog):
    exc = Exception("gemini HTTP 400: API key not valid — generativelanguage.googleapis.com")
    with caplog.at_level(logging.ERROR, logger="glc.errors"):
        safe_detail("provider gemini", exc)
    assert "googleapis.com" in caplog.text
    assert "API key not valid" in caplog.text


def test_safe_http_error_status_code_preserved():
    exc = Exception("upstream is down")
    http_exc = safe_http_error(502, "provider gemini", exc)
    assert http_exc.status_code == 502
    assert "upstream is down" not in http_exc.detail
