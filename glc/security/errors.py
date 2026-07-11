"""Client-safe error responses.

Invariant 1: adapters (and, by extension, any untrusted caller of the
data plane) must never see provider API keys — and that includes seeing
them indirectly, through a raw upstream error body that names the
provider's auth failure, endpoint host, or account state. Section 6
finding C4: /v1/chat returned the raw Gemini error JSON verbatim,
including `generativelanguage.googleapis.com` and the exact "API key
not valid" message.

Full detail still reaches the operator: every call site here also logs
the real exception, keyed by a short incident id the operator can
correlate against server logs (and, where the caller already does it,
against glc.db.log_call's `error` column, which was never client-facing
to begin with).
"""

from __future__ import annotations

import logging
import secrets

from fastapi import HTTPException

_log = logging.getLogger("glc.errors")


def safe_detail(context: str, exc: Exception) -> str:
    """Log the real error and return a generic, incident-keyed message
    safe to send to an untrusted caller."""
    incident = secrets.token_hex(4)
    _log.error("incident=%s context=%s error=%r", incident, context, exc)
    return f"{context} failed (incident {incident})"


def safe_http_error(status_code: int, context: str, exc: Exception) -> HTTPException:
    return HTTPException(status_code, safe_detail(context, exc))
