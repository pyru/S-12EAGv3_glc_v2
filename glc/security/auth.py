"""FastAPI dependencies gating the public data plane.

Invariant 2 (every action checked against the actual caller) and
invariant 8 (hard limits on every run) both live here. Every data-plane
and info-disclosure route (`/v1/chat`, `/v1/vision`, `/v1/embed`,
`/v1/speak`, `/v1/transcribe`, `/v1/status`, `/v1/providers`,
`/v1/capabilities`, `/v1/cost/by_agent`, `/v1/calls`, `/v1/routers`,
`/v1/embedders`) depends on `require_data_plane_credential`; the
call-shaped routes additionally depend on `enforce_data_plane_limits`.
"""

from __future__ import annotations

import hmac
import os

from fastapi import Header, HTTPException

from glc.security import credentials

BOOTSTRAP_KEY_ENV = "GLC_ADAPTER_BOOTSTRAP_KEY"
DAILY_TOKEN_BUDGET_ENV = "GLC_DAILY_TOKEN_BUDGET"
DEFAULT_DAILY_TOKEN_BUDGET = 200_000
DATA_PLANE_TOOL = "data_plane"


async def require_data_plane_credential(authorization: str | None = Header(default=None)) -> str:
    """Every data-plane / info-disclosure route requires a valid,
    single-use, short-lived credential minted by
    POST /v1/internal/credential — never a standing shared secret.
    Also enforces invariant 8's per-caller rate limit, reusing the same
    limiter channel adapters use, keyed by the credential's component."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer credential (Authorization: Bearer <token>)")
    token = authorization.removeprefix("Bearer ").strip()
    try:
        component = credentials.verify(token, tool=DATA_PLANE_TOOL)
    except credentials.CredentialError as e:
        raise HTTPException(403, f"credential rejected: {e}") from None

    from glc.security.rate_limits import get_rate_limiter

    ok, why = get_rate_limiter().check_message("_data_plane", component)
    if not ok:
        raise HTTPException(429, why)
    return component


def require_bootstrap_key(authorization: str | None) -> None:
    """Guards POST /v1/internal/credential: only a component holding the
    shared adapter-bootstrap secret may request a scoped credential.
    This secret is deliberately separate from GLC_CREDENTIAL_SIGNING_KEY
    (which only the gateway holds) and from glc-llm-keys (which the
    bootstrap-holding component never sees)."""
    expected = os.environ.get(BOOTSTRAP_KEY_ENV)
    if not expected:
        raise HTTPException(503, f"{BOOTSTRAP_KEY_ENV} not configured on this deployment")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer bootstrap key")
    presented = authorization.removeprefix("Bearer ").strip()
    if not hmac.compare_digest(presented, expected):
        raise HTTPException(403, "bootstrap key mismatch")


async def enforce_data_plane_limits() -> None:
    """Invariant 8: every run has a hard cost limit. Checked against the
    day's already-logged token usage before the call is allowed to run;
    a single expensive call cannot itself be capped mid-flight, so this
    is a circuit breaker for the *next* call once the budget is spent,
    not a per-call token cap (glc.llm_schemas already caps max_tokens
    per request)."""
    from glc import db

    cap = int(os.environ.get(DAILY_TOKEN_BUDGET_ENV, DEFAULT_DAILY_TOKEN_BUDGET))
    agg = db.aggregate(call_role="worker")
    used = sum((r.get("in_tok") or 0) + (r.get("out_tok") or 0) for r in agg.values())
    if used >= cap:
        raise HTTPException(402, f"daily token budget exhausted ({used}/{cap} tokens); resets at day rollover")
