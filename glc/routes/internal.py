"""POST /v1/internal/credential — issues a single-use, tool-scoped,
short-lived credential for the data plane (see glc/security/auth.py and
glc/security/credentials.py). Guarded by the adapter-bootstrap secret,
which is deliberately not the same secret as the LLM provider keys or
the credential-signing key — a component that can request a chat
credential still never sees a provider key directly (invariant 1), and
still only gets a token good for exactly one data-plane call
(invariant 4).
"""

from __future__ import annotations

from fastapi import APIRouter, Header

from glc.security import credentials
from glc.security.auth import DATA_PLANE_TOOL, require_bootstrap_key

router = APIRouter()


@router.post("/v1/internal/credential")
async def mint_credential(component: str = "adapter", authorization: str | None = Header(default=None)):
    require_bootstrap_key(authorization)
    token = credentials.mint(component, DATA_PLANE_TOOL)
    return {"token": token, "tool": DATA_PLANE_TOOL, "ttl_seconds": credentials.DEFAULT_TTL_SECONDS}
