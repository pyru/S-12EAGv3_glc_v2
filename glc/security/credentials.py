"""Short-lived, single-use, tool-scoped credentials.

Session 12 Section 4, invariant 4: "A credential must work only for one
specific tool call." Before this module, the only credential in the
system was the install token — a single static secret good for every
control-plane call forever, and (per leak 4) readable by any code
sharing the gateway process.

`mint()` is called by the trusted core (the gateway) to hand a caller a
token good for exactly one named tool call, for a short TTL, once. Reuse,
tool-mismatch, expiry, or a bad signature all fail closed.

This does not, by itself, stop code running inside the gateway process
from reading the signing key (that requires process separation — see
`glc/main.py`'s `create_app(mode=...)` and `modal_app.py`). What it does
close is the standing, ambient, infinitely-reusable nature of the
install token when used to authenticate the public data plane.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time

SIGNING_KEY_ENV = "GLC_CREDENTIAL_SIGNING_KEY"
DEFAULT_TTL_SECONDS = 30

# Single-use nonce tracker. In-memory is sufficient: a credential is only
# ever meant to be redeemed once, by the process that just minted it or
# verifies it, within a TTL of seconds — it does not need to survive a
# restart.
_used_nonces: dict[str, float] = {}


class CredentialError(Exception):
    pass


def _signing_key() -> bytes:
    key = os.environ.get(SIGNING_KEY_ENV)
    if not key:
        raise CredentialError(f"{SIGNING_KEY_ENV} is not configured on this component")
    return key.encode()


def mint(component: str, tool: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> str:
    """Issue a token that authorises exactly one call to `tool`, from
    `component`'s perspective, expiring in `ttl_seconds`."""
    nonce = secrets.token_urlsafe(16)
    exp = int(time.time()) + ttl_seconds
    payload = f"{component}:{tool}:{nonce}:{exp}"
    sig = hmac.new(_signing_key(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def verify(token: str, tool: str) -> str:
    """Verify a token for use against `tool`. Returns the minted
    `component` name on success. Raises CredentialError on any failure,
    and marks the credential's nonce spent so it cannot be replayed."""
    parts = token.split(":")
    if len(parts) != 5:
        raise CredentialError("malformed credential")
    component, tok_tool, nonce, exp_s, sig = parts
    try:
        exp = int(exp_s)
    except ValueError:
        raise CredentialError("malformed credential") from None

    payload = f"{component}:{tok_tool}:{nonce}:{exp}"
    expected = hmac.new(_signing_key(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise CredentialError("bad signature")

    now = time.time()
    for n, e in list(_used_nonces.items()):
        if e < now:
            del _used_nonces[n]

    if now > exp:
        raise CredentialError("credential expired")
    if tok_tool != tool:
        raise CredentialError(f"credential scoped to {tok_tool!r}, not {tool!r}")
    if nonce in _used_nonces:
        raise CredentialError("credential already used")

    _used_nonces[nonce] = exp
    return component
