"""Modal deployment wrapper for glc_v1 (Session 12, hardened past Move 1).

Move 1 wrapped the whole gateway as a single Function with one shared
Secret — every finding in Section 6 group A and Section 7 traces back to
that. This file deploys two separate Modal Functions instead, built from
the same glc.main.create_app(mode=...) factory:

  - fastapi_app / "gateway": the data plane (chat/vision/embed/speak/
    transcribe + the info-disclosure reads + the internal credential
    minter). Gets glc-llm-keys and glc-credential-signing-key. Never
    gets the install token or any channel-specific secret.
  - control_app / "control": the control plane and channel adapters
    (kill/pair/presence + the channel webhook/WS routes). Gets
    glc-channel-secrets and glc-adapter-bootstrap. Never gets
    glc-llm-keys — closes A4/leak 1 (adapters reading provider keys via
    the shared process environment) and shrinks leak 6's (unbounded
    egress) blast radius to a container that has no provider keys to
    exfiltrate in the first place.

Both Functions share the persistent Volume (their SQLite files don't
overlap: gateway owns gateway.sqlite, the cost ledger; control owns
audit.sqlite, pairings.sqlite, and install_token) and are capped at
max_containers=1 — closing A6 (concurrent containers writing the same
SQLite file with no coordinated single writer) by construction, at the
cost of no horizontal scaling. That's the right tradeoff for a
single-student, scale-to-zero, free-tier deployment; it would not be
for a production multi-tenant one.

Deploy with:   uv run modal deploy modal_app.py
"""

from pathlib import Path

import modal

app = modal.App("glc-v1-gateway")

LOCAL_GLC = Path(__file__).parent / "glc"

# Pinned to the exact versions resolved by uv.lock at the time this was
# hardened (A5: modal_app.py previously built on rolling debian_slim
# with >= dep ranges, drifting out from under uv.lock on every rebuild —
# a supply-chain hygiene gap that widens the blast radius of every other
# finding here). Bump deliberately, together with uv.lock, not silently.
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "fastapi==0.137.1",
        "uvicorn[standard]==0.49.0",
        "httpx==0.28.1",
        "python-dotenv==1.2.2",
        "pydantic==2.13.4",
        "jsonschema==4.26.0",
        "pyyaml==6.0.3",
        "websockets==16.0",
        "twilio==9.10.9",
    )
    .env({"GLC_CONFIG_DIR": "/data/glc"})
    .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")
)

data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)

# Provider keys — gateway only. Created with `modal secret create
# glc-llm-keys ...` (mock values).
llm_secret = modal.Secret.from_name("glc-llm-keys")

# The credential-signing key gateway uses to mint and verify the
# short-lived, single-use, tool-scoped credentials that authenticate
# data-plane calls (glc/security/credentials.py) — gateway only. Created
# with `modal secret create glc-signing-key GLC_CREDENTIAL_SIGNING_KEY=...`.
signing_secret = modal.Secret.from_name("glc-signing-key")

# The bootstrap key a low-trust component presents to request a scoped
# data-plane credential (POST /v1/internal/credential) — shared between
# gateway (to verify the request) and control (to make it). Deliberately
# its own secret: holding it lets you ask for one credential at a time,
# it does not by itself grant provider-key access. Created with
# `modal secret create glc-adapter-bootstrap GLC_ADAPTER_BOOTSTRAP_KEY=...`.
bootstrap_secret = modal.Secret.from_name("glc-adapter-bootstrap")

# Per-channel tokens (Telegram/Discord/Twilio/... bot tokens, webhook
# shared secrets) — control only; gateway never sees these either.
# Created with `modal secret create glc-channel-secrets ...` (mock
# values — this deployment doesn't register live channel adapters).
channel_secret = modal.Secret.from_name("glc-channel-secrets")


@app.function(
    image=image,
    volumes={"/data": data_volume},
    secrets=[llm_secret, signing_secret, bootstrap_secret],
    min_containers=0,
    max_containers=1,  # A6: one writer for gateway.sqlite, no exceptions
)
@modal.asgi_app()
def fastapi_app():
    """The public data plane. Holds provider keys; never holds the
    install token or a channel secret."""
    import os

    os.makedirs("/data/glc", exist_ok=True)

    from glc.main import create_app

    return create_app(mode="gateway")


@app.function(
    image=image,
    volumes={"/data": data_volume},
    secrets=[channel_secret, bootstrap_secret],
    min_containers=0,
    max_containers=1,  # A6: one writer for audit.sqlite/pairings.sqlite
)
@modal.asgi_app()
def control_app():
    """The control plane and channel adapters. Holds the install token
    and per-channel secrets; never holds a provider key."""
    import os

    os.makedirs("/data/glc", exist_ok=True)

    from glc.main import create_app

    return create_app(mode="control")
