"""FastAPI app for glc_v1. Port 8111 by default. V9 routes are mounted
as-is (S9 Browser / S10 Computer-Use clients work unchanged); the new
S11 surfaces (transcribe, speak, channels WS, control) sit alongside.
"""

from __future__ import annotations

import os
import signal
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

ROOT = Path(__file__).parent
load_dotenv(ROOT.parent / ".env")  # repo .env, if present

import glc.policy.engine as _policy_engine_module  # noqa: E402
from glc import db  # noqa: E402
from glc import embedders as E  # noqa: E402
from glc import providers as P  # noqa: E402
from glc.audit import init_store as init_audit  # noqa: E402
from glc.cache import GeminiCache  # noqa: E402
from glc.config import get_or_create_install_token  # noqa: E402
from glc.policy import reload_engine  # noqa: E402
from glc.routes import channels as channels_route  # noqa: E402
from glc.routes import chat as chat_route  # noqa: E402
from glc.routes import control as control_route  # noqa: E402
from glc.routes import internal as internal_route  # noqa: E402
from glc.routes import speak as speak_route  # noqa: E402
from glc.routes import transcribe as transcribe_route  # noqa: E402
from glc.routing import Router, RouterPool  # noqa: E402

PORT = int(os.getenv("GLC_PORT", "8111"))

# Captured here, at process start, independently of glc/policy/engine.py's
# own internal capture — an out-of-band reference for the watchdog below.
# See glc/policy/engine.py's _PRISTINE_EVALUATE docstring for why no
# in-process code can *prevent* glc.policy.engine.evaluate being rebound
# (Section 7 leak 5), only detect it after the fact.
_PRISTINE_POLICY_EVALUATE = _policy_engine_module.evaluate

POLICY_INTEGRITY_CHECK_INTERVAL_S = float(os.getenv("GLC_POLICY_INTEGRITY_INTERVAL_S", "10"))


def check_policy_integrity_once() -> bool:
    """Runs one tamper check. Returns True (and records an audit-log
    entry) if either PolicyEngine.evaluate or glc.policy.engine.evaluate
    no longer matches the reference captured at process start."""
    from glc.audit import append as audit_append
    from glc.policy.engine import is_tampered

    tampered = is_tampered() or (_policy_engine_module.evaluate is not _PRISTINE_POLICY_EVALUATE)
    if tampered:
        audit_append(
            channel="_system",
            channel_user_id="policy_engine_watchdog",
            trust_level="owner_paired",
            event_type="policy_engine_tampered",
            result={"detail": "PolicyEngine.evaluate or glc.policy.engine.evaluate was rebound at runtime"},
        )
        print("[glc] CRITICAL: policy engine tampering detected — recorded to audit log")
    return tampered


async def _policy_integrity_watchdog() -> None:
    """Periodically, independently of whether anything actually calls
    the policy engine, check whether it's been tampered with. This is a
    detector, not a preventer — see the module-load-time capture above.
    A positive hit is written to the audit log, which (since the leak 2
    fix) the same in-process attacker can no longer erase."""
    import asyncio

    while True:
        try:
            await asyncio.sleep(POLICY_INTEGRITY_CHECK_INTERVAL_S)
            check_policy_integrity_once()
        except asyncio.CancelledError:
            return
        except Exception as e:  # pragma: no cover
            print(f"[glc] policy integrity watchdog error: {e!r}")


def _install_sighup_reload() -> None:
    """Hot-reload policy.yaml on SIGHUP. Windows lacks SIGHUP so this is
    a no-op there."""
    if not hasattr(signal, "SIGHUP"):
        return

    def _handler(signum, frame):  # noqa: ARG001
        try:
            reload_engine()
            print("[glc] policy.yaml reloaded via SIGHUP")
        except Exception as e:
            print(f"[glc] SIGHUP reload failed: {e!r}")

    try:
        signal.signal(signal.SIGHUP, _handler)
    except ValueError:
        # signal() only works on the main thread; tests using TestClient
        # spawn lifespan from a worker thread. Silent skip is correct here.
        pass


def _make_lifespan(mode: Literal["full", "gateway", "control"]):
    """A mode-specific lifespan, so "gateway" and "control" — deployed as
    two separate Modal Functions writing to a shared Volume — don't both
    open and write the same SQLite files they have no reason to touch.
    That reduces exactly the kind of concurrent-writer risk finding A6
    describes, on top of the Secret separation this split exists for."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        import asyncio

        needs_data_plane = mode in ("full", "gateway")
        needs_control_plane = mode in ("full", "control")

        if needs_data_plane:
            db.init()
            app.state.cache = GeminiCache(ttl_seconds=300)
            app.state.providers = P.build_providers(app.state.cache)
            app.state.router = Router(app.state.providers, chat_route.ORDER)
            app.state.router_providers = P.build_router_providers()
            app.state.router_pool = RouterPool(app.state.router_providers, chat_route.ROUTER_ORDER)
            app.state.embedders, app.state.embed_order = E.build_embedders()
        if needs_control_plane:
            init_audit()
            get_or_create_install_token()
            _install_sighup_reload()
        app.state.started_at = time.time()
        app.state.registered_channels = []
        # Each Modal Function is its own process with its own copy of
        # glc.policy.engine's module state, so the watchdog runs
        # regardless of mode — a container split already contains leak
        # 5's blast radius to whichever process was actually tampered.
        watchdog = asyncio.create_task(_policy_integrity_watchdog())
        try:
            yield
        finally:
            watchdog.cancel()

    return lifespan


def create_app(mode: Literal["full", "gateway", "control"] = "full") -> FastAPI:
    """`mode` decides which routers — and therefore which secrets this
    process needs — get mounted.

    - "gateway": the data plane (chat/vision/embed/speak/transcribe +
      the info-disclosure reads + the internal credential minter). Needs
      glc-llm-keys and the credential-signing key. Never needs the
      install token or any channel-specific secret.
    - "control": the control plane and channel adapters (kill/pair/
      presence + the channel webhook/WS routes). Needs the install
      token, per-channel secrets, and the credential-signing key's
      bootstrap half — never glc-llm-keys. A component compromised here
      (leak 1, leak 6) simply has no provider key in its environment to
      steal (invariant 1).
    - "full": both, in one process — the default for local dev
      (`uv run glc serve`) and the existing test suite, which was
      written against a single combined app. `modal_app.py` deploys
      "gateway" and "control" as two separate Modal Functions with two
      separate Secrets instead of "full".

    Swagger/OpenAPI (`/docs`, `/openapi.json`) are only mounted when
    GLC_DEBUG_DOCS=1 — closing the free route-map reconnaissance a
    public, unauthenticated /openapi.json otherwise hands an attacker.
    """
    docs_enabled = os.getenv("GLC_DEBUG_DOCS") == "1"
    application = FastAPI(
        title="GLC v1 — Gateway for LLMs and Channels",
        lifespan=_make_lifespan(mode),
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )

    if mode in ("full", "gateway"):
        application.include_router(chat_route.router)
        application.include_router(transcribe_route.router)
        application.include_router(speak_route.router)
        application.include_router(internal_route.router)
    if mode in ("full", "control"):
        application.include_router(control_route.router)
        application.include_router(channels_route.router)

    @application.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return (
            "<html><body style='font-family:sans-serif;max-width:680px;margin:2em auto'>"
            "<h1>GLC v1</h1>"
            f"<p>Gateway for LLMs and Channels — mode={mode}.</p>"
            "</body></html>"
        )

    @application.get("/healthz")
    async def healthz():
        return {"ok": True, "port": PORT, "mode": mode}

    return application


app = create_app("full")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("glc.main:app", host="0.0.0.0", port=PORT, reload=False)
