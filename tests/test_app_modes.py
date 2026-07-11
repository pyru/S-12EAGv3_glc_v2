"""create_app(mode=...) route separation — the code-level half of the
gateway/control Secret split (invariants 1 and 4; Section 6 A3/A4 and
Section 7 leak 1/leak 6). The other half — that the "control" Modal
Function's container literally never receives the glc-llm-keys Secret —
is a modal_app.py / `modal secret` deployment fact, not something a
local test process can observe; see modal_app.py's comments and
FINDINGS.md for how that's verified against the live deployment."""

from __future__ import annotations

DATA_PLANE_PATHS = ["/v1/chat", "/v1/vision", "/v1/embed", "/v1/status", "/v1/providers"]
CONTROL_PLANE_PATHS = ["/v1/control/kill", "/v1/control/pair", "/v1/control/presence"]


def test_gateway_mode_has_no_control_routes():
    # Deferred import: glc.main builds its module-level `app` singleton
    # (glc.main.app = create_app("full")) at import time, reading
    # GLC_DEBUG_DOCS from the environment right then. A top-level import
    # here would run during pytest collection, before conftest's autouse
    # fixture has set that env var, permanently locking docs off for the
    # shared `app` every other test's app_client fixture depends on.
    from glc.main import create_app

    app = create_app("gateway")
    paths = set(app.openapi()["paths"].keys())
    for p in CONTROL_PLANE_PATHS:
        assert p not in paths
    for p in DATA_PLANE_PATHS:
        assert p in paths


def test_control_mode_has_no_data_plane_routes():
    from glc.main import create_app

    app = create_app("control")
    paths = set(app.openapi()["paths"].keys())
    for p in DATA_PLANE_PATHS:
        assert p not in paths
    for p in CONTROL_PLANE_PATHS:
        assert p in paths


def test_gateway_mode_boots_and_serves_healthz():
    from fastapi.testclient import TestClient

    from glc.main import create_app

    app = create_app("gateway")
    with TestClient(app) as c:
        r = c.get("/healthz")
        assert r.status_code == 200
        assert r.json()["mode"] == "gateway"


def test_control_mode_boots_and_serves_healthz():
    from fastapi.testclient import TestClient

    from glc.main import create_app

    app = create_app("control")
    with TestClient(app) as c:
        r = c.get("/healthz")
        assert r.status_code == 200
        assert r.json()["mode"] == "control"
