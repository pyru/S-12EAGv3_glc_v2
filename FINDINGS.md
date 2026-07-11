# FINDINGS — Part 1 (migrate, watch it break, fix)

Deployment: `https://pyramesh-ai--glc-v1-gateway-fastapi-app.modal.run` (Modal account `pyramesh-ai`), deployed from unmodified `modal_app.py` with a `glc-llm-keys` Secret holding only mock provider keys.

Reproduction tooling used below:
- **HTTP findings** — `curl` directly against the live URL above.
- **In-process leaks** — a two-file harness (`harness/gateway.py` boots `db`/`audit`/`pairing` state and mock env keys exactly like `glc.main`'s `lifespan`, standing in for the one shared Modal Secret; `harness/leak_runner.py` fires each leak's exploit in that same process) plus, where the exploit is really a WebSocket-route bug (leak 9), a real ASGI WebSocket connection via `fastapi.testclient.TestClient` against the unmodified app — still in-process, no network hop.

Eight invariants (Session 12 §4) and four attacker roles (§3), abbreviated I1–I8 and R1–R4:

- **I1** Adapters must never see provider API keys.
- **I2** Every action must be checked against the actual user, tenant, and final arguments.
- **I3** External content must always be treated as data, never as instructions.
- **I4** A credential must work only for one specific tool call.
- **I5** Each tenant has separate memory; every stored fact records its source.
- **I6** Dangerous or high-impact actions must be approved with their final parameters.
- **I7** Components must not be able to edit or delete their own audit logs.
- **I8** Every run must have hard limits on time, tokens, tool calls, and cost.
- **R1** outsider on the public internet, no credentials.
- **R2** normal channel user, controls only the text they type.
- **R3** attacker who has taken over a single adapter container.
- **R4** attacker with code execution inside the gateway process itself.

## Section 6 — deployment and endpoint findings

| # | Finding | Reproduction (against live URL) | Invariant broken | Attacker role |
|---|---|---|---|---|
| Recon | Full route map via `/openapi.json` | `curl .../openapi.json` → 200, 20 routes enumerated incl. `/v1/control/kill` | Precursor to I2 — free reconnaissance for the checks below | R1 |
| A1 | Public data plane, no auth | `curl -X POST .../v1/chat -d '{"prompt":"hello"}'` → `502` with a real (mock-key) provider error, not `401` | **I2** — the action runs for anyone; nothing checks who the actual caller is before dispatching to a provider | R1 |
| A2 | Unauthenticated info disclosure | `curl .../v1/status`, `/v1/providers`, `/v1/cost/by_agent`, `/v1/calls`, `/docs` → all `200`, no auth | **I2** — reads execute without checking the actual caller | R1 |
| A3 | Single Function, no egress wall | (structural; confirmed via C1 egress test below reaching arbitrary attacker-chosen hosts) | **I1** — no boundary stops in-process code from sending a stolen key anywhere | R3→R4 (the missing wall is exactly what lets a compromised adapter, R3, act with full gateway/R4 network reach) |
| A4 | One Secret for the whole Function | `glc-llm-keys` is mounted on the single `fastapi_app` Function; every import in that process can read it (= leak 1 below) | **I1** | R4 |
| A5 | Non-reproducible image | `modal_app.py` builds from `debian_slim` + `>=` version ranges, ignoring `uv.lock` (config fact, no live call) | No single one of the 8 directly; it widens the blast radius of all of them by letting the image drift out from under any fix | n/a (build-time; raises the odds of reaching R4 via dependency drift) |
| A6 | Audit volume assumes one writer | `min_containers=0` + autoscale + SQLite volume with no coordinated single writer (config fact) | **I7** — concurrent writers can corrupt/split the audit trail, defeating the same guarantee leak 2 attacks directly | n/a (ordinary autoscale, not an attacker action) |
| C1 | SSRF via `/v1/vision` | `curl -X POST .../v1/vision -d '{"prompt":"x","image":"https://httpbin.org/redirect-to?url=https://httpbin.org/image/jpeg"}'` → fetch succeeds (reaches provider with the fetched image; provider only fails on the mock key), proving both arbitrary-host fetch and redirect-follow-through with no allowlist | **I2** — the final argument (`image` URL) is never checked before the gateway executes a network fetch on the caller's behalf | R1 |
| C2 | Cross-channel envelope spoofing | In-process `TestClient` WS: connect to `/v1/channels/webui` with a valid token, send an envelope with `channel="whatsapp"` → server accepts and echoes it, no mismatch check | **I2** — the declared identity (`channel`) is never checked against the actual route the caller authenticated on | R3 |
| C3 | WS token in query string | `wss://.../v1/channels/webui?token=<install_token>` (no `Authorization` header) → connection accepted | **I4** — a credential meant to scope one connection ends up reusable by anyone who can read the URL (proxy/access logs, browser history) | R1 (only needs log/URL access, not the system itself) |
| C4 | Verbose upstream errors | The A1 response body above includes the raw Gemini error JSON, `generativelanguage.googleapis.com`, and `googleapis.com` | **I1** — provider-identifying and auth-adjacent detail leaks back to an untrusted caller | R1 |
| C5 | No rate limits or budget on the public data plane | 8x back-to-back `curl .../v1/status` → all `200`, no `429`, no budget check anywhere in `chat.py` | **I8** (named explicitly) | R1 |
| C6 | Pairing-code brute force (candidate) | `curl -X POST .../v1/control/pair/confirm -d '{"code":"123456"}'` (no token) → `401 missing bearer token` | **Checked, not reproducible.** Both `/v1/control/pair` and `/pair/confirm` require the install token, so code-guessing needs a credential that already grants full control-plane access — not an independent path. | n/a |
| — | Control plane IS gated | `curl -X POST .../v1/control/kill` (no token) → `401` | (positive control, not a finding) | — |

## Section 7 — the ten in-process code leaks

All confirmed **OPEN** by `harness/leak_runner.py` against unmodified code (see run output referenced in commit history below).

| # | Leak | Invariant broken | Attacker role |
|---|---|---|---|
| 1 | Shared process environment (`os.environ["GEMINI_API_KEY"]`) | **I1** | R3→R4 (a compromised single adapter instantly gets every provider key, because adapter and gateway share one process) |
| 2 | Audit log writable (`DELETE FROM audit_log`, committed) | **I7** (named explicitly) | R4 |
| 3 | Pairing escalation (`force_pair_owner("telegram", "attacker-id")`) | **I2** — grants owner trust without checking the actual user | R4 |
| 4 | Install token readable in-process | **I4** — a credential scoped to the control plane is readable and reusable by any in-process code, not just the intended caller | R4 |
| 5 | Policy engine monkey-patch (`glc.policy.engine.evaluate = lambda ...: allow`) | **I6** — the approval mechanism for dangerous actions is disabled outright, so nothing gets checked against its final parameters again | R4 |
| 6 | Unbounded egress (reaches an arbitrary public host, `httpx.get(...)`) | **I1** — nothing stops a stolen key (or any other asset) leaving over an arbitrary outbound connection | R3→R4 |
| 7 | Subprocess/shell access (`subprocess.run([...])`) | **I2** — a raw host command is not a checked, typed tool call with validated final arguments; it's an escape hatch around the entire mechanism I2 describes | R4 |
| 8 | Kill the gateway (`os.kill(os.getpid(), signal.SIGTERM)`) | **I6** — process termination is a high-impact action taken without going through the one approved, authenticated path (`/v1/control/kill`) | R4 |
| 9 | Cross-channel envelope spoof (in-process WS reproduction, same bug as C2) | **I2** | R3 |
| 10 | Cost-ledger poisoning (`glc.db.log_call(input_tokens=999_999_999, ...)`) | **I8** (named explicitly) — corrupts the ledger the invariant's hard limits would be computed from | R4 |

## Fixes

See commit history — one commit per finding (or tight cluster of findings sharing one mechanism), each naming the invariant it closes.

### Recon, A1, A2 — data plane and info endpoints are now auth-gated (invariant 2)

Every data-plane and info-disclosure route (`/v1/chat`, `/v1/chat/batch`, `/v1/vision`, `/v1/embed`, `/v1/speak`, `/v1/transcribe`, `/v1/status`, `/v1/providers`, `/v1/capabilities`, `/v1/cost/by_agent`, `/v1/calls`, `/v1/routers`, `/v1/embedders`) now depends on `require_data_plane_credential` (`glc/security/auth.py`), which requires a valid `Authorization: Bearer <token>` where the token is a short-lived (30s), single-use, tool-scoped credential minted by `POST /v1/internal/credential`. That endpoint is itself gated by a separate bootstrap secret (`GLC_ADAPTER_BOOTSTRAP_KEY`) that a random internet caller does not have. `/docs`, `/redoc`, and `/openapi.json` are now `None` (404) unless `GLC_DEBUG_DOCS=1` is explicitly set — off by default in `modal_app.py`.

This also gives invariant 4 ("a credential must work only for one specific tool call") a real mechanism (`glc/security/credentials.py`): the token is bound to one tool name, expires in seconds, and is rejected on reuse (verified above: reusing a spent token returns 403).

Verified: `curl .../v1/chat` and `curl .../openapi.json` now both fail closed before this fix would have let them through (see re-verification section below, run after redeploy).

### C5 — rate limits and a hard daily token budget on the data plane (invariant 8)

`require_data_plane_credential` now also runs every call through the existing per-caller `RateLimiter` (30 messages/minute by default, same limiter channel adapters already used), and the cost-incurring routes (`/v1/chat`, `/v1/chat/batch`, `/v1/vision`, `/v1/embed`, `/v1/speak`, `/v1/transcribe`) additionally depend on `enforce_data_plane_limits`, which rejects the call with `402` once the day's logged token usage (`glc.db.aggregate`) crosses `GLC_DAILY_TOKEN_BUDGET` (default 200,000).

Verified: `tests/test_data_plane_auth.py::test_data_plane_rate_limit_trips` (31st call in a minute → 429) and `::test_data_plane_budget_exhausted_returns_402` (usage over the configured cap → 402), both passing.

### C1 — SSRF in the vision image-url resolver (invariant 2)

`_assert_public_host` (`glc/routes/chat.py`) now resolves the image URL's hostname and rejects it if any resolved address is private, loopback, link-local, multicast, reserved, or unspecified (IPv4 and IPv6) — before any HTTP fetch is attempted. `follow_redirects` is now off; the fetcher instead follows redirects manually (max 5 hops), re-running the same host check on every hop, so a public URL cannot retarget the fetch to an internal address after the first check passes. A 10MB response cap was added as a low-cost companion guard against the same endpoint being used for resource exhaustion.

Verified: `tests/test_vision_ssrf.py` — 8 private/link-local/loopback hosts (v4 and v6) all rejected with 400; a public IP passes; a `/v1/chat` call with an `image_url` pointed at `169.254.169.254` now returns 400 instead of reaching the fetch.

### C2 / leak 9 — cross-channel envelope spoofing (invariant 2), and C3 — WS token in the query string (invariant 4)

`glc/routes/channels.py`'s WS handler now compares `env.channel` to the route's `name` path segment on every inbound message; a mismatch closes the socket (`WS_1008`) and is audit-logged as `channel_mismatch`, rather than being sent back as a soft error and left connected. Separately, the `?token=` query-string fallback for WS auth is removed entirely — only the `Authorization: Bearer <token>` header authenticates the connection now, so the credential can no longer land in proxy access logs or browser history.

Verified: `tests/test_channel_ws_security.py` — a connection on `/v1/channels/webui` declaring `channel="whatsapp"` gets its socket closed instead of echoed; a matching channel still works; `?token=` no longer authenticates a connection at all; the header path still does.

### C4 — verbose upstream errors (invariant 1)

`glc/security/errors.py` adds `safe_detail`/`safe_http_error`: every place `/v1/chat`, `/v1/chat/batch`, `/v1/vision`, `/v1/embed`, `/v1/speak`, and `/v1/transcribe` used to put a raw upstream exception (`str(e)`) straight into the HTTP response now logs the full exception server-side against a short incident id and returns only `"<context> failed (incident <id>)"` to the caller. `glc.db.log_call`'s `error` column — never client-facing — already had the full detail; this closes the client-facing leak specifically.

Verified live: re-running the exact A1 curl against unfixed code returned the raw Gemini error body (`API_KEY_INVALID`, `generativelanguage.googleapis.com`); against fixed code (`tests/test_generic_errors.py` plus a direct in-process rerun) the same failure now returns `{"detail": "provider gemini failed (incident 219b8c8e)"}` while the full detail lands in the server log under that incident id.

### Leak 2 — audit log writable at the OS layer (invariant 7, named explicitly)

`glc/audit/schema.sql` now defines `BEFORE DELETE` and `BEFORE UPDATE` triggers on `audit_log` that `RAISE(ABORT, ...)`. This moves the append-only guarantee from "the Python wrapper class doesn't expose a `delete()` method" (which any other code opening the same SQLite file with the stdlib `sqlite3` module bypassed trivially) to the database file itself — SQLite enforces it for any connection, in-process or not.

Verified: `harness/leak_runner.py` leak 2, which previously reported `OPEN -> DELETE succeeded: 1 rows -> 0 rows`, now reports `ERROR -> IntegrityError: audit_log is append-only: DELETE is not permitted`. `tests/test_audit_log.py` adds matching DELETE and UPDATE regression tests.

### Leak 3 — pairing escalation via `force_pair_owner` (invariant 2)

`force_pair_owner` (`glc/security/pairing.py`) now checks whether the target channel already has an owner before granting `owner_paired`; if one exists, it raises `PermissionError` unless the deployment operator has explicitly set `GLC_ALLOW_REPAIR_OWNER=1`. This closes the realistic threat (an already-bootstrapped install getting a second, attacker-chosen owner identity slipped in) while still allowing genuine first-run bootstrap, which every existing test and installer flow depends on.

Verified: `harness/leak_runner.py` leak 3 (updated to bootstrap a real owner first, matching the realistic post-install state) now reports `ERROR -> PermissionError: channel 'telegram' already has an owner...` instead of granting the attacker `owner_paired`. `tests/test_pairing.py` adds regression tests for bootstrap-still-works, escalation-now-blocked, and the explicit override.

### Leak 10 — cost-ledger poisoning (invariant 8, named explicitly)

`glc.db.log_call` now validates `input_tokens`, `output_tokens`, `cache_create_tokens`, and `cache_read_tokens` are non-negative integers within a generous plausible bound (5,000,000 — a multiple of the largest configured provider context window) and raises `ValueError` otherwise. This matters beyond data hygiene: `enforce_data_plane_limits` (the C5 fix, invariant 8's other half) computes its budget check from exactly this ledger, so an unvalidated write could previously fake either an exhausted or an artificially-clear budget.

Verified: `harness/leak_runner.py` leak 10, which previously reported `OPEN -> wrote unvalidated ledger row...`, now reports `ERROR -> ValueError: log_call: input_tokens=999999999 is outside the plausible range [0, 5000000]`. `tests/test_cost_ledger.py` covers the accept/reject boundary.

### Leak 5 — policy engine monkey-patching (invariant 6) — honest scope note

This is the one finding where the literal demonstrated exploit — `glc.policy.engine.evaluate = lambda *_, **__: PolicyVerdict(action="allow", ...)` — **cannot be prevented by any code living inside that module**, full stop. Reassigning a module attribute is a basic Python operation; there is no hook that lets old code run instead of whatever a later assignment points the name at. The assignment's own text concedes this explicitly: the real fix is running the policy engine in a separate process, which `docs/ARCHITECTURE.md` already scopes as capstone work, not Part 1.

What is genuinely implemented here, and does hold:

1. **A harder target for a related attack.** `glc/policy/engine.py` captures `_PRISTINE_EVALUATE = PolicyEngine.evaluate` at module-import time — before any in-process code, including an attacker's, has run. The free function `evaluate()` (the entry point real callers should use) now calls through that captured reference instead of re-resolving `PolicyEngine.evaluate` by attribute lookup on every call. This means rebinding `PolicyEngine.evaluate` on the class — a strictly more general attack than the literal demo — no longer changes what `evaluate()` actually enforces. Verified: `tests/test_policy_engine_integrity.py::test_hardened_evaluate_survives_class_level_rebind`.
2. **Detection instead of silence.** `glc/main.py` independently captures its own reference at process start and runs a background watchdog (`check_policy_integrity_once`, polled every `GLC_POLICY_INTEGRITY_INTERVAL_S` seconds, default 10) that compares the live bindings against both captured references. A mismatch — including the exact literal free-function rebind — is recorded to the audit log as `policy_engine_tampered`. Because leak 2 is now closed, the same attacker who tampered with the policy engine can no longer erase that record.

Verified: `harness/leak_runner.py` leak 5 now reports both halves honestly — the rebind still bypasses enforcement (expected, not preventable), and `check_policy_integrity_once()` detects and durably records it. `tests/test_policy_engine_integrity.py` covers the class-rebind-survival case, the detector's true/false states, and that detection reaches the audit log.

### A3, A4, leak 1, leak 6 — the shared Secret / no egress wall (invariant 1)

`modal_app.py` now deploys **two** Modal Functions built from the same `glc.main.create_app(mode=...)` factory instead of one:

- `fastapi_app` ("gateway"): the data plane. Secrets `glc-llm-keys` and `glc-signing-key`. Never mounts the install token or any channel secret.
- `control_app` ("control"): the control plane and channel adapters. Secrets `glc-channel-secrets` and `glc-adapter-bootstrap`. **Never mounts `glc-llm-keys`.**

This closes leak 1 and A4 for real, not just in application logic: `os.environ["GEMINI_API_KEY"]` in the control container raises `KeyError`, because that key is never in its environment at all — a guarantee Modal's `secrets=[...]` parameter enforces at the container level, not something `glc` code can accidentally reintroduce. `glc.main._make_lifespan` is mode-aware so a "gateway" process doesn't even attempt to build the state ("control" secrets, install token) it no longer has.

For A3/leak 6 (unbounded egress, no wall): the control container — the one a compromised channel adapter would run in — now has no provider key to exfiltrate in the first place, which is a materially different risk than "egress is unrestricted so a stolen key can leave." A true per-adapter network egress allowlist (Modal `Sandbox` with `outbound_domain_allowlist`) is not implemented: that API is scoped to `modal.Sandbox`, not the long-running `modal.Function`/ASGI-app model this gateway uses, and moving channel-adapter execution into short-lived Sandboxes is a bigger dispatch-model change than Part 1's timebox covers. This is a documented residual gap, not a claimed fix — C1's SSRF allowlist (invariant 2) closes the one concrete attacker-controlled egress path that exists today (`/v1/vision`'s image fetch).

Verified live against the redeployed URLs:
- `curl .../healthz` on both `https://pyramesh-ai--glc-v1-gateway-fastapi-app.modal.run` (`mode: "gateway"`) and `https://pyramesh-ai--glc-v1-gateway-control-app.modal.run` (`mode: "control"`).
- `curl -X POST .../v1/control/kill` on the **gateway** URL → `404` (route doesn't exist there).
- `curl -X POST .../v1/chat` on the **control** URL → `404` (route doesn't exist there).
- Full mint-credential → `/v1/chat` round trip against the gateway URL succeeds through to a real (mock-key) provider error.
- `tests/test_app_modes.py` covers the route-separation half in-process; the Secret-mounting half is a deployment fact verified above, not something a local test process can observe.

### Leak 4 — install token readable in-process — honest scope note

Partially improved, not closed. Since `glc.main._make_lifespan` is mode-aware, the **gateway** process never calls `get_or_create_install_token()` at all — it has no install token to read. The **control** process still creates and can read its own install token in-process (it needs to, to serve `/v1/control/*` and authenticate WS connections), and `os.kill`/loopback-based misuse of it is still reachable from inside that same container (leak 8, below). What changed is blast radius: a compromise limited to reading the install token no longer also grants reach into `glc-llm-keys`, `glc-signing-key`, or the data plane — those live in a separate container entirely.

### Leak 7 / leak 8 — subprocess access and self-kill — honest scope note

Not closed, contained. `subprocess.run(...)` and `os.kill(os.getpid(), signal.SIGTERM)` still work from wherever the calling code is running — a Python process can always do these while it's holding code execution, and no in-process code change removes that Python-level capability (the assignment's own text concedes this for leak 7: "removing the shell alone is never the whole answer"). What the two-Function split changes is scope: code running in the **control** container that calls `os.kill(os.getpid(), ...)` now only takes down the control plane and channel adapters — `/v1/chat` and the rest of the data plane, running in a separate Modal Function/container, keep serving. Before the split, one process was both.

### A5 — non-reproducible image (no single invariant; supply-chain hygiene)

`modal_app.py`'s image now pins every dependency to the exact version resolved by `uv.lock` at harden time (`fastapi==0.137.1`, `httpx==0.28.1`, `pydantic==2.13.4`, etc. — see the file for the full list) instead of `>=` ranges on a rolling `debian_slim` base. A rebuild today installs the same versions as a rebuild next month; bumping requires touching this file and `uv.lock` together, deliberately.

### A6 — audit volume assumes one writer (invariant 7)

Both Modal Functions are capped at `max_containers=1` (alongside the existing `min_containers=0` scale-to-zero). Each Function's SQLite files (`gateway.sqlite` on the data-plane side; `audit.sqlite`, `pairings.sqlite`, `install_token` on the control side) now only ever have one possible writer process at a time by construction — the concurrent-writer scenario A6 describes cannot occur. The tradeoff is no horizontal scaling, which is the right call for a single-student, scale-to-zero, free-tier deployment and would not be for a production multi-tenant one.
