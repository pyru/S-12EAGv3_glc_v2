"""Section 7 leak 5: glc.policy.engine.evaluate = lambda *_, **__: allow.

No in-process code can prevent a module attribute being reassigned —
that is a fact about Python, not a bug here (see glc/policy/engine.py's
_PRISTINE_EVALUATE docstring). What this suite proves instead:

1. A caller that holds an early reference to the real evaluate (the
   pattern every real caller should use) keeps enforcing correctly even
   after PolicyEngine.evaluate itself is rebound.
2. The tamper condition is detectable, and detection lands in the audit
   log — which, since leak 2's fix, the same attacker can't erase.
"""

from __future__ import annotations

import glc.policy.engine as engine_module
from glc.policy.engine import PolicyEngine, evaluate, is_tampered
from glc.policy.schemas import PolicyVerdict


def test_is_tampered_false_initially():
    assert is_tampered() is False


def test_is_tampered_true_after_class_rebind():
    original = PolicyEngine.evaluate
    try:
        PolicyEngine.evaluate = lambda *_, **__: PolicyVerdict(action="allow", reason="pirate")
        assert is_tampered() is True
    finally:
        PolicyEngine.evaluate = original
    assert is_tampered() is False


def test_hardened_evaluate_survives_class_level_rebind():
    """The exact demoed leak 5 mechanism, one level up: rebinding
    PolicyEngine.evaluate on the class. The free function `evaluate`
    (which real callers should import once, early) must keep enforcing
    the real policy — untrusted callers must still be denied — even
    while the class attribute is tampered."""
    original = PolicyEngine.evaluate
    try:
        PolicyEngine.evaluate = lambda *_, **__: PolicyVerdict(action="allow", reason="pirate")
        verdict = evaluate({"name": "email.send"}, {"trust_level": "untrusted", "channel": "telegram"})
        assert verdict.action == "deny"
        assert verdict.reason != "pirate"
    finally:
        PolicyEngine.evaluate = original


def test_check_policy_integrity_once_records_audit_entry_on_tamper():
    from glc.audit import query
    from glc.main import check_policy_integrity_once

    original = PolicyEngine.evaluate
    try:
        assert check_policy_integrity_once() is False
        PolicyEngine.evaluate = lambda *_, **__: PolicyVerdict(action="allow", reason="pirate")
        assert check_policy_integrity_once() is True
        rows = query(limit=5)
        assert any(r["event_type"] == "policy_engine_tampered" for r in rows)
    finally:
        PolicyEngine.evaluate = original


def test_module_level_evaluate_rebind_is_undetectable_from_inside_but_detected_by_watchdog():
    """The literal leak 5 demo: rebinding the free function itself. No
    code living inside the old `evaluate` can run anymore — that's the
    fundamental limitation. But main.py captured its own independent
    reference at import time, so its watchdog check still flags it."""
    from glc.main import check_policy_integrity_once

    original = engine_module.evaluate
    try:
        engine_module.evaluate = lambda *_, **__: PolicyVerdict(action="allow", reason="pirate")
        assert check_policy_integrity_once() is True
    finally:
        engine_module.evaluate = original
