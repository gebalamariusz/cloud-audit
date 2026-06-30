"""Tests for Proof Mode - IAM policy-simulator verification (proof.py).

The IAM policy simulator (simulate_principal_policy) is not implemented by moto,
so the verification logic is dependency-injected: a fake simulate function feeds
controlled EvaluationResults. This pins the decision semantics exhaustively
without live AWS - including the resource-scoping gate and condition-key handling
that prevent over-reporting.
"""

from __future__ import annotations

from typing import Any

from cloud_audit.models import EscalationCategory, EscalationPath, Severity
from cloud_audit.proof import (
    _evaluate_simulation,
    _verify_one,
    make_simulate_fn,
    verify_escalation_paths,
    verify_report_escalations,
)

OWN = "123456789012"
# A resource-insensitive action (broad "*" simulation is meaningful) used as the
# default so most tests exercise the real simulate path rather than the gate.
SAFE_ACTION = "iam:CreatePolicyVersion"


def _path(
    arn: str = f"arn:aws:iam::{OWN}:user/u",
    actions: list[str] | None = None,
    method: str = "CreatePolicyVersion",
    category: EscalationCategory = EscalationCategory.IAM_SELF_MUTATION,
) -> EscalationPath:
    return EscalationPath(
        principal_arn=arn,
        principal_name="u",
        principal_type="User",
        method=method,
        category=category,
        required_actions=actions or [SAFE_ACTION],
        target_privilege="admin",
        severity=Severity.HIGH,
    )


def _results(actions: list[str], decision: str) -> list[dict[str, Any]]:
    return [{"EvalActionName": a, "EvalDecision": decision} for a in actions]


# ---------------------------------------------------------------------------
# _evaluate_simulation - decision semantics
# ---------------------------------------------------------------------------


def test_evaluate_all_allowed() -> None:
    verified, detail = _evaluate_simulation(_results([SAFE_ACTION], "allowed"), [SAFE_ACTION])
    assert verified is True
    assert "allowed by the iam policy simulator" in detail.lower()


def test_evaluate_explicit_deny() -> None:
    verified, detail = _evaluate_simulation(_results([SAFE_ACTION], "explicitDeny"), [SAFE_ACTION])
    assert verified is False
    assert "false positive" in detail.lower()


def test_evaluate_implicit_deny() -> None:
    verified, _ = _evaluate_simulation(_results([SAFE_ACTION], "implicitDeny"), [SAFE_ACTION])
    assert verified is False


def test_evaluate_unknown_decision_is_false() -> None:
    """A future/unexpected EvalDecision value is treated as not-allowed (safe default)."""
    verified, _ = _evaluate_simulation(_results([SAFE_ACTION], "futureValue"), [SAFE_ACTION])
    assert verified is False


def test_evaluate_missing_action_is_none() -> None:
    results = _results([SAFE_ACTION], "allowed")
    verified, detail = _evaluate_simulation(results, [SAFE_ACTION, "iam:AttachUserPolicy"])
    assert verified is None
    assert "incomplete" in detail.lower()


def test_evaluate_empty_results_is_none() -> None:
    verified, _ = _evaluate_simulation([], [SAFE_ACTION])
    assert verified is None


def test_evaluate_empty_required_actions_is_none() -> None:
    """Empty action set must not be vacuously verified True."""
    verified, detail = _evaluate_simulation([], [])
    assert verified is None
    assert "no required actions" in detail.lower()


def test_evaluate_missing_context_gated_is_none() -> None:
    """Allowed only because a condition key (e.g. MFA) was unevaluated -> not asserted."""
    results = [
        {
            "EvalActionName": SAFE_ACTION,
            "EvalDecision": "allowed",
            "MissingContextValues": ["aws:MultiFactorAuthPresent"],
        }
    ]
    verified, detail = _evaluate_simulation(results, [SAFE_ACTION])
    assert verified is None
    assert "condition key" in detail.lower()
    assert "MultiFactorAuthPresent" in detail


def test_evaluate_multi_action_all_allowed() -> None:
    actions = ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"]
    verified, _ = _evaluate_simulation(_results(actions, "allowed"), actions)
    assert verified is True


def test_evaluate_multi_action_one_denied() -> None:
    actions = ["iam:CreatePolicyVersion", "iam:AttachUserPolicy"]
    results = [
        {"EvalActionName": "iam:CreatePolicyVersion", "EvalDecision": "allowed"},
        {"EvalActionName": "iam:AttachUserPolicy", "EvalDecision": "implicitDeny"},
    ]
    verified, detail = _evaluate_simulation(results, actions)
    assert verified is False
    assert "iam:AttachUserPolicy" in detail


def test_evaluate_ignores_malformed_entries() -> None:
    results = [{"EvalActionName": SAFE_ACTION, "EvalDecision": "allowed"}, {"junk": 1}, "nope"]
    verified, _ = _evaluate_simulation(results, [SAFE_ACTION])  # type: ignore[list-item]
    assert verified is True


# ---------------------------------------------------------------------------
# _verify_one - resource-scoping gate (CRITICAL #1 fix)
# ---------------------------------------------------------------------------


def test_verify_one_resource_insensitive_allowed() -> None:
    verified, _ = _verify_one([SAFE_ACTION], "arn", lambda a, x: _results(x, "allowed"))
    assert verified is True


def test_verify_one_passrole_not_asserted() -> None:
    """iam:PassRole is resource-scoped; a '*' simulation must NOT assert verified."""
    called = []
    verified, detail = _verify_one(["iam:PassRole"], "arn", lambda a, x: called.append(x) or _results(x, "allowed"))
    assert verified is None
    assert "resource-scoped" in detail.lower()
    assert called == []  # gate short-circuits before any API call


def test_verify_one_assumerole_not_asserted() -> None:
    verified, detail = _verify_one(["sts:AssumeRole"], "arn", lambda a, x: _results(x, "allowed"))
    assert verified is None
    assert "resource-scoped" in detail.lower()


def test_verify_one_mixed_with_scoped_action_not_asserted() -> None:
    """If ANY required action is resource-scoped, the whole path is not asserted."""
    verified, _ = _verify_one([SAFE_ACTION, "iam:PassRole"], "arn", lambda a, x: _results(x, "allowed"))
    assert verified is None


def test_verify_one_deny_removal_not_asserted() -> None:
    """Deny-removal actions are resource-scoped + not grant-semantics -> not asserted."""
    for action in ("iam:DeleteUserPolicy", "iam:DetachUserPolicy", "iam:DeleteRolePolicy"):
        verified, detail = _verify_one([action], "arn", lambda a, x: _results(x, "allowed"))
        assert verified is None, action
        assert "resource-scoped" in detail.lower()


def test_verify_one_empty_is_none() -> None:
    verified, _ = _verify_one([], "arn", lambda a, x: _results(x, "allowed"))
    assert verified is None


def test_verify_one_simulate_error_is_none() -> None:
    def _boom(a: str, x: list[str]) -> list[dict[str, Any]]:
        raise RuntimeError("AccessDenied on simulate")

    verified, detail = _verify_one([SAFE_ACTION], "arn", _boom)
    assert verified is None
    assert "unavailable" in detail.lower()


# ---------------------------------------------------------------------------
# verify_escalation_paths
# ---------------------------------------------------------------------------


def test_verify_paths_allowed_sets_true() -> None:
    paths = [_path()]
    verify_escalation_paths(paths, lambda a, x: _results(x, "allowed"))
    assert paths[0].verified is True
    assert paths[0].verification_detail


def test_verify_paths_denied_sets_false() -> None:
    paths = [_path()]
    verify_escalation_paths(paths, lambda a, x: _results(x, "implicitDeny"))
    assert paths[0].verified is False


def test_verify_paths_passrole_path_not_asserted() -> None:
    paths = [_path(actions=["iam:PassRole"], method="PassRole+EC2", category=EscalationCategory.PASSROLE_SERVICE)]
    verify_escalation_paths(paths, lambda a, x: _results(x, "allowed"))
    assert paths[0].verified is None
    assert "resource-scoped" in paths[0].verification_detail.lower()


def test_verify_paths_dedupes_api_calls() -> None:
    calls: list[tuple[str, tuple[str, ...]]] = []

    def _counting(arn: str, actions: list[str]) -> list[dict[str, Any]]:
        calls.append((arn, tuple(actions)))
        return _results(actions, "allowed")

    # two identical resource-insensitive paths + one different insensitive action
    paths = [_path(), _path(), _path(actions=["iam:AttachUserPolicy"], method="AttachUserPolicy")]
    verify_escalation_paths(paths, _counting)
    assert len(calls) == 2  # deduped to 2 unique (principal, action-set) keys
    assert all(p.verified is True for p in paths)


def test_verify_paths_per_path_isolation() -> None:
    """A simulator error for one path must not affect another."""

    def _sim(arn: str, actions: list[str]) -> list[dict[str, Any]]:
        if "boom" in arn:
            raise RuntimeError("throttled")
        return _results(actions, "allowed")

    paths = [_path(arn=f"arn:aws:iam::{OWN}:user/boom"), _path(arn=f"arn:aws:iam::{OWN}:user/ok")]
    verify_escalation_paths(paths, _sim)
    assert paths[0].verified is None
    assert paths[1].verified is True


def test_verify_paths_empty_is_noop() -> None:
    verify_escalation_paths([], lambda a, x: _results(x, "allowed"))  # must not raise


# ---------------------------------------------------------------------------
# verify_report_escalations + make_simulate_fn (provider-backed path)
# ---------------------------------------------------------------------------


class _FakeIam:
    def __init__(self, decision: str = "allowed") -> None:
        self.decision = decision
        self.calls = 0

    def simulate_principal_policy(self, PolicySourceArn: str, ActionNames: list[str]) -> dict[str, Any]:  # noqa: N803
        self.calls += 1
        return {"EvaluationResults": _results(ActionNames, self.decision)}


class _FakeProvider:
    def __init__(self, iam: _FakeIam) -> None:
        self._iam = iam

    def client(self, service: str, region_name: str | None = None) -> _FakeIam:
        return self._iam


def test_verify_report_counts_policy_allowed() -> None:
    iam = _FakeIam("allowed")
    # one resource-insensitive (counts) + one resource-scoped (not asserted)
    paths = [_path(), _path(actions=["iam:PassRole"], method="PassRole", category=EscalationCategory.PASSROLE_SERVICE)]
    n = verify_report_escalations(_FakeProvider(iam), paths)  # type: ignore[arg-type]
    assert n == 1  # only the resource-insensitive path is policy-allowed
    assert paths[0].verified is True
    assert paths[1].verified is None
    assert iam.calls == 1  # the resource-scoped path never hit the API


def test_verify_report_empty_returns_zero() -> None:
    iam = _FakeIam("allowed")
    assert verify_report_escalations(_FakeProvider(iam), []) == 0  # type: ignore[arg-type]
    assert iam.calls == 0


def test_make_simulate_fn_calls_iam() -> None:
    iam = _FakeIam("allowed")
    fn = make_simulate_fn(_FakeProvider(iam))  # type: ignore[arg-type]
    res = fn("arn:aws:iam::123456789012:user/u", ["iam:CreatePolicyVersion"])
    assert res[0]["EvalDecision"] == "allowed"
    assert iam.calls == 1


def test_escalation_path_defaults_verified_none() -> None:
    """Backward compat: paths default to unchecked (verified=None)."""
    p = _path()
    assert p.verified is None
    assert p.verification_detail == ""
