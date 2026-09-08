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
    ATTACKER_CONTEXT_ENTRIES,
    _evaluate_simulation,
    _verify_one,
    make_simulate_fn,
    verify_escalation_paths,
    verify_report_escalations,
    verify_resource_access,
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


# ---------------------------------------------------------------------------
# verify_resource_access - per-resource simulation (ResourceArns + ContextEntries)
# ---------------------------------------------------------------------------

ROLE = f"arn:aws:iam::{OWN}:role/agent-exec"
BUCKET_A = "arn:aws:s3:::kb-docs/*"
BUCKET_B = "arn:aws:s3:::hr-files/*"


def _per_resource(
    action: str, decisions: dict[str, str], missing: dict[str, list[str]] | None = None
) -> list[dict[str, Any]]:
    """Response shape 1: one EvaluationResult per (action, resource) with EvalResourceName."""
    out: list[dict[str, Any]] = []
    for arn, decision in decisions.items():
        entry: dict[str, Any] = {"EvalActionName": action, "EvalDecision": decision, "EvalResourceName": arn}
        if missing and arn in missing:
            entry["MissingContextValues"] = missing[arn]
        out.append(entry)
    return out


class _RecordingSimulate:
    """Fake SimulateFn that records how it was called and returns canned results."""

    def __init__(self, results: list[dict[str, Any]] | Exception) -> None:
        self.results = results
        self.calls: list[dict[str, Any]] = []

    def __call__(
        self,
        principal_arn: str,
        action_names: list[str],
        resource_arns: list[str] | None = None,
        context_entries: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        self.calls.append(
            {
                "principal": principal_arn,
                "actions": action_names,
                "resource_arns": resource_arns,
                "context_entries": context_entries,
            }
        )
        if isinstance(self.results, Exception):
            raise self.results
        return self.results


def test_verify_resource_access_allowed_and_denied_per_resource() -> None:
    sim = _RecordingSimulate(_per_resource("s3:GetObject", {BUCKET_A: "allowed", BUCKET_B: "implicitDeny"}))
    proofs = verify_resource_access(ROLE, "s3:GetObject", [BUCKET_A, BUCKET_B], sim)
    assert [p.resource_arn for p in proofs] == [BUCKET_A, BUCKET_B]
    assert proofs[0].allowed is True
    assert "not executed" in proofs[0].detail
    assert "resource-based policy" in proofs[0].detail
    assert proofs[1].allowed is False
    assert proofs[1].decision == "implicitDeny"
    # single API call for the whole list, resources + action passed through
    assert len(sim.calls) == 1
    assert sim.calls[0]["actions"] == ["s3:GetObject"]
    assert sim.calls[0]["resource_arns"] == [BUCKET_A, BUCKET_B]


def test_verify_resource_access_resource_specific_results_shape() -> None:
    """Response shape 2: one EvaluationResult per action carrying ResourceSpecificResults."""
    results = [
        {
            "EvalActionName": "sts:AssumeRole",
            "EvalDecision": "allowed",
            "ResourceSpecificResults": [
                {"EvalResourceName": "arn:aws:iam::123456789012:role/a", "EvalResourceDecision": "allowed"},
                {"EvalResourceName": "arn:aws:iam::123456789012:role/b", "EvalResourceDecision": "explicitDeny"},
            ],
        }
    ]
    sim = _RecordingSimulate(results)
    proofs = verify_resource_access(
        ROLE, "sts:AssumeRole", ["arn:aws:iam::123456789012:role/a", "arn:aws:iam::123456789012:role/b"], sim
    )
    assert proofs[0].allowed is True
    assert proofs[1].allowed is False
    assert proofs[1].decision == "explicitDeny"


def test_verify_resource_access_denied_by_scp_names_the_layer() -> None:
    results = [
        {
            "EvalActionName": "s3:GetObject",
            "EvalDecision": "implicitDeny",
            "EvalResourceName": BUCKET_A,
            "OrganizationsDecisionDetail": {"AllowedByOrganizations": False},
        }
    ]
    proofs = verify_resource_access(ROLE, "s3:GetObject", [BUCKET_A], _RecordingSimulate(results))
    assert proofs[0].allowed is False
    assert "denied by SCP" in proofs[0].detail


def test_verify_resource_access_denied_by_boundary_names_the_layer() -> None:
    results = [
        {
            "EvalActionName": "s3:GetObject",
            "EvalDecision": "implicitDeny",
            "EvalResourceName": BUCKET_A,
            "PermissionsBoundaryDecisionDetail": {"AllowedByPermissionsBoundary": False},
        }
    ]
    proofs = verify_resource_access(ROLE, "s3:GetObject", [BUCKET_A], _RecordingSimulate(results))
    assert proofs[0].allowed is False
    assert "permissions boundary" in proofs[0].detail


def test_verify_resource_access_missing_context_is_none() -> None:
    results = _per_resource("s3:GetObject", {BUCKET_A: "allowed"}, missing={BUCKET_A: ["aws:SourceIp"]})
    proofs = verify_resource_access(ROLE, "s3:GetObject", [BUCKET_A], _RecordingSimulate(results))
    assert proofs[0].allowed is None
    assert "aws:SourceIp" in proofs[0].detail


def test_verify_resource_access_simulate_error_never_raises() -> None:
    sim = _RecordingSimulate(RuntimeError("throttled"))
    proofs = verify_resource_access(ROLE, "s3:GetObject", [BUCKET_A, BUCKET_B], sim)
    assert len(proofs) == 2
    assert all(p.allowed is None for p in proofs)
    assert all("throttled" in p.detail for p in proofs)


def test_verify_resource_access_empty_resources_is_noop() -> None:
    sim = _RecordingSimulate([])
    assert verify_resource_access(ROLE, "s3:GetObject", [], sim) == []
    assert sim.calls == []


def test_verify_resource_access_dedupes_preserving_order() -> None:
    sim = _RecordingSimulate(_per_resource("s3:GetObject", {BUCKET_B: "allowed", BUCKET_A: "allowed"}))
    proofs = verify_resource_access(ROLE, "s3:GetObject", [BUCKET_B, BUCKET_A, BUCKET_B], sim)
    assert [p.resource_arn for p in proofs] == [BUCKET_B, BUCKET_A]
    assert sim.calls[0]["resource_arns"] == [BUCKET_B, BUCKET_A]


def test_verify_resource_access_incomplete_resource_is_none() -> None:
    sim = _RecordingSimulate(_per_resource("s3:GetObject", {BUCKET_A: "allowed"}))
    proofs = verify_resource_access(ROLE, "s3:GetObject", [BUCKET_A, BUCKET_B], sim)
    assert proofs[0].allowed is True
    assert proofs[1].allowed is None
    assert "Incomplete" in proofs[1].detail


def test_verify_resource_access_star_verdict_falls_back() -> None:
    """A result without EvalResourceName applies to every requested resource."""
    results = [{"EvalActionName": "s3:GetObject", "EvalDecision": "allowed"}]
    proofs = verify_resource_access(ROLE, "s3:GetObject", [BUCKET_A, BUCKET_B], _RecordingSimulate(results))
    assert all(p.allowed is True for p in proofs)


def test_verify_resource_access_passes_attacker_context() -> None:
    sim = _RecordingSimulate(_per_resource("s3:GetObject", {BUCKET_A: "allowed"}))
    verify_resource_access(ROLE, "s3:GetObject", [BUCKET_A], sim, context_entries=ATTACKER_CONTEXT_ENTRIES)
    ctx = sim.calls[0]["context_entries"]
    assert ctx is not None
    names = {c["ContextKeyName"] for c in ctx}
    assert names == {"aws:MultiFactorAuthPresent", "aws:SecureTransport"}


def test_verify_resource_access_omits_context_when_not_given() -> None:
    sim = _RecordingSimulate(_per_resource("s3:GetObject", {BUCKET_A: "allowed"}))
    verify_resource_access(ROLE, "s3:GetObject", [BUCKET_A], sim)
    assert sim.calls[0]["context_entries"] is None


def test_evaluate_broad_path_names_scp_deny() -> None:
    """The broad escalation check surfaces the denying layer in its detail text."""
    results = [
        {
            "EvalActionName": SAFE_ACTION,
            "EvalDecision": "implicitDeny",
            "OrganizationsDecisionDetail": {"AllowedByOrganizations": False},
        }
    ]
    verified, detail = _evaluate_simulation(results, [SAFE_ACTION])
    assert verified is False
    assert "denied by SCP" in detail


def test_evaluate_broad_path_true_detail_reflects_simulator_scope() -> None:
    verified, detail = _evaluate_simulation(_results([SAFE_ACTION], "allowed"), [SAFE_ACTION])
    assert verified is True
    assert "SCPs" in detail
    assert "resource-based policies" in detail


class _FakeIamCtx:
    """IAM stub that records simulate_principal_policy kwargs and can paginate."""

    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages
        self.calls: list[dict[str, Any]] = []

    def simulate_principal_policy(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(dict(kwargs))
        return self.pages[len(self.calls) - 1]


def test_make_simulate_fn_passes_resource_arns_and_context() -> None:
    iam = _FakeIamCtx([{"EvaluationResults": _per_resource("s3:GetObject", {BUCKET_A: "allowed"})}])
    fn = make_simulate_fn(_FakeProvider(iam))  # type: ignore[arg-type]
    fn(ROLE, ["s3:GetObject"], resource_arns=[BUCKET_A], context_entries=ATTACKER_CONTEXT_ENTRIES)
    call = iam.calls[0]
    assert call["PolicySourceArn"] == ROLE
    assert call["ActionNames"] == ["s3:GetObject"]
    assert call["ResourceArns"] == [BUCKET_A]
    assert call["ContextEntries"] == ATTACKER_CONTEXT_ENTRIES
    assert "Marker" not in call


def test_make_simulate_fn_broad_call_omits_optional_params() -> None:
    iam = _FakeIamCtx([{"EvaluationResults": _results([SAFE_ACTION], "allowed")}])
    fn = make_simulate_fn(_FakeProvider(iam))  # type: ignore[arg-type]
    fn(ROLE, [SAFE_ACTION])
    assert set(iam.calls[0].keys()) == {"PolicySourceArn", "ActionNames"}


def test_make_simulate_fn_follows_marker_pagination() -> None:
    page1 = {
        "EvaluationResults": _per_resource("s3:GetObject", {BUCKET_A: "allowed"}),
        "IsTruncated": True,
        "Marker": "m1",
    }
    page2 = {"EvaluationResults": _per_resource("s3:GetObject", {BUCKET_B: "implicitDeny"}), "IsTruncated": False}
    iam = _FakeIamCtx([page1, page2])
    fn = make_simulate_fn(_FakeProvider(iam))  # type: ignore[arg-type]
    res = fn(ROLE, ["s3:GetObject"], resource_arns=[BUCKET_A, BUCKET_B])
    assert [r["EvalResourceName"] for r in res] == [BUCKET_A, BUCKET_B]
    assert len(iam.calls) == 2
    assert iam.calls[1]["Marker"] == "m1"
