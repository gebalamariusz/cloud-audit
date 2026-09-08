"""Proof Mode - read-only IAM policy-simulator checks.

cloud-audit detects IAM privilege-escalation paths statically (effective-permission
resolution in ``iam_analyzer``). Proof Mode cross-checks findings against AWS's
own authorization engine via ``iam:SimulatePrincipalPolicy`` - a **read-only**
call that asks whether the principal's policies allow the actions the finding
requires. Two entry points:

- ``verify_escalation_paths`` / ``verify_report_escalations`` - the original
  broad check over escalation paths (``scan --verify``).
- ``verify_resource_access`` - per-resource simulation for a single action
  (``ResourceArns`` + optional ``ContextEntries``), used to prove data reach and
  lateral movement from a concrete principal, e.g. an AI agent's execution role.

What the simulator evaluates (IAM API reference, state as of 2026-07-30):

- Identity-based policies of the principal (inline, attached, group-inherited).
- The permissions boundary attached to the principal (one boundary at a time).
- Service control policies (SCPs) of the principal's organization, including
  their condition keys and resource scoping. The simulator returns
  ``OrganizationsDecisionDetail.AllowedByOrganizations`` but, for security
  reasons, not the matched SCP statements.
- Context keys you supply in ``ContextEntries``. Principal/organization keys
  (``aws:PrincipalAccount``, ``aws:PrincipalOrgID``...) are populated by AWS.

What it does NOT evaluate:

- Resource control policies (RCPs).
- Resource-based policies unless supplied via ``ResourcePolicy`` - and
  resource-based policy simulation is not supported for IAM roles at all.
- VPC endpoint policies, role chaining, multiple resource-based policies on one
  resource ("results can still differ from live behavior").
- Session policies and anything about the *actual* request: the simulator
  never calls the service.

Honest framing of the results (this matters):

- ``verified=True`` / ``allowed=True`` - the simulator returned ``allowed``.
  This confirms the **permission exists** under the evaluated policy types; it
  is simulated, not executed, and is not a guarantee an end-to-end attack
  succeeds.
- ``verified=False`` / ``allowed=False`` - the simulator denied the action
  (explicit or implicit, possibly by an SCP or the boundary). Strong signal that
  the statically-detected path is a false positive.
- ``None`` - not asserted: incomplete result, or allowed only under condition
  keys we did not supply, or (escalation paths) the method is resource-scoped
  and no target resource is known.

Resource-scoping caveat for escalation paths: without ``ResourceArns`` the
simulator evaluates against ``*``. For resource-scoped methods (``iam:PassRole``
to a specific role, ``sts:AssumeRole`` to a specific role, compute-hijack into a
specific target) an ``allowed`` on ``*`` does NOT prove the *specific* target is
privileged or even passable, so those paths stay ``None``. Only methods where a
broad evaluation is semantically meaningful (IAM self-mutation / credential
creation, where "allowed at all" is the escalation) are asserted.

``PolicyExclusionList`` ("what if this policy were removed") exists in the IAM
API since 2026-07 but requires a newer botocore than cloud-audit pins; it is
deliberately not used here.

Opt-in: adds one IAM API call per unique (principal, action-set, resources).
``iam:SimulatePrincipalPolicy`` has no per-call charge; the opt-in exists to
control latency / API throttling, not cost.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cloud_audit.models import EscalationPath
    from cloud_audit.providers.aws.provider import AWSProvider

# A SimulateFn takes (principal_arn, action_names) and returns the IAM simulator's
# EvaluationResults list. The resource-scoped entry point calls it with two extra
# keyword arguments, ``resource_arns`` and ``context_entries``; the broad
# escalation path keeps the two-positional-argument form so simple fakes keep
# working. Injected so the verification logic is testable without live AWS
# (moto does not implement simulate_principal_policy).
SimulateFn = Callable[..., list[dict[str, Any]]]

# Escalation actions where a broad (ResourceArns omitted -> "*") simulation is
# semantically meaningful: these grant the principal power over its own
# permissions or create new credentials, so "allowed at all" IS the escalation.
# Everything NOT in this set is treated as resource-scoped and left unasserted,
# because a "*" simulation over-reports for actions whose exploitability depends
# on a specific target resource (PassRole/AssumeRole/compute-hijack/etc.).
# Stored lowercase; matched case-insensitively.
RESOURCE_INSENSITIVE_ACTIONS = {
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:attachuserpolicy",
    "iam:attachgrouppolicy",
    "iam:attachrolepolicy",
    "iam:putuserpolicy",
    "iam:putgrouppolicy",
    "iam:putrolepolicy",
    "iam:createaccesskey",
    "iam:createloginprofile",
    "iam:updateloginprofile",
    "iam:addusertogroup",
    "iam:createuser",
    "iam:createrole",
    "iam:createservicelinkedrole",
    "iam:updateaccesskey",
    "iam:deactivatemfadevice",
    "iam:deletevirtualmfadevice",
}
# Deliberately EXCLUDED from assertion (do NOT add back): deny-removal actions
# iam:DetachUserPolicy / DeleteUserPolicy / DetachRolePolicy / DeleteRolePolicy.
# They are resource-scoped (a "*" simulation over-reports, like PassRole) AND they
# "remove a blocking Deny" rather than grant access - the simulator cannot confirm
# the detached policy actually contained the blocker, so they are not assertable
# even with per-action ResourceArns. They fall through the gate to verified=None.

# Context an attacker holding the principal's credentials realistically has:
# no MFA on the session (stolen keys, hijacked agent role) and TLS transport.
# Supplying these makes MFA-gated allows evaluate deterministically instead of
# surfacing as "missing context". Opt-in via ``context_entries``; the broad
# escalation check does not use them, to keep its historical semantics.
ATTACKER_CONTEXT_ENTRIES: list[dict[str, Any]] = [
    {
        "ContextKeyName": "aws:MultiFactorAuthPresent",
        "ContextKeyValues": ["false"],
        "ContextKeyType": "boolean",
    },
    {
        "ContextKeyName": "aws:SecureTransport",
        "ContextKeyValues": ["true"],
        "ContextKeyType": "boolean",
    },
]

_VERIFIED_TRUE_DETAIL = (
    "All required actions allowed by the IAM policy simulator (simulated, not executed). "
    "Broad check on '*' resources: identity policies, the attached permissions boundary and SCPs "
    "are evaluated; resource-based policies, RCPs and trust conditions are not."
)


@dataclass(frozen=True)
class ResourceProof:
    """Simulator verdict for one (action, resource) pair."""

    action: str
    resource_arn: str
    decision: str
    """Raw simulator decision: ``allowed``, ``explicitDeny``, ``implicitDeny`` or ``unknown``."""
    allowed: bool | None
    """``True``/``False`` when asserted; ``None`` when incomplete or gated on unsupplied context."""
    detail: str


def _evaluate_simulation(eval_results: list[dict[str, Any]], required_actions: list[str]) -> tuple[bool | None, str]:
    """Decide verification status from IAM simulator ``EvaluationResults``.

    Returns ``(verified, detail)``:

    - ``True``  - every required action evaluated to ``"allowed"`` with no
      unevaluated condition keys.
    - ``False`` - at least one required action was denied (explicit or implicit);
      the principal lacks the permission, so the static path is likely a false
      positive.
    - ``None``  - incomplete (a required action has no result) or allowed only
      under condition keys that were not supplied to the simulator.
    """
    if not required_actions:
        return None, "No required actions to verify"

    decisions: dict[str, str] = {}
    missing_context: dict[str, list[str]] = {}
    deny_reasons: dict[str, str] = {}
    for r in eval_results:
        if not isinstance(r, dict):
            continue
        name = r.get("EvalActionName")
        decision = r.get("EvalDecision")
        if isinstance(name, str) and isinstance(decision, str):
            decisions[name] = decision
            mcv = r.get("MissingContextValues")
            if isinstance(mcv, list) and mcv:
                missing_context[name] = [v for v in mcv if isinstance(v, str)]
            reason = _deny_reason(r)
            if reason:
                deny_reasons[name] = reason

    missing = [a for a in required_actions if a not in decisions]
    if missing:
        return None, f"Incomplete simulation: no result for {', '.join(missing)}"

    denied = [a for a in required_actions if decisions.get(a) != "allowed"]
    if denied:
        reasons = ", ".join(f"{a}={decisions[a]}{deny_reasons.get(a, '')}" for a in denied)
        return False, f"Simulator denied: {reasons} (principal lacks the permission - likely a false positive)"

    # Allowed, but if any action only passed because a required condition key was
    # absent (e.g. aws:MultiFactorAuthPresent), we must not assert exploitability.
    gated = [a for a in required_actions if a in missing_context]
    if gated:
        keys = sorted({k for a in gated for k in missing_context[a]})
        return None, f"Allowed only with unevaluated condition keys ({', '.join(keys)}); not asserted"

    return True, _VERIFIED_TRUE_DETAIL


def _deny_reason(entry: dict[str, Any]) -> str:
    """Name the policy layer that denied, when the simulator says so.

    ``OrganizationsDecisionDetail.AllowedByOrganizations=False`` means an SCP
    denied; ``PermissionsBoundaryDecisionDetail.AllowedByPermissionsBoundary=False``
    means the boundary denied. Returned as a short suffix, empty when unknown.
    """
    org = entry.get("OrganizationsDecisionDetail")
    if isinstance(org, dict) and org.get("AllowedByOrganizations") is False:
        return " (denied by SCP)"
    boundary = entry.get("PermissionsBoundaryDecisionDetail")
    if isinstance(boundary, dict) and boundary.get("AllowedByPermissionsBoundary") is False:
        return " (denied by permissions boundary)"
    return ""


def _verify_one(required_actions: list[str], principal_arn: str, simulate_fn: SimulateFn) -> tuple[bool | None, str]:
    """Verify a single action-set, applying the resource-scoping gate first."""
    if not required_actions:
        return None, "No required actions to verify"

    resource_scoped = [a for a in required_actions if a.lower() not in RESOURCE_INSENSITIVE_ACTIONS]
    if resource_scoped:
        return None, (
            f"Not asserted: resource-scoped action(s) {', '.join(resource_scoped)}. "
            "Without resource ARNs the simulator evaluates against '*', which cannot confirm the "
            "specific target resource is privileged/passable. Requires resource-level simulation."
        )

    try:
        results = simulate_fn(principal_arn, required_actions)
    except Exception as e:  # read-only verification must never break a scan
        return None, f"Verification unavailable: {e}"
    return _evaluate_simulation(results, required_actions)


def verify_escalation_paths(paths: list[EscalationPath], simulate_fn: SimulateFn) -> None:
    """Annotate each escalation path with a Proof Mode result.

    Mutates ``paths`` in place: sets ``verified`` and ``verification_detail``.
    Deduplicates work per unique ``(principal_arn, sorted actions)``. A simulator
    error for one path leaves it ``None`` and never affects the others.
    """
    cache: dict[tuple[str, tuple[str, ...]], tuple[bool | None, str]] = {}
    for path in paths:
        actions = list(path.required_actions)
        key = (path.principal_arn, tuple(sorted(actions)))
        if key not in cache:
            cache[key] = _verify_one(actions, path.principal_arn, simulate_fn)
        path.verified, path.verification_detail = cache[key]


# ---------------------------------------------------------------------------
# Per-resource simulation (data reach, lateral movement)
# ---------------------------------------------------------------------------


def _resource_verdicts(eval_results: list[dict[str, Any]], action: str) -> dict[str, tuple[str, list[str], str]]:
    """Map ``resource_arn -> (decision, missing_context_keys, deny_reason)`` for one action.

    Handles both response shapes: one ``EvaluationResult`` per (action, resource)
    carrying ``EvalResourceName``, and one per action carrying
    ``ResourceSpecificResults``. When a result names no resource it is recorded
    under ``"*"``.
    """
    verdicts: dict[str, tuple[str, list[str], str]] = {}
    for r in eval_results:
        if not isinstance(r, dict) or r.get("EvalActionName") != action:
            continue
        specific = r.get("ResourceSpecificResults")
        if isinstance(specific, list) and specific:
            for rs in specific:
                if not isinstance(rs, dict):
                    continue
                name = rs.get("EvalResourceName")
                decision = rs.get("EvalResourceDecision")
                if isinstance(name, str) and isinstance(decision, str):
                    mcv = rs.get("MissingContextValues")
                    keys = [v for v in mcv if isinstance(v, str)] if isinstance(mcv, list) else []
                    verdicts[name] = (decision, keys, _deny_reason(rs) or _deny_reason(r))
            continue
        decision = r.get("EvalDecision")
        if not isinstance(decision, str):
            continue
        name = r.get("EvalResourceName")
        mcv = r.get("MissingContextValues")
        keys = [v for v in mcv if isinstance(v, str)] if isinstance(mcv, list) else []
        verdicts[name if isinstance(name, str) else "*"] = (decision, keys, _deny_reason(r))
    return verdicts


def verify_resource_access(
    principal_arn: str,
    action: str,
    resource_arns: list[str],
    simulate_fn: SimulateFn,
    context_entries: list[dict[str, Any]] | None = None,
) -> list[ResourceProof]:
    """Ask the simulator whether ``principal_arn`` may perform ``action`` on each resource.

    One API call for the whole resource list. Returns one ``ResourceProof`` per
    requested resource, in input order. A simulator error yields ``allowed=None``
    for every resource with the error in ``detail`` - verification must never
    break the caller. Resource-based policies are not simulated (unsupported for
    IAM roles), which the detail text states for every allowed verdict.
    """
    if not resource_arns:
        return []
    # Preserve order, drop duplicates.
    unique: list[str] = list(dict.fromkeys(resource_arns))
    try:
        results = simulate_fn(
            principal_arn,
            [action],
            resource_arns=unique,
            context_entries=context_entries or None,
        )
    except Exception as e:  # read-only verification must never break the caller
        return [ResourceProof(action, arn, "unknown", None, f"Verification unavailable: {e}") for arn in unique]

    verdicts = _resource_verdicts(results, action)
    proofs: list[ResourceProof] = []
    for arn in unique:
        entry = verdicts.get(arn) or verdicts.get("*")
        if entry is None:
            proofs.append(
                ResourceProof(action, arn, "unknown", None, "Incomplete simulation: no result for this resource")
            )
            continue
        decision, missing, reason = entry
        if decision != "allowed":
            proofs.append(
                ResourceProof(
                    action,
                    arn,
                    decision,
                    False,
                    f"Simulator denied ({decision}{reason})",
                )
            )
        elif missing:
            proofs.append(
                ResourceProof(
                    action,
                    arn,
                    decision,
                    None,
                    f"Allowed only with unevaluated condition keys ({', '.join(sorted(set(missing)))}); not asserted",
                )
            )
        else:
            proofs.append(
                ResourceProof(
                    action,
                    arn,
                    decision,
                    True,
                    "Allowed by the IAM policy simulator on this resource (simulated, not executed; "
                    "identity policies, permissions boundary and SCPs evaluated; "
                    "resource-based policy of the target not simulated)",
                )
            )
    return proofs


def make_simulate_fn(provider: AWSProvider) -> SimulateFn:
    """Build a ``SimulateFn`` backed by the AWS IAM policy simulator (read-only).

    Accepts the optional ``resource_arns`` / ``context_entries`` keyword arguments
    and follows ``Marker`` pagination so long resource lists are complete.
    """
    iam = provider.client("iam")

    def _simulate(
        principal_arn: str,
        action_names: list[str],
        resource_arns: list[str] | None = None,
        context_entries: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"PolicySourceArn": principal_arn, "ActionNames": action_names}
        if resource_arns:
            params["ResourceArns"] = resource_arns
        if context_entries:
            params["ContextEntries"] = context_entries
        results: list[dict[str, Any]] = []
        marker: str | None = None
        while True:
            if marker:
                params["Marker"] = marker
            resp = iam.simulate_principal_policy(**params)
            results.extend(resp.get("EvaluationResults", []))
            if not resp.get("IsTruncated"):
                break
            marker = resp.get("Marker")
            if not marker:
                break
        return results

    return _simulate


def verify_report_escalations(provider: AWSProvider, paths: list[EscalationPath]) -> int:
    """Run Proof Mode over a report's escalation paths. Returns count of policy-allowed paths.

    Convenience wrapper used by the scanner: builds the live simulate function and
    annotates the paths. Safe to call with an empty list.
    """
    if not paths:
        return 0
    verify_escalation_paths(paths, make_simulate_fn(provider))
    return sum(1 for p in paths if p.verified is True)
