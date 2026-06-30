"""Proof Mode - read-only IAM policy-simulator check for escalation paths.

cloud-audit detects IAM privilege-escalation paths statically (effective-permission
resolution in ``iam_analyzer``). Proof Mode cross-checks each path against AWS's
own authorization engine via ``iam:SimulatePrincipalPolicy`` - a **read-only**
call that asks whether the principal's policies allow the actions the escalation
method requires.

What it does and does NOT claim (honest framing - this matters):

- ``verified=True``  - the IAM policy simulator returned ``allowed`` for every
  required action. This confirms the **permission exists**; it is *simulated, not
  executed*, and the simulator does NOT factor in SCPs, permission boundaries,
  resource policies, or trust conditions. It is "policy-allowed", not a guarantee
  the end-to-end attack succeeds.
- ``verified=False`` - the simulator denied a required action (explicit or
  implicit). This is the strongest signal: the statically-detected path is very
  likely a false positive because the principal lacks the permission.
- ``verified=None``  - not asserted. Either the result was incomplete, the action
  is gated by condition keys we did not supply, or the escalation method is
  **resource-scoped** (see below).

Resource-scoping caveat (the reason some paths stay ``None``): without
``ResourceArns`` the simulator evaluates against ``*``. For resource-scoped
methods (``iam:PassRole`` to a specific role, ``sts:AssumeRole`` to a specific
role, compute-hijack into a specific target) an ``allowed`` on ``*`` does NOT
prove the *specific* target is privileged or even passable - so we deliberately
do not assert ``verified`` for those and leave them ``None`` with an explanation.
Only methods where a broad (``*``) evaluation is semantically meaningful (IAM
self-mutation / credential creation, where "allowed at all" is the escalation)
are asserted. A future enhancement can supply per-action ``ResourceArns`` to
cover the resource-scoped methods too.

Opt-in (``scan --verify``): adds one IAM API call per unique
(principal, action-set). ``iam:SimulatePrincipalPolicy`` has no per-call charge;
the opt-in exists to control latency / API throttling, not cost.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cloud_audit.models import EscalationPath
    from cloud_audit.providers.aws.provider import AWSProvider

# A SimulateFn takes (principal_arn, action_names) and returns the IAM simulator's
# EvaluationResults list. Injected so the verification logic is testable without
# live AWS (moto does not implement simulate_principal_policy).
SimulateFn = Callable[[str, list[str]], list[dict[str, Any]]]

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

_VERIFIED_TRUE_DETAIL = (
    "All required actions allowed by the IAM policy simulator (simulated, not executed). "
    "Broad check: SCPs, permission boundaries, resource policies and trust conditions are not factored in."
)


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

    missing = [a for a in required_actions if a not in decisions]
    if missing:
        return None, f"Incomplete simulation: no result for {', '.join(missing)}"

    denied = [a for a in required_actions if decisions.get(a) != "allowed"]
    if denied:
        reasons = ", ".join(f"{a}={decisions[a]}" for a in denied)
        return False, f"Simulator denied: {reasons} (principal lacks the permission - likely a false positive)"

    # Allowed, but if any action only passed because a required condition key was
    # absent (e.g. aws:MultiFactorAuthPresent), we must not assert exploitability.
    gated = [a for a in required_actions if a in missing_context]
    if gated:
        keys = sorted({k for a in gated for k in missing_context[a]})
        return None, f"Allowed only with unevaluated condition keys ({', '.join(keys)}); not asserted"

    return True, _VERIFIED_TRUE_DETAIL


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


def make_simulate_fn(provider: AWSProvider) -> SimulateFn:
    """Build a ``SimulateFn`` backed by the AWS IAM policy simulator (read-only)."""
    iam = provider.client("iam")

    def _simulate(principal_arn: str, action_names: list[str]) -> list[dict[str, Any]]:
        resp = iam.simulate_principal_policy(PolicySourceArn=principal_arn, ActionNames=action_names)
        results: list[dict[str, Any]] = resp.get("EvaluationResults", [])
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
