"""IAM Trust Policy Graph Analyzer (Tier 3 of v2.1.0).

Detects lateral privilege escalation via AssumeRole chains by:
1. Parsing AssumeRolePolicyDocument from each role
2. Building a directed graph: trusted-principal -> assumable-role
3. Computing reachability from non-admin principals to admin roles
4. Flagging overly-permissive trust policies (wildcards, cross-account roots)

This module is the lightweight counterpart to PMapper - it does not evaluate
trust policy conditions semantically (MFA, ExternalId, SourceArn). Instead it
flags their presence so users can verify them manually. SCP and permission
boundary effects are out of scope for v2.1.0 and documented as known limitations.

References:
- AWS IAM trust policy semantics:
  https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
- pathfinding.cloud lateral movement paths
"""

from __future__ import annotations

import fnmatch
import json
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from cloud_audit.models import EscalationCategory, EscalationPath, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.iam_analyzer import ResolvedPrincipal


# ---------------------------------------------------------------------------
# Lateral method catalog (informational - detection logic is below)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class _LateralMethodDef:
    """Catalog entry for a lateral escalation method."""

    name: str
    category: EscalationCategory
    base_severity: Severity
    description: str


LATERAL_METHODS: dict[str, _LateralMethodDef] = {
    "AssumeRole:Direct": _LateralMethodDef(
        name="AssumeRole:Direct",
        category=EscalationCategory.LATERAL_ASSUME_ROLE,
        base_severity=Severity.CRITICAL,
        description="Direct sts:AssumeRole into a role with admin permissions (1 hop)",
    ),
    "AssumeRole:Chain": _LateralMethodDef(
        name="AssumeRole:Chain",
        category=EscalationCategory.LATERAL_ASSUME_ROLE,
        base_severity=Severity.CRITICAL,
        description="Multi-hop sts:AssumeRole chain ending at an admin role",
    ),
    "AssumeRole:WildcardTrust": _LateralMethodDef(
        name="AssumeRole:WildcardTrust",
        category=EscalationCategory.LATERAL_ASSUME_ROLE,
        base_severity=Severity.CRITICAL,
        description="Role with overly-permissive trust policy (Principal: *) - any AWS identity can assume",
    ),
    "AssumeRole:CrossAccountRoot": _LateralMethodDef(
        name="AssumeRole:CrossAccountRoot",
        category=EscalationCategory.LATERAL_ASSUME_ROLE,
        base_severity=Severity.HIGH,
        description="Role trusts an external AWS account root - any IAM identity in that account can assume",
    ),
}


# ---------------------------------------------------------------------------
# Trust policy parsing
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class TrustedPrincipal:
    """A principal entity allowed to assume a role."""

    kind: str  # "AWS", "Service", "Federated", "CanonicalUser", "Wildcard"
    value: str  # ARN, service domain, federation provider URL, or "*"


def parse_trust_policy(trust_doc: dict[str, Any] | str) -> tuple[list[TrustedPrincipal], bool]:
    """Extract trusted principals from a role's AssumeRolePolicyDocument.

    Returns (principals, has_conditions). Skips Deny statements and statements
    whose action does not include some form of sts:AssumeRole*.
    """
    doc = json.loads(trust_doc) if isinstance(trust_doc, str) else trust_doc

    principals: list[TrustedPrincipal] = []
    has_conditions = False

    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        # Only entries that grant some sts:AssumeRole* form
        if not any("AssumeRole" in str(a) for a in actions):
            continue

        if "Condition" in stmt:
            has_conditions = True

        principal_block = stmt.get("Principal")
        if principal_block == "*":
            principals.append(TrustedPrincipal(kind="Wildcard", value="*"))
            continue

        if isinstance(principal_block, dict):
            for kind, value in principal_block.items():
                values = [value] if isinstance(value, str) else list(value)
                for v in values:
                    if v == "*":
                        principals.append(TrustedPrincipal(kind="Wildcard", value="*"))
                    else:
                        principals.append(TrustedPrincipal(kind=str(kind), value=str(v)))

    return principals, has_conditions


# ---------------------------------------------------------------------------
# Graph data structures
# ---------------------------------------------------------------------------
@dataclass
class TrustEdge:
    """Directed edge: trusted_principal -> role they can assume."""

    source_arn: str  # ARN, "*" for wildcard, or "<account>:root" for account root
    source_kind: str  # "AWS", "Service", "Federated", "CanonicalUser", "Wildcard"
    target_role_arn: str
    target_role_name: str
    has_conditions: bool


@dataclass
class AssumeRoleGraph:
    """Directed graph of assume-role relationships."""

    edges: list[TrustEdge] = field(default_factory=list)
    role_admin_status: dict[str, bool] = field(default_factory=dict)  # role_arn -> is_admin
    role_arn_to_name: dict[str, str] = field(default_factory=dict)
    account_id: str = ""


# ---------------------------------------------------------------------------
# Admin detection helpers
# ---------------------------------------------------------------------------
_AWS_ADMIN_MANAGED_POLICIES = frozenset(
    {
        "arn:aws:iam::aws:policy/AdministratorAccess",
    }
)


def _doc_grants_admin(doc: dict[str, Any]) -> bool:
    """Check if a policy document grants admin (* on *) without explicit deny on it."""
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        if any(a in {"*", "*:*"} for a in actions) and any(r == "*" for r in resources):
            return True
    return False


def _role_is_admin(role_data: dict[str, Any], policies_map: dict[str, dict[str, Any]]) -> bool:
    """Check if a role has admin permissions through any of its attached/inline policies."""
    # Inline policies on the role
    for policy in role_data.get("RolePolicyList", []):
        doc = policy.get("PolicyDocument", {})
        if isinstance(doc, str):
            doc = json.loads(doc)
        if _doc_grants_admin(doc):
            return True

    # Attached managed policies
    for attached in role_data.get("AttachedManagedPolicies", []):
        policy_arn = attached.get("PolicyArn", "")
        if policy_arn in _AWS_ADMIN_MANAGED_POLICIES:
            return True
        # Customer managed policy - resolve from policies_map
        policy_data = policies_map.get(policy_arn)
        if not policy_data:
            continue
        for version in policy_data.get("PolicyVersionList", []):
            if not version.get("IsDefaultVersion"):
                continue
            doc = version.get("Document", {})
            if isinstance(doc, str):
                doc = json.loads(doc)
            if _doc_grants_admin(doc):
                return True

    return False


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------
def _extract_account_id_from_arn(arn: str) -> str:
    """Extract account ID from an IAM ARN (positions 4 in colon-split).

    Returns empty string if ARN format is unrecognized.
    """
    parts = arn.split(":")
    if len(parts) >= 5:
        return parts[4]
    return ""


def _normalize_aws_principal(value: str, account_id_hint: str) -> str:
    """Normalize an AWS principal value to its canonical form for graph lookups.

    AWS allows several forms in trust policies:
    - Full ARN: arn:aws:iam::123:user/alice -> kept as is
    - Account ID number: "123456789012" -> "arn:aws:iam::123456789012:root"
    - Account root ARN: arn:aws:iam::123:root -> kept as is

    A bare account ID and the corresponding :root ARN are equivalent in AWS
    semantics, so we canonicalize bare IDs to the :root form.
    """
    if value.isdigit() and len(value) == 12:
        return f"arn:aws:iam::{value}:root"
    return value


def build_assume_role_graph(auth_details: dict[str, Any]) -> AssumeRoleGraph:
    """Build an assume-role graph from RoleDetailList trust policies."""
    graph = AssumeRoleGraph()

    policies_map = {p["Arn"]: p for p in auth_details.get("Policies", [])}
    roles = auth_details.get("RoleDetailList", [])

    # Determine account_id from the first role's ARN
    if roles:
        graph.account_id = _extract_account_id_from_arn(roles[0]["Arn"])

    for role in roles:
        role_arn = role["Arn"]
        role_name = role["RoleName"]

        # Skip AWS service-linked roles - they cannot be assumed by users
        if "/aws-service-role/" in role.get("Path", ""):
            continue

        graph.role_arn_to_name[role_arn] = role_name
        graph.role_admin_status[role_arn] = _role_is_admin(role, policies_map)

        trust_doc = role.get("AssumeRolePolicyDocument", {})
        if isinstance(trust_doc, str):
            trust_doc = json.loads(trust_doc)

        trusted, has_conditions = parse_trust_policy(trust_doc)
        for tp in trusted:
            normalized_value = _normalize_aws_principal(tp.value, graph.account_id) if tp.kind == "AWS" else tp.value
            graph.edges.append(
                TrustEdge(
                    source_arn=normalized_value,
                    source_kind=tp.kind,
                    target_role_arn=role_arn,
                    target_role_name=role_name,
                    has_conditions=has_conditions,
                )
            )

    return graph


# ---------------------------------------------------------------------------
# Reachability and lateral path detection
# ---------------------------------------------------------------------------
_MAX_CHAIN_LENGTH = 5  # max number of nodes in path (= max 4 hops)


def _has_assume_role(principal: ResolvedPrincipal) -> bool:
    """Check if a resolved principal can call sts:AssumeRole (allow minus deny)."""
    for denied in principal.denied_actions:
        if fnmatch.fnmatch("sts:assumerole", denied.lower()):
            return False
    return any(fnmatch.fnmatch("sts:assumerole", allowed.lower()) for allowed in principal.allowed_actions)


def _arn_in_account(arn: str, account_id: str) -> bool:
    """Check whether an ARN belongs to a specific account."""
    return _extract_account_id_from_arn(arn) == account_id


def _build_adjacency(edges: list[TrustEdge]) -> dict[str, list[TrustEdge]]:
    """source_arn -> list of edges originating from it."""
    adj: dict[str, list[TrustEdge]] = {}
    for edge in edges:
        adj.setdefault(edge.source_arn, []).append(edge)
    return adj


def _find_chain_to_admin(
    graph: AssumeRoleGraph,
    source_principal: ResolvedPrincipal,
    role_can_assume: dict[str, bool],
) -> list[TrustEdge] | None:
    """BFS from source principal through trust graph to find shortest chain to an admin role.

    Returns a list of edges (the chain) or None if no admin is reachable.
    Chain length is bounded by _MAX_CHAIN_LENGTH to avoid pathological inputs.
    """
    adj = _build_adjacency(graph.edges)
    same_account_root = f"arn:aws:iam::{graph.account_id}:root" if graph.account_id else None

    def neighbors(node: str) -> list[TrustEdge]:
        """Return outgoing edges from node, expanding same-account-root semantics.

        Any role that trusts <our_account>:root is reachable from any principal
        in our account (with sts:AssumeRole). We expand that here so BFS finds
        them naturally.
        """
        result = list(adj.get(node, []))
        if same_account_root and same_account_root in adj and _arn_in_account(node, graph.account_id):
            result.extend(adj[same_account_root])
        return result

    # BFS state: queue of (current_arn, edges_taken)
    queue: deque[tuple[str, list[TrustEdge]]] = deque()
    queue.append((source_principal.arn, []))
    visited: set[str] = {source_principal.arn}

    while queue:
        current, edges_taken = queue.popleft()

        # Intermediate roles need sts:AssumeRole; the source principal was
        # already verified before this function was called.
        if edges_taken and not role_can_assume.get(current, False):
            continue

        for edge in neighbors(current):
            if edge.target_role_arn in visited:
                continue

            new_edges = [*edges_taken, edge]

            if graph.role_admin_status.get(edge.target_role_arn, False):
                return new_edges

            if len(new_edges) >= _MAX_CHAIN_LENGTH - 1:
                continue
            visited.add(edge.target_role_arn)
            queue.append((edge.target_role_arn, new_edges))

    return None


def _make_chain_path(
    principal: ResolvedPrincipal,
    chain: list[TrustEdge],
    graph: AssumeRoleGraph,
) -> EscalationPath:
    """Build EscalationPath for an AssumeRole chain ending at admin role."""
    method = "AssumeRole:Direct" if len(chain) == 1 else "AssumeRole:Chain"
    method_def = LATERAL_METHODS[method]

    hops_readable = [principal.name] + [edge.target_role_name for edge in chain]
    hops_str = " -> ".join(hops_readable)

    has_any_conditions = any(edge.has_conditions for edge in chain)
    privilege_text = f"Admin via AssumeRole chain: {hops_str}"
    if has_any_conditions:
        privilege_text += " (one or more roles have trust conditions - verify their effectiveness)"

    return EscalationPath(
        principal_arn=principal.arn,
        principal_name=principal.name,
        principal_type=principal.principal_type,
        method=method,
        category=EscalationCategory.LATERAL_ASSUME_ROLE,
        required_actions=["sts:AssumeRole"],
        target_privilege=privilege_text,
        severity=method_def.base_severity,
    )


def _detect_wildcard_trust(graph: AssumeRoleGraph) -> list[EscalationPath]:
    """Find roles with overly-permissive trust (Principal: *)."""
    paths: list[EscalationPath] = []
    seen_roles: set[str] = set()

    for edge in graph.edges:
        if edge.source_arn != "*":
            continue
        if edge.target_role_arn in seen_roles:
            continue
        seen_roles.add(edge.target_role_arn)

        is_admin = graph.role_admin_status.get(edge.target_role_arn, False)
        severity = Severity.CRITICAL if is_admin else Severity.HIGH

        if is_admin:
            target_priv = "Any AWS principal can assume this admin role"
        else:
            target_priv = "Any AWS principal can assume this role"
        if edge.has_conditions:
            target_priv += " (trust policy has conditions - verify their effectiveness)"

        paths.append(
            EscalationPath(
                principal_arn=edge.target_role_arn,
                principal_name=edge.target_role_name,
                principal_type="Role",
                method="AssumeRole:WildcardTrust",
                category=EscalationCategory.LATERAL_ASSUME_ROLE,
                required_actions=["sts:AssumeRole"],
                target_privilege=target_priv,
                severity=severity,
            )
        )

    return paths


def _detect_cross_account_root(graph: AssumeRoleGraph) -> list[EscalationPath]:
    """Find roles trusting an external AWS account's root principal."""
    paths: list[EscalationPath] = []
    seen: set[tuple[str, str]] = set()  # (role_arn, external_account)

    for edge in graph.edges:
        if edge.source_kind != "AWS":
            continue
        if not edge.source_arn.startswith("arn:aws:iam::"):
            continue
        if not edge.source_arn.endswith(":root"):
            continue

        external_account = _extract_account_id_from_arn(edge.source_arn)
        if not external_account:
            continue
        if not graph.account_id or external_account == graph.account_id:
            continue

        key = (edge.target_role_arn, external_account)
        if key in seen:
            continue
        seen.add(key)

        is_admin = graph.role_admin_status.get(edge.target_role_arn, False)
        severity = Severity.CRITICAL if is_admin else Severity.HIGH

        if is_admin:
            target_priv = f"External account {external_account} root principal can assume this admin role"
        else:
            target_priv = f"External account {external_account} root principal can assume this role"
        if edge.has_conditions:
            target_priv += " (conditions present - verify ExternalId/MFA effectiveness)"

        paths.append(
            EscalationPath(
                principal_arn=edge.target_role_arn,
                principal_name=edge.target_role_name,
                principal_type="Role",
                method="AssumeRole:CrossAccountRoot",
                category=EscalationCategory.LATERAL_ASSUME_ROLE,
                required_actions=["sts:AssumeRole"],
                target_privilege=target_priv,
                severity=severity,
            )
        )

    return paths


def find_lateral_escalations(
    graph: AssumeRoleGraph,
    principals: list[ResolvedPrincipal],
) -> list[EscalationPath]:
    """Detect lateral escalation paths through AssumeRole graph.

    Detects 4 types of lateral movement:
    - AssumeRole:Direct - 1 hop principal -> admin role
    - AssumeRole:Chain - multi-hop principal -> ... -> admin role
    - AssumeRole:WildcardTrust - role trusted by Principal: *
    - AssumeRole:CrossAccountRoot - role trusted by external account root
    """
    paths: list[EscalationPath] = []

    # 1+2. WildcardTrust + CrossAccountRoot - role-centric findings
    paths.extend(_detect_wildcard_trust(graph))
    paths.extend(_detect_cross_account_root(graph))

    # Build sts:AssumeRole capability map for roles (intermediate hops need it)
    role_can_assume: dict[str, bool] = {}
    for principal in principals:
        if principal.principal_type == "Role":
            role_can_assume[principal.arn] = _has_assume_role(principal)

    # 3+4. Direct + Chain - principal-centric findings
    for principal in principals:
        # Skip principals that are already admin
        if any(a in {"*", "*:*"} for a in principal.allowed_actions if a not in principal.denied_actions):
            continue
        if not _has_assume_role(principal):
            continue

        chain = _find_chain_to_admin(graph, principal, role_can_assume)
        if chain is not None:
            paths.append(_make_chain_path(principal, chain, graph))

    return paths
