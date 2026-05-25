"""Blast Radius Analysis - forward BFS from arbitrary AWS resource.

Computes "what an attacker could reach if THIS resource is compromised" by
expanding outward from a seed resource through the existing scan data:

- EC2 instance -> attached IAM role -> reachable roles via AssumeRole graph
- IAM Role / User -> resolved allowed actions -> data resources + assumable roles
- Lambda function -> execution role -> ...
- S3 bucket -> IAM principals with access (backward direction)

Output:
- Rich tree for CLI
- Mermaid graph TD diagram
- BlastRadiusGraph v1.0 JSON (schema contract with cloud-audit-demo)

Pure in-memory operation on ScanReport. No AWS API calls at blast-radius time.

References:
- Roadmap v3.0.0 Feature 2 (ROADMAP.md)
- Schema contract: cloud-audit-demo/src/types/blast-radius.ts
- Design plan: BLAST-RADIUS-PLAN-2026-05-15.md
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, Field

from cloud_audit import __version__
from cloud_audit.models import ScanReport, Severity

if TYPE_CHECKING:
    from rich.tree import Tree


# ---------------------------------------------------------------------------
# Schema types (mirror cloud-audit-demo/src/types/blast-radius.ts v1.0)
# ---------------------------------------------------------------------------

VizNodeType = Literal["internet", "compute", "identity", "network", "storage", "finding", "impact"]
NodeStatus = Literal["external", "safe", "compromised", "exploited", "stolen", "exfiltrated"]
EdgeType = Literal["network", "iam", "data", "exploit"]
FixEffort = Literal["LOW", "MEDIUM", "HIGH"]
SourceType = Literal["live-scan", "historical-incident"]
CodeLanguage = Literal["http", "json", "bash", "yaml", "text"]


class CodeExample(BaseModel):
    language: CodeLanguage
    title: str
    content: str
    caption: str | None = None


class BlastNode(BaseModel):
    id: str
    type: VizNodeType
    label: str
    sub: str
    status: NodeStatus
    highValue: bool = False
    bfsStep: int = 0
    actionTitle: str | None = None
    actionDescription: str | None = None
    codeExample: CodeExample | None = None
    resource_arn: str | None = None
    tags: dict[str, str] | None = None


class BlastEdge(BaseModel):
    id: str | None = None
    source: str
    target: str
    label: str
    step: int
    type: EdgeType


class BlastNarrativeStep(BaseModel):
    step: int
    title: str
    description: str
    nodeIds: list[str]
    edgeIds: list[str] | None = None


class BlastFix(BaseModel):
    id: str
    title: str
    breaks_chain: bool
    effort: FixEffort
    cli_command: str | None = None
    terraform: str | None = None
    doc_url: str | None = None


class BlastStatBox(BaseModel):
    value: str
    label: str
    emphasis: Literal["normal", "highlight", "danger"] | None = None


class BlastSummary(BaseModel):
    headline: str
    impact_usd: int | None = None
    duration: str | None = None
    sources: list[str] = Field(default_factory=list)
    stats: list[BlastStatBox] = Field(default_factory=list)
    nodes_reachable: int | None = None
    paths_found: int | None = None
    risk_score: int | None = None


class BlastSource(BaseModel):
    type: SourceType
    aws_account_id: str | None = None
    region: str | None = None
    resource_id: str | None = None
    scenario_id: str | None = None
    scenario_name: str | None = None
    year: int | None = None


class BlastDetection(BaseModel):
    check_id: str
    title: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    finding_id: str | None = None


class BlastRadiusResult(BaseModel):
    """Top-level blast radius analysis result matching BlastRadiusGraph v1.0."""

    schema_version: Literal["1.0"] = "1.0"
    generated_at: str
    generator: dict[str, str] = Field(default_factory=lambda: {"name": "cloud-audit", "version": __version__})
    source: BlastSource
    summary: BlastSummary
    nodes: list[BlastNode] = Field(default_factory=list)
    edges: list[BlastEdge] = Field(default_factory=list)
    narrative: list[BlastNarrativeStep] = Field(default_factory=list)
    fixes: list[BlastFix] = Field(default_factory=list)
    cloud_audit_detects: list[BlastDetection] = Field(default_factory=list)

    def to_graph_dict(self) -> dict[str, object]:
        """Serialize to BlastRadiusGraph v1.0 wire format."""
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "generator": self.generator,
            "source": self.source.model_dump(exclude_none=True),
            "summary": self.summary.model_dump(exclude_none=True),
            "graph": {
                "nodes": [n.model_dump(exclude_none=True) for n in self.nodes],
                "edges": [e.model_dump(exclude_none=True) for e in self.edges],
            },
            "narrative": [n.model_dump(exclude_none=True) for n in self.narrative],
            "fixes": [f.model_dump(exclude_none=True) for f in self.fixes],
            "cloud_audit_detects": [d.model_dump(exclude_none=True) for d in self.cloud_audit_detects],
        }


# ---------------------------------------------------------------------------
# Resource type detection
# ---------------------------------------------------------------------------

ResourceType = Literal["ec2", "iam_role", "iam_user", "lambda", "s3_bucket", "secret", "unknown"]

# ARN / id regex patterns
_PATTERNS: list[tuple[re.Pattern[str], ResourceType]] = [
    (re.compile(r"^i-[0-9a-f]{8,17}$"), "ec2"),
    (re.compile(r"^arn:aws:iam::\d+:role/.+"), "iam_role"),
    (re.compile(r"^arn:aws:iam::\d+:user/.+"), "iam_user"),
    (re.compile(r"^arn:aws:lambda:[^:]+:\d+:function:.+"), "lambda"),
    (re.compile(r"^arn:aws:s3:::[^/]+$"), "s3_bucket"),
    (re.compile(r"^arn:aws:secretsmanager:.+"), "secret"),
]


def detect_resource_type(resource_id: str) -> ResourceType:
    """Detect resource type from ARN or short identifier."""
    for pattern, rtype in _PATTERNS:
        if pattern.match(resource_id):
            return rtype
    return "unknown"


# ---------------------------------------------------------------------------
# IAM policy helpers (lightweight - operates on findings, not raw AWS data)
# ---------------------------------------------------------------------------

# Admin-class managed policies
_ADMIN_POLICIES = frozenset(
    {
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/PowerUserAccess",
    }
)

# Sensitive permission patterns we use for highlighting reachability
_SENSITIVE_ACTION_PREFIXES = (
    "iam:",
    "sts:assumerole",
    "s3:",
    "secretsmanager:",
    "kms:",
    "ec2:",
    "lambda:",
    "rds:",
)


def _action_class(action: str) -> str:
    """Classify an IAM action into a high-level service bucket for storytelling."""
    a = action.lower()
    if a in {"*", "*:*"}:
        return "admin"
    if a.startswith(("iam:", "sts:assumerole")):
        return "iam"
    if a.startswith("s3:"):
        return "s3"
    if a.startswith("secretsmanager:"):
        return "secrets"
    if a.startswith("kms:"):
        return "kms"
    if a.startswith("ec2:"):
        return "ec2"
    if a.startswith("lambda:"):
        return "lambda"
    if a.startswith("rds:"):
        return "rds"
    return "other"


# ---------------------------------------------------------------------------
# Storytelling templates
# Mapped by (node_type, edge_type) - 15 initial templates covering 80% of MVP paths.
# Future iterations extend with per-action-class templates.
# ---------------------------------------------------------------------------

STORYTELLING: dict[tuple[str, str], dict[str, str]] = {
    ("compute", "iam"): {
        "actionTitle": "IAM credentials exposed via instance metadata",
        "actionDescription": (
            "Compute resource has an attached IAM role. An attacker with code execution "
            "on this resource can query the instance metadata service (IMDS) and obtain "
            "temporary IAM credentials for that role."
        ),
    },
    ("compute", "network"): {
        "actionTitle": "Network reachable via attached interface",
        "actionDescription": (
            "Compute resource is associated with the given network surface (security "
            "group, subnet, or interface). Once compromised, the attacker has the same "
            "network position as legitimate traffic."
        ),
    },
    ("identity", "iam"): {
        "actionTitle": "Identity grants broad permissions",
        "actionDescription": (
            "The attached IAM policy grants actions that allow an attacker to perform "
            "privileged operations - data access, lateral movement, or further escalation."
        ),
    },
    ("identity", "data"): {
        "actionTitle": "Data accessible via stolen identity",
        "actionDescription": (
            "Stolen IAM credentials can be used to read or modify the data resource "
            "directly via AWS APIs. No additional exploitation needed once the identity "
            "is compromised."
        ),
    },
    ("identity", "exploit"): {
        "actionTitle": "Privilege escalation primitive",
        "actionDescription": (
            "Stolen identity can self-modify permissions or assume higher-privileged "
            "roles, escalating access beyond the initial blast."
        ),
    },
    ("storage", "data"): {
        "actionTitle": "Data exfiltrated from storage",
        "actionDescription": (
            "Data store reachable via the compromised identity. Attacker can list and "
            "download contents using legitimate-looking AWS API calls."
        ),
    },
    ("network", "iam"): {
        "actionTitle": "Network exposure enables credential theft",
        "actionDescription": (
            "Network configuration (e.g. IMDSv1, open security group) allows an attacker "
            "to reach a credential issuance endpoint without authentication."
        ),
    },
    ("network", "network"): {
        "actionTitle": "Lateral network reach",
        "actionDescription": (
            "Network position allows pivoting to adjacent subnets, peered VPCs, or other "
            "compute resources sharing the same security boundary."
        ),
    },
    ("impact", "exploit"): {
        "actionTitle": "Final impact reached",
        "actionDescription": (
            "Terminal impact state. From this point an attacker controls high-value assets "
            "(admin role, customer data, key material)."
        ),
    },
    ("identity", "network"): {
        "actionTitle": "Identity allows VPC manipulation",
        "actionDescription": (
            "IAM permissions include network configuration changes (ec2:Modify*, VPC "
            "peering, security group edits). Attacker can broaden the perimeter or "
            "create persistence."
        ),
    },
    ("storage", "iam"): {
        "actionTitle": "Storage policy grants additional principals",
        "actionDescription": (
            "Resource-based policy on this storage object grants additional principals "
            "access. Attacker can pivot to those identities."
        ),
    },
    ("internet", "exploit"): {
        "actionTitle": "External entry point",
        "actionDescription": (
            "Untrusted public network. Initial position before compromise of any resource inside the account."
        ),
    },
    ("compute", "exploit"): {
        "actionTitle": "Compute instance compromised",
        "actionDescription": (
            "Workload running on this compute resource is the assumed entry foothold for "
            "the blast radius computation. From here all attached identity, network, and "
            "data resources become reachable."
        ),
    },
    ("identity", "data:s3"): {
        "actionTitle": "S3 access granted by stolen identity",
        "actionDescription": (
            "Stolen identity has s3:* (or matching scoped) permission on the bucket. "
            "Attacker can ListBucket and GetObject every key it contains."
        ),
    },
    ("identity", "data:secrets"): {
        "actionTitle": "Secrets readable via stolen identity",
        "actionDescription": (
            "Stolen identity has secretsmanager:GetSecretValue on the secret. Attacker "
            "retrieves the cleartext credential and pivots to the downstream system."
        ),
    },
}


def _story_for(node_type: str, edge_type: str) -> tuple[str | None, str | None]:
    """Lookup storytelling template, falling back to None if no match."""
    template = STORYTELLING.get((node_type, edge_type))
    if template:
        return template.get("actionTitle"), template.get("actionDescription")
    return None, None


# ---------------------------------------------------------------------------
# Compute engine
# ---------------------------------------------------------------------------


_ID_MAX_LEN = 120


def _make_id(prefix: str, value: str) -> str:
    """Build a stable graph node id from prefix + value, sanitized for graph tools.

    If the sanitized id would exceed ``_ID_MAX_LEN`` characters, append a short
    deterministic hash of (prefix, value) so two long-but-different inputs do
    not collide post-truncation (CWE-345 / CWE-1023). Hashing prefix + value
    together (not value alone) prevents the cross-prefix collision case where
    seed + lateral share the same target ARN — they would otherwise yield the
    same digest suffix and differ only in the truncated head.
    """
    sanitized = re.sub(r"[^A-Za-z0-9_-]+", "_", value)
    candidate = f"{prefix}_{sanitized}"
    if len(candidate) <= _ID_MAX_LEN:
        return candidate
    digest = hashlib.sha256(f"{prefix}::{value}".encode("utf-8", errors="surrogatepass")).hexdigest()[:10]
    # leave room for the hash suffix and one separator
    head = candidate[: _ID_MAX_LEN - len(digest) - 1]
    return f"{head}_{digest}"


def _mermaid_escape(text: str) -> str:
    """Escape user-controlled content for safe inclusion in Mermaid labels.

    Mermaid labels are commonly rendered inside HTML pages (GitHub READMEs,
    docs sites, slide tools). Without HTML-entity encoding, untrusted scan
    data could inject ``<script>`` tags (CWE-79). Mermaid also breaks if a
    label contains an unescaped newline, ``"`` or ``]``.
    """
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("`", "&#96;")
        .replace("\\", "&#92;")
        .replace("\n", " ")
        .replace("\r", " ")
        .replace("\t", " ")
        .replace("[", "&#91;")
        .replace("]", "&#93;")
        .replace("{", "&#123;")
        .replace("}", "&#125;")
        .replace("|", "&#124;")
    )


def _arn_role_name(arn: str) -> str:
    """Extract role/user name from an IAM ARN."""
    return arn.rsplit("/", 1)[-1] if "/" in arn else arn


def _short_label(resource_id: str, max_len: int = 32) -> str:
    """Shorten a long ARN or id for compact display."""
    if len(resource_id) <= max_len:
        return resource_id
    head = resource_id[: max_len - 4]
    return f"{head}..."


def _is_admin_principal(allowed_actions: set[str], denied_actions: set[str]) -> bool:
    """Determine whether the resolved actions amount to admin (*:*)."""
    if any(d in {"*", "*:*"} for d in denied_actions):
        return False
    return any(a in {"*", "*:*"} for a in allowed_actions)


def _collect_iam_actions_for_resource(
    report: ScanReport,
    role_or_user_arn: str,
) -> tuple[set[str], set[str], bool]:
    """Return (allowed_actions, denied_actions, is_admin) for an IAM principal.

    Best-effort lookup against the report's findings. In MVP scope, we rely on
    findings the existing IAM analyzer surfaces (escalation paths, admin
    detections). If the principal does not appear in findings, return empty
    sets - the seed node still renders with degraded narrative.
    """
    allowed: set[str] = set()
    denied: set[str] = set()
    is_admin = False

    arn_lower = role_or_user_arn.lower()

    # Aggregate from escalation paths
    for path in report.escalation_paths:
        if path.principal_arn.lower() == arn_lower:
            allowed.update(path.required_actions)
            # Wildcard trust / admin chain target hints at admin reachable
            if "Admin" in path.target_privilege or "admin" in path.target_privilege:
                is_admin = True

    # Findings can hint at high privilege when title/description references admin
    for finding in report.all_findings:
        if finding.resource_id.lower() == arn_lower and "admin" in finding.title.lower():
            is_admin = True

    return allowed, denied, is_admin


def _seed_node_for_resource(
    resource_id: str,
    resource_type: ResourceType,
    report: ScanReport,
) -> BlastNode:
    """Build the starting (seed) node for the blast radius graph."""
    if resource_type == "ec2":
        node_type: VizNodeType = "compute"
        sub = "EC2 instance (assumed compromised)"
    elif resource_type in {"iam_role", "iam_user"}:
        node_type = "identity"
        sub = ("IAM Role" if resource_type == "iam_role" else "IAM User") + " (assumed compromised)"
    elif resource_type == "lambda":
        node_type = "compute"
        sub = "Lambda function (assumed compromised)"
    elif resource_type == "s3_bucket":
        node_type = "storage"
        sub = "S3 bucket (target of interest)"
    elif resource_type == "secret":
        node_type = "storage"
        sub = "Secret (target of interest)"
    else:
        node_type = "compute"
        sub = "Resource (assumed compromised)"

    title, desc = _story_for(node_type, "exploit")

    return BlastNode(
        id=_make_id("seed", resource_id),
        type=node_type,
        label=_short_label(resource_id),
        sub=sub,
        status="compromised",
        bfsStep=0,
        actionTitle=title,
        actionDescription=desc,
        resource_arn=resource_id if resource_id.startswith("arn:") else None,
        highValue=resource_type in {"s3_bucket", "secret"},
    )


def _principal_has_any_escalation(report: ScanReport, arn: str) -> tuple[bool, str]:
    """Return (has_escalation_path, sample_method) for an IAM principal.

    The presence of ANY escalation_path entry for a principal is by definition
    a privilege escalation primitive (the methods in
    iam_analyzer.ESCALATION_METHODS each require admin-class actions). A path
    whose ``target_privilege`` text omits the word "admin" is still an
    escalation candidate (e.g. "Modify trust policy to allow self to assume
    role" leads to admin via a second hop).
    """
    arn_lower = arn.lower()
    for path in report.escalation_paths:
        if path.principal_arn.lower() == arn_lower:
            return True, path.method
    return False, ""


def _expand_iam_role(
    seed: BlastNode,
    resource_arn: str,
    report: ScanReport,
    next_step: int,
) -> list[tuple[BlastNode, BlastEdge]]:
    """Expansion rule: IAM role -> data access + assumable roles + impact."""
    expansions: list[tuple[BlastNode, BlastEdge]] = []
    allowed, denied, is_admin = _collect_iam_actions_for_resource(report, resource_arn)

    if is_admin or _is_admin_principal(allowed, denied):
        impact_node = BlastNode(
            id=_make_id("impact", "account_takeover"),
            type="impact",
            label="Account Takeover",
            sub="Full AWS admin",
            status="stolen",
            bfsStep=next_step,
            highValue=True,
            actionTitle="Final impact reached",
            actionDescription=(
                "The reachable identity carries admin privileges (e.g. AdministratorAccess). "
                "Compromise of the seed resource is equivalent to a full AWS account takeover."
            ),
        )
        edge = BlastEdge(
            source=seed.id,
            target=impact_node.id,
            label="grants admin",
            step=next_step,
            type="exploit",
        )
        expansions.append((impact_node, edge))
    else:
        has_escalation, sample_method = _principal_has_any_escalation(report, resource_arn)
        if has_escalation:
            impact_node = BlastNode(
                id=_make_id("impact", "privilege_escalation"),
                type="impact",
                label="Privilege Escalation",
                sub=f"non-admin primitive ({sample_method})",
                status="exploited",
                bfsStep=next_step,
                highValue=True,
                actionTitle="Escalation primitive reachable",
                actionDescription=(
                    "The identity holds at least one IAM escalation primitive "
                    f"({sample_method}). Even though it does not directly grant "
                    "AdministratorAccess, it can be chained with another method to "
                    "reach admin (e.g. modify trust policy then assume privileged "
                    "role; create access key for another user)."
                ),
            )
            edge = BlastEdge(
                source=seed.id,
                target=impact_node.id,
                label=sample_method,
                step=next_step,
                type="exploit",
            )
            expansions.append((impact_node, edge))

    # Lateral via AssumeRole chains - drawn from escalation paths
    chain_paths_seen: set[str] = set()
    for path in report.escalation_paths:
        if path.principal_arn.lower() != resource_arn.lower():
            continue
        if not path.method.startswith("AssumeRole"):
            continue
        target = path.target_privilege
        if target in chain_paths_seen:
            continue
        chain_paths_seen.add(target)
        # Preserve the full target ARN (when available) on `resource_arn` so
        # subsequent BFS hops can resolve it back to the IAM analyzer's data
        # without relying on the truncated label. Without this, lateral chains
        # past one hop silently fail to resolve and the blast graph stops.
        chain_node = BlastNode(
            id=_make_id("lateral", target),
            type="identity",
            label=_short_label(target, 40),
            sub="AssumeRole chain target",
            status="stolen",
            bfsStep=next_step,
            highValue="Admin" in target or "admin" in target,
            resource_arn=target if target.startswith("arn:") else None,
            actionTitle="Lateral privilege via AssumeRole",
            actionDescription=(
                "Trust policy of a downstream role allows the seed identity (or a role it "
                "can reach) to assume it. Each hop carries the same admin-or-not classification."
            ),
        )
        chain_edge = BlastEdge(
            source=seed.id,
            target=chain_node.id,
            label=path.method,
            step=next_step,
            type="iam",
        )
        expansions.append((chain_node, chain_edge))

    # Data side - S3 / secrets - heuristic by action class hint from findings
    data_hints = _collect_data_hints_for_principal(report, resource_arn)
    for hint in data_hints:
        data_node = BlastNode(
            id=_make_id("data", hint["resource"]),
            type="storage",
            label=_short_label(hint["resource"], 36),
            sub=hint["sub"],
            status="exfiltrated",
            bfsStep=next_step,
            highValue=True,
            actionTitle=hint["action_title"],
            actionDescription=hint["action_description"],
        )
        data_edge = BlastEdge(
            source=seed.id,
            target=data_node.id,
            label=hint["edge_label"],
            step=next_step,
            type="data",
        )
        expansions.append((data_node, data_edge))

    return expansions


def _collect_data_hints_for_principal(report: ScanReport, principal_arn: str) -> list[dict[str, str]]:
    """Heuristic: when the principal is admin or has wildcard S3/secrets, flag those.

    Without raw IAM policy documents in the report this is a best-effort
    representation. Future v3.0.0 expansion will use the AWS API directly.
    """
    hints: list[dict[str, str]] = []

    _, _, is_admin = _collect_iam_actions_for_resource(report, principal_arn)
    if not is_admin:
        return hints

    # If admin, list S3 buckets that appear as resources in findings as
    # candidate reachable storage. This favors precision-over-recall.
    seen_buckets: set[str] = set()
    for finding in report.all_findings:
        rid = finding.resource_id
        if not rid.startswith("arn:aws:s3:::"):
            continue
        if rid in seen_buckets:
            continue
        seen_buckets.add(rid)
        title, desc = _story_for("identity", "data:s3")
        hints.append(
            {
                "resource": rid,
                "sub": "S3 bucket (reachable via admin)",
                "edge_label": "s3:GetObject + ListBucket",
                "action_title": title or "S3 access granted",
                "action_description": desc or "",
            }
        )

    seen_secrets: set[str] = set()
    for finding in report.all_findings:
        rid = finding.resource_id
        if not rid.startswith("arn:aws:secretsmanager:"):
            continue
        if rid in seen_secrets:
            continue
        seen_secrets.add(rid)
        title, desc = _story_for("identity", "data:secrets")
        hints.append(
            {
                "resource": rid,
                "sub": "Secret (reachable via admin)",
                "edge_label": "secretsmanager:GetSecretValue",
                "action_title": title or "Secret readable",
                "action_description": desc or "",
            }
        )

    return hints


def _find_attached_role_for_ec2(report: ScanReport, instance_id: str) -> str | None:
    """Look for any finding that links this EC2 instance to an IAM role.

    The MVP uses references in attack chains (AC-01, AC-02) where the chain's
    resources list includes both the instance id and the role name.
    """
    for chain in report.attack_chains:
        if instance_id not in chain.resources:
            continue
        for step in chain.viz_steps:
            if step.type == "identity":
                # viz_step.label is the role name in AC-01
                return step.label
    return None


def _find_execution_role_for_lambda(report: ScanReport, function_arn_or_name: str) -> str | None:
    """Best-effort lookup of Lambda execution role from chains.

    Only returns a role when the requested function ARN actually appears in
    the chain's ``resources`` list. A previous version of this function also
    matched on chain id alone (``AC-05``/``AC-23``/``AC-24``) which could
    return the role of an UNRELATED Lambda in the same scan, producing an
    incorrect blast radius (CWE-697).
    """
    for chain in report.attack_chains:
        if function_arn_or_name not in chain.resources:
            continue
        for step in chain.viz_steps:
            if step.type == "identity":
                return step.label
    return None


def compute_blast_radius(
    report: ScanReport,
    resource_id: str,
    max_depth: int = 5,
    max_nodes: int = 50,
) -> BlastRadiusResult:
    """Compute forward blast radius from a single AWS resource using scan data.

    Operates purely on the in-memory ``ScanReport``. No AWS API calls.

    Args:
        report: A completed scan report (loaded from JSON or from a fresh scan).
        resource_id: ARN or short identifier of the seed resource.
        max_depth: Maximum BFS depth (defaults to 5 hops).
        max_nodes: Hard cap on total nodes in the result graph (defaults to 50).

    Returns:
        BlastRadiusResult containing graph, narrative, fixes, and summary.
    """
    resource_type = detect_resource_type(resource_id)

    seed = _seed_node_for_resource(resource_id, resource_type, report)
    nodes: list[BlastNode] = [seed]
    edges: list[BlastEdge] = []
    visited: set[str] = {seed.id}

    # If the seed is a compute resource, link it to its attached IAM role first
    if resource_type == "ec2":
        role_name = _find_attached_role_for_ec2(report, resource_id)
        if role_name:
            role_node_id = _make_id("role", role_name)
            role_node = BlastNode(
                id=role_node_id,
                type="identity",
                label=role_name,
                sub="IAM Role attached to instance",
                status="stolen",
                bfsStep=1,
                actionTitle=_story_for("compute", "iam")[0],
                actionDescription=_story_for("compute", "iam")[1],
            )
            nodes.append(role_node)
            visited.add(role_node_id)
            edges.append(
                BlastEdge(
                    source=seed.id,
                    target=role_node_id,
                    label="IMDS credentials",
                    step=1,
                    type="iam",
                )
            )
    elif resource_type == "lambda":
        role_name = _find_execution_role_for_lambda(report, resource_id)
        if role_name:
            role_node_id = _make_id("role", role_name)
            role_node = BlastNode(
                id=role_node_id,
                type="identity",
                label=role_name,
                sub="Lambda execution role",
                status="stolen",
                bfsStep=1,
                actionTitle="Execution role grants Lambda's permissions",
                actionDescription=(
                    "Any code an attacker can execute inside the function inherits its "
                    "execution role permissions automatically."
                ),
            )
            nodes.append(role_node)
            visited.add(role_node_id)
            edges.append(
                BlastEdge(
                    source=seed.id,
                    target=role_node_id,
                    label="execution role",
                    step=1,
                    type="iam",
                )
            )

    # BFS queue of (node, depth, focused_arn). focused_arn is the IAM arn we
    # treat as the "stolen identity" for the next expansion step.
    queue: deque[tuple[BlastNode, int, str]] = deque()

    # Track IAM ARNs (and ARN-fragments) that have already been represented in
    # the graph so a cycle of mutual AssumeRole trusts does not emit the same
    # underlying resource twice with different graph-id prefixes (CWE-1023).
    visited_arns: set[str] = {resource_id.lower().strip()}

    # Identify which node should drive the IAM-side expansion. For IAM seeds
    # that's the seed itself; for compute seeds it's the linked role (if any).
    # In both cases we start BFS at depth=0 — the compute->role linkage is a
    # bookkeeping edge, not a privilege hop, so `--max-depth=1` should still
    # be able to surface Account Takeover from an EC2 with an attached admin
    # role (pre-fix it required `--max-depth=2`).
    if resource_type in {"iam_role", "iam_user"}:
        queue.append((seed, 0, resource_id))
    elif resource_type in {"ec2", "lambda"}:
        # If we linked an IAM role above, expand from that node at depth 0.
        for n in nodes[1:]:
            if n.type == "identity":
                queue.append((n, 0, n.label))
                visited_arns.add(n.label.lower().strip())
                break
    elif resource_type in {"s3_bucket", "secret"}:
        # Data-side seed: backward direction not in MVP scope - just emit the
        # seed and let the summary acknowledge limited reach.
        pass

    while queue and len(nodes) < max_nodes:
        current_node, depth, focused_arn = queue.popleft()
        if depth >= max_depth:
            continue

        # For IAM-typed expansions we need a "real" ARN. If we only have a
        # role name (from EC2 expansion), best-effort match against findings.
        target_arn = focused_arn if focused_arn.startswith("arn:") else _resolve_role_arn(report, focused_arn)
        if not target_arn:
            continue

        canonical_arn = target_arn.lower().strip()
        # Skip if this underlying ARN has already been expanded (prevents
        # emitting a cycle-induced duplicate node with a different prefix).
        if canonical_arn in visited_arns and current_node.bfsStep > 0:
            continue
        visited_arns.add(canonical_arn)

        expansions = _expand_iam_role(current_node, target_arn, report, depth + 1)
        for new_node, edge in expansions:
            if new_node.id in visited:
                continue
            # Cycle guard for star-graph topologies (A trusts B+C, B trusts A,
            # C trusts A). `_make_id` uses different prefixes for "seed" and
            # "lateral", so graph-id dedup alone wouldn't catch a second
            # appearance of the seed-role as a lateral target. Track the
            # underlying ARN/label so we skip it here regardless of prefix.
            if new_node.type == "identity":
                # `resource_arn` is set for seed/expansion nodes; lateral nodes
                # carry the target privilege string in `label` instead.
                lateral_key = (new_node.resource_arn or new_node.label or "").lower().strip()
                if lateral_key and lateral_key in visited_arns:
                    continue
            if len(nodes) >= max_nodes:
                break
            visited.add(new_node.id)
            nodes.append(new_node)
            edges.append(edge)
            # Continue BFS only through identity nodes (admin chain hops).
            # Prefer the full ARN stored on the node — falls back to the
            # truncated label only when the upstream IAM analyzer didn't
            # provide an ARN. Without this, lateral chains past hop 1 don't
            # resolve and the blast graph silently stops.
            if new_node.type == "identity" and depth + 1 < max_depth:
                arn_hint = new_node.resource_arn or new_node.label
                queue.append((new_node, depth + 1, arn_hint))
                # Record the ARN/label so subsequent star-graph hops can't
                # re-emit it under a different graph-id prefix.
                lateral_key = (new_node.resource_arn or new_node.label or "").lower().strip()
                if lateral_key:
                    visited_arns.add(lateral_key)

    # Narrative reconstruction - group by bfsStep
    narrative = _build_narrative(nodes, edges)

    # Fixes from findings that have remediation attached
    fixes = _collect_fixes(report, nodes, max_fixes=6)

    # Detections that contributed to this blast radius
    detects = _collect_detections(report, nodes)

    # Summary
    impact_usd = _estimate_blast_impact(nodes, report)
    risk_score = _risk_score(nodes, report)
    headline = _headline(resource_id, resource_type, nodes)

    summary = BlastSummary(
        headline=headline,
        impact_usd=impact_usd,
        sources=[],
        stats=_build_stats(nodes, edges, fixes),
        nodes_reachable=len(nodes),
        paths_found=len([n for n in nodes if n.type == "impact"]),
        risk_score=risk_score,
    )

    source = BlastSource(
        type="live-scan",
        aws_account_id=report.account_id or None,
        region=(report.regions[0] if report.regions else None),
        resource_id=resource_id,
    )

    return BlastRadiusResult(
        generated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        source=source,
        summary=summary,
        nodes=nodes,
        edges=edges,
        narrative=narrative,
        fixes=fixes,
        cloud_audit_detects=detects,
    )


def _resolve_role_arn(report: ScanReport, role_name_or_arn: str) -> str | None:
    """Resolve a role short name to an ARN.

    Tries three sources in order:
      1. The input is already an ARN — passthrough.
      2. `report.escalation_paths` (the IAM analyzer's primary index).
      3. `report.all_findings` resource_ids — catches roles that have findings
         (e.g. AdministratorAccess attached) but no separate escalation path
         (because they ARE already admin). Without this fallback an EC2 seed
         with an attached admin role would never expand to Account Takeover.
    """
    if role_name_or_arn.startswith("arn:"):
        return role_name_or_arn
    for path in report.escalation_paths:
        if path.principal_name == role_name_or_arn or path.principal_arn.endswith(f"/{role_name_or_arn}"):
            return path.principal_arn
    # Fallback: scan findings for any iam role ARN matching this short name.
    needle = f"/{role_name_or_arn}"
    for finding in report.all_findings:
        rid = finding.resource_id or ""
        if rid.startswith("arn:aws:iam::") and ":role/" in rid and rid.endswith(needle):
            return rid
    return None


def _build_narrative(nodes: list[BlastNode], edges: list[BlastEdge]) -> list[BlastNarrativeStep]:
    """Group nodes by bfsStep into a sequential narrative."""
    by_step: dict[int, list[BlastNode]] = {}
    for n in nodes:
        by_step.setdefault(n.bfsStep, []).append(n)

    edges_by_step: dict[int, list[BlastEdge]] = {}
    for e in edges:
        edges_by_step.setdefault(e.step, []).append(e)

    narrative: list[BlastNarrativeStep] = []
    for step in sorted(by_step.keys()):
        if step == 0:
            title = "Seed: assumed compromised resource"
        elif any(n.type == "impact" for n in by_step[step]):
            title = "Final impact reached"
        else:
            title = f"Step {step}: blast propagation"
        description = "; ".join((n.actionDescription or f"{n.label} ({n.sub})")[:240] for n in by_step[step][:3])
        narrative.append(
            BlastNarrativeStep(
                step=step,
                title=title,
                description=description,
                nodeIds=[n.id for n in by_step[step]],
                edgeIds=[(e.id or f"{e.source}->{e.target}") for e in edges_by_step.get(step, [])] or None,
            )
        )
    return narrative


def _label_matches_arn(resource_id: str, node_labels: set[str]) -> bool:
    """Match a finding's resource_id against blast-node short labels.

    Requires the label to align with a full ARN path segment (after `/` or
    `:`), not just any trailing substring. Short labels (<6 chars) are
    excluded entirely to avoid e.g. `"role"` matching every IAM ARN.
    """
    if not resource_id:
        return False
    for label in node_labels:
        if not label or len(label) < 6:
            continue
        if resource_id.endswith((f"/{label}", f":{label}")):
            return True
    return False


def _collect_fixes(report: ScanReport, nodes: list[BlastNode], max_fixes: int = 6) -> list[BlastFix]:
    """Pull remediations attached to findings that affect any blast node."""
    fixes: list[BlastFix] = []
    seen: set[str] = set()
    node_labels = {n.label for n in nodes}
    node_arns = {n.resource_arn for n in nodes if n.resource_arn}

    for finding in report.all_findings:
        if not finding.remediation:
            continue
        if finding.check_id in seen:
            continue
        if (
            finding.resource_id in node_arns
            or finding.resource_id in node_labels
            or _label_matches_arn(finding.resource_id, node_labels)
        ):
            seen.add(finding.check_id)
            effort_value = finding.remediation.effort.value.upper()
            effort_typed: FixEffort = "LOW"
            if effort_value in ("LOW", "MEDIUM", "HIGH"):
                effort_typed = effort_value  # type: ignore[assignment]
            fixes.append(
                BlastFix(
                    id=finding.check_id,
                    title=finding.title,
                    breaks_chain=finding.severity in (Severity.CRITICAL, Severity.HIGH),
                    effort=effort_typed,
                    cli_command=finding.remediation.cli or None,
                    terraform=finding.remediation.terraform or None,
                    doc_url=finding.remediation.doc_url or None,
                )
            )
            if len(fixes) >= max_fixes:
                break
    return fixes


def _collect_detections(report: ScanReport, nodes: list[BlastNode]) -> list[BlastDetection]:
    """Findings that align with the blast radius (same resources)."""
    out: list[BlastDetection] = []
    seen_ids: set[tuple[str, str]] = set()
    node_arns = {n.resource_arn for n in nodes if n.resource_arn}
    node_labels = {n.label for n in nodes}

    for finding in report.all_findings:
        key = (finding.check_id, finding.resource_id)
        if key in seen_ids:
            continue
        if (
            finding.resource_id in node_arns
            or finding.resource_id in node_labels
            or _label_matches_arn(finding.resource_id, node_labels)
        ):
            seen_ids.add(key)
            severity_str = finding.severity.value.upper()
            if severity_str in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                out.append(
                    BlastDetection(
                        check_id=finding.check_id,
                        title=finding.title,
                        severity=severity_str,  # type: ignore[arg-type]
                    )
                )
    return out


def _estimate_blast_impact(nodes: list[BlastNode], report: ScanReport) -> int | None:
    """Estimate dollar impact: sum chain risk for chains that overlap blast nodes."""
    total = 0
    node_labels = {n.label for n in nodes}
    node_arns = {n.resource_arn for n in nodes if n.resource_arn}

    for chain in report.attack_chains:
        if not chain.cost_estimate:
            continue
        if not any(r in node_labels or r in node_arns for r in chain.resources):
            continue
        total += chain.cost_estimate.high_usd
    return total or None


def _risk_score(nodes: list[BlastNode], report: ScanReport) -> int:
    """Risk score 0-100: weighted by node types reachable + impact present.

    Pure heuristic - documented so users understand it is not a calibrated metric.
    """
    score = 0
    if any(n.type == "impact" for n in nodes):
        score += 50
    if any(n.type == "identity" and (n.highValue or n.sub.startswith("Lateral")) for n in nodes):
        score += 20
    if any(n.type == "storage" and n.highValue for n in nodes):
        score += 20
    score += min(10, max(0, len(nodes) - 1))
    return min(100, score)


def _headline(resource_id: str, resource_type: ResourceType, nodes: list[BlastNode]) -> str:
    impact_nodes = [n for n in nodes if n.type == "impact"]
    reach_count = max(0, len(nodes) - 1)
    if impact_nodes:
        return f"Compromise of {_short_label(resource_id)} leads to {impact_nodes[0].label} via {reach_count} hop(s)."
    if reach_count == 0:
        return f"No reachable resources detected for {_short_label(resource_id)} in current scan data."
    return f"Compromise of {_short_label(resource_id)} reaches {reach_count} additional resource(s)."


def _build_stats(nodes: list[BlastNode], edges: list[BlastEdge], fixes: list[BlastFix]) -> list[BlastStatBox]:
    impact = sum(1 for n in nodes if n.type == "impact")
    identities = sum(1 for n in nodes if n.type == "identity")
    storage = sum(1 for n in nodes if n.type == "storage")
    return [
        BlastStatBox(value=str(max(0, len(nodes) - 1)), label="reachable resources", emphasis="highlight"),
        BlastStatBox(value=str(len(edges)), label="edges traversed"),
        BlastStatBox(
            value=str(impact + identities + storage),
            label="high-value nodes",
            emphasis="danger" if (impact + storage) else "normal",
        ),
        BlastStatBox(value=str(len(fixes)), label="available fixes"),
    ]


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------


def to_tree(result: BlastRadiusResult) -> Tree:
    """Render the blast radius as a Rich Tree for CLI display."""
    from rich.tree import Tree

    nodes_by_id = {n.id: n for n in result.nodes}
    children: dict[str, list[tuple[BlastEdge, BlastNode]]] = {n.id: [] for n in result.nodes}

    for edge in result.edges:
        target_node = nodes_by_id.get(edge.target)
        if target_node:
            children.setdefault(edge.source, []).append((edge, target_node))

    seed = result.nodes[0] if result.nodes else None
    if seed is None:
        return Tree("(empty blast radius)")

    root = Tree(_format_node_line(seed, edge=None))
    _attach_children(root, seed.id, children)
    return root


def _format_node_line(node: BlastNode, edge: BlastEdge | None) -> str:
    """Format a Rich-markup line for a graph node.

    User-controlled strings (``node.label``, ``node.sub``, ``edge.label``) are
    escaped with ``rich.markup.escape`` so a label like ``[red]X[/red]`` does
    not get reinterpreted as Rich color directives in the terminal (defense
    in depth against console-side markup injection).
    """
    from rich.markup import escape as _rich_escape

    color = {
        "internet": "bold yellow",
        "compute": "bold cyan",
        "identity": "bold magenta",
        "network": "blue",
        "storage": "bold green",
        "finding": "yellow",
        "impact": "bold red",
    }.get(node.type, "white")
    edge_part = f" [dim](via {_rich_escape(edge.label)}, type={edge.type})[/dim]" if edge else ""
    label = f"[{color}]{_rich_escape(node.label)}[/{color}]"
    sub = f" [dim]- {_rich_escape(node.sub)}[/dim]" if node.sub else ""
    high = " [bold red]<high-value>[/bold red]" if node.highValue else ""
    return f"{label}{sub}{edge_part}{high}"


def _attach_children(
    parent: Tree,
    node_id: str,
    children: dict[str, list[tuple[BlastEdge, BlastNode]]],
    seen: set[str] | None = None,
) -> None:
    seen = seen or {node_id}
    for edge, child_node in sorted(children.get(node_id, []), key=lambda x: x[0].step):
        if child_node.id in seen:
            continue
        seen.add(child_node.id)
        subtree = parent.add(_format_node_line(child_node, edge))
        _attach_children(subtree, child_node.id, children, seen)


def to_mermaid(result: BlastRadiusResult) -> str:
    """Generate a Mermaid graph TD diagram of the blast radius."""
    lines = ["graph TD"]
    style_classes = {
        "internet": "fill:#fef3c7,stroke:#d97706",
        "compute": "fill:#cffafe,stroke:#0891b2",
        "identity": "fill:#fce7f3,stroke:#db2777",
        "network": "fill:#dbeafe,stroke:#2563eb",
        "storage": "fill:#dcfce7,stroke:#16a34a",
        "finding": "fill:#fef9c3,stroke:#ca8a04",
        "impact": "fill:#fee2e2,stroke:#dc2626",
    }

    for node in result.nodes:
        safe_id = re.sub(r"[^A-Za-z0-9_]", "_", node.id)
        safe_label = _mermaid_escape(node.label)
        shape_open, shape_close = ("[", "]") if node.type != "storage" else ("[(", ")]")
        if node.type == "impact":
            shape_open, shape_close = ("((", "))")
        sub_safe = _mermaid_escape(node.sub)
        lines.append(f'    {safe_id}{shape_open}"<b>{safe_label}</b><br/>{sub_safe}"{shape_close}')

    for edge in result.edges:
        src = re.sub(r"[^A-Za-z0-9_]", "_", edge.source)
        tgt = re.sub(r"[^A-Za-z0-9_]", "_", edge.target)
        label_safe = _mermaid_escape(edge.label)
        lines.append(f'    {src} -- "{label_safe}" --> {tgt}')

    for node in result.nodes:
        safe_id = re.sub(r"[^A-Za-z0-9_]", "_", node.id)
        css = style_classes.get(node.type, "")
        if css:
            lines.append(f"    style {safe_id} {css}")

    return "\n".join(lines)


def to_json_str(result: BlastRadiusResult, indent: int = 2) -> str:
    """Serialize to BlastRadiusGraph v1.0 JSON string."""
    return json.dumps(result.to_graph_dict(), indent=indent, sort_keys=False)
