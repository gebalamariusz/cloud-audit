"""Core data models for cloud-audit findings and reports."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    SECURITY = "security"
    COST = "cost"
    RELIABILITY = "reliability"
    PERFORMANCE = "performance"
    THREAT = "threat"


class Effort(str, Enum):
    """Estimated effort to implement the remediation."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Remediation(BaseModel):
    """Remediation details for a finding - CLI command, Terraform HCL, and docs link."""

    cli: str = Field(description="AWS CLI command (copy-paste ready)")
    terraform: str = Field(description="Terraform HCL snippet")
    doc_url: str = Field(description="Link to AWS documentation")
    effort: Effort = Field(description="Estimated remediation effort")


SEVERITY_WEIGHT = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


class CostEstimateData(BaseModel):
    """Estimated financial risk for a finding or attack chain."""

    low_usd: int = Field(description="Low-end estimate in USD")
    high_usd: int = Field(description="High-end estimate in USD")
    display: str = Field(description="Human-readable range, e.g. '$50K - $500K'")
    rationale: str = Field(description="Source/reasoning for the estimate")
    source_url: str = Field(default="", description="URL to the source data backing this estimate")


class Finding(BaseModel):
    """A single audit finding - one issue detected in the infrastructure."""

    check_id: str = Field(description="Unique check identifier, e.g. 'aws-iam-001'")
    title: str = Field(description="Short human-readable title")
    severity: Severity
    category: Category
    resource_type: str = Field(description="AWS resource type, e.g. 'AWS::IAM::User'")
    resource_id: str = Field(description="Resource identifier (ARN, ID, or name)")
    region: str = Field(default="global")
    description: str = Field(description="What is wrong")
    recommendation: str = Field(description="How to fix it")
    remediation: Remediation | None = Field(default=None, description="Structured remediation details")
    compliance_refs: list[str] = Field(default_factory=list, description="Compliance references, e.g. ['CIS 1.5']")
    cost_estimate: CostEstimateData | None = Field(default=None, description="Estimated breach cost range")
    threat_pattern_id: str | None = Field(
        default=None,
        description="Threat feed pattern identifier, e.g. 'TF-003-quarantine-policy' (None for regular checks)",
    )
    references: list[str] = Field(
        default_factory=list,
        description="External references (research reports, CVE links, blog posts) backing this finding",
    )


class CheckResult(BaseModel):
    """Result of running a single check - may produce 0..N findings."""

    check_id: str
    check_name: str
    findings: list[Finding] = Field(default_factory=list)
    resources_scanned: int = 0
    error: str | None = None
    coverage_gaps: list[str] = Field(
        default_factory=list,
        description=(
            "Regions or resources the check could not read (typically AccessDenied for the scanner's "
            "own credentials). A check with gaps and no findings is 'not assessed there', not a clean pass."
        ),
    )


VizNodeType = Literal["internet", "compute", "identity", "network", "storage", "finding", "impact"]


class VizStep(BaseModel):
    """A single step in an attack chain visualization."""

    label: str = Field(description="Resource name or short label")
    sub: str = Field(description="Resource type or subtitle")
    type: VizNodeType = Field(description="Node type for visualization styling")
    edge_label: str = Field(default="", description="Label on the edge FROM this node to the next")


class AttackChain(BaseModel):
    """A detected attack chain - multiple findings that together form an exploitable attack path."""

    chain_id: str = Field(description="Unique chain identifier, e.g. 'AC-01'")
    name: str = Field(description="Human-readable name, e.g. 'Internet-Exposed Admin Instance'")
    severity: Severity
    findings: list[Finding] = Field(description="Component findings that form this chain")
    attack_narrative: str = Field(description="How an attacker exploits this chain step by step")
    priority_fix: str = Field(description="The single fix that breaks the chain (lowest effort)")
    mitre_refs: list[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs")
    resources: list[str] = Field(default_factory=list, description="Affected resource IDs")
    cost_estimate: CostEstimateData | None = Field(default=None, description="Estimated breach cost for this chain")
    viz_steps: list[VizStep] = Field(default_factory=list, description="Visualization steps for attack path graph")


class EscalationCategory(str, Enum):
    """Categories of IAM privilege escalation."""

    IAM_SELF_MUTATION = "iam_self_mutation"
    CREDENTIAL_ACCESS = "credential_access"
    PASSROLE_SERVICE = "passrole_service"
    LAMBDA_CODE_MOD = "lambda_code_modification"
    TRUST_POLICY_ABUSE = "trust_policy_abuse"
    PERMISSION_BOUNDARY = "permission_boundary_bypass"
    RESOURCE_POLICY_ABUSE = "resource_policy_abuse"
    COMPUTE_HIJACK = "compute_hijack"
    LATERAL_ASSUME_ROLE = "lateral_assume_role"


class EscalationPath(BaseModel):
    """A detected IAM privilege escalation path."""

    principal_arn: str = Field(description="ARN of the principal that can escalate")
    principal_name: str = Field(description="Human-readable name (user/role name)")
    principal_type: str = Field(description="'User' or 'Role'")
    method: str = Field(description="Escalation method, e.g. 'CreatePolicyVersion'")
    category: EscalationCategory
    required_actions: list[str] = Field(description="IAM actions needed for this path")
    target_privilege: str = Field(description="What privilege is gained")
    severity: Severity
    resource_constraints: list[str] = Field(
        default_factory=list, description="Resource ARN constraints (empty = wildcard)"
    )
    verified: bool | None = Field(
        default=None,
        description=(
            "Proof Mode: True if exploitability was confirmed via iam:SimulatePrincipalPolicy, "
            "False if the simulator denied a required action, None if not checked or unavailable."
        ),
    )
    verification_detail: str = Field(
        default="", description="Evidence/explanation of the Proof Mode verification result."
    )


class AgentTool(BaseModel):
    """A capability an AI agent can invoke, and the IAM identity that capability runs as."""

    name: str = Field(description="Tool / action group / gateway target name")
    kind: str = Field(
        description=(
            "action_group_lambda | action_group_custom_control | knowledge_base | "
            "gateway_target_lambda | gateway_target_openapi | gateway_target_mcp_server | "
            "gateway_target_api_gateway | gateway_target_smithy"
        )
    )
    target_arn: str = Field(default="", description="ARN of the backend (Lambda, Knowledge Base, ...) when known")
    execution_role_arn: str = Field(
        default="",
        description="IAM role the backend executes as. Empty when unknown or when the backend is not IAM-bound.",
    )
    region: str = ""
    detail: str = Field(default="", description="Short evidence note, e.g. schema size or credential provider type")


class AgentIdentity(BaseModel):
    """An AI agent (or agent sandbox) deployed in the account and the IAM identities it acts through.

    ``principal_arns`` are the roles the agent itself runs as. ``tools`` carry their
    own execution roles. A hijacked agent acts with the union of both: the full role
    on identity takeover, the tools' roles on behaviour takeover (prompt injection).
    """

    agent_id: str
    name: str
    kind: str = Field(
        description=(
            "bedrock_agent | agentcore_runtime | agentcore_gateway | agentcore_code_interpreter | agentcore_browser"
        )
    )
    arn: str = ""
    region: str = ""
    principal_arns: list[str] = Field(default_factory=list, description="IAM roles the agent runs as")
    tools: list[AgentTool] = Field(default_factory=list)
    data_sources: list[str] = Field(
        default_factory=list, description="Data the agent is wired to read, e.g. S3 bucket ARNs behind Knowledge Bases"
    )
    foundation_model: str = ""
    guardrail_attached: bool | None = Field(default=None, description="None when the resource type has no guardrail")
    notes: list[str] = Field(
        default_factory=list, description="Config facts relevant to blast radius, e.g. network mode"
    )


class PolicyGrant(BaseModel):
    """One (action, resource) fragment of a principal's IAM policy, as written.

    Kept deliberately raw: patterns are not expanded and conditions are not
    evaluated (flagged only). The IAM policy simulator, not this model, decides
    the effective outcome; see ``proof.verify_resource_access``. ``NotAction`` /
    ``NotResource`` statements are recorded as one grant per resource with the
    listed patterns joined after a ``NotAction:`` / ``NotResource:`` prefix and the
    matching flag set, so consumers cannot mistake "everything except X" for "X".
    """

    action: str = Field(description="Action pattern as written, e.g. 's3:GetObject', 's3:*', '*'")
    resource: str = Field(description="Resource pattern as written, e.g. '*' or an ARN with wildcards")
    effect: str = Field(description="'Allow' or 'Deny'")
    has_condition: bool = False
    not_action: bool = False
    not_resource: bool = False
    source: str = Field(default="", description="Where it came from: inline:<name>, managed:<arn>, group:<name>/...")


class RootCauseFix(BaseModel):
    """A single root-cause fix that breaks multiple attack chains."""

    check_id: str = Field(description="Check that produced the findings, e.g. 'aws-vpc-002'")
    fix_title: str = Field(description="Human-readable fix name, e.g. 'Restrict security groups'")
    effort: Effort = Field(description="Estimated remediation effort")
    findings_closed: int = Field(description="Number of findings this fix resolves")
    chains_broken: list[str] = Field(description="Chain IDs broken by this fix, e.g. ['AC-01', 'AC-02']")
    remediation: Remediation | None = Field(default=None, description="CLI + Terraform fix")
    total_risk_reduced: CostEstimateData | None = Field(default=None, description="Aggregate risk reduced")


class ScanSummary(BaseModel):
    """Aggregated summary of a full scan."""

    total_findings: int = 0
    attack_chains_detected: int = 0
    escalation_paths_detected: int = 0
    agents_discovered: int = 0
    by_severity: dict[Severity, int] = Field(default_factory=dict)
    by_category: dict[Category, int] = Field(default_factory=dict)
    resources_scanned: int = 0
    checks_passed: int = 0
    checks_failed: int = 0
    checks_errored: int = 0
    coverage_gaps: int = Field(
        default=0, description="Total region/resource reads denied to the scanner (see CheckResult.coverage_gaps)"
    )
    score: int = Field(default=100, description="Overall health score 0-100")
    total_risk_exposure: CostEstimateData | None = Field(default=None, description="Aggregate risk exposure estimate")


class ScanReport(BaseModel):
    """Complete scan report - the top-level output."""

    provider: str
    account_id: str = ""
    regions: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_seconds: float = 0.0
    summary: ScanSummary = Field(default_factory=ScanSummary)
    results: list[CheckResult] = Field(default_factory=list)
    attack_chains: list[AttackChain] = Field(default_factory=list)
    root_causes: list[RootCauseFix] = Field(default_factory=list)
    escalation_paths: list[EscalationPath] = Field(default_factory=list)
    agents: list[AgentIdentity] = Field(
        default_factory=list,
        description="AI agents and agent sandboxes discovered (Bedrock Agents, AgentCore) with their IAM identities",
    )
    agent_inventory_gaps: list[str] = Field(
        default_factory=list,
        description="Regions where the agent inventory was denied a read (not assessed there)",
    )
    principal_grants: dict[str, list[PolicyGrant]] = Field(
        default_factory=dict,
        description=(
            "Raw policy statements per IAM principal, collected only for AI agent identities and their tools' "
            "execution roles (bounded by design). Feeds agent-blast data reach; conditions are flagged, not evaluated."
        ),
    )
    # Security graph (v3.0.0+) - SecurityGraph.to_dict() output, or None for
    # older scans that predate the backbone. Kept as a plain dict so consumers
    # can round-trip the report without importing the graph module.
    security_graph: dict[str, object] | None = Field(
        default=None,
        description="Optional in-memory SecurityGraph serialized form (v3.0.0+).",
    )

    @property
    def all_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        for result in self.results:
            findings.extend(result.findings)
        return findings

    def compute_summary(self) -> None:
        """Aggregate results into summary. Call once after all checks complete."""
        self.summary.resources_scanned = sum(r.resources_scanned for r in self.results)
        self.summary.checks_passed = sum(1 for r in self.results if not r.findings and not r.error)
        self.summary.checks_failed = sum(1 for r in self.results if r.findings)
        self.summary.checks_errored = sum(1 for r in self.results if r.error)
        self.summary.coverage_gaps = sum(len(r.coverage_gaps) for r in self.results) + len(self.agent_inventory_gaps)
        self.summary.agents_discovered = len(self.agents)

        # Single pass over findings for severity, category counts and penalty
        sev_counts: dict[Severity, int] = {}
        cat_counts: dict[Category, int] = {}
        total = 0
        penalty = 0
        for result in self.results:
            for f in result.findings:
                total += 1
                sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
                cat_counts[f.category] = cat_counts.get(f.category, 0) + 1
                penalty += SEVERITY_WEIGHT[f.severity]

        self.summary.total_findings = total
        self.summary.by_severity = sev_counts
        self.summary.by_category = cat_counts
        self.summary.score = max(0, 100 - penalty)
