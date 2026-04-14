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


class CheckResult(BaseModel):
    """Result of running a single check - may produce 0..N findings."""

    check_id: str
    check_name: str
    findings: list[Finding] = Field(default_factory=list)
    resources_scanned: int = 0
    error: str | None = None


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
    by_severity: dict[Severity, int] = Field(default_factory=dict)
    by_category: dict[Category, int] = Field(default_factory=dict)
    resources_scanned: int = 0
    checks_passed: int = 0
    checks_failed: int = 0
    checks_errored: int = 0
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
