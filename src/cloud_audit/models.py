"""Core data models for cloud-audit findings and reports."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

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


SEVERITY_SCORE = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 5,
    Severity.MEDIUM: 15,
    Severity.LOW: 25,
    Severity.INFO: 35,
}

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


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


class CheckResult(BaseModel):
    """Result of running a single check - may produce 0..N findings."""

    check_id: str
    check_name: str
    findings: list[Finding] = Field(default_factory=list)
    resources_scanned: int = 0
    error: str | None = None


class ScanSummary(BaseModel):
    """Aggregated summary of a full scan."""

    total_findings: int = 0
    by_severity: dict[Severity, int] = Field(default_factory=dict)
    by_category: dict[Category, int] = Field(default_factory=dict)
    resources_scanned: int = 0
    checks_passed: int = 0
    checks_failed: int = 0
    checks_errored: int = 0
    score: int = Field(default=100, description="Overall health score 0-100")


class ScanReport(BaseModel):
    """Complete scan report - the top-level output."""

    provider: str
    account_id: str = ""
    regions: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_seconds: float = 0.0
    summary: ScanSummary = Field(default_factory=ScanSummary)
    results: list[CheckResult] = Field(default_factory=list)

    @property
    def all_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        for result in self.results:
            findings.extend(result.findings)
        return findings

    def compute_summary(self) -> None:
        findings = self.all_findings
        self.summary.total_findings = len(findings)
        self.summary.resources_scanned = sum(r.resources_scanned for r in self.results)
        self.summary.checks_passed = sum(1 for r in self.results if not r.findings and not r.error)
        self.summary.checks_failed = sum(1 for r in self.results if r.findings)
        self.summary.checks_errored = sum(1 for r in self.results if r.error)

        self.summary.by_severity = {}
        for sev in Severity:
            count = sum(1 for f in findings if f.severity == sev)
            if count:
                self.summary.by_severity[sev] = count

        self.summary.by_category = {}
        for cat in Category:
            count = sum(1 for f in findings if f.category == cat)
            if count:
                self.summary.by_category[cat] = count

        # Score: start at 100, subtract based on severity weights
        penalty = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
        self.summary.score = max(0, 100 - penalty)
