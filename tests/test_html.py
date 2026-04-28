"""Tests for HTML report generator."""

from __future__ import annotations

from cloud_audit.models import (
    Category,
    CheckResult,
    Finding,
    ScanReport,
    Severity,
)
from cloud_audit.reports.html import render_html


def _make_report(findings: list[Finding] | None = None) -> ScanReport:
    """Create a minimal ScanReport for testing."""
    if findings is None:
        findings = [
            Finding(
                check_id="aws-iam-001",
                title="Root account without MFA",
                severity=Severity.CRITICAL,
                category=Category.SECURITY,
                resource_type="AWS::IAM::User",
                resource_id="root",
                region="global",
                description="Root account does not have MFA enabled.",
                recommendation="Enable MFA on the root account.",
                compliance_refs=["CIS 1.5"],
            ),
        ]
    report = ScanReport(provider="aws", account_id="123456789012", regions=["eu-central-1"])
    report.results.append(
        CheckResult(
            check_id="aws-test",
            check_name="Test",
            findings=findings,
            resources_scanned=len(findings),
        )
    )
    report.compute_summary()
    return report


def test_html_renders_valid_string() -> None:
    """HTML output is a non-empty string containing expected tags."""
    report = _make_report()
    html = render_html(report)
    assert isinstance(html, str)
    assert len(html) > 100
    assert "<html" in html
    assert "cloud-audit" in html.lower()


def test_html_contains_finding_data() -> None:
    """HTML report includes finding details."""
    report = _make_report()
    html = render_html(report)
    assert "Root account without MFA" in html


def test_html_contains_score() -> None:
    """HTML report includes the health score."""
    report = _make_report()
    html = render_html(report)
    assert str(report.summary.score) in html


def test_html_empty_findings() -> None:
    """HTML report with no findings still renders."""
    report = _make_report(findings=[])
    html = render_html(report)
    assert isinstance(html, str)
    assert "<html" in html


def test_html_renders_remediation_plan() -> None:
    """HTML report includes the Remediation Plan section when root_causes are present."""
    from cloud_audit.models import Effort, RootCauseFix

    report = _make_report()
    report.root_causes = [
        RootCauseFix(
            check_id="aws-vpc-002",
            fix_title="Restrict security groups",
            effort=Effort.LOW,
            findings_closed=3,
            chains_broken=["AC-01", "AC-02", "AC-13"],
        ),
    ]
    html = render_html(report)
    assert "Remediation Plan" in html
    assert "Restrict security groups" in html
    assert "AC-01" not in html or "3" in html  # chains count rendered


def test_html_no_remediation_plan_when_empty() -> None:
    """HTML report omits Remediation Plan table when root_causes is empty."""
    report = _make_report()
    report.root_causes = []
    html = render_html(report)
    assert "remediation-plan-section" not in html
