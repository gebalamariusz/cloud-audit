"""Tests for SARIF v2.1.0 report generator."""

from __future__ import annotations

import json

from cloud_audit.models import (
    Category,
    CheckResult,
    Effort,
    Finding,
    Remediation,
    ScanReport,
    Severity,
)
from cloud_audit.reports.sarif import generate_sarif


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
                remediation=Remediation(
                    cli="aws iam create-virtual-mfa-device --virtual-mfa-device-name root-mfa",
                    terraform='resource "aws_iam_virtual_mfa_device" "root" {}',
                    doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html",
                    effort=Effort.LOW,
                ),
                compliance_refs=["CIS 1.5"],
            ),
            Finding(
                check_id="aws-s3-002",
                title="S3 bucket not encrypted",
                severity=Severity.MEDIUM,
                category=Category.SECURITY,
                resource_type="AWS::S3::Bucket",
                resource_id="my-bucket",
                region="global",
                description="Bucket does not have encryption.",
                recommendation="Enable encryption.",
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


def test_sarif_valid_json() -> None:
    """SARIF output is valid JSON."""
    report = _make_report()
    sarif_str = generate_sarif(report)
    data = json.loads(sarif_str)
    assert isinstance(data, dict)


def test_sarif_schema_version() -> None:
    """SARIF has correct schema and version."""
    report = _make_report()
    data = json.loads(generate_sarif(report))
    assert data["version"] == "2.1.0"
    assert "$schema" in data


def test_sarif_has_runs() -> None:
    """SARIF has exactly one run."""
    report = _make_report()
    data = json.loads(generate_sarif(report))
    assert len(data["runs"]) == 1


def test_sarif_tool_info() -> None:
    """SARIF tool section has cloud-audit info."""
    report = _make_report()
    data = json.loads(generate_sarif(report))
    driver = data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "cloud-audit"
    assert "version" in driver
    assert "rules" in driver


def test_sarif_rules_from_findings() -> None:
    """Rules are generated from unique check IDs."""
    report = _make_report()
    data = json.loads(generate_sarif(report))
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert "aws-iam-001" in rule_ids
    assert "aws-s3-002" in rule_ids


def test_sarif_severity_mapping() -> None:
    """CRITICAL maps to error, MEDIUM maps to warning."""
    report = _make_report()
    data = json.loads(generate_sarif(report))
    results = data["runs"][0]["results"]
    critical_result = next(r for r in results if r["ruleId"] == "aws-iam-001")
    medium_result = next(r for r in results if r["ruleId"] == "aws-s3-002")
    assert critical_result["level"] == "error"
    assert medium_result["level"] == "warning"


def test_sarif_fingerprints() -> None:
    """Each result has a partialFingerprints for deduplication."""
    report = _make_report()
    data = json.loads(generate_sarif(report))
    for result in data["runs"][0]["results"]:
        assert "partialFingerprints" in result
        assert "primaryLocationLineHash" in result["partialFingerprints"]
        assert len(result["partialFingerprints"]["primaryLocationLineHash"]) == 64  # SHA-256 hex


def test_sarif_fingerprint_stable() -> None:
    """Same check_id + resource_id produces same fingerprint."""
    report = _make_report()
    sarif1 = json.loads(generate_sarif(report))
    sarif2 = json.loads(generate_sarif(report))
    fp1 = sarif1["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
    fp2 = sarif2["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
    assert fp1 == fp2


def test_sarif_empty_findings() -> None:
    """Report with no findings produces valid SARIF with empty results."""
    report = _make_report(findings=[])
    data = json.loads(generate_sarif(report))
    assert data["runs"][0]["results"] == []
    assert data["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_remediation_in_properties() -> None:
    """Findings with remediation have remediation info in properties."""
    report = _make_report()
    data = json.loads(generate_sarif(report))
    iam_result = next(r for r in data["runs"][0]["results"] if r["ruleId"] == "aws-iam-001")
    assert "remediation_cli" in iam_result["properties"]
    assert "remediation_doc" in iam_result["properties"]


def test_sarif_no_remediation_properties_without_remediation() -> None:
    """Findings without remediation have no remediation properties."""
    report = _make_report()
    data = json.loads(generate_sarif(report))
    s3_result = next(r for r in data["runs"][0]["results"] if r["ruleId"] == "aws-s3-002")
    assert "remediation_cli" not in s3_result["properties"]


def test_sarif_compliance_tags_in_rules() -> None:
    """CIS refs are included as tags in rules."""
    report = _make_report()
    data = json.loads(generate_sarif(report))
    iam_rule = next(r for r in data["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "aws-iam-001")
    assert "properties" in iam_rule
    assert "CIS 1.5" in iam_rule["properties"]["tags"]
