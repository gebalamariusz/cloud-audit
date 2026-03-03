"""Tests for CLI remediation and export-fixes flags."""

from __future__ import annotations

from pathlib import Path

from cloud_audit.cli import _export_fixes, _print_remediation
from cloud_audit.models import (
    Category,
    CheckResult,
    Effort,
    Finding,
    Remediation,
    ScanReport,
    Severity,
)


def _make_finding(
    *,
    check_id: str = "aws-test-001",
    severity: Severity = Severity.HIGH,
    with_remediation: bool = True,
) -> Finding:
    """Create a test finding with optional remediation."""
    remediation = None
    if with_remediation:
        cli_cmd = (
            "aws s3api put-public-access-block --bucket test-bucket"
            " --public-access-block-configuration BlockPublicAcls=true"
        )
        tf_snippet = 'resource "aws_s3_bucket_public_access_block" "example" {\n  bucket = aws_s3_bucket.example.id\n}'
        remediation = Remediation(
            cli=cli_cmd,
            terraform=tf_snippet,
            doc_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
            effort=Effort.LOW,
        )
    return Finding(
        check_id=check_id,
        title="Test bucket without public access block",
        severity=severity,
        category=Category.SECURITY,
        resource_type="AWS::S3::Bucket",
        resource_id="test-bucket",
        region="global",
        description="Bucket does not have public access block enabled.",
        recommendation="Enable public access block.",
        remediation=remediation,
        compliance_refs=["CIS 2.1.5"] if with_remediation else [],
    )


def _make_report(findings: list[Finding]) -> ScanReport:
    """Create a minimal ScanReport with given findings."""
    report = ScanReport(
        provider="aws",
        account_id="123456789012",
        regions=["eu-central-1"],
    )
    report.results.append(
        CheckResult(
            check_id="aws-test-001",
            check_name="Test Check",
            findings=findings,
            resources_scanned=len(findings),
        )
    )
    report.compute_summary()
    return report


def test_print_remediation_shows_output(capsys: object) -> None:
    """--remediation flag prints CLI commands and compliance refs."""
    finding = _make_finding(with_remediation=True)
    # _print_remediation uses rich Console, so we just verify it doesn't crash
    _print_remediation([finding])


def test_print_remediation_skips_no_remediation() -> None:
    """No remediation findings - nothing printed."""
    finding = _make_finding(with_remediation=False)
    # Should not raise
    _print_remediation([finding])


def test_print_remediation_empty_list() -> None:
    """Empty findings list - nothing printed."""
    _print_remediation([])


def test_export_fixes_creates_script(tmp_path: Path) -> None:
    """--export-fixes generates a valid bash script with commented commands."""
    finding = _make_finding(with_remediation=True)
    output_path = tmp_path / "fixes.sh"

    _export_fixes([finding], output_path)

    assert output_path.exists()
    content = output_path.read_text(encoding="utf-8")

    # Bash script structure
    assert content.startswith("#!/bin/bash")
    assert "set -e" in content
    assert "DRY RUN" in content

    # Finding details
    assert "test-bucket" in content
    assert "CIS 2.1.5" in content

    # CLI command is commented out
    assert "# aws s3api put-public-access-block" in content


def test_export_fixes_multiple_findings(tmp_path: Path) -> None:
    """Multiple findings are all included in the script."""
    findings = [
        _make_finding(check_id="aws-test-001", severity=Severity.CRITICAL),
        _make_finding(check_id="aws-test-002", severity=Severity.LOW),
    ]
    output_path = tmp_path / "fixes.sh"

    _export_fixes(findings, output_path)

    content = output_path.read_text(encoding="utf-8")
    assert "Total actionable findings: 2" in content
    # CRITICAL should come before LOW
    crit_pos = content.index("[CRITICAL]")
    low_pos = content.index("[LOW]")
    assert crit_pos < low_pos


def test_export_fixes_no_actionable(tmp_path: Path) -> None:
    """No remediation findings - no file created."""
    finding = _make_finding(with_remediation=False)
    output_path = tmp_path / "fixes.sh"

    _export_fixes([finding], output_path)

    assert not output_path.exists()


def test_export_fixes_empty_findings(tmp_path: Path) -> None:
    """Empty findings list - no file created."""
    output_path = tmp_path / "fixes.sh"

    _export_fixes([], output_path)

    assert not output_path.exists()
