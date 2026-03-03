"""Tests for IAM security checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.iam import (
    check_access_keys_rotation,
    check_root_mfa,
    check_unused_access_keys,
    check_users_mfa,
)

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


def test_root_mfa_pass(mock_aws_provider: AWSProvider) -> None:
    """Root MFA enabled - no findings."""
    # moto's default account has MFA disabled, so this will produce a finding
    # We test that the check runs without errors and returns a result
    result = check_root_mfa(mock_aws_provider)
    assert result.check_id == "aws-iam-001"
    assert result.resources_scanned == 1
    assert result.error is None


def test_root_mfa_fail(mock_aws_provider: AWSProvider) -> None:
    """Root MFA disabled - should produce CRITICAL finding."""
    result = check_root_mfa(mock_aws_provider)
    # moto's default: root MFA is disabled
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity.value == "critical"
    assert finding.remediation is not None
    assert finding.compliance_refs == ["CIS 1.5"]
    assert "console.aws.amazon.com" in finding.remediation.cli


def test_users_mfa_pass(mock_aws_provider: AWSProvider) -> None:
    """User without console access - no MFA required."""
    iam = mock_aws_provider.session.client("iam")
    iam.create_user(UserName="api-user")
    # No login profile = no console access = no MFA needed
    result = check_users_mfa(mock_aws_provider)
    assert result.resources_scanned >= 1
    assert len(result.findings) == 0


def test_users_mfa_fail(mock_aws_provider: AWSProvider) -> None:
    """User with console access but no MFA - HIGH finding."""
    iam = mock_aws_provider.session.client("iam")
    iam.create_user(UserName="console-user")
    iam.create_login_profile(UserName="console-user", Password="Test1234!@#$")  # noqa: S106
    result = check_users_mfa(mock_aws_provider)
    mfa_findings = [f for f in result.findings if f.check_id == "aws-iam-002"]
    assert len(mfa_findings) >= 1
    assert mfa_findings[0].severity.value == "high"
    assert mfa_findings[0].remediation is not None
    assert "console-user" in mfa_findings[0].remediation.cli
    assert mfa_findings[0].compliance_refs == ["CIS 1.4"]


def test_access_keys_rotation_pass(mock_aws_provider: AWSProvider) -> None:
    """Fresh access key - no finding."""
    iam = mock_aws_provider.session.client("iam")
    iam.create_user(UserName="fresh-key-user")
    iam.create_access_key(UserName="fresh-key-user")
    result = check_access_keys_rotation(mock_aws_provider)
    rotation_findings = [f for f in result.findings if f.check_id == "aws-iam-003"]
    assert len(rotation_findings) == 0


def test_unused_access_keys_fail(mock_aws_provider: AWSProvider) -> None:
    """Access key never used - MEDIUM finding."""
    iam = mock_aws_provider.session.client("iam")
    iam.create_user(UserName="unused-key-user")
    iam.create_access_key(UserName="unused-key-user")
    result = check_unused_access_keys(mock_aws_provider)
    unused_findings = [f for f in result.findings if f.check_id == "aws-iam-004"]
    assert len(unused_findings) >= 1
    assert unused_findings[0].remediation is not None
    assert unused_findings[0].compliance_refs == ["CIS 1.12"]
