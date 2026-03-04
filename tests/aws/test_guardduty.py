"""Tests for GuardDuty security checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.guardduty import (
    check_guardduty_enabled,
    check_guardduty_findings,
)

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


def test_guardduty_not_enabled(mock_aws_provider: AWSProvider) -> None:
    """No GuardDuty detector - HIGH finding."""
    result = check_guardduty_enabled(mock_aws_provider)
    assert result.check_id == "aws-gd-001"
    assert result.resources_scanned == 1
    assert len(result.findings) == 1
    assert result.findings[0].severity.value == "high"


def test_guardduty_enabled(mock_aws_provider: AWSProvider) -> None:
    """GuardDuty detector exists - no finding."""
    gd = mock_aws_provider.session.client("guardduty", region_name="eu-central-1")
    gd.create_detector(Enable=True)

    result = check_guardduty_enabled(mock_aws_provider)
    assert result.resources_scanned == 1
    assert len(result.findings) == 0


def test_guardduty_findings_no_detector(mock_aws_provider: AWSProvider) -> None:
    """No detector - no findings check runs without error."""
    result = check_guardduty_findings(mock_aws_provider)
    assert result.check_id == "aws-gd-002"
    assert result.error is None


def test_guardduty_findings_clean(mock_aws_provider: AWSProvider) -> None:
    """Detector with no old findings - no finding."""
    gd = mock_aws_provider.session.client("guardduty", region_name="eu-central-1")
    gd.create_detector(Enable=True)

    result = check_guardduty_findings(mock_aws_provider)
    assert result.resources_scanned >= 1
    assert len(result.findings) == 0
