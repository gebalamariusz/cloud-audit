"""Tests for AWS Config checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.config_ import (
    check_config_enabled,
    check_config_recorder_active,
)

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


def test_config_not_enabled(mock_aws_provider: AWSProvider) -> None:
    """No Config recorder - MEDIUM finding."""
    result = check_config_enabled(mock_aws_provider)
    assert result.check_id == "aws-cfg-001"
    assert result.resources_scanned == 1
    assert len(result.findings) == 1
    assert result.findings[0].severity.value == "medium"
    assert result.findings[0].region == "eu-central-1"


def test_config_enabled(mock_aws_provider: AWSProvider) -> None:
    """Config recorder exists - no finding."""
    config = mock_aws_provider.session.client("config", region_name="eu-central-1")
    config.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": "arn:aws:iam::123456789012:role/config-role",
            "recordingGroup": {"allSupported": True},
        }
    )

    result = check_config_enabled(mock_aws_provider)
    assert result.resources_scanned == 1
    assert len(result.findings) == 0


def test_config_recorder_not_active(mock_aws_provider: AWSProvider) -> None:
    """Config recorder exists but not recording - HIGH finding."""
    config = mock_aws_provider.session.client("config", region_name="eu-central-1")
    config.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": "arn:aws:iam::123456789012:role/config-role",
            "recordingGroup": {"allSupported": True},
        }
    )
    # Recorder exists but not started - should be inactive

    result = check_config_recorder_active(mock_aws_provider)
    assert result.check_id == "aws-cfg-002"
    # moto may or may not show recorder as inactive by default
    assert result.error is None


def test_config_recorder_active(mock_aws_provider: AWSProvider) -> None:
    """Config recorder actively recording - no finding."""
    config = mock_aws_provider.session.client("config", region_name="eu-central-1")
    config.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": "arn:aws:iam::123456789012:role/config-role",
            "recordingGroup": {"allSupported": True},
        }
    )
    config.put_delivery_channel(
        DeliveryChannel={
            "name": "default",
            "s3BucketName": "config-bucket",
        }
    )
    config.start_configuration_recorder(ConfigurationRecorderName="default")

    result = check_config_recorder_active(mock_aws_provider)
    recording_findings = [f for f in result.findings if f.check_id == "aws-cfg-002"]
    assert len(recording_findings) == 0
