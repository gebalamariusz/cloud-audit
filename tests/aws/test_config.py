"""Tests for AWS Config checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.config_ import (
    check_config_enabled,
    check_config_recorder_active,
    check_delivery_channel,
    check_recording_group_complete,
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
    assert result.error is None
    findings = [f for f in result.findings if f.check_id == "aws-cfg-002"]
    assert len(findings) >= 1, "Expected at least one finding for inactive config recorder"
    assert findings[0].severity.value == "high"


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


# -----------------------------------------------------------------------------
# aws-cfg-003 - Recording group complete (allSupported + includeGlobalResourceTypes)
# -----------------------------------------------------------------------------


def test_cfg_003_no_recorder_no_finding(mock_aws_provider: AWSProvider) -> None:
    """No recorder at all - aws-cfg-001 handles, aws-cfg-003 stays silent."""
    result = check_recording_group_complete(mock_aws_provider)
    assert result.check_id == "aws-cfg-003"
    assert len(result.findings) == 0


def test_cfg_003_complete_recording_group_no_finding(mock_aws_provider: AWSProvider) -> None:
    """allSupported=true + includeGlobalResourceTypes=true - no finding."""
    config = mock_aws_provider.session.client("config", region_name="eu-central-1")
    config.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": "arn:aws:iam::123456789012:role/config-role",
            "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True},
        }
    )

    result = check_recording_group_complete(mock_aws_provider)
    assert len(result.findings) == 0


def test_cfg_003_inclusion_strategy_produces_medium(mock_aws_provider: AWSProvider) -> None:
    """recordingStrategy.useOnly=INCLUSION_BY_RESOURCE_TYPES - MEDIUM finding.

    Modern recordingStrategy explicitly limits the recorder to a subset of
    resource types - exactly the "incomplete inventory" anti-pattern.
    """
    config = mock_aws_provider.session.client("config", region_name="eu-central-1")
    config.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": "arn:aws:iam::123456789012:role/config-role",
            "recordingGroup": {
                "allSupported": False,
                "resourceTypes": ["AWS::S3::Bucket"],
                "includeGlobalResourceTypes": False,
                "recordingStrategy": {"useOnly": "INCLUSION_BY_RESOURCE_TYPES"},
            },
        }
    )

    result = check_recording_group_complete(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-cfg-003"]
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"
    assert "INCLUSION_BY_RESOURCE_TYPES" in findings[0].description


def test_cfg_003_exclusion_strategy_produces_medium(mock_aws_provider: AWSProvider) -> None:
    """recordingStrategy.useOnly=EXCLUSION_BY_RESOURCE_TYPES - MEDIUM finding."""
    config = mock_aws_provider.session.client("config", region_name="eu-central-1")
    config.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": "arn:aws:iam::123456789012:role/config-role",
            "recordingGroup": {
                "allSupported": False,
                "exclusionByResourceTypes": {"resourceTypes": ["AWS::SSM::ManagedInstanceInventory"]},
                "recordingStrategy": {"useOnly": "EXCLUSION_BY_RESOURCE_TYPES"},
            },
        }
    )

    result = check_recording_group_complete(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-cfg-003"]
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"
    assert "EXCLUSION_BY_RESOURCE_TYPES" in findings[0].description


# -----------------------------------------------------------------------------
# aws-cfg-004 - Delivery channel exists and properly configured
# -----------------------------------------------------------------------------


def test_cfg_004_no_recorder_no_finding(mock_aws_provider: AWSProvider) -> None:
    """No recorder - aws-cfg-001 handles, aws-cfg-004 stays silent."""
    result = check_delivery_channel(mock_aws_provider)
    assert result.check_id == "aws-cfg-004"
    assert len(result.findings) == 0


def test_cfg_004_recorder_but_no_delivery_channel_produces_high(
    mock_aws_provider: AWSProvider,
) -> None:
    """Recorder exists but no delivery channel - HIGH finding."""
    config = mock_aws_provider.session.client("config", region_name="eu-central-1")
    config.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": "arn:aws:iam::123456789012:role/config-role",
            "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True},
        }
    )

    result = check_delivery_channel(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-cfg-004"]
    assert len(findings) == 1
    assert findings[0].severity.value == "high"
    assert "no delivery channel" in findings[0].title


def test_cfg_004_delivery_channel_with_daily_snapshots_produces_low(
    mock_aws_provider: AWSProvider,
) -> None:
    """Delivery channel exists with TwentyFour_Hours snapshot frequency - LOW finding."""
    config = mock_aws_provider.session.client("config", region_name="eu-central-1")
    config.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": "arn:aws:iam::123456789012:role/config-role",
            "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True},
        }
    )
    config.put_delivery_channel(
        DeliveryChannel={
            "name": "default",
            "s3BucketName": "config-bucket",
            "configSnapshotDeliveryProperties": {"deliveryFrequency": "TwentyFour_Hours"},
        }
    )

    result = check_delivery_channel(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-cfg-004"]
    assert len(findings) == 1
    assert findings[0].severity.value == "low"
    assert "TwentyFour_Hours" in findings[0].description


def test_cfg_004_delivery_channel_well_configured_no_finding(
    mock_aws_provider: AWSProvider,
) -> None:
    """Delivery channel with One_Hour snapshots and KMS - no finding."""
    config = mock_aws_provider.session.client("config", region_name="eu-central-1")
    config.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": "arn:aws:iam::123456789012:role/config-role",
            "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True},
        }
    )
    config.put_delivery_channel(
        DeliveryChannel={
            "name": "default",
            "s3BucketName": "config-bucket",
            "s3KmsKeyArn": "arn:aws:kms:eu-central-1:123456789012:key/abc-123",
            "configSnapshotDeliveryProperties": {"deliveryFrequency": "One_Hour"},
        }
    )

    result = check_delivery_channel(mock_aws_provider)
    findings = [f for f in result.findings if f.check_id == "aws-cfg-004"]
    assert len(findings) == 0
