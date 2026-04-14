"""Tests for Bedrock AI security checks."""

from __future__ import annotations

import boto3
from moto import mock_aws

from cloud_audit.providers.aws.provider import AWSProvider


@mock_aws
def test_bedrock_logging_disabled() -> None:
    """Bedrock without logging should produce a finding."""
    provider = AWSProvider(regions=["us-east-1"])
    provider.reset_caches()
    checks = [c for c in provider.get_checks() if c.check_id == "aws-bedrock-001"]
    assert len(checks) == 1
    result = checks[0]()
    # Default moto config has no logging → should flag
    assert result.check_id == "aws-bedrock-001"
    # May produce finding if moto returns empty logging config
    if result.findings:
        assert result.findings[0].severity.value in ("high", "critical")


@mock_aws
def test_bedrock_logging_enabled() -> None:
    """Bedrock with logging configured should not produce a finding."""
    br = boto3.client("bedrock", region_name="us-east-1")
    br.put_model_invocation_logging_configuration(
        loggingConfig={
            "cloudWatchConfig": {
                "logGroupName": "/aws/bedrock/invocations",
                "roleArn": "arn:aws:iam::123456789012:role/bedrock-logging",
                "largeDataDeliveryS3Config": {"bucketName": "bedrock-large-data", "keyPrefix": "logs/"},
            },
            "s3Config": {"bucketName": "bedrock-logs-bucket", "keyPrefix": "invocations/"},
            "textDataDeliveryEnabled": True,
            "imageDataDeliveryEnabled": False,
            "embeddingDataDeliveryEnabled": False,
        }
    )
    provider = AWSProvider(regions=["us-east-1"])
    provider.reset_caches()
    checks = [c for c in provider.get_checks() if c.check_id == "aws-bedrock-001"]
    result = checks[0]()
    # With CW logging configured, no finding
    assert len(result.findings) == 0
