"""Tests for KMS security checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.kms import (
    check_kms_key_policy,
    check_kms_key_rotation,
)

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


def test_kms_key_rotation_disabled(mock_aws_provider: AWSProvider) -> None:
    """Customer-managed key without rotation - MEDIUM finding."""
    kms = mock_aws_provider.session.client("kms", region_name="eu-central-1")
    key = kms.create_key(Description="test-key")
    key_id = key["KeyMetadata"]["KeyId"]

    result = check_kms_key_rotation(mock_aws_provider)
    assert result.check_id == "aws-kms-001"
    assert result.resources_scanned >= 1
    rotation_findings = [f for f in result.findings if key_id[:12] in f.title]
    assert len(rotation_findings) >= 1
    assert rotation_findings[0].severity.value == "medium"
    assert rotation_findings[0].compliance_refs == ["CIS 3.6"]


def test_kms_key_rotation_enabled(mock_aws_provider: AWSProvider) -> None:
    """Customer-managed key with rotation - no finding."""
    kms = mock_aws_provider.session.client("kms", region_name="eu-central-1")
    key = kms.create_key(Description="test-key")
    key_id = key["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=key_id)

    result = check_kms_key_rotation(mock_aws_provider)
    rotation_findings = [f for f in result.findings if key_id[:12] in f.title]
    assert len(rotation_findings) == 0


def test_kms_key_policy_wildcard(mock_aws_provider: AWSProvider) -> None:
    """Key with wildcard principal (no conditions) - HIGH finding."""
    import json

    kms = mock_aws_provider.session.client("kms", region_name="eu-central-1")
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowAll",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "kms:*",
                    "Resource": "*",
                }
            ],
        }
    )
    key = kms.create_key(Description="open-key", Policy=policy)
    key_id = key["KeyMetadata"]["KeyId"]

    result = check_kms_key_policy(mock_aws_provider)
    assert result.check_id == "aws-kms-002"
    assert result.resources_scanned >= 1
    policy_findings = [f for f in result.findings if key_id[:12] in f.title]
    assert len(policy_findings) >= 1
    assert policy_findings[0].severity.value == "high"


def test_kms_key_policy_restricted(mock_aws_provider: AWSProvider) -> None:
    """Key with restricted principal - no finding."""
    import json

    kms = mock_aws_provider.session.client("kms", region_name="eu-central-1")
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowRoot",
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                }
            ],
        }
    )
    key = kms.create_key(Description="restricted-key", Policy=policy)
    key_id = key["KeyMetadata"]["KeyId"]

    result = check_kms_key_policy(mock_aws_provider)
    policy_findings = [f for f in result.findings if key_id[:12] in f.title]
    assert len(policy_findings) == 0
