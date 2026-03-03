"""Tests for EC2 security and cost checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.ec2 import (
    check_public_amis,
    check_stopped_instances,
    check_unencrypted_volumes,
)

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


def test_public_amis_pass(mock_aws_provider: AWSProvider) -> None:
    """No custom AMIs - no findings."""
    result = check_public_amis(mock_aws_provider)
    assert result.error is None
    assert len(result.findings) == 0


def test_unencrypted_volumes_pass(mock_aws_provider: AWSProvider) -> None:
    """Encrypted volume - no finding."""
    ec2 = mock_aws_provider.session.client("ec2", region_name="eu-central-1")
    ec2.create_volume(
        AvailabilityZone="eu-central-1a",
        Size=10,
        Encrypted=True,
    )
    result = check_unencrypted_volumes(mock_aws_provider)
    assert result.resources_scanned >= 1
    enc_findings = [f for f in result.findings if f.check_id == "aws-ec2-002"]
    assert len(enc_findings) == 0


def test_unencrypted_volumes_fail(mock_aws_provider: AWSProvider) -> None:
    """Unencrypted volume - MEDIUM finding."""
    ec2 = mock_aws_provider.session.client("ec2", region_name="eu-central-1")
    ec2.create_volume(
        AvailabilityZone="eu-central-1a",
        Size=20,
        Encrypted=False,
    )
    result = check_unencrypted_volumes(mock_aws_provider)
    unenc_findings = [f for f in result.findings if f.check_id == "aws-ec2-002"]
    assert len(unenc_findings) >= 1
    assert unenc_findings[0].severity.value == "medium"
    assert unenc_findings[0].remediation is not None
    assert "enable-ebs-encryption-by-default" in unenc_findings[0].remediation.cli
    assert unenc_findings[0].compliance_refs == ["CIS 2.2.1"]


def test_stopped_instances_pass(mock_aws_provider: AWSProvider) -> None:
    """No stopped instances - no findings."""
    result = check_stopped_instances(mock_aws_provider)
    assert result.error is None
    assert len(result.findings) == 0


def test_stopped_instances_fail(mock_aws_provider: AWSProvider) -> None:
    """Stopped instance - LOW finding."""
    ec2 = mock_aws_provider.session.client("ec2", region_name="eu-central-1")
    # Launch and then stop an instance
    resp = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro")
    instance_id = resp["Instances"][0]["InstanceId"]
    ec2.stop_instances(InstanceIds=[instance_id])
    result = check_stopped_instances(mock_aws_provider)
    stopped_findings = [f for f in result.findings if f.check_id == "aws-ec2-003"]
    assert len(stopped_findings) >= 1
    assert stopped_findings[0].severity.value == "low"
    assert stopped_findings[0].remediation is not None
    assert "terminate-instances" in stopped_findings[0].remediation.cli
