"""Tests for Elastic IP cost checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.eip import check_unattached_eips

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


def test_unattached_eips_pass(mock_aws_provider: AWSProvider) -> None:
    """No EIPs - no findings."""
    result = check_unattached_eips(mock_aws_provider)
    assert result.error is None
    assert len(result.findings) == 0


def test_attached_eip_pass(mock_aws_provider: AWSProvider) -> None:
    """EIP attached to instance - no finding."""
    ec2 = mock_aws_provider.session.client("ec2", region_name="eu-central-1")
    # Launch an instance and attach an EIP
    resp = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro")
    instance_id = resp["Instances"][0]["InstanceId"]
    alloc = ec2.allocate_address(Domain="vpc")
    ec2.associate_address(AllocationId=alloc["AllocationId"], InstanceId=instance_id)
    result = check_unattached_eips(mock_aws_provider)
    assert len(result.findings) == 0


def test_unattached_eip_fail(mock_aws_provider: AWSProvider) -> None:
    """Unattached EIP - LOW finding."""
    ec2 = mock_aws_provider.session.client("ec2", region_name="eu-central-1")
    alloc = ec2.allocate_address(Domain="vpc")
    result = check_unattached_eips(mock_aws_provider)
    eip_findings = [f for f in result.findings if f.check_id == "aws-eip-001"]
    assert len(eip_findings) >= 1
    assert eip_findings[0].severity.value == "low"
    assert eip_findings[0].remediation is not None
    assert "release-address" in eip_findings[0].remediation.cli
    assert alloc["AllocationId"] in eip_findings[0].remediation.cli
