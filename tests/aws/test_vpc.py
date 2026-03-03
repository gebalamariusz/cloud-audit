"""Tests for VPC security checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.vpc import (
    check_default_vpc_in_use,
    check_open_security_groups,
    check_vpc_flow_logs,
)

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


def test_default_vpc_pass(mock_aws_provider: AWSProvider) -> None:
    """Default VPC with no ENIs - no finding."""
    result = check_default_vpc_in_use(mock_aws_provider)
    assert result.error is None
    # moto creates a default VPC, but with no ENIs it should pass
    eni_findings = [f for f in result.findings if f.check_id == "aws-vpc-001"]
    assert len(eni_findings) == 0


def test_open_security_groups_pass(mock_aws_provider: AWSProvider) -> None:
    """Security group with restricted rules - no finding."""
    ec2 = mock_aws_provider.session.client("ec2", region_name="eu-central-1")
    sg = ec2.create_security_group(GroupName="restricted-sg", Description="Restricted SG")
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            }
        ],
    )
    result = check_open_security_groups(mock_aws_provider)
    sg_findings = [f for f in result.findings if f.resource_id == sg["GroupId"]]
    assert len(sg_findings) == 0


def test_open_security_groups_fail_all_traffic(mock_aws_provider: AWSProvider) -> None:
    """Security group open to all traffic - CRITICAL finding."""
    ec2 = mock_aws_provider.session.client("ec2", region_name="eu-central-1")
    sg = ec2.create_security_group(GroupName="wide-open-sg", Description="Wide open")
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    result = check_open_security_groups(mock_aws_provider)
    sg_findings = [f for f in result.findings if f.resource_id == sg["GroupId"]]
    assert len(sg_findings) >= 1
    assert sg_findings[0].severity.value == "critical"
    assert sg_findings[0].remediation is not None
    assert "revoke-security-group-ingress" in sg_findings[0].remediation.cli
    assert sg_findings[0].compliance_refs == ["CIS 5.2"]


def test_open_security_groups_fail_ssh(mock_aws_provider: AWSProvider) -> None:
    """Security group with SSH open to internet - CRITICAL finding."""
    ec2 = mock_aws_provider.session.client("ec2", region_name="eu-central-1")
    sg = ec2.create_security_group(GroupName="ssh-open-sg", Description="SSH open")
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    result = check_open_security_groups(mock_aws_provider)
    ssh_findings = [f for f in result.findings if f.resource_id == sg["GroupId"]]
    assert len(ssh_findings) >= 1
    assert ssh_findings[0].severity.value == "critical"
    assert "SSH" in ssh_findings[0].title


def test_vpc_flow_logs_pass(mock_aws_provider: AWSProvider) -> None:
    """VPC with flow logs - no finding."""
    ec2 = mock_aws_provider.session.client("ec2", region_name="eu-central-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]
    ec2.create_flow_logs(
        ResourceIds=[vpc_id],
        ResourceType="VPC",
        TrafficType="ALL",
        LogDestinationType="cloud-watch-logs",
        LogGroupName=f"/aws/vpc/flow-logs/{vpc_id}",
        DeliverLogsPermissionArn="arn:aws:iam::123456789012:role/flow-log-role",
    )
    result = check_vpc_flow_logs(mock_aws_provider)
    vpc_findings = [f for f in result.findings if f.resource_id == vpc_id]
    assert len(vpc_findings) == 0


def test_vpc_flow_logs_fail(mock_aws_provider: AWSProvider) -> None:
    """VPC without flow logs - MEDIUM finding."""
    ec2 = mock_aws_provider.session.client("ec2", region_name="eu-central-1")
    vpc = ec2.create_vpc(CidrBlock="10.1.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]
    result = check_vpc_flow_logs(mock_aws_provider)
    vpc_findings = [f for f in result.findings if f.resource_id == vpc_id]
    assert len(vpc_findings) == 1
    assert vpc_findings[0].severity.value == "medium"
    assert vpc_findings[0].remediation is not None
    assert "create-flow-logs" in vpc_findings[0].remediation.cli
    assert vpc_findings[0].compliance_refs == ["CIS 3.7"]
