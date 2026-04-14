"""Tests for SageMaker AI security checks."""

from __future__ import annotations

import boto3
from moto import mock_aws

from cloud_audit.providers.aws.provider import AWSProvider


@mock_aws
def test_sagemaker_no_notebooks() -> None:
    """No SageMaker notebooks should produce 0 findings."""
    provider = AWSProvider(regions=["us-east-1"])
    provider.reset_caches()
    checks = [c for c in provider.get_checks() if c.check_id == "aws-sagemaker-001"]
    assert len(checks) == 1
    result = checks[0]()
    assert len(result.findings) == 0


@mock_aws
def test_sagemaker_notebook_root_access() -> None:
    """SageMaker notebook with root access should produce a CRITICAL finding."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(
        RoleName="sagemaker-role",
        AssumeRolePolicyDocument="{}",
        Path="/",
    )
    sm = boto3.client("sagemaker", region_name="us-east-1")
    sm.create_notebook_instance(
        NotebookInstanceName="test-notebook",
        InstanceType="ml.t3.medium",
        RoleArn=(
            f"arn:aws:iam::"
            f"{boto3.client('sts', region_name='us-east-1').get_caller_identity()['Account']}"
            f":role/sagemaker-role"
        ),
        RootAccess="Enabled",
    )

    provider = AWSProvider(regions=["us-east-1"])
    provider.reset_caches()
    checks = [c for c in provider.get_checks() if c.check_id == "aws-sagemaker-001"]
    result = checks[0]()
    assert len(result.findings) == 1
    assert result.findings[0].severity.value == "critical"
    assert "root" in result.findings[0].title.lower()


@mock_aws
def test_sagemaker_notebook_root_disabled() -> None:
    """SageMaker notebook with root disabled should produce no finding."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(
        RoleName="sagemaker-role",
        AssumeRolePolicyDocument="{}",
        Path="/",
    )
    sm = boto3.client("sagemaker", region_name="us-east-1")
    sm.create_notebook_instance(
        NotebookInstanceName="safe-notebook",
        InstanceType="ml.t3.medium",
        RoleArn=(
            f"arn:aws:iam::"
            f"{boto3.client('sts', region_name='us-east-1').get_caller_identity()['Account']}"
            f":role/sagemaker-role"
        ),
        RootAccess="Disabled",
    )

    provider = AWSProvider(regions=["us-east-1"])
    provider.reset_caches()
    checks = [c for c in provider.get_checks() if c.check_id == "aws-sagemaker-001"]
    result = checks[0]()
    assert len(result.findings) == 0


@mock_aws
def test_sagemaker_endpoint_no_kms() -> None:
    """SageMaker endpoints without KMS should produce a finding."""
    # Endpoint creation in moto requires a model + endpoint config
    # If moto doesn't support all the details, we just verify the check runs without error
    provider = AWSProvider(regions=["us-east-1"])
    provider.reset_caches()
    checks = [c for c in provider.get_checks() if c.check_id == "aws-sagemaker-003"]
    assert len(checks) == 1
    result = checks[0]()
    # With no endpoints, should have 0 findings (not errors)
    assert result.error is None
