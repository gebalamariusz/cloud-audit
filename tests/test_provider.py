"""Tests for AWSProvider — assume_role support."""

from __future__ import annotations

from typing import TYPE_CHECKING

import boto3
from moto import mock_aws

if TYPE_CHECKING:
    import pytest


@mock_aws
def test_assume_role_creates_session(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provider with role_arn should assume the role and use temporary credentials."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-central-1")

    # Create the role that will be assumed
    iam = boto3.client("iam", region_name="eu-central-1")
    trust_policy = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName="audit-role", AssumeRolePolicyDocument=trust_policy)
    role_arn = f"arn:aws:iam::{boto3.client('sts').get_caller_identity()['Account']}:role/audit-role"

    from cloud_audit.providers.aws.provider import AWSProvider

    provider = AWSProvider(regions=["eu-central-1"], role_arn=role_arn)

    # Should be able to get account ID with assumed credentials
    account_id = provider.get_account_id()
    assert account_id  # non-empty
    assert provider.get_provider_name() == "aws"


@mock_aws
def test_provider_without_role_arn(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provider without role_arn uses the base session directly."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-central-1")

    from cloud_audit.providers.aws.provider import AWSProvider

    provider = AWSProvider(regions=["eu-central-1"])
    account_id = provider.get_account_id()
    assert account_id
