"""Shared test fixtures for cloud-audit."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from moto import mock_aws

if TYPE_CHECKING:
    from collections.abc import Generator

    from cloud_audit.providers.aws.provider import AWSProvider


@pytest.fixture()
def aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set dummy AWS credentials for moto."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-central-1")


@pytest.fixture()
def mock_aws_provider(aws_env: None) -> Generator[AWSProvider, None, None]:
    """Create a real AWSProvider backed by moto's mock AWS services."""
    from cloud_audit.providers.aws.checks.s3 import _reset_bucket_cache

    _reset_bucket_cache()
    with mock_aws():
        from cloud_audit.providers.aws.provider import AWSProvider

        provider = AWSProvider(regions=["eu-central-1"])
        yield provider
    _reset_bucket_cache()
