"""Tests for CloudTrail security checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.cloudtrail import (
    check_cloudtrail_bucket_public,
    check_cloudtrail_enabled,
    check_cloudtrail_log_validation,
)

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


def test_cloudtrail_enabled_no_trails(mock_aws_provider: AWSProvider) -> None:
    """No trails configured - CRITICAL finding."""
    result = check_cloudtrail_enabled(mock_aws_provider)
    assert result.check_id == "aws-ct-001"
    assert result.resources_scanned == 1
    assert len(result.findings) == 1
    assert result.findings[0].severity.value == "critical"
    assert result.findings[0].compliance_refs == ["CIS 3.1"]


def test_cloudtrail_enabled_single_region(mock_aws_provider: AWSProvider) -> None:
    """Trail exists but not multi-region - HIGH finding."""
    s3 = mock_aws_provider.session.client("s3", region_name="eu-central-1")
    s3.create_bucket(
        Bucket="audit-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    ct = mock_aws_provider.session.client("cloudtrail", region_name="eu-central-1")
    ct.create_trail(Name="test-trail", S3BucketName="audit-bucket", IsMultiRegionTrail=False)
    ct.start_logging(Name="test-trail")

    result = check_cloudtrail_enabled(mock_aws_provider)
    assert result.resources_scanned == 1
    assert len(result.findings) == 1
    assert result.findings[0].severity.value == "high"


def test_cloudtrail_enabled_multi_region(mock_aws_provider: AWSProvider) -> None:
    """Multi-region trail - no finding."""
    s3 = mock_aws_provider.session.client("s3", region_name="eu-central-1")
    s3.create_bucket(
        Bucket="audit-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    ct = mock_aws_provider.session.client("cloudtrail", region_name="eu-central-1")
    ct.create_trail(Name="main-trail", S3BucketName="audit-bucket", IsMultiRegionTrail=True)
    ct.start_logging(Name="main-trail")

    result = check_cloudtrail_enabled(mock_aws_provider)
    assert len(result.findings) == 0


def test_cloudtrail_log_validation_disabled(mock_aws_provider: AWSProvider) -> None:
    """Trail without log validation - HIGH finding."""
    s3 = mock_aws_provider.session.client("s3", region_name="eu-central-1")
    s3.create_bucket(
        Bucket="audit-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    ct = mock_aws_provider.session.client("cloudtrail", region_name="eu-central-1")
    ct.create_trail(
        Name="test-trail",
        S3BucketName="audit-bucket",
        EnableLogFileValidation=False,
    )

    result = check_cloudtrail_log_validation(mock_aws_provider)
    assert result.resources_scanned >= 1
    assert len(result.findings) >= 1
    assert result.findings[0].severity.value == "high"
    assert result.findings[0].compliance_refs == ["CIS 3.2"]


def test_cloudtrail_log_validation_enabled(mock_aws_provider: AWSProvider) -> None:
    """Trail with log validation - no finding."""
    s3 = mock_aws_provider.session.client("s3", region_name="eu-central-1")
    s3.create_bucket(
        Bucket="audit-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    ct = mock_aws_provider.session.client("cloudtrail", region_name="eu-central-1")
    ct.create_trail(
        Name="test-trail",
        S3BucketName="audit-bucket",
        EnableLogFileValidation=True,
    )

    result = check_cloudtrail_log_validation(mock_aws_provider)
    val_findings = [f for f in result.findings if f.resource_id == "test-trail"]
    assert len(val_findings) == 0


def test_cloudtrail_bucket_public_blocked(mock_aws_provider: AWSProvider) -> None:
    """Trail bucket with public access blocked - no finding."""
    s3 = mock_aws_provider.session.client("s3", region_name="eu-central-1")
    s3.create_bucket(
        Bucket="audit-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    s3.put_public_access_block(
        Bucket="audit-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    ct = mock_aws_provider.session.client("cloudtrail", region_name="eu-central-1")
    ct.create_trail(Name="test-trail", S3BucketName="audit-bucket")

    result = check_cloudtrail_bucket_public(mock_aws_provider)
    assert result.resources_scanned >= 1
    assert len(result.findings) == 0


def test_cloudtrail_bucket_public_open(mock_aws_provider: AWSProvider) -> None:
    """Trail bucket without public access block - CRITICAL finding."""
    s3 = mock_aws_provider.session.client("s3", region_name="eu-central-1")
    s3.create_bucket(
        Bucket="open-audit-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    ct = mock_aws_provider.session.client("cloudtrail", region_name="eu-central-1")
    ct.create_trail(Name="test-trail", S3BucketName="open-audit-bucket")

    result = check_cloudtrail_bucket_public(mock_aws_provider)
    assert result.resources_scanned >= 1
    assert len(result.findings) >= 1
    assert result.findings[0].severity.value == "critical"
    assert result.findings[0].compliance_refs == ["CIS 3.3"]
