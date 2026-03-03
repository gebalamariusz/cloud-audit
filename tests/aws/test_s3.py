"""Tests for S3 security checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.s3 import (
    check_bucket_encryption,
    check_bucket_versioning,
    check_public_buckets,
)

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


def test_public_buckets_pass(mock_aws_provider: AWSProvider) -> None:
    """Bucket with full public access block - no findings."""
    s3 = mock_aws_provider.session.client("s3")
    s3.create_bucket(
        Bucket="secure-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    s3.put_public_access_block(
        Bucket="secure-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    result = check_public_buckets(mock_aws_provider)
    assert result.resources_scanned >= 1
    public_findings = [f for f in result.findings if f.resource_id == "secure-bucket"]
    assert len(public_findings) == 0


def test_public_buckets_fail(mock_aws_provider: AWSProvider) -> None:
    """Bucket without public access block - HIGH finding."""
    s3 = mock_aws_provider.session.client("s3")
    s3.create_bucket(
        Bucket="open-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    # No public access block set
    result = check_public_buckets(mock_aws_provider)
    open_findings = [f for f in result.findings if f.resource_id == "open-bucket"]
    assert len(open_findings) >= 1
    assert open_findings[0].severity.value == "high"
    assert open_findings[0].remediation is not None
    assert "put-public-access-block" in open_findings[0].remediation.cli
    assert open_findings[0].compliance_refs == ["CIS 2.1.5"]


def test_bucket_encryption_pass(mock_aws_provider: AWSProvider) -> None:
    """Bucket with encryption - no finding."""
    s3 = mock_aws_provider.session.client("s3")
    s3.create_bucket(
        Bucket="encrypted-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    s3.put_bucket_encryption(
        Bucket="encrypted-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    result = check_bucket_encryption(mock_aws_provider)
    enc_findings = [f for f in result.findings if f.resource_id == "encrypted-bucket"]
    assert len(enc_findings) == 0


def test_bucket_versioning_pass(mock_aws_provider: AWSProvider) -> None:
    """Bucket with versioning - no finding."""
    s3 = mock_aws_provider.session.client("s3")
    s3.create_bucket(
        Bucket="versioned-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    s3.put_bucket_versioning(
        Bucket="versioned-bucket",
        VersioningConfiguration={"Status": "Enabled"},
    )
    result = check_bucket_versioning(mock_aws_provider)
    ver_findings = [f for f in result.findings if f.resource_id == "versioned-bucket"]
    assert len(ver_findings) == 0


def test_bucket_versioning_fail(mock_aws_provider: AWSProvider) -> None:
    """Bucket without versioning - LOW finding."""
    s3 = mock_aws_provider.session.client("s3")
    s3.create_bucket(
        Bucket="unversioned-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    result = check_bucket_versioning(mock_aws_provider)
    ver_findings = [f for f in result.findings if f.resource_id == "unversioned-bucket"]
    assert len(ver_findings) == 1
    assert ver_findings[0].severity.value == "low"
    assert ver_findings[0].remediation is not None
    assert "put-bucket-versioning" in ver_findings[0].remediation.cli
