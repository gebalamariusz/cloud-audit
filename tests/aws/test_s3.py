"""Tests for S3 security checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.s3 import (
    check_access_logging,
    check_bucket_encryption,
    check_bucket_lifecycle,
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


def test_bucket_encryption_kms_pass(mock_aws_provider: AWSProvider) -> None:
    """Bucket with SSE-KMS encryption - no finding."""
    s3 = mock_aws_provider.session.client("s3")
    s3.create_bucket(
        Bucket="kms-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    s3.put_bucket_encryption(
        Bucket="kms-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
        },
    )
    result = check_bucket_encryption(mock_aws_provider)
    enc_findings = [f for f in result.findings if f.resource_id == "kms-bucket"]
    assert len(enc_findings) == 0


def test_bucket_encryption_sse_s3_low(mock_aws_provider: AWSProvider) -> None:
    """Bucket with SSE-S3 (AES256) - LOW finding recommending SSE-KMS."""
    s3 = mock_aws_provider.session.client("s3")
    s3.create_bucket(
        Bucket="sse-s3-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    s3.put_bucket_encryption(
        Bucket="sse-s3-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    result = check_bucket_encryption(mock_aws_provider)
    enc_findings = [f for f in result.findings if f.resource_id == "sse-s3-bucket"]
    assert len(enc_findings) == 1
    assert enc_findings[0].severity.value == "low"
    assert "SSE-KMS" in enc_findings[0].title
    assert enc_findings[0].remediation is not None
    assert "aws:kms" in enc_findings[0].remediation.cli
    assert enc_findings[0].compliance_refs == ["CIS 2.1.1"]


def test_bucket_encryption_dsse_kms_pass(mock_aws_provider: AWSProvider) -> None:
    """Bucket with DSSE-KMS (dual-layer) encryption - no finding."""
    s3 = mock_aws_provider.session.client("s3")
    s3.create_bucket(
        Bucket="dsse-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    s3.put_bucket_encryption(
        Bucket="dsse-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms:dsse"}}]
        },
    )
    result = check_bucket_encryption(mock_aws_provider)
    enc_findings = [f for f in result.findings if f.resource_id == "dsse-bucket"]
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


def test_bucket_lifecycle_pass(mock_aws_provider: AWSProvider) -> None:
    """Unversioned bucket with full lifecycle (transition + AbortMPU) - no finding."""
    s3 = mock_aws_provider.session.client("s3")
    s3.create_bucket(
        Bucket="lifecycle-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    s3.put_bucket_lifecycle_configuration(
        Bucket="lifecycle-bucket",
        LifecycleConfiguration={
            "Rules": [
                {
                    "ID": "archive",
                    "Status": "Enabled",
                    "Filter": {"Prefix": ""},
                    "Transitions": [{"Days": 90, "StorageClass": "GLACIER"}],
                    "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
                }
            ]
        },
    )
    result = check_bucket_lifecycle(mock_aws_provider)
    findings = [f for f in result.findings if f.resource_id == "lifecycle-bucket"]
    assert len(findings) == 0


def test_bucket_lifecycle_fail(mock_aws_provider: AWSProvider) -> None:
    """Unversioned bucket without lifecycle rules - LOW finding."""
    s3 = mock_aws_provider.session.client("s3")
    s3.create_bucket(
        Bucket="no-lifecycle-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    result = check_bucket_lifecycle(mock_aws_provider)
    findings = [f for f in result.findings if f.resource_id == "no-lifecycle-bucket"]
    assert len(findings) == 1
    assert findings[0].severity.value == "low"
    assert findings[0].category.value == "cost"
    assert findings[0].region == "global"


def test_bucket_lifecycle_versioned_without_ncve_medium(mock_aws_provider: AWSProvider) -> None:
    """Versioning-enabled bucket with no lifecycle - MEDIUM (storage runaway)."""
    s3 = mock_aws_provider.session.client("s3")
    s3.create_bucket(
        Bucket="versioned-no-lifecycle",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    s3.put_bucket_versioning(
        Bucket="versioned-no-lifecycle",
        VersioningConfiguration={"Status": "Enabled"},
    )

    result = check_bucket_lifecycle(mock_aws_provider)
    findings = [f for f in result.findings if f.resource_id == "versioned-no-lifecycle"]
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"
    assert "noncurrent" in findings[0].title.lower()


def test_bucket_lifecycle_versioned_with_ncve_passes(mock_aws_provider: AWSProvider) -> None:
    """Versioning-enabled bucket with NCVE + AbortMPU lifecycle rule - no finding."""
    s3 = mock_aws_provider.session.client("s3")
    s3.create_bucket(
        Bucket="versioned-with-ncve",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    s3.put_bucket_versioning(
        Bucket="versioned-with-ncve",
        VersioningConfiguration={"Status": "Enabled"},
    )
    s3.put_bucket_lifecycle_configuration(
        Bucket="versioned-with-ncve",
        LifecycleConfiguration={
            "Rules": [
                {
                    "ID": "expire-noncurrent",
                    "Status": "Enabled",
                    "Filter": {"Prefix": ""},
                    "NoncurrentVersionExpiration": {"NoncurrentDays": 90},
                    "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
                }
            ]
        },
    )

    result = check_bucket_lifecycle(mock_aws_provider)
    findings = [f for f in result.findings if f.resource_id == "versioned-with-ncve"]
    assert len(findings) == 0


def test_bucket_lifecycle_versioned_rules_without_ncve_medium(
    mock_aws_provider: AWSProvider,
) -> None:
    """Versioning-enabled bucket with lifecycle but missing NCVE - MEDIUM finding."""
    s3 = mock_aws_provider.session.client("s3")
    s3.create_bucket(
        Bucket="versioned-rules-no-ncve",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    s3.put_bucket_versioning(
        Bucket="versioned-rules-no-ncve",
        VersioningConfiguration={"Status": "Enabled"},
    )
    # Rule with transitions and AbortMPU but no NoncurrentVersionExpiration
    s3.put_bucket_lifecycle_configuration(
        Bucket="versioned-rules-no-ncve",
        LifecycleConfiguration={
            "Rules": [
                {
                    "ID": "archive-only",
                    "Status": "Enabled",
                    "Filter": {"Prefix": ""},
                    "Transitions": [{"Days": 90, "StorageClass": "GLACIER"}],
                    "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
                }
            ]
        },
    )

    result = check_bucket_lifecycle(mock_aws_provider)
    findings = [f for f in result.findings if f.resource_id == "versioned-rules-no-ncve"]
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"
    assert "NoncurrentVersionExpiration" in findings[0].title


def test_bucket_lifecycle_missing_abort_mpu_low(mock_aws_provider: AWSProvider) -> None:
    """Unversioned bucket with lifecycle but no AbortMPU - LOW finding."""
    s3 = mock_aws_provider.session.client("s3")
    s3.create_bucket(
        Bucket="no-abort-mpu-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    # Rule with transition but no AbortMPU
    s3.put_bucket_lifecycle_configuration(
        Bucket="no-abort-mpu-bucket",
        LifecycleConfiguration={
            "Rules": [
                {
                    "ID": "archive-only",
                    "Status": "Enabled",
                    "Filter": {"Prefix": ""},
                    "Transitions": [{"Days": 90, "StorageClass": "GLACIER"}],
                }
            ]
        },
    )

    result = check_bucket_lifecycle(mock_aws_provider)
    findings = [f for f in result.findings if f.resource_id == "no-abort-mpu-bucket"]
    assert len(findings) == 1
    assert findings[0].severity.value == "low"
    assert "AbortIncompleteMultipartUpload" in findings[0].title


def test_access_logging_pass(mock_aws_provider: AWSProvider) -> None:
    """Bucket with access logging - no finding."""
    s3 = mock_aws_provider.session.client("s3")
    s3.create_bucket(
        Bucket="logged-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    s3.create_bucket(
        Bucket="logged-bucket-logs",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    # Grant log-delivery group write access (required by moto)
    s3.put_bucket_acl(Bucket="logged-bucket-logs", ACL="log-delivery-write")
    s3.put_bucket_logging(
        Bucket="logged-bucket",
        BucketLoggingStatus={
            "LoggingEnabled": {
                "TargetBucket": "logged-bucket-logs",
                "TargetPrefix": "access-logs/",
            }
        },
    )
    result = check_access_logging(mock_aws_provider)
    findings = [f for f in result.findings if f.resource_id == "logged-bucket"]
    assert len(findings) == 0


def test_access_logging_fail(mock_aws_provider: AWSProvider) -> None:
    """Bucket without access logging - MEDIUM finding."""
    s3 = mock_aws_provider.session.client("s3")
    s3.create_bucket(
        Bucket="unlogged-bucket",
        CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
    )
    result = check_access_logging(mock_aws_provider)
    findings = [f for f in result.findings if f.resource_id == "unlogged-bucket"]
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"
    assert findings[0].remediation is not None
