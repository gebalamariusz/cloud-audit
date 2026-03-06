"""S3 security and cost checks."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def _tf_name(name: str) -> str:
    """Sanitize a resource name for use as a Terraform identifier."""
    sanitized = name.replace(".", "_").replace("-", "_")
    if sanitized and sanitized[0].isdigit():
        sanitized = f"bucket_{sanitized}"
    return sanitized


def _s3_public_access_remediation(name: str) -> Remediation:
    return Remediation(
        cli=(
            f"aws s3api put-public-access-block --bucket {name} "
            f"--public-access-block-configuration "
            f"BlockPublicAcls=true,IgnorePublicAcls=true,"
            f"BlockPublicPolicy=true,RestrictPublicBuckets=true"
        ),
        terraform=(
            f'resource "aws_s3_bucket_public_access_block" "{_tf_name(name)}" {{\n'
            f'  bucket                  = "{name}"\n'
            f"  block_public_acls       = true\n"
            f"  ignore_public_acls      = true\n"
            f"  block_public_policy     = true\n"
            f"  restrict_public_buckets = true\n"
            f"}}"
        ),
        doc_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        effort=Effort.LOW,
    )


_bucket_cache: list[Any] | None = None


def _reset_bucket_cache() -> None:
    """Reset the bucket list cache (called between scans and in tests)."""
    global _bucket_cache  # noqa: PLW0603
    _bucket_cache = None


def _list_buckets(provider: AWSProvider) -> list[Any]:
    """Fetch S3 bucket list once per scan (module-level cache)."""
    global _bucket_cache  # noqa: PLW0603
    if _bucket_cache is None:
        s3 = provider.session.client("s3")
        _bucket_cache = s3.list_buckets()["Buckets"]
    return _bucket_cache


def check_public_buckets(provider: AWSProvider) -> CheckResult:
    """Check for S3 buckets with public access."""
    s3 = provider.session.client("s3")
    result = CheckResult(check_id="aws-s3-001", check_name="Public S3 buckets")

    try:
        buckets = _list_buckets(provider)
        for bucket in buckets:
            name = bucket["Name"]
            result.resources_scanned += 1

            try:
                public_access = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                all_blocked = all(
                    [
                        public_access.get("BlockPublicAcls", False),
                        public_access.get("IgnorePublicAcls", False),
                        public_access.get("BlockPublicPolicy", False),
                        public_access.get("RestrictPublicBuckets", False),
                    ]
                )
                if not all_blocked:
                    result.findings.append(
                        Finding(
                            check_id="aws-s3-001",
                            title=f"S3 bucket '{name}' does not block all public access",
                            severity=Severity.HIGH,
                            category=Category.SECURITY,
                            resource_type="AWS::S3::Bucket",
                            resource_id=name,
                            description=f"Bucket '{name}' has incomplete public access block configuration.",
                            recommendation="Enable all four public access block settings unless the bucket explicitly needs public access.",
                            remediation=_s3_public_access_remediation(name),
                            compliance_refs=["CIS 2.1.5"],
                        )
                    )
            except Exception as exc:
                error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if error_code == "NoSuchPublicAccessBlockConfiguration":
                    # No public access block configured at all
                    result.findings.append(
                        Finding(
                            check_id="aws-s3-001",
                            title=f"S3 bucket '{name}' has no public access block",
                            severity=Severity.HIGH,
                            category=Category.SECURITY,
                            resource_type="AWS::S3::Bucket",
                            resource_id=name,
                            description=f"Bucket '{name}' does not have a public access block configuration.",
                            recommendation="Add a public access block to the bucket with all four settings enabled.",
                            remediation=_s3_public_access_remediation(name),
                            compliance_refs=["CIS 2.1.5"],
                        )
                    )
                # AccessDenied or other errors: skip (don't produce false positive)
    except Exception as e:
        result.error = str(e)

    return result


def check_bucket_encryption(provider: AWSProvider) -> CheckResult:
    """Check if S3 buckets have default encryption enabled."""
    s3 = provider.session.client("s3")
    result = CheckResult(check_id="aws-s3-002", check_name="S3 bucket encryption")

    try:
        buckets = _list_buckets(provider)
        for bucket in buckets:
            name = bucket["Name"]
            result.resources_scanned += 1

            try:
                s3.get_bucket_encryption(Bucket=name)
            except s3.exceptions.ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                    result.findings.append(
                        Finding(
                            check_id="aws-s3-002",
                            title=f"S3 bucket '{name}' has no default encryption",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            resource_type="AWS::S3::Bucket",
                            resource_id=name,
                            description=f"Bucket '{name}' does not have default server-side encryption configured.",
                            recommendation="Enable default encryption with SSE-S3 (AES-256) or SSE-KMS.",
                            remediation=Remediation(
                                cli=(
                                    f"aws s3api put-bucket-encryption --bucket {name} "
                                    f"--server-side-encryption-configuration "
                                    f'\'{{"Rules":[{{"ApplyServerSideEncryptionByDefault":{{"SSEAlgorithm":"AES256"}}}}]}}\''
                                ),
                                terraform=(
                                    f'resource "aws_s3_bucket_server_side_encryption_configuration" "{_tf_name(name)}" {{\n'
                                    f'  bucket = "{name}"\n'
                                    f"  rule {{\n"
                                    f"    apply_server_side_encryption_by_default {{\n"
                                    f'      sse_algorithm = "AES256"\n'
                                    f"    }}\n"
                                    f"  }}\n"
                                    f"}}"
                                ),
                                doc_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
                                effort=Effort.LOW,
                            ),
                            compliance_refs=["CIS 2.1.1"],
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def check_bucket_versioning(provider: AWSProvider) -> CheckResult:
    """Check if S3 buckets have versioning enabled."""
    s3 = provider.session.client("s3")
    result = CheckResult(check_id="aws-s3-003", check_name="S3 bucket versioning")

    try:
        buckets = _list_buckets(provider)
        for bucket in buckets:
            name = bucket["Name"]
            result.resources_scanned += 1

            versioning = s3.get_bucket_versioning(Bucket=name)
            status = versioning.get("Status", "Disabled")

            if status != "Enabled":
                result.findings.append(
                    Finding(
                        check_id="aws-s3-003",
                        title=f"S3 bucket '{name}' does not have versioning enabled",
                        severity=Severity.LOW,
                        category=Category.RELIABILITY,
                        resource_type="AWS::S3::Bucket",
                        resource_id=name,
                        description=f"Bucket '{name}' versioning is '{status}'. Without versioning, deleted or overwritten objects cannot be recovered.",
                        recommendation="Enable versioning to protect against accidental deletion or overwrites.",
                        remediation=Remediation(
                            cli=f"aws s3api put-bucket-versioning --bucket {name} --versioning-configuration Status=Enabled",
                            terraform=(
                                f'resource "aws_s3_bucket_versioning" "{_tf_name(name)}" {{\n'
                                f'  bucket = "{name}"\n'
                                f"  versioning_configuration {{\n"
                                f'    status = "Enabled"\n'
                                f"  }}\n"
                                f"}}"
                            ),
                            doc_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
                            effort=Effort.LOW,
                        ),
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def _lifecycle_remediation(name: str) -> Remediation:
    """Build remediation for missing/disabled lifecycle rules."""
    return Remediation(
        cli=(
            f"aws s3api put-bucket-lifecycle-configuration --bucket {name} "
            f"--lifecycle-configuration '{{"
            f'"Rules":[{{"ID":"auto-archive","Status":"Enabled",'
            f'"Transitions":[{{"Days":90,"StorageClass":"GLACIER"}}],'
            f'"Filter":{{"Prefix":""}}}}]}}\''
        ),
        terraform=(
            f'resource "aws_s3_bucket_lifecycle_configuration" "{_tf_name(name)}" {{\n'
            f'  bucket = "{name}"\n'
            f"  rule {{\n"
            f'    id     = "auto-archive"\n'
            f'    status = "Enabled"\n'
            f"    transition {{\n"
            f"      days          = 90\n"
            f'      storage_class = "GLACIER"\n'
            f"    }}\n"
            f"  }}\n"
            f"}}"
        ),
        doc_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html",
        effort=Effort.LOW,
    )


def check_bucket_lifecycle(provider: AWSProvider) -> CheckResult:
    """Check if S3 buckets have lifecycle rules configured."""
    s3 = provider.session.client("s3")
    result = CheckResult(check_id="aws-s3-004", check_name="S3 bucket lifecycle policy")

    try:
        buckets = _list_buckets(provider)
        for bucket in buckets:
            name = bucket["Name"]
            result.resources_scanned += 1

            try:
                lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=name)
                rules = lifecycle.get("Rules", [])
                has_enabled = any(r.get("Status") == "Enabled" for r in rules)
                if not has_enabled:
                    result.findings.append(
                        Finding(
                            check_id="aws-s3-004",
                            title=f"S3 bucket '{name}' has no active lifecycle rules",
                            severity=Severity.LOW,
                            category=Category.COST,
                            resource_type="AWS::S3::Bucket",
                            resource_id=name,
                            description=f"Bucket '{name}' has lifecycle rules but none are enabled. Old or incomplete objects accumulate cost.",
                            recommendation="Enable lifecycle rules to transition or expire objects automatically.",
                            remediation=_lifecycle_remediation(name),
                        )
                    )
            except Exception as exc:
                error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if error_code == "NoSuchLifecycleConfiguration":
                    result.findings.append(
                        Finding(
                            check_id="aws-s3-004",
                            title=f"S3 bucket '{name}' has no lifecycle policy",
                            severity=Severity.LOW,
                            category=Category.COST,
                            resource_type="AWS::S3::Bucket",
                            resource_id=name,
                            description=f"Bucket '{name}' has no lifecycle configuration. Objects never expire or transition to cheaper storage.",
                            recommendation="Add lifecycle rules to transition old objects to Glacier or expire them.",
                            remediation=_lifecycle_remediation(name),
                        )
                    )
                else:
                    continue
    except Exception as e:
        result.error = str(e)

    return result


def check_access_logging(provider: AWSProvider) -> CheckResult:
    """Check if S3 buckets have server access logging enabled."""
    s3 = provider.session.client("s3")
    result = CheckResult(check_id="aws-s3-005", check_name="S3 access logging")

    try:
        buckets = _list_buckets(provider)
        for bucket in buckets:
            name = bucket["Name"]
            result.resources_scanned += 1

            try:
                logging_config = s3.get_bucket_logging(Bucket=name)
                if "LoggingEnabled" not in logging_config:
                    result.findings.append(
                        Finding(
                            check_id="aws-s3-005",
                            title=f"S3 bucket '{name}' does not have access logging enabled",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            resource_type="AWS::S3::Bucket",
                            resource_id=name,
                            description=f"Bucket '{name}' has no server access logging. Access attempts are not being recorded.",
                            recommendation="Enable server access logging to track requests to the bucket.",
                            remediation=Remediation(
                                cli=(
                                    f"aws s3api put-bucket-logging --bucket {name} "
                                    f"--bucket-logging-status '{{"
                                    f'"LoggingEnabled":{{"TargetBucket":"{name}-logs","TargetPrefix":"access-logs/"}}}}\''
                                ),
                                terraform=(
                                    f'resource "aws_s3_bucket_logging" "{_tf_name(name)}" {{\n'
                                    f'  bucket        = "{name}"\n'
                                    f'  target_bucket = "{name}-logs"\n'
                                    f'  target_prefix = "access-logs/"\n'
                                    f"}}"
                                ),
                                doc_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html",
                                effort=Effort.LOW,
                            ),
                        )
                    )
            except Exception:
                continue
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all S3 checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_public_buckets, provider, check_id="aws-s3-001", category=Category.SECURITY),
        make_check(check_bucket_encryption, provider, check_id="aws-s3-002", category=Category.SECURITY),
        make_check(check_bucket_versioning, provider, check_id="aws-s3-003", category=Category.RELIABILITY),
        make_check(check_bucket_lifecycle, provider, check_id="aws-s3-004", category=Category.COST),
        make_check(check_access_logging, provider, check_id="aws-s3-005", category=Category.SECURITY),
    ]
