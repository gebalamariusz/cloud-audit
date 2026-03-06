"""CloudTrail visibility checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_cloudtrail_enabled(provider: AWSProvider) -> CheckResult:
    """Check if CloudTrail is enabled with multi-region logging."""
    result = CheckResult(check_id="aws-ct-001", check_name="CloudTrail enabled")

    try:
        ct = provider.session.client("cloudtrail", region_name=provider.regions[0])
        trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
        result.resources_scanned = 1

        multi_region = any(t.get("IsMultiRegionTrail", False) for t in trails)

        if not trails:
            result.findings.append(
                Finding(
                    check_id="aws-ct-001",
                    title="No CloudTrail trails configured",
                    severity=Severity.CRITICAL,
                    category=Category.SECURITY,
                    resource_type="AWS::CloudTrail::Trail",
                    resource_id="none",
                    description="No CloudTrail trails exist. All API activity is unmonitored.",
                    recommendation="Create a multi-region CloudTrail trail immediately.",
                    remediation=Remediation(
                        cli=(
                            "aws cloudtrail create-trail "
                            "--name main-trail "
                            "--s3-bucket-name YOUR-AUDIT-BUCKET "
                            "--is-multi-region-trail "
                            "--enable-log-file-validation\n"
                            "aws cloudtrail start-logging --name main-trail"
                        ),
                        terraform=(
                            'resource "aws_cloudtrail" "main" {\n'
                            '  name                          = "main-trail"\n'
                            "  s3_bucket_name                = aws_s3_bucket.audit.id\n"
                            "  is_multi_region_trail         = true\n"
                            "  enable_log_file_validation    = true\n"
                            "  include_global_service_events = true\n"
                            "}"
                        ),
                        doc_url="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html",
                        effort=Effort.MEDIUM,
                    ),
                    compliance_refs=["CIS 3.1"],
                )
            )
        elif not multi_region:
            trail_name = trails[0].get("Name", "unknown")
            result.findings.append(
                Finding(
                    check_id="aws-ct-001",
                    title=f"CloudTrail '{trail_name}' is not multi-region",
                    severity=Severity.HIGH,
                    category=Category.SECURITY,
                    resource_type="AWS::CloudTrail::Trail",
                    resource_id=trail_name,
                    description=(
                        f"Trail '{trail_name}' only logs events in its home region. "
                        "Activity in other regions goes unmonitored."
                    ),
                    recommendation="Enable multi-region logging on the trail.",
                    remediation=Remediation(
                        cli=(f"aws cloudtrail update-trail --name {trail_name} --is-multi-region-trail"),
                        terraform=('resource "aws_cloudtrail" "main" {\n  # ...\n  is_multi_region_trail = true\n}'),
                        doc_url="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html",
                        effort=Effort.LOW,
                    ),
                    compliance_refs=["CIS 3.1"],
                )
            )
    except Exception as e:
        result.error = str(e)

    return result


def check_cloudtrail_log_validation(provider: AWSProvider) -> CheckResult:
    """Check if CloudTrail log file validation is enabled."""
    result = CheckResult(check_id="aws-ct-002", check_name="CloudTrail log validation")

    try:
        ct = provider.session.client("cloudtrail", region_name=provider.regions[0])
        trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
        # Deduplicate by trail ARN (shadow trails appear in multiple regions)
        seen_arns: set[str] = set()

        for trail in trails:
            trail_arn = trail.get("TrailARN", "")
            if trail_arn in seen_arns:
                continue
            seen_arns.add(trail_arn)
            trail_name = trail.get("Name", "unknown")
            result.resources_scanned += 1

            if not trail.get("LogFileValidationEnabled", False):
                result.findings.append(
                    Finding(
                        check_id="aws-ct-002",
                        title=f"CloudTrail '{trail_name}' has log validation disabled",
                        severity=Severity.HIGH,
                        category=Category.SECURITY,
                        resource_type="AWS::CloudTrail::Trail",
                        resource_id=trail_name,
                        description=(
                            f"Trail '{trail_name}' does not validate log file integrity. "
                            "An attacker could modify or delete logs without detection."
                        ),
                        recommendation="Enable log file validation on the trail.",
                        remediation=Remediation(
                            cli=(f"aws cloudtrail update-trail --name {trail_name} --enable-log-file-validation"),
                            terraform=(
                                'resource "aws_cloudtrail" "main" {\n  # ...\n  enable_log_file_validation = true\n}'
                            ),
                            doc_url="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html",
                            effort=Effort.LOW,
                        ),
                        compliance_refs=["CIS 3.2"],
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def check_cloudtrail_bucket_public(provider: AWSProvider) -> CheckResult:
    """Check if CloudTrail S3 bucket is not publicly accessible."""
    result = CheckResult(check_id="aws-ct-003", check_name="CloudTrail S3 bucket public")

    try:
        ct = provider.session.client("cloudtrail", region_name=provider.regions[0])
        s3 = provider.session.client("s3")
        trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
        seen_arns: set[str] = set()

        for trail in trails:
            trail_arn = trail.get("TrailARN", "")
            if trail_arn in seen_arns:
                continue
            seen_arns.add(trail_arn)
            bucket_name = trail.get("S3BucketName")
            trail_name = trail.get("Name", "unknown")
            if not bucket_name:
                continue
            result.resources_scanned += 1

            try:
                public_access = s3.get_public_access_block(Bucket=bucket_name)
                config = public_access["PublicAccessBlockConfiguration"]
                all_blocked = (
                    config.get("BlockPublicAcls", False)
                    and config.get("IgnorePublicAcls", False)
                    and config.get("BlockPublicPolicy", False)
                    and config.get("RestrictPublicBuckets", False)
                )
            except Exception as exc:
                error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if error_code == "NoSuchPublicAccessBlockConfiguration":
                    all_blocked = False
                else:
                    # Bucket might not exist or we don't have access
                    continue

            if not all_blocked:
                result.findings.append(
                    Finding(
                        check_id="aws-ct-003",
                        title=f"CloudTrail bucket '{bucket_name}' lacks public access block",
                        severity=Severity.CRITICAL,
                        category=Category.SECURITY,
                        resource_type="AWS::S3::Bucket",
                        resource_id=bucket_name,
                        description=(
                            f"The S3 bucket '{bucket_name}' used by trail '{trail_name}' "
                            "does not have all public access blocks enabled. "
                            "CloudTrail logs could be exposed publicly."
                        ),
                        recommendation="Enable all public access blocks on the CloudTrail bucket.",
                        remediation=Remediation(
                            cli=(
                                f"aws s3api put-public-access-block "
                                f"--bucket {bucket_name} "
                                f"--public-access-block-configuration "
                                f"BlockPublicAcls=true,"
                                f"IgnorePublicAcls=true,"
                                f"BlockPublicPolicy=true,"
                                f"RestrictPublicBuckets=true"
                            ),
                            terraform=(
                                f'resource "aws_s3_bucket_public_access_block" "{bucket_name}" {{\n'
                                f"  bucket                  = aws_s3_bucket.cloudtrail.id\n"
                                f"  block_public_acls       = true\n"
                                f"  ignore_public_acls      = true\n"
                                f"  block_public_policy     = true\n"
                                f"  restrict_public_buckets = true\n"
                                f"}}"
                            ),
                            doc_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                            effort=Effort.LOW,
                        ),
                        compliance_refs=["CIS 3.3"],
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all CloudTrail checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_cloudtrail_enabled, provider, check_id="aws-ct-001", category=Category.SECURITY),
        make_check(check_cloudtrail_log_validation, provider, check_id="aws-ct-002", category=Category.SECURITY),
        make_check(check_cloudtrail_bucket_public, provider, check_id="aws-ct-003", category=Category.SECURITY),
    ]
