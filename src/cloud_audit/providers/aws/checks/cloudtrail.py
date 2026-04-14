"""CloudTrail visibility checks."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn

# Module-level trail cache (reset between scans via _reset_trail_cache)
_trail_cache: list[Any] | None = None
_trail_lock = __import__("threading").Lock()


def _reset_trail_cache() -> None:
    """Reset the trail cache. Called between scans in tests."""
    global _trail_cache
    with _trail_lock:
        _trail_cache = None


def _list_trails(provider: AWSProvider) -> list[Any]:
    """Fetch CloudTrail trails once per scan (module-level cache, thread-safe)."""
    global _trail_cache
    with _trail_lock:
        if _trail_cache is None:
            ct = provider.session.client("cloudtrail", region_name=provider.regions[0])
            _trail_cache = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
        return _trail_cache


def check_cloudtrail_enabled(provider: AWSProvider) -> CheckResult:
    """Check if CloudTrail is enabled with multi-region logging."""
    result = CheckResult(check_id="aws-ct-001", check_name="CloudTrail enabled")

    try:
        trails = _list_trails(provider)
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
                            "# Create S3 bucket for CloudTrail logs first:\n"
                            "aws s3api create-bucket --bucket YOUR-AUDIT-BUCKET "
                            "--region us-east-1\n"
                            "aws cloudtrail create-trail "
                            "--name main-trail "
                            "--s3-bucket-name YOUR-AUDIT-BUCKET "
                            "--is-multi-region-trail "
                            "--enable-log-file-validation\n"
                            "aws cloudtrail start-logging --name main-trail"
                        ),
                        terraform=(
                            'resource "aws_s3_bucket" "audit" {\n'
                            '  bucket = "YOUR-ORG-cloudtrail-logs"  # Choose a unique name\n'
                            "}\n"
                            "\n"
                            'resource "aws_s3_bucket_policy" "audit" {\n'
                            "  bucket = aws_s3_bucket.audit.id\n"
                            "  policy = jsonencode({\n"
                            '    Version = "2012-10-17"\n'
                            "    Statement = [\n"
                            "      {\n"
                            '        Sid       = "AWSCloudTrailAclCheck"\n'
                            '        Effect    = "Allow"\n'
                            '        Principal = { Service = "cloudtrail.amazonaws.com" }\n'
                            '        Action    = "s3:GetBucketAcl"\n'
                            "        Resource  = aws_s3_bucket.audit.arn\n"
                            "      },\n"
                            "      {\n"
                            '        Sid       = "AWSCloudTrailWrite"\n'
                            '        Effect    = "Allow"\n'
                            '        Principal = { Service = "cloudtrail.amazonaws.com" }\n'
                            '        Action    = "s3:PutObject"\n'
                            '        Resource  = "${aws_s3_bucket.audit.arn}/*"\n'
                            '        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }\n'
                            "      }\n"
                            "    ]\n"
                            "  })\n"
                            "}\n"
                            "\n"
                            'resource "aws_cloudtrail" "main" {\n'
                            '  name                          = "main-trail"\n'
                            "  s3_bucket_name                = aws_s3_bucket.audit.id\n"
                            "  is_multi_region_trail         = true\n"
                            "  enable_log_file_validation    = true\n"
                            "  include_global_service_events = true\n"
                            "\n"
                            "  depends_on = [aws_s3_bucket_policy.audit]\n"
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
        trails = _list_trails(provider)
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
        s3 = provider.session.client("s3")
        trails = _list_trails(provider)
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
                        compliance_refs=[],  # CIS 3.3 was removed in v3.0; this is a security best practice check
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def check_cloudtrail_kms_encryption(provider: AWSProvider) -> CheckResult:
    """Check if CloudTrail logs are encrypted with KMS CMK (CIS 3.5)."""
    result = CheckResult(check_id="aws-ct-005", check_name="CloudTrail KMS encryption")

    try:
        account_id = provider.get_account_id()
        region = provider.regions[0]
        trails = _list_trails(provider)
        seen_arns: set[str] = set()

        for trail in trails:
            trail_arn = trail.get("TrailARN", "")
            if trail_arn in seen_arns:
                continue
            seen_arns.add(trail_arn)
            trail_name = trail.get("Name", "unknown")
            result.resources_scanned += 1

            if not trail.get("KmsKeyId"):
                result.findings.append(
                    Finding(
                        check_id="aws-ct-005",
                        title=f"CloudTrail '{trail_name}' is not encrypted with KMS",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        resource_type="AWS::CloudTrail::Trail",
                        resource_id=trail_name,
                        description=(
                            f"Trail '{trail_name}' does not use SSE-KMS encryption. "
                            f"Without KMS encryption, CloudTrail logs are encrypted with S3 "
                            f"default encryption (SSE-S3) which offers less control over key management."
                        ),
                        recommendation="Enable SSE-KMS encryption on the CloudTrail trail.",
                        remediation=Remediation(
                            cli=(
                                f"# Create a KMS key for CloudTrail, then enable:\n"
                                f"aws cloudtrail update-trail --name {trail_name} "
                                f"--kms-key-id arn:aws:kms:{region}:{account_id}:key/KEY_ID"
                            ),
                            terraform=(
                                'resource "aws_kms_key" "cloudtrail" {\n'
                                '  description = "KMS key for CloudTrail log encryption"\n'
                                "  enable_key_rotation = true\n"
                                "\n"
                                "  policy = jsonencode({\n"
                                '    Version = "2012-10-17"\n'
                                "    Statement = [\n"
                                "      {\n"
                                '        Sid       = "EnableRootAccountAccess"\n'
                                '        Effect    = "Allow"\n'
                                f'        Principal = {{ AWS = "arn:aws:iam::{account_id}:root" }}\n'
                                '        Action    = "kms:*"\n'
                                '        Resource  = "*"\n'
                                "      },\n"
                                "      {\n"
                                '        Sid       = "AllowCloudTrailEncrypt"\n'
                                '        Effect    = "Allow"\n'
                                '        Principal = { Service = "cloudtrail.amazonaws.com" }\n'
                                '        Action    = "kms:GenerateDataKey*"\n'
                                '        Resource  = "*"\n'
                                "      }\n"
                                "    ]\n"
                                "  })\n"
                                "}\n"
                                "\n"
                                f'resource "aws_cloudtrail" "main" {{\n'
                                f'  name       = "{trail_name}"\n'
                                "  # ...\n"
                                "  kms_key_id = aws_kms_key.cloudtrail.arn\n"
                                "}"
                            ),
                            doc_url="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html",
                            effort=Effort.MEDIUM,
                        ),
                        compliance_refs=["CIS 3.5"],
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def check_s3_object_write_logging(provider: AWSProvider) -> CheckResult:
    """Check if S3 object-level write events are logged in CloudTrail (CIS 3.8)."""
    result = CheckResult(check_id="aws-ct-006", check_name="S3 object-level write logging")

    try:
        ct = provider.session.client("cloudtrail", region_name=provider.regions[0])
        trails = _list_trails(provider)
        result.resources_scanned = 1

        has_s3_write_logging = False
        for trail in trails:
            if not trail.get("IsMultiRegionTrail", False):
                continue
            trail_arn = trail.get("TrailARN", "")
            try:
                selectors = ct.get_event_selectors(TrailName=trail_arn)
                # Check advanced event selectors first
                for aes in selectors.get("AdvancedEventSelectors", []):
                    fields = {fs.get("Field"): fs.get("Equals", []) for fs in aes.get("FieldSelectors", [])}
                    is_data = "Data" in fields.get("eventCategory", [])
                    is_s3 = "AWS::S3::Object" in fields.get("resources.type", [])
                    is_write = "false" in fields.get("readOnly", []) or "readOnly" not in fields
                    if is_data and is_s3 and is_write:
                        has_s3_write_logging = True
                        break
                # Check classic event selectors
                for es in selectors.get("EventSelectors", []):
                    for dr in es.get("DataResources", []):
                        if dr.get("Type") == "AWS::S3::Object" and es.get("ReadWriteType") in ("WriteOnly", "All"):
                            has_s3_write_logging = True
                            break
            except Exception:
                continue

        if not has_s3_write_logging:
            result.findings.append(
                Finding(
                    check_id="aws-ct-006",
                    title="S3 object-level write events are not logged in CloudTrail",
                    severity=Severity.MEDIUM,
                    category=Category.SECURITY,
                    resource_type="AWS::CloudTrail::Trail",
                    resource_id="s3-data-events",
                    description=(
                        "No multi-region CloudTrail trail is configured to log S3 object-level "
                        "write events (PutObject, DeleteObject, etc.). Without this, you cannot "
                        "detect unauthorized modifications to S3 data."
                    ),
                    recommendation="Enable S3 data event logging (write) on a multi-region trail.",
                    remediation=Remediation(
                        cli=(
                            "aws cloudtrail put-event-selectors --trail-name main-trail "
                            '--event-selectors \'[{"ReadWriteType":"WriteOnly","DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3"]}]}]\''
                        ),
                        terraform=(
                            'resource "aws_cloudtrail" "main" {\n'
                            "  # ...\n"
                            "  event_selector {\n"
                            '    read_write_type           = "WriteOnly"\n'
                            "    include_management_events = true\n"
                            "    data_resource {\n"
                            '      type   = "AWS::S3::Object"\n'
                            '      values = ["arn:aws:s3"]\n'
                            "    }\n"
                            "  }\n"
                            "}"
                        ),
                        doc_url="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html",
                        effort=Effort.LOW,
                    ),
                    compliance_refs=["CIS 3.8"],
                )
            )
    except Exception as e:
        result.error = str(e)

    return result


def check_s3_object_read_logging(provider: AWSProvider) -> CheckResult:
    """Check if S3 object-level read events are logged in CloudTrail (CIS 3.9)."""
    result = CheckResult(check_id="aws-ct-007", check_name="S3 object-level read logging")

    try:
        ct = provider.session.client("cloudtrail", region_name=provider.regions[0])
        trails = _list_trails(provider)
        result.resources_scanned = 1

        has_s3_read_logging = False
        for trail in trails:
            if not trail.get("IsMultiRegionTrail", False):
                continue
            trail_arn = trail.get("TrailARN", "")
            try:
                selectors = ct.get_event_selectors(TrailName=trail_arn)
                for aes in selectors.get("AdvancedEventSelectors", []):
                    fields = {fs.get("Field"): fs.get("Equals", []) for fs in aes.get("FieldSelectors", [])}
                    is_data = "Data" in fields.get("eventCategory", [])
                    is_s3 = "AWS::S3::Object" in fields.get("resources.type", [])
                    is_read = "true" in fields.get("readOnly", []) or "readOnly" not in fields
                    if is_data and is_s3 and is_read:
                        has_s3_read_logging = True
                        break
                for es in selectors.get("EventSelectors", []):
                    for dr in es.get("DataResources", []):
                        if dr.get("Type") == "AWS::S3::Object" and es.get("ReadWriteType") in ("ReadOnly", "All"):
                            has_s3_read_logging = True
                            break
            except Exception:
                continue

        if not has_s3_read_logging:
            result.findings.append(
                Finding(
                    check_id="aws-ct-007",
                    title="S3 object-level read events are not logged in CloudTrail",
                    severity=Severity.MEDIUM,
                    category=Category.SECURITY,
                    resource_type="AWS::CloudTrail::Trail",
                    resource_id="s3-data-events",
                    description=(
                        "No multi-region CloudTrail trail is configured to log S3 object-level "
                        "read events (GetObject). Without this, you cannot detect unauthorized "
                        "access to S3 data."
                    ),
                    recommendation="Enable S3 data event logging (read) on a multi-region trail.",
                    remediation=Remediation(
                        cli=(
                            "aws cloudtrail put-event-selectors --trail-name main-trail "
                            '--event-selectors \'[{"ReadWriteType":"ReadOnly","DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3"]}]}]\''
                        ),
                        terraform=(
                            'resource "aws_cloudtrail" "main" {\n'
                            "  # ...\n"
                            "  event_selector {\n"
                            '    read_write_type           = "ReadOnly"\n'
                            "    include_management_events = true\n"
                            "    data_resource {\n"
                            '      type   = "AWS::S3::Object"\n'
                            '      values = ["arn:aws:s3"]\n'
                            "    }\n"
                            "  }\n"
                            "}"
                        ),
                        doc_url="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html",
                        effort=Effort.LOW,
                    ),
                    compliance_refs=["CIS 3.9"],
                )
            )
    except Exception as e:
        result.error = str(e)

    return result


def check_cloudtrail_bucket_access_logging(provider: AWSProvider) -> CheckResult:
    """Check if CloudTrail S3 bucket has server access logging enabled (CIS 3.4)."""
    result = CheckResult(check_id="aws-ct-004", check_name="CloudTrail S3 bucket access logging")

    try:
        s3 = provider.session.client("s3")
        trails = _list_trails(provider)
        seen_buckets: set[str] = set()

        for trail in trails:
            bucket_name = trail.get("S3BucketName")
            trail_name = trail.get("Name", "unknown")
            if not bucket_name or bucket_name in seen_buckets:
                continue
            seen_buckets.add(bucket_name)
            result.resources_scanned += 1

            try:
                logging_config = s3.get_bucket_logging(Bucket=bucket_name)
                logging_enabled = "LoggingEnabled" in logging_config
            except Exception:
                # Bucket might not exist or we don't have access
                continue

            if not logging_enabled:
                result.findings.append(
                    Finding(
                        check_id="aws-ct-004",
                        title=f"CloudTrail bucket '{bucket_name}' has no access logging",
                        severity=Severity.HIGH,
                        category=Category.SECURITY,
                        resource_type="AWS::S3::Bucket",
                        resource_id=bucket_name,
                        description=(
                            f"The S3 bucket '{bucket_name}' used by trail '{trail_name}' "
                            "does not have server access logging enabled. "
                            "Without access logging, you cannot detect unauthorized "
                            "access to CloudTrail log files."
                        ),
                        recommendation="Enable server access logging on the CloudTrail S3 bucket.",
                        remediation=Remediation(
                            cli=(
                                f"# Create a logging bucket first (if needed):\n"
                                f"aws s3api create-bucket --bucket {bucket_name}-access-logs "
                                f"--region {provider.regions[0]}\n"
                                f"# Enable access logging:\n"
                                f"aws s3api put-bucket-logging --bucket {bucket_name} "
                                f"--bucket-logging-status '{{"
                                f'"LoggingEnabled": {{"TargetBucket": "{bucket_name}-access-logs", '
                                f'"TargetPrefix": "access-logs/"}}}}\''
                            ),
                            terraform=(
                                'resource "aws_s3_bucket_logging" "cloudtrail" {\n'
                                "  bucket        = aws_s3_bucket.cloudtrail.id\n"
                                "  target_bucket = aws_s3_bucket.access_logs.id\n"
                                '  target_prefix = "access-logs/"\n'
                                "}"
                            ),
                            doc_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html",
                            effort=Effort.LOW,
                        ),
                        compliance_refs=["CIS 3.4"],
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def check_cloudtrail_cloudwatch_logs(provider: AWSProvider) -> CheckResult:
    """Check if multi-region CloudTrail trails deliver logs to CloudWatch Logs."""
    result = CheckResult(check_id="aws-ct-008", check_name="CloudTrail CloudWatch Logs integration")

    try:
        account_id = provider.get_account_id()
        region = provider.regions[0]
        trails = _list_trails(provider)
        seen_arns: set[str] = set()

        for trail in trails:
            trail_arn = trail.get("TrailARN", "")
            if trail_arn in seen_arns:
                continue
            seen_arns.add(trail_arn)

            # Only check multi-region trails (the important ones)
            if not trail.get("IsMultiRegionTrail", False):
                continue

            trail_name = trail.get("Name", "unknown")
            result.resources_scanned += 1

            if not trail.get("CloudWatchLogsLogGroupArn"):
                result.findings.append(
                    Finding(
                        check_id="aws-ct-008",
                        title=f"CloudTrail '{trail_name}' does not deliver logs to CloudWatch",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        resource_type="AWS::CloudTrail::Trail",
                        resource_id=trail_name,
                        description=(
                            f"Multi-region trail '{trail_name}' does not have CloudWatch Logs "
                            "integration configured. Without CloudWatch Logs delivery, you cannot "
                            "create metric filters, alarms, or real-time alerts for suspicious "
                            "API activity detected by CloudTrail."
                        ),
                        recommendation="Configure the trail to deliver logs to a CloudWatch Logs log group.",
                        remediation=Remediation(
                            cli=(
                                f"# 1. Create log group:\n"
                                f"aws logs create-log-group --log-group-name cloudtrail-logs --region {region}\n"
                                f"# 2. Create IAM role (see doc_url for trust policy), then:\n"
                                f"aws cloudtrail update-trail \\\n"
                                f"  --name {trail_name} \\\n"
                                f"  --cloud-watch-logs-log-group-arn arn:aws:logs:{region}:{account_id}:log-group:cloudtrail-logs:* \\\n"
                                f"  --cloud-watch-logs-role-arn arn:aws:iam::{account_id}:role/cloudtrail-cloudwatch-role"
                            ),
                            terraform=(
                                'resource "aws_cloudwatch_log_group" "cloudtrail" {\n'
                                '  name              = "cloudtrail-logs"\n'
                                "  retention_in_days = 365\n"
                                "}\n"
                                "\n"
                                'resource "aws_iam_role" "cloudtrail_cloudwatch" {\n'
                                '  name = "cloudtrail-cloudwatch-role"\n'
                                "\n"
                                "  assume_role_policy = jsonencode({\n"
                                '    Version = "2012-10-17"\n'
                                "    Statement = [{\n"
                                '      Effect    = "Allow"\n'
                                '      Principal = { Service = "cloudtrail.amazonaws.com" }\n'
                                '      Action    = "sts:AssumeRole"\n'
                                "    }]\n"
                                "  })\n"
                                "}\n"
                                "\n"
                                'resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {\n'
                                '  name = "cloudtrail-cloudwatch-policy"\n'
                                "  role = aws_iam_role.cloudtrail_cloudwatch.id\n"
                                "\n"
                                "  policy = jsonencode({\n"
                                '    Version = "2012-10-17"\n'
                                "    Statement = [{\n"
                                '      Effect   = "Allow"\n'
                                '      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]\n'
                                '      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"\n'
                                "    }]\n"
                                "  })\n"
                                "}\n"
                                "\n"
                                f'resource "aws_cloudtrail" "main" {{\n'
                                f'  name                       = "{trail_name}"\n'
                                "  # ...\n"
                                '  cloud_watch_logs_group_arn  = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"\n'
                                "  cloud_watch_logs_role_arn   = aws_iam_role.cloudtrail_cloudwatch.arn\n"
                                "}"
                            ),
                            doc_url="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html",
                            effort=Effort.MEDIUM,
                        ),
                        compliance_refs=[],
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
        make_check(check_cloudtrail_bucket_access_logging, provider, check_id="aws-ct-004", category=Category.SECURITY),
        make_check(check_cloudtrail_kms_encryption, provider, check_id="aws-ct-005", category=Category.SECURITY),
        make_check(check_s3_object_write_logging, provider, check_id="aws-ct-006", category=Category.SECURITY),
        make_check(check_s3_object_read_logging, provider, check_id="aws-ct-007", category=Category.SECURITY),
        make_check(check_cloudtrail_cloudwatch_logs, provider, check_id="aws-ct-008", category=Category.SECURITY),
    ]
