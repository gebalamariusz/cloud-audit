"""CloudWatch visibility checks."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def _has_root_usage_alarm(logs: Any, cw: Any, lg_name: str) -> bool:
    """Return True if the log group has a root-usage metric filter with an alarm."""
    try:
        mf_paginator = logs.get_paginator("describe_metric_filters")
        all_filters: list[Any] = []
        for mf_page in mf_paginator.paginate(logGroupName=lg_name):
            all_filters.extend(mf_page.get("metricFilters", []))
    except Exception:
        return False

    for mf in all_filters:
        pattern = mf.get("filterPattern", "")
        if "Root" not in pattern and "root" not in pattern:
            continue
        if "userIdentity" not in pattern and "ConsoleLogin" not in pattern:
            continue

        for mt in mf.get("metricTransformations", []):
            metric_name = mt.get("metricName", "")
            metric_ns = mt.get("metricNamespace", "")
            if not metric_name:
                continue
            try:
                alarms = cw.describe_alarms_for_metric(
                    MetricName=metric_name,
                    Namespace=metric_ns,
                ).get("MetricAlarms", [])
                if alarms:
                    return True
            except Exception:
                continue
    return False


def check_root_usage_alarm(provider: AWSProvider) -> CheckResult:
    """Check if a CloudWatch alarm exists for root account usage."""
    result = CheckResult(check_id="aws-cw-001", check_name="Root account usage alarm")

    try:
        region = provider.regions[0]
        logs = provider.session.client("logs", region_name=region)
        cw = provider.session.client("cloudwatch", region_name=region)
        result.resources_scanned = 1

        found = False

        # Try CloudTrail-named log groups first (most common convention)
        ct_prefixes = ["cloudtrail", "CloudTrail", "aws-cloudtrail"]
        paginator = logs.get_paginator("describe_log_groups")
        for prefix in ct_prefixes:
            try:
                for page in paginator.paginate(logGroupNamePrefix=prefix):
                    for lg in page["logGroups"]:
                        if _has_root_usage_alarm(logs, cw, lg["logGroupName"]):
                            found = True
                            break
                    if found:
                        break
            except Exception:
                continue
            if found:
                break

        # Fall back to scanning all log groups if not found
        if not found:
            for page in paginator.paginate():
                for lg in page["logGroups"]:
                    lg_name = lg["logGroupName"]
                    if _has_root_usage_alarm(logs, cw, lg_name):
                        found = True
                        break
                if found:
                    break

        # Find the CloudTrail log group for remediation
        ct_lg_name = _find_cloudtrail_log_group(provider, region)
        ct_lg_display = ct_lg_name if ct_lg_name else "<CLOUDTRAIL_LOG_GROUP>"

        if not found:
            result.findings.append(
                Finding(
                    check_id="aws-cw-001",
                    title="No CloudWatch alarm for root account usage",
                    severity=Severity.HIGH,
                    category=Category.SECURITY,
                    resource_type="AWS::CloudWatch::Alarm",
                    resource_id="root-usage-alarm",
                    region=region,
                    description=(
                        "No CloudWatch metric filter and alarm configured "
                        "to detect root account usage. Root account activity "
                        "should be monitored and alerted on immediately."
                    ),
                    recommendation=(
                        "Create a metric filter on the CloudTrail log group "
                        "for root account usage and attach a CloudWatch alarm."
                    ),
                    remediation=Remediation(
                        cli=(
                            "# Create metric filter for root usage:\n"
                            "aws logs put-metric-filter \\\n"
                            f"  --log-group-name {ct_lg_display} \\\n"
                            "  --filter-name RootAccountUsage \\\n"
                            "  --filter-pattern "
                            '\'{ $.userIdentity.type = "Root" '
                            "&& $.userIdentity.invokedBy NOT EXISTS "
                            "&& $.eventType != "
                            '"AwsServiceEvent" }\' \\\n'
                            "  --metric-transformations "
                            "metricName=RootAccountUsage,"
                            "metricNamespace=CISBenchmark,"
                            "metricValue=1\n"
                            "# Create alarm:\n"
                            "aws cloudwatch put-metric-alarm \\\n"
                            "  --alarm-name RootAccountUsage \\\n"
                            "  --metric-name RootAccountUsage \\\n"
                            "  --namespace CISBenchmark \\\n"
                            "  --statistic Sum \\\n"
                            "  --period 300 \\\n"
                            "  --threshold 1 \\\n"
                            "  --comparison-operator GreaterThanOrEqualToThreshold \\\n"
                            "  --evaluation-periods 1 \\\n"
                            "  --alarm-actions <SNS_TOPIC_ARN>"
                        ),
                        terraform=(
                            'resource "aws_cloudwatch_log_metric_filter" "root_usage" {\n'
                            '  name           = "RootAccountUsage"\n'
                            "  log_group_name = aws_cloudwatch_log_group.cloudtrail.name\n"
                            '  pattern        = "{ $.userIdentity.type = \\"Root\\" '
                            "&& $.userIdentity.invokedBy NOT EXISTS "
                            '&& $.eventType != \\"AwsServiceEvent\\" }"\n'
                            "\n"
                            "  metric_transformation {\n"
                            '    name      = "RootAccountUsage"\n'
                            '    namespace = "CISBenchmark"\n'
                            '    value     = "1"\n'
                            "  }\n"
                            "}\n"
                            "\n"
                            'resource "aws_cloudwatch_metric_alarm" "root_usage" {\n'
                            '  alarm_name          = "RootAccountUsage"\n'
                            '  metric_name         = "RootAccountUsage"\n'
                            '  namespace           = "CISBenchmark"\n'
                            '  statistic           = "Sum"\n'
                            "  period              = 300\n"
                            "  threshold           = 1\n"
                            '  comparison_operator = "GreaterThanOrEqualToThreshold"\n'
                            "  evaluation_periods  = 1\n"
                            "  alarm_actions       = [aws_sns_topic.alerts.arn]\n"
                            "}"
                        ),
                        doc_url="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html",
                        effort=Effort.MEDIUM,
                    ),
                    compliance_refs=["CIS 4.3"],
                )
            )
    except Exception as e:
        result.error = str(e)

    return result


def _has_metric_filter_with_alarm(logs: Any, cw: Any, lg_name: str, pattern_keywords: list[str]) -> bool:
    """Return True if log group has a metric filter matching keywords with an active alarm."""
    try:
        mf_paginator = logs.get_paginator("describe_metric_filters")
        all_filters: list[Any] = []
        for mf_page in mf_paginator.paginate(logGroupName=lg_name):
            all_filters.extend(mf_page.get("metricFilters", []))
    except Exception:
        return False

    for mf in all_filters:
        pattern = mf.get("filterPattern", "")
        if not all(kw in pattern for kw in pattern_keywords):
            continue
        for mt in mf.get("metricTransformations", []):
            metric_name = mt.get("metricName", "")
            metric_ns = mt.get("metricNamespace", "")
            if not metric_name:
                continue
            try:
                alarms = cw.describe_alarms_for_metric(
                    MetricName=metric_name,
                    Namespace=metric_ns,
                ).get("MetricAlarms", [])
                if alarms:
                    return True
            except Exception:
                continue
    return False


def _find_cloudtrail_log_group(provider: Any, region: str) -> str | None:
    """Find the CloudTrail log group name by querying CloudTrail API.

    Queries CloudTrail for the actual CloudWatch Logs log group ARN configured
    on multi-region trails. Falls back to prefix-based search if no trail has
    CloudWatch integration configured.
    """
    # Primary: query CloudTrail for the configured log group
    try:
        ct = provider.session.client("cloudtrail", region_name=region)
        trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
        for trail in trails:
            if trail.get("IsMultiRegionTrail") and trail.get("CloudWatchLogsLogGroupArn"):
                arn = trail["CloudWatchLogsLogGroupArn"]
                # ARN format: arn:aws:logs:region:account:log-group:NAME:*
                parts = arn.split(":")
                if len(parts) >= 7:
                    return str(parts[6])
    except Exception:  # noqa: S110 - CloudTrail API may not be accessible
        pass

    # Fallback: search by common prefixes
    try:
        logs = provider.session.client("logs", region_name=region)
        ct_prefixes = ["cloudtrail", "CloudTrail", "aws-cloudtrail"]
        paginator = logs.get_paginator("describe_log_groups")
        for prefix in ct_prefixes:
            try:
                for page in paginator.paginate(logGroupNamePrefix=prefix):
                    for lg in page["logGroups"]:
                        return str(lg["logGroupName"])
            except Exception:
                continue
    except Exception:  # noqa: S110 - Logs API may not be accessible
        pass

    return None


# CIS Section 4 monitoring checks - each checks for a metric filter + alarm on CloudTrail log group
_CIS_MONITORING_CHECKS: list[dict[str, Any]] = [
    {
        "check_id": "aws-cw-002",
        "check_name": "Unauthorized API calls alarm",
        "cis_id": "4.1",
        "title": "No alarm for unauthorized API calls",
        "pattern_keywords": ["UnauthorizedAccess", "AccessDenied"],
        "pattern_alt_keywords": ["errorCode", "UnauthorizedAccess"],
        "filter_pattern": '{ ($.errorCode = "*UnauthorizedAccess*") || ($.errorCode = "AccessDenied*") }',
        "description": "unauthorized API calls (AccessDenied, UnauthorizedAccess)",
    },
    {
        "check_id": "aws-cw-003",
        "check_name": "Console sign-in without MFA alarm",
        "cis_id": "4.2",
        "title": "No alarm for console sign-in without MFA",
        "pattern_keywords": ["ConsoleLogin", "MFAUsed"],
        "pattern_alt_keywords": ["ConsoleLogin"],
        "filter_pattern": '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }',
        "description": "console sign-in without MFA",
    },
    {
        "check_id": "aws-cw-004",
        "check_name": "IAM policy changes alarm",
        "cis_id": "4.4",
        "title": "No alarm for IAM policy changes",
        "pattern_keywords": ["CreatePolicy", "AttachRolePolicy"],
        "pattern_alt_keywords": ["DeletePolicy", "PutRolePolicy"],
        "filter_pattern": "{ ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ... }",
        "description": "IAM policy changes (CreatePolicy, DeletePolicy, AttachRolePolicy, etc.)",
    },
    {
        "check_id": "aws-cw-005",
        "check_name": "CloudTrail config changes alarm",
        "cis_id": "4.5",
        "title": "No alarm for CloudTrail configuration changes",
        "pattern_keywords": ["CreateTrail", "DeleteTrail"],
        "pattern_alt_keywords": ["UpdateTrail", "StopLogging"],
        "filter_pattern": "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }",
        "description": "CloudTrail configuration changes",
    },
    {
        "check_id": "aws-cw-006",
        "check_name": "Console auth failures alarm",
        "cis_id": "4.6",
        "title": "No alarm for console authentication failures",
        "pattern_keywords": ["ConsoleLogin", "Failed"],
        "pattern_alt_keywords": ["ConsoleLogin", "errorMessage"],
        "filter_pattern": '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }',
        "description": "console authentication failures",
    },
    {
        "check_id": "aws-cw-007",
        "check_name": "CMK disable/deletion alarm",
        "cis_id": "4.7",
        "title": "No alarm for CMK disable or scheduled deletion",
        "pattern_keywords": ["DisableKey", "ScheduleKeyDeletion"],
        "pattern_alt_keywords": ["kms", "Disable"],
        "filter_pattern": "{ ($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion)) }",
        "description": "KMS CMK disable or scheduled deletion",
    },
    {
        "check_id": "aws-cw-008",
        "check_name": "S3 bucket policy changes alarm",
        "cis_id": "4.8",
        "title": "No alarm for S3 bucket policy changes",
        "pattern_keywords": ["PutBucketPolicy", "DeleteBucketPolicy"],
        "pattern_alt_keywords": ["PutBucketAcl", "s3"],
        "filter_pattern": "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ...) }",
        "description": "S3 bucket policy changes",
    },
    {
        "check_id": "aws-cw-009",
        "check_name": "Config changes alarm",
        "cis_id": "4.9",
        "title": "No alarm for AWS Config configuration changes",
        "pattern_keywords": ["StopConfigurationRecorder", "DeleteDeliveryChannel"],
        "pattern_alt_keywords": ["PutConfigurationRecorder", "config"],
        "filter_pattern": "{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ...) }",
        "description": "AWS Config configuration changes",
    },
    {
        "check_id": "aws-cw-010",
        "check_name": "Security group changes alarm",
        "cis_id": "4.10",
        "title": "No alarm for security group changes",
        "pattern_keywords": ["AuthorizeSecurityGroupIngress", "CreateSecurityGroup"],
        "pattern_alt_keywords": ["RevokeSecurityGroupIngress", "DeleteSecurityGroup"],
        "filter_pattern": "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ... }",
        "description": "security group changes",
    },
    {
        "check_id": "aws-cw-011",
        "check_name": "NACL changes alarm",
        "cis_id": "4.11",
        "title": "No alarm for Network ACL changes",
        "pattern_keywords": ["CreateNetworkAcl", "DeleteNetworkAcl"],
        "pattern_alt_keywords": ["ReplaceNetworkAclEntry", "NetworkAcl"],
        "filter_pattern": "{ ($.eventName = CreateNetworkAcl) || ($.eventName = DeleteNetworkAcl) || ... }",
        "description": "Network ACL changes",
    },
    {
        "check_id": "aws-cw-012",
        "check_name": "Network gateway changes alarm",
        "cis_id": "4.12",
        "title": "No alarm for network gateway changes",
        "pattern_keywords": ["CreateCustomerGateway", "AttachInternetGateway"],
        "pattern_alt_keywords": ["DeleteInternetGateway", "DetachInternetGateway"],
        "filter_pattern": "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ... }",
        "description": "network gateway changes",
    },
    {
        "check_id": "aws-cw-013",
        "check_name": "Route table changes alarm",
        "cis_id": "4.13",
        "title": "No alarm for route table changes",
        "pattern_keywords": ["CreateRoute", "DeleteRoute"],
        "pattern_alt_keywords": ["ReplaceRoute", "CreateRouteTable"],
        "filter_pattern": "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ... }",
        "description": "route table changes",
    },
    {
        "check_id": "aws-cw-014",
        "check_name": "VPC changes alarm",
        "cis_id": "4.14",
        "title": "No alarm for VPC changes",
        "pattern_keywords": ["CreateVpc", "DeleteVpc"],
        "pattern_alt_keywords": ["ModifyVpcAttribute", "AcceptVpcPeeringConnection"],
        "filter_pattern": "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ... }",
        "description": "VPC changes",
    },
    {
        "check_id": "aws-cw-015",
        "check_name": "Organizations changes alarm",
        "cis_id": "4.15",
        "title": "No alarm for AWS Organizations changes",
        "pattern_keywords": ["organizations.amazonaws.com"],
        "pattern_alt_keywords": ["InviteAccountToOrganization", "CreateOrganization"],
        "filter_pattern": "{ ($.eventSource = organizations.amazonaws.com) }",
        "description": "AWS Organizations changes",
    },
]


def _make_monitoring_check(check_def: dict[str, Any]) -> Any:
    """Factory for CIS Section 4 monitoring checks."""

    def _check(provider: AWSProvider) -> CheckResult:
        result = CheckResult(check_id=check_def["check_id"], check_name=check_def["check_name"])

        try:
            region = provider.regions[0]
            logs_client = provider.session.client("logs", region_name=region)
            cw_client = provider.session.client("cloudwatch", region_name=region)
            result.resources_scanned = 1

            lg_name = _find_cloudtrail_log_group(provider, region)
            found = False

            if lg_name:
                # Try primary keywords
                found = _has_metric_filter_with_alarm(logs_client, cw_client, lg_name, check_def["pattern_keywords"])
                # Try alt keywords if primary didn't match
                if not found:
                    found = _has_metric_filter_with_alarm(
                        logs_client, cw_client, lg_name, check_def["pattern_alt_keywords"]
                    )

            if not found:
                # Use discovered log group name in remediation if available
                lg_display = lg_name if lg_name else "<CLOUDTRAIL_LOG_GROUP>"
                result.findings.append(
                    Finding(
                        check_id=check_def["check_id"],
                        title=check_def["title"],
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        resource_type="AWS::CloudWatch::Alarm",
                        resource_id=f"cis-{check_def['cis_id']}-alarm",
                        region=region,
                        description=(
                            f"No CloudWatch metric filter and alarm configured to detect "
                            f"{check_def['description']}. Without this monitoring, "
                            f"critical changes go undetected."
                        ),
                        recommendation=(
                            f"Create a metric filter on the CloudTrail log group for "
                            f"{check_def['description']} and attach a CloudWatch alarm with SNS notification."
                        ),
                        remediation=Remediation(
                            cli=(
                                f"# Create metric filter:\n"
                                f"aws logs put-metric-filter \\\n"
                                f"  --log-group-name {lg_display} \\\n"
                                f"  --filter-name CIS-{check_def['cis_id']} \\\n"
                                f"  --filter-pattern '{check_def['filter_pattern']}' \\\n"
                                f"  --metric-transformations "
                                f"metricName=CIS-{check_def['cis_id'].replace('.', '-')},"
                                f"metricNamespace=CISBenchmark,metricValue=1\n"
                                f"# Create alarm:\n"
                                f"aws cloudwatch put-metric-alarm \\\n"
                                f"  --alarm-name CIS-{check_def['cis_id']} \\\n"
                                f"  --metric-name CIS-{check_def['cis_id'].replace('.', '-')} \\\n"
                                f"  --namespace CISBenchmark \\\n"
                                f"  --statistic Sum --period 300 --threshold 1 \\\n"
                                f"  --comparison-operator GreaterThanOrEqualToThreshold \\\n"
                                f"  --evaluation-periods 1 \\\n"
                                f"  --alarm-actions <SNS_TOPIC_ARN>"
                            ),
                            terraform=(
                                f'resource "aws_cloudwatch_log_metric_filter" "cis_{check_def["cis_id"].replace(".", "_")}" {{\n'
                                f'  name           = "CIS-{check_def["cis_id"]}"\n'
                                f"  log_group_name = aws_cloudwatch_log_group.cloudtrail.name\n"
                                f'  pattern        = "{check_def["filter_pattern"]}"\n'
                                f"\n"
                                f"  metric_transformation {{\n"
                                f'    name      = "CIS-{check_def["cis_id"].replace(".", "-")}"\n'
                                f'    namespace = "CISBenchmark"\n'
                                f'    value     = "1"\n'
                                f"  }}\n"
                                f"}}\n"
                                f"\n"
                                f'resource "aws_cloudwatch_metric_alarm" "cis_{check_def["cis_id"].replace(".", "_")}" {{\n'
                                f'  alarm_name          = "CIS-{check_def["cis_id"]}"\n'
                                f'  metric_name         = "CIS-{check_def["cis_id"].replace(".", "-")}"\n'
                                f'  namespace           = "CISBenchmark"\n'
                                f'  statistic           = "Sum"\n'
                                f"  period              = 300\n"
                                f"  threshold           = 1\n"
                                f'  comparison_operator = "GreaterThanOrEqualToThreshold"\n'
                                f"  evaluation_periods  = 1\n"
                                f"  alarm_actions       = [aws_sns_topic.alerts.arn]\n"
                                f"}}"
                            ),
                            doc_url="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html",
                            effort=Effort.MEDIUM,
                        ),
                        compliance_refs=[f"CIS {check_def['cis_id']}"],
                    )
                )
        except Exception as e:
            result.error = str(e)

        return result

    _check.__name__ = f"check_cis_{check_def['cis_id'].replace('.', '_')}"
    _check.__doc__ = f"CIS {check_def['cis_id']}: {check_def['check_name']}"
    return _check


def check_log_group_kms_encryption(provider: AWSProvider) -> CheckResult:
    """Check if security-relevant CloudWatch log groups are encrypted with KMS."""
    result = CheckResult(check_id="aws-cw-016", check_name="CloudWatch log group KMS encryption")

    # Only check log groups with security-relevant names
    security_keywords = ("cloudtrail", "vpc")

    try:
        account_id = provider.get_account_id()
        for region in provider.regions:
            logs = provider.session.client("logs", region_name=region)
            paginator = logs.get_paginator("describe_log_groups")

            try:
                for page in paginator.paginate():
                    for lg in page.get("logGroups", []):
                        lg_name = lg.get("logGroupName", "")
                        lg_lower = lg_name.lower()

                        # Only check security-relevant log groups
                        if not any(kw in lg_lower for kw in security_keywords):
                            continue

                        result.resources_scanned += 1

                        if not lg.get("kmsKeyId"):
                            result.findings.append(
                                Finding(
                                    check_id="aws-cw-016",
                                    title=f"Log group '{lg_name}' is not encrypted with KMS",
                                    severity=Severity.MEDIUM,
                                    category=Category.SECURITY,
                                    resource_type="AWS::Logs::LogGroup",
                                    resource_id=lg_name,
                                    region=region,
                                    description=(
                                        f"CloudWatch log group '{lg_name}' does not use KMS encryption. "
                                        "Security-relevant log groups (CloudTrail, VPC flow logs) should "
                                        "be encrypted with a customer-managed KMS key for additional "
                                        "access control and audit trail."
                                    ),
                                    recommendation="Associate a KMS key with the log group to encrypt log data at rest.",
                                    remediation=Remediation(
                                        cli=(
                                            f"aws logs associate-kms-key \\\n"
                                            f"  --log-group-name '{lg_name}' \\\n"
                                            f"  --kms-key-id arn:aws:kms:{region}:{account_id}:key/KEY_ID \\\n"
                                            f"  --region {region}"
                                        ),
                                        terraform=(
                                            'resource "aws_cloudwatch_log_group" "this" {\n'
                                            f'  name              = "{lg_name}"\n'
                                            "  kms_key_id        = aws_kms_key.logs.arn\n"
                                            "  retention_in_days = 365\n"
                                            "}"
                                        ),
                                        doc_url="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html",
                                        effort=Effort.MEDIUM,
                                    ),
                                    compliance_refs=[],
                                )
                            )
            except Exception as exc:
                error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if error_code in ("AccessDeniedException",):
                    continue
                raise
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all CloudWatch checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    checks = [
        make_check(check_root_usage_alarm, provider, check_id="aws-cw-001", category=Category.SECURITY),
    ]

    # Add CIS Section 4 monitoring checks
    for check_def in _CIS_MONITORING_CHECKS:
        check_fn = _make_monitoring_check(check_def)
        checks.append(make_check(check_fn, provider, check_id=check_def["check_id"], category=Category.SECURITY))

    checks.append(
        make_check(check_log_group_kms_encryption, provider, check_id="aws-cw-016", category=Category.SECURITY),
    )

    return checks
