"""CloudWatch visibility checks."""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_root_usage_alarm(provider: AWSProvider) -> CheckResult:
    """Check if a CloudWatch alarm exists for root account usage."""
    result = CheckResult(check_id="aws-cw-001", check_name="Root account usage alarm")

    try:
        region = provider.regions[0]
        logs = provider.session.client("logs", region_name=region)
        cw = provider.session.client("cloudwatch", region_name=region)
        result.resources_scanned = 1

        # Look for a metric filter on CloudTrail log group that watches for root usage
        found = False
        paginator = logs.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            for lg in page["logGroups"]:
                lg_name = lg["logGroupName"]
                try:
                    filters = logs.describe_metric_filters(logGroupName=lg_name).get("metricFilters", [])
                except Exception:
                    continue

                for mf in filters:
                    pattern = mf.get("filterPattern", "")
                    # CIS 4.3 pattern matches root usage
                    if "Root" not in pattern and "root" not in pattern:
                        continue
                    if "userIdentity" not in pattern and "ConsoleLogin" not in pattern:
                        continue

                    # Check if there's an alarm on this metric
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
                                found = True
                                break
                        except Exception:
                            continue
                    if found:
                        break
                if found:
                    break
            if found:
                break

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
                            "  --log-group-name <CLOUDTRAIL_LOG_GROUP> \\\n"
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


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all CloudWatch checks bound to the provider."""
    checks: list[CheckFn] = [
        partial(check_root_usage_alarm, provider),
    ]
    for fn in checks:
        fn.category = Category.SECURITY
    return checks
