"""Tests for CloudWatch security checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.cloudwatch import check_root_usage_alarm

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


def test_root_usage_alarm_missing(mock_aws_provider: AWSProvider) -> None:
    """No root usage alarm configured - HIGH finding."""
    result = check_root_usage_alarm(mock_aws_provider)
    assert result.check_id == "aws-cw-001"
    assert result.resources_scanned == 1
    assert len(result.findings) == 1
    assert result.findings[0].severity.value == "high"
    assert result.findings[0].compliance_refs == ["CIS 4.3"]


def test_root_usage_alarm_present(mock_aws_provider: AWSProvider) -> None:
    """Root usage alarm configured - no finding."""
    logs = mock_aws_provider.session.client("logs", region_name="eu-central-1")
    cw = mock_aws_provider.session.client("cloudwatch", region_name="eu-central-1")

    # Create log group + metric filter + alarm
    logs.create_log_group(logGroupName="/aws/cloudtrail/test")
    logs.put_metric_filter(
        logGroupName="/aws/cloudtrail/test",
        filterName="RootAccountUsage",
        filterPattern='{ $.userIdentity.type = "Root" }',
        metricTransformations=[
            {
                "metricName": "RootAccountUsage",
                "metricNamespace": "CISBenchmark",
                "metricValue": "1",
            }
        ],
    )
    cw.put_metric_alarm(
        AlarmName="RootAccountUsage",
        MetricName="RootAccountUsage",
        Namespace="CISBenchmark",
        Statistic="Sum",
        Period=300,
        Threshold=1.0,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        EvaluationPeriods=1,
    )

    result = check_root_usage_alarm(mock_aws_provider)
    assert len(result.findings) == 0
