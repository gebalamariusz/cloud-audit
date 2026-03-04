"""AWS Config visibility checks."""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_config_enabled(provider: AWSProvider) -> CheckResult:
    """Check if AWS Config is enabled in each region."""
    result = CheckResult(check_id="aws-cfg-001", check_name="AWS Config enabled")

    try:
        for region in provider.regions:
            config = provider.session.client("config", region_name=region)
            result.resources_scanned += 1

            recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])

            if not recorders:
                result.findings.append(
                    Finding(
                        check_id="aws-cfg-001",
                        title=f"AWS Config is not enabled in {region}",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        resource_type="AWS::Config::ConfigurationRecorder",
                        resource_id=f"config-{region}",
                        region=region,
                        description=(
                            f"AWS Config is not enabled in {region}. "
                            "No configuration history or change tracking for resources."
                        ),
                        recommendation="Enable AWS Config in all active regions.",
                        remediation=Remediation(
                            cli=(
                                f"aws configservice put-configuration-recorder "
                                f"--configuration-recorder name=default,"
                                f"roleARN=arn:aws:iam::ACCOUNT_ID:role/aws-service-role/"
                                f"config.amazonaws.com/AWSServiceRoleForConfig "
                                f"--recording-group allSupported=true,"
                                f"includeGlobalResourceTypes=true "
                                f"--region {region}"
                            ),
                            terraform=(
                                'resource "aws_config_configuration_recorder" "main" {\n'
                                '  name     = "default"\n'
                                "  role_arn = aws_iam_role.config.arn\n"
                                "\n"
                                "  recording_group {\n"
                                "    all_supported                 = true\n"
                                "    include_global_resource_types = true\n"
                                "  }\n"
                                "}"
                            ),
                            doc_url="https://docs.aws.amazon.com/config/latest/developerguide/gs-console.html",
                            effort=Effort.MEDIUM,
                        ),
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def check_config_recorder_active(provider: AWSProvider) -> CheckResult:
    """Check if AWS Config recorder is actively recording."""
    result = CheckResult(check_id="aws-cfg-002", check_name="Config recorder active")

    try:
        for region in provider.regions:
            config = provider.session.client("config", region_name=region)

            recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
            if not recorders:
                continue

            status_list = config.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])

            for status in status_list:
                recorder_name = status.get("name", "default")
                result.resources_scanned += 1

                if not status.get("recording", False):
                    result.findings.append(
                        Finding(
                            check_id="aws-cfg-002",
                            title=f"Config recorder '{recorder_name}' is stopped in {region}",
                            severity=Severity.HIGH,
                            category=Category.SECURITY,
                            resource_type="AWS::Config::ConfigurationRecorder",
                            resource_id=recorder_name,
                            region=region,
                            description=(
                                f"AWS Config recorder '{recorder_name}' exists in {region} "
                                "but is not actively recording. Configuration changes are not tracked."
                            ),
                            recommendation="Start the Config recorder.",
                            remediation=Remediation(
                                cli=(
                                    f"aws configservice start-configuration-recorder "
                                    f"--configuration-recorder-name {recorder_name} "
                                    f"--region {region}"
                                ),
                                terraform=(
                                    'resource "aws_config_configuration_recorder_status" "main" {\n'
                                    "  name       = aws_config_configuration_recorder.main.name\n"
                                    "  is_enabled = true\n"
                                    "}"
                                ),
                                doc_url="https://docs.aws.amazon.com/config/latest/developerguide/stop-start-recorder.html",
                                effort=Effort.LOW,
                            ),
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all AWS Config checks bound to the provider."""
    checks: list[CheckFn] = [
        partial(check_config_enabled, provider),
        partial(check_config_recorder_active, provider),
    ]
    for fn in checks:
        fn.category = Category.SECURITY
    return checks
