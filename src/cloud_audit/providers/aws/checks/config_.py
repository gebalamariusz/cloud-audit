"""AWS Config visibility checks.

Four checks ship as of v2.3.1:

- ``aws-cfg-001`` — AWS Config recorder enabled per region (MEDIUM, existing)
- ``aws-cfg-002`` — AWS Config recorder actively recording (HIGH, existing)
- ``aws-cfg-003`` — Recording group records all supported resources (MEDIUM, new)
- ``aws-cfg-004`` — Delivery channel exists and is configured for fast snapshots (tiered, new)

The two new checks are added based on community feedback that the
single ``aws-cfg-001`` check was insufficient to detect partial AWS Config
deployments. A recorder can exist but record only a subset of resource
types; a recorder can exist but lack a delivery channel; a delivery
channel can exist but be configured for once-daily snapshots only.
Each of those is a distinct gap with a distinct fix.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def _is_service_linked_recorder(recorder: dict) -> bool:
    """Detect AWS service-linked recorders that should be ignored by audit checks.

    Service-linked recorders are created by other AWS services (for example
    AWS Security Hub, AWS Audit Manager) and report ``recordingScope=INTERNAL``.
    They satisfy the recorder's own purpose but do NOT replace a
    customer-managed recorder. Treat them as if they did not exist.
    """
    return recorder.get("recordingScope", "PAID") == "INTERNAL"


def check_config_enabled(provider: AWSProvider) -> CheckResult:
    """``aws-cfg-001`` - AWS Config enabled in each region."""
    result = CheckResult(check_id="aws-cfg-001", check_name="AWS Config enabled")

    try:
        account_id = provider.get_account_id()
        for region in provider.regions:
            config = provider.session.client("config", region_name=region)
            result.resources_scanned += 1

            recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
            customer_recorders = [r for r in recorders if not _is_service_linked_recorder(r)]

            if not customer_recorders:
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
                                f"# Create the service-linked role (one-time, if not already created):\n"
                                f"aws iam create-service-linked-role --aws-service-name config.amazonaws.com\n"
                                f"# Enable Config recorder:\n"
                                f"aws configservice put-configuration-recorder "
                                f"--configuration-recorder name=default,"
                                f"roleARN=arn:aws:iam::{account_id}:role/aws-service-role/"
                                f"config.amazonaws.com/AWSServiceRoleForConfig "
                                f"--recording-group allSupported=true,"
                                f"includeGlobalResourceTypes=true "
                                f"--region {region}"
                            ),
                            terraform=(
                                "# AWS Config uses a service-linked role by default:\n"
                                'resource "aws_config_configuration_recorder" "main" {\n'
                                '  name     = "default"\n'
                                f'  role_arn = "arn:aws:iam::{account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"\n'
                                "\n"
                                "  recording_group {\n"
                                "    all_supported                 = true\n"
                                "    include_global_resource_types = true\n"
                                "  }\n"
                                "}\n"
                                "\n"
                                'resource "aws_config_configuration_recorder_status" "main" {\n'
                                "  name       = aws_config_configuration_recorder.main.name\n"
                                "  is_enabled = true\n"
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
    """``aws-cfg-002`` - AWS Config recorder is actively recording."""
    result = CheckResult(check_id="aws-cfg-002", check_name="Config recorder active")

    try:
        for region in provider.regions:
            config = provider.session.client("config", region_name=region)

            recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
            customer_recorders = [r for r in recorders if not _is_service_linked_recorder(r)]
            if not customer_recorders:
                continue

            customer_names = {r["name"] for r in customer_recorders}
            status_list = config.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])

            for status in status_list:
                recorder_name = status.get("name", "default")
                if recorder_name not in customer_names:
                    continue  # Ignore service-linked recorders
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
                                "but is not actively recording. Configuration changes are not tracked. "
                                "This is a common attacker post-credential-theft behaviour to hide "
                                "the evidence trail of subsequent activity."
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


def _is_recording_group_complete(recording_group: dict) -> tuple[bool, str]:
    """Check whether a recording group records all supported resource types.

    Returns a (is_complete, reason) tuple. A recording group is complete when
    every supported resource type is recorded - including global resources
    (IAM, CloudFront, Route53 etc.) which are only emitted from a single
    designated region per account.

    Two configurations qualify as complete:

    1. Legacy mode: ``allSupported=true`` and ``includeGlobalResourceTypes=true``.
    2. Modern recording strategy: ``recordingStrategy.useOnly`` equals
       ``"ALL_SUPPORTED_RESOURCE_TYPES"`` (which implicitly covers globals).

    Anything else is incomplete.
    """
    recording_strategy = recording_group.get("recordingStrategy", {})
    strategy = recording_strategy.get("useOnly") if recording_strategy else None

    if strategy == "ALL_SUPPORTED_RESOURCE_TYPES":
        return True, ""
    if strategy in ("INCLUSION_BY_RESOURCE_TYPES", "EXCLUSION_BY_RESOURCE_TYPES"):
        return False, f"recordingStrategy.useOnly is '{strategy}', not ALL_SUPPORTED_RESOURCE_TYPES"

    # Legacy mode - check allSupported + includeGlobalResourceTypes
    all_supported = recording_group.get("allSupported", False)
    include_globals = recording_group.get("includeGlobalResourceTypes", False)

    if not all_supported:
        return False, "allSupported is false"
    if not include_globals:
        return False, "includeGlobalResourceTypes is false (IAM/CloudFront/Route53 changes not tracked)"

    return True, ""


def check_recording_group_complete(provider: AWSProvider) -> CheckResult:
    """``aws-cfg-003`` - Recording group records all supported resource types.

    A Config recorder with ``allSupported=false`` or
    ``includeGlobalResourceTypes=false`` produces an incomplete configuration
    history. Resource types not in the recording group are invisible to
    Config rules, Conformance Packs, and incident-response queries.

    Global resources (IAM, CloudFront, Route53, etc.) are only emitted from
    a single recorder per account - usually ``us-east-1``. If
    ``includeGlobalResourceTypes=false`` everywhere, those changes are
    permanently lost from the configuration timeline.
    """
    result = CheckResult(check_id="aws-cfg-003", check_name="Config recording group complete")

    try:
        for region in provider.regions:
            config = provider.session.client("config", region_name=region)

            recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
            customer_recorders = [r for r in recorders if not _is_service_linked_recorder(r)]
            if not customer_recorders:
                continue  # aws-cfg-001 handles the "no recorder" case

            for recorder in customer_recorders:
                recorder_name = recorder.get("name", "default")
                result.resources_scanned += 1

                recording_group = recorder.get("recordingGroup", {})
                is_complete, reason = _is_recording_group_complete(recording_group)
                if is_complete:
                    continue

                result.findings.append(
                    Finding(
                        check_id="aws-cfg-003",
                        title=(
                            f"Config recorder '{recorder_name}' in {region} does not record "
                            "all supported resource types"
                        ),
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        resource_type="AWS::Config::ConfigurationRecorder",
                        resource_id=recorder_name,
                        region=region,
                        description=(
                            f"Recorder '{recorder_name}' has an incomplete recording group: "
                            f"{reason}. Resource types outside the recording group are "
                            "invisible to AWS Config rules, Conformance Packs, and "
                            "incident-response queries. Global resources (IAM, CloudFront, "
                            "Route53) are only emitted by one recorder per account, so a "
                            "missing global-resource flag silently drops every IAM change "
                            "from the configuration timeline."
                        ),
                        recommendation=(
                            "Set allSupported=true and includeGlobalResourceTypes=true (or use "
                            "recordingStrategy.useOnly=ALL_SUPPORTED_RESOURCE_TYPES). For multi-region "
                            "accounts, enable includeGlobalResourceTypes in exactly one designated region."
                        ),
                        remediation=Remediation(
                            cli=(
                                f"aws configservice put-configuration-recorder "
                                f"--configuration-recorder name={recorder_name},"
                                f"roleARN=$(aws iam get-role --role-name AWSServiceRoleForConfig "
                                f"--query Role.Arn --output text) "
                                f"--recording-group allSupported=true,includeGlobalResourceTypes=true "
                                f"--region {region}"
                            ),
                            terraform=(
                                f'resource "aws_config_configuration_recorder" "{recorder_name}" {{\n'
                                f'  name     = "{recorder_name}"\n'
                                f"  role_arn = aws_iam_role.config.arn\n\n"
                                f"  recording_group {{\n"
                                f"    all_supported                 = true\n"
                                f"    include_global_resource_types = true  # only in ONE region per account\n"
                                f"  }}\n"
                                f"}}"
                            ),
                            doc_url=("https://docs.aws.amazon.com/config/latest/developerguide/select-resources.html"),
                            effort=Effort.LOW,
                        ),
                        compliance_refs=["CIS 3.5", "SOC2 CC7.2", "ISO27001 A.8.15"],
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def _evaluate_delivery_channel(channel: dict) -> tuple[Severity | None, str, str]:
    """Evaluate a single delivery channel.

    Returns ``(severity, title_suffix, description_detail)`` if the channel
    has issues, else ``(None, "", "")``. Severity is the highest tier of any
    problem detected on the channel.
    """
    s3_bucket = channel.get("s3BucketName")
    if not s3_bucket:
        return (
            Severity.HIGH,
            "is missing an S3 destination bucket",
            "no S3 bucket configured - configuration snapshots and history are not delivered",
        )

    snapshot_props = channel.get("configSnapshotDeliveryProperties", {})
    snapshot_freq = snapshot_props.get("deliveryFrequency", "TwentyFour_Hours")
    has_kms = bool(channel.get("s3KmsKeyArn"))

    issues = []
    if snapshot_freq == "TwentyFour_Hours":
        issues.append(
            "configSnapshotDeliveryProperties.deliveryFrequency is TwentyFour_Hours "
            "(slowest option - IR queries see at best 24-hour-old snapshots)"
        )
    if not has_kms:
        issues.append("s3KmsKeyArn is not set (deliveries are encrypted with SSE-S3, not a CMK)")

    if not issues:
        return (None, "", "")

    return (
        Severity.LOW,
        "has a misconfigured delivery channel",
        "; ".join(issues),
    )


def check_delivery_channel(provider: AWSProvider) -> CheckResult:
    """``aws-cfg-004`` - Delivery channel exists and is properly configured.

    The delivery channel is what makes Config history actually queryable -
    snapshots and configuration history items are written to S3 (and
    optionally SNS) on the channel's cadence. A recorder without a delivery
    channel produces in-memory configuration state that disappears when the
    recorder stops.

    Three tiers of finding:

    - ``HIGH``: no delivery channel exists for a region with an active recorder.
    - ``LOW``: delivery channel exists but ``deliveryFrequency`` is the slowest
      24-hour option, OR ``s3KmsKeyArn`` is not set (SSE-S3 instead of a CMK).
    """
    result = CheckResult(check_id="aws-cfg-004", check_name="Config delivery channel")

    try:
        for region in provider.regions:
            config = provider.session.client("config", region_name=region)

            recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
            customer_recorders = [r for r in recorders if not _is_service_linked_recorder(r)]
            if not customer_recorders:
                continue  # aws-cfg-001 handles this

            result.resources_scanned += 1
            channels = config.describe_delivery_channels().get("DeliveryChannels", [])

            if not channels:
                result.findings.append(
                    Finding(
                        check_id="aws-cfg-004",
                        title=f"AWS Config has no delivery channel in {region}",
                        severity=Severity.HIGH,
                        category=Category.SECURITY,
                        resource_type="AWS::Config::DeliveryChannel",
                        resource_id=f"config-channel-{region}",
                        region=region,
                        description=(
                            f"A Config recorder exists in {region}, but no delivery channel is "
                            "configured. Configuration snapshots and history items are not "
                            "delivered anywhere, so the recorder data cannot be queried after "
                            "the recorder stops or restarts."
                        ),
                        recommendation=(
                            "Create a delivery channel pointing at an S3 bucket "
                            "(ideally encrypted with a CMK) and an SNS topic for notifications."
                        ),
                        remediation=Remediation(
                            cli=(
                                f"aws configservice put-delivery-channel "
                                f"--delivery-channel name=default,"
                                f"s3BucketName=<your-config-bucket>,"
                                f"s3KmsKeyArn=arn:aws:kms:{region}:<account-id>:key/<key-id>,"
                                f"configSnapshotDeliveryProperties={{deliveryFrequency=One_Hour}} "
                                f"--region {region}"
                            ),
                            terraform=(
                                'resource "aws_config_delivery_channel" "main" {\n'
                                '  name           = "default"\n'
                                "  s3_bucket_name = aws_s3_bucket.config.id\n"
                                "  s3_kms_key_arn = aws_kms_key.config.arn\n\n"
                                "  snapshot_delivery_properties {\n"
                                '    delivery_frequency = "One_Hour"\n'
                                "  }\n"
                                "}"
                            ),
                            doc_url=(
                                "https://docs.aws.amazon.com/config/latest/developerguide/manage-delivery-channel.html"
                            ),
                            effort=Effort.MEDIUM,
                        ),
                        compliance_refs=["CIS 3.5", "SOC2 CC7.2", "ISO27001 A.8.15"],
                    )
                )
                continue

            for channel in channels:
                severity, title_suffix, description_detail = _evaluate_delivery_channel(channel)
                if severity is None:
                    continue

                channel_name = channel.get("name", "default")
                result.findings.append(
                    Finding(
                        check_id="aws-cfg-004",
                        title=f"Config delivery channel '{channel_name}' in {region} {title_suffix}",
                        severity=severity,
                        category=Category.SECURITY,
                        resource_type="AWS::Config::DeliveryChannel",
                        resource_id=channel_name,
                        region=region,
                        description=(
                            f"Delivery channel '{channel_name}' has issues: {description_detail}. "
                            "Faster snapshot delivery and CMK-based encryption are recommended "
                            "for security-sensitive accounts."
                        ),
                        recommendation=(
                            "Set configSnapshotDeliveryProperties.deliveryFrequency=One_Hour "
                            "and provide s3KmsKeyArn with a CMK in the same region."
                        ),
                        remediation=Remediation(
                            cli=(
                                f"aws configservice put-delivery-channel "
                                f"--delivery-channel name={channel_name},"
                                f"s3BucketName={channel.get('s3BucketName', '<your-bucket>')},"
                                f"s3KmsKeyArn=arn:aws:kms:{region}:<account-id>:key/<key-id>,"
                                f"configSnapshotDeliveryProperties={{deliveryFrequency=One_Hour}} "
                                f"--region {region}"
                            ),
                            terraform=(
                                f'resource "aws_config_delivery_channel" "{channel_name}" {{\n'
                                f'  name           = "{channel_name}"\n'
                                f"  s3_bucket_name = aws_s3_bucket.config.id\n"
                                f"  s3_kms_key_arn = aws_kms_key.config.arn  # add this for CMK encryption\n\n"
                                f"  snapshot_delivery_properties {{\n"
                                f'    delivery_frequency = "One_Hour"  # was TwentyFour_Hours\n'
                                f"  }}\n"
                                f"}}"
                            ),
                            doc_url=(
                                "https://docs.aws.amazon.com/config/latest/developerguide/manage-delivery-channel.html"
                            ),
                            effort=Effort.LOW,
                        ),
                        compliance_refs=["CIS 3.5", "SOC2 CC7.2", "ISO27001 A.8.15"],
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all AWS Config checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_config_enabled, provider, check_id="aws-cfg-001", category=Category.SECURITY),
        make_check(check_config_recorder_active, provider, check_id="aws-cfg-002", category=Category.SECURITY),
        make_check(
            check_recording_group_complete,
            provider,
            check_id="aws-cfg-003",
            category=Category.SECURITY,
        ),
        make_check(check_delivery_channel, provider, check_id="aws-cfg-004", category=Category.SECURITY),
    ]
