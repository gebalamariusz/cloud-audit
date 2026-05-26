"""DynamoDB security and operational hygiene checks.

Three checks ship in v2.3.1, all added based on community feedback:

- ``aws-ddb-001`` — encryption at rest visibility (tiered LOW/HIGH/CRITICAL)
- ``aws-ddb-002`` — point-in-time recovery enabled (MEDIUM)
- ``aws-ddb-003`` — autoscaling on PROVISIONED billing tables (MEDIUM)

Severity assignments anchor to AWS Security Hub DynamoDB.1 and DynamoDB.2
(both MEDIUM). The encryption check fills a gap — AWS FSBP has no DDB
table encryption-at-rest control today, so cloud-audit is more opinionated
than the AWS managed standard. The rationale is that compliance auditors
(SOC 2, HIPAA, ISO 27001) typically want a CloudTrail-visible audit trail
for the encryption key, which the default AWS-owned key does not provide.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


# Per-region cache of Application Auto Scaling targets for DynamoDB.
# describe_scalable_targets(ServiceNamespace="dynamodb") returns ALL DDB
# targets (tables + GSIs, read + write) in one call - cache it per scan,
# per region so aws-ddb-003 does not hit the API once per table.
_targets_cache: dict[str, set[tuple[str, str]]] = {}
_cache_lock = threading.Lock()


def _reset_ddb_cache() -> None:
    """Reset per-region scalable-targets cache. Called between scans and in tests."""
    global _targets_cache
    with _cache_lock:
        _targets_cache = {}


def _tf_name(name: str) -> str:
    """Sanitize a DynamoDB table name for use as a Terraform identifier."""
    sanitized = name.replace(".", "_").replace("-", "_")
    if sanitized and sanitized[0].isdigit():
        sanitized = f"ddb_{sanitized}"
    return sanitized


def _list_tables(client: Any) -> list[str]:
    """List all DynamoDB table names in the region using pagination."""
    names: list[str] = []
    paginator = client.get_paginator("list_tables")
    for page in paginator.paginate():
        names.extend(page.get("TableNames", []))
    return names


def _get_scalable_targets(provider: AWSProvider, region: str) -> set[tuple[str, str]]:
    """Return the set of (ResourceId, ScalableDimension) tuples registered for DynamoDB.

    Resource IDs are ``table/<TableName>`` for tables and
    ``table/<TableName>/index/<IndexName>`` for global secondary indexes.
    Scalable dimensions are ``dynamodb:table:ReadCapacityUnits`` /
    ``WriteCapacityUnits`` plus the ``dynamodb:index:*`` variants.

    One API call returns every target in the region, so the result is cached
    per (region) for the duration of the scan.
    """
    with _cache_lock:
        if region in _targets_cache:
            return _targets_cache[region]

    aas = provider.session.client("application-autoscaling", region_name=region)
    targets: set[tuple[str, str]] = set()
    try:
        paginator = aas.get_paginator("describe_scalable_targets")
        for page in paginator.paginate(ServiceNamespace="dynamodb"):
            for t in page.get("ScalableTargets", []):
                targets.add((t["ResourceId"], t["ScalableDimension"]))
    except ClientError:
        # AccessDenied or transient API failure - treat as "no targets known"
        # rather than failing the whole check. aws-ddb-003 will simply report
        # missing autoscaling for any PROVISIONED table found.
        pass

    with _cache_lock:
        _targets_cache[region] = targets
    return targets


def _ddb_encryption_remediation(table_name: str, region: str) -> Remediation:
    """Build remediation for promoting a DDB table to AWS-managed KMS or CMK."""
    tf = _tf_name(table_name)
    return Remediation(
        cli=(
            f"# Promote to AWS-managed KMS (alias/aws/dynamodb):\n"
            f"aws dynamodb update-table --table-name {table_name} "
            f"--sse-specification Enabled=true,SSEType=KMS --region {region}\n"
            f"# Or use a customer-managed CMK for full audit + rotation control:\n"
            f"aws dynamodb update-table --table-name {table_name} "
            f"--sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=alias/my-cmk "
            f"--region {region}"
        ),
        terraform=(
            f'resource "aws_kms_key" "ddb_{tf}" {{\n'
            f'  description             = "CMK for DynamoDB {table_name}"\n'
            f"  deletion_window_in_days = 30\n"
            f"  enable_key_rotation     = true\n"
            f"}}\n\n"
            f'resource "aws_dynamodb_table" "{tf}" {{\n'
            f'  name = "{table_name}"\n'
            f"  # ... existing fields ...\n"
            f"  server_side_encryption {{\n"
            f"    enabled     = true\n"
            f"    kms_key_arn = aws_kms_key.ddb_{tf}.arn\n"
            f"  }}\n"
            f"}}"
        ),
        doc_url="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/encryption.tutorial.html",
        effort=Effort.LOW,
    )


def _ddb_pitr_remediation(table_name: str, region: str) -> Remediation:
    """Build remediation for enabling point-in-time recovery."""
    tf = _tf_name(table_name)
    return Remediation(
        cli=(
            f"aws dynamodb update-continuous-backups --table-name {table_name} "
            f"--point-in-time-recovery-specification PointInTimeRecoveryEnabled=true "
            f"--region {region}"
        ),
        terraform=(
            f'resource "aws_dynamodb_table" "{tf}" {{\n'
            f'  name = "{table_name}"\n'
            f"  # ... existing fields ...\n"
            f"  point_in_time_recovery {{\n"
            f"    enabled = true\n"
            f"  }}\n"
            f"}}"
        ),
        doc_url="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html",
        effort=Effort.LOW,
    )


def _ddb_autoscaling_remediation(table_name: str, region: str) -> Remediation:
    """Build remediation for registering Application Auto Scaling targets."""
    tf = _tf_name(table_name)
    return Remediation(
        cli=(
            f"# Register read capacity scalable target:\n"
            f"aws application-autoscaling register-scalable-target "
            f"--service-namespace dynamodb --resource-id 'table/{table_name}' "
            f"--scalable-dimension dynamodb:table:ReadCapacityUnits "
            f"--min-capacity 5 --max-capacity 1000 --region {region}\n"
            f"# Register write capacity scalable target:\n"
            f"aws application-autoscaling register-scalable-target "
            f"--service-namespace dynamodb --resource-id 'table/{table_name}' "
            f"--scalable-dimension dynamodb:table:WriteCapacityUnits "
            f"--min-capacity 5 --max-capacity 1000 --region {region}\n"
            f"# Attach a target-tracking policy on read capacity:\n"
            f"aws application-autoscaling put-scaling-policy "
            f"--policy-name '{table_name}-read-tt' "
            f"--service-namespace dynamodb --resource-id 'table/{table_name}' "
            f"--scalable-dimension dynamodb:table:ReadCapacityUnits "
            f"--policy-type TargetTrackingScaling "
            f"--target-tracking-scaling-policy-configuration "
            f'\'{{"TargetValue":70.0,'
            f'"PredefinedMetricSpecification":{{"PredefinedMetricType":"DynamoDBReadCapacityUtilization"}},'
            f'"ScaleInCooldown":60,"ScaleOutCooldown":60}}\' '
            f"--region {region}\n"
            f"# Repeat the put-scaling-policy for WriteCapacityUnits "
            f"with PredefinedMetricType=DynamoDBWriteCapacityUtilization.\n"
            f"# Alternative remediation - switch to on-demand pricing:\n"
            f"aws dynamodb update-table --table-name {table_name} "
            f"--billing-mode PAY_PER_REQUEST --region {region}"
        ),
        terraform=(
            f'resource "aws_appautoscaling_target" "ddb_read_{tf}" {{\n'
            f'  service_namespace  = "dynamodb"\n'
            f'  resource_id        = "table/{table_name}"\n'
            f'  scalable_dimension = "dynamodb:table:ReadCapacityUnits"\n'
            f"  min_capacity       = 5\n"
            f"  max_capacity       = 1000\n"
            f"}}\n\n"
            f'resource "aws_appautoscaling_target" "ddb_write_{tf}" {{\n'
            f'  service_namespace  = "dynamodb"\n'
            f'  resource_id        = "table/{table_name}"\n'
            f'  scalable_dimension = "dynamodb:table:WriteCapacityUnits"\n'
            f"  min_capacity       = 5\n"
            f"  max_capacity       = 1000\n"
            f"}}\n\n"
            f'resource "aws_appautoscaling_policy" "ddb_read_pol_{tf}" {{\n'
            f'  name               = "{table_name}-read-target-tracking"\n'
            f"  service_namespace  = aws_appautoscaling_target.ddb_read_{tf}.service_namespace\n"
            f"  resource_id        = aws_appautoscaling_target.ddb_read_{tf}.resource_id\n"
            f"  scalable_dimension = aws_appautoscaling_target.ddb_read_{tf}.scalable_dimension\n"
            f'  policy_type        = "TargetTrackingScaling"\n\n'
            f"  target_tracking_scaling_policy_configuration {{\n"
            f"    target_value = 70.0\n"
            f"    predefined_metric_specification {{\n"
            f'      predefined_metric_type = "DynamoDBReadCapacityUtilization"\n'
            f"    }}\n"
            f"    scale_in_cooldown  = 60\n"
            f"    scale_out_cooldown = 60\n"
            f"  }}\n"
            f"}}\n"
            f"# Repeat aws_appautoscaling_policy block for WriteCapacityUnits."
        ),
        doc_url="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/AutoScaling.html",
        effort=Effort.MEDIUM,
    )


def check_encryption_at_rest(provider: AWSProvider) -> CheckResult:
    """``aws-ddb-001`` - DynamoDB encryption at rest visibility.

    Encryption is always active on DynamoDB tables; the question is which
    key. This check surfaces the customer-visible encryption metadata:

    - ``SSEDescription`` absent (AWS-owned default key) -> ``LOW`` finding.
      Encryption is on, but the key lives outside the customer account so
      there are no CloudTrail KMS events, no rotation evidence, and no way
      to revoke decrypt access in an incident. Compliance auditors typically
      need an audit trail, so this is surfaced as a low-severity finding.
    - ``InaccessibleEncryptionDateTime`` set -> ``CRITICAL``. The CMK
      backing the table has been disabled, deleted, or had access revoked.
      AWS will archive the table after 7 days and the data is unrecoverable.
    - ``Status`` not ``ENABLED`` on a live table -> ``HIGH``. Defensive
      catch for transitional or disabled states that should not be visible
      on a steady-state ``ACTIVE`` table.
    - AWS-managed KMS (``alias/aws/dynamodb``) or customer-managed CMK
      with ``Status='ENABLED'`` -> no finding.
    """
    result = CheckResult(check_id="aws-ddb-001", check_name="DynamoDB encryption at rest")

    try:
        for region in provider.regions:
            client = provider.session.client("dynamodb", region_name=region)
            try:
                tables = _list_tables(client)
            except ClientError as exc:
                error_code = exc.response.get("Error", {}).get("Code", "")
                if error_code in ("AccessDeniedException", "UnauthorizedOperation"):
                    continue
                raise

            for name in tables:
                result.resources_scanned += 1
                try:
                    desc = client.describe_table(TableName=name)["Table"]
                except ClientError as exc:
                    error_code = exc.response.get("Error", {}).get("Code", "")
                    if error_code in ("ResourceNotFoundException", "AccessDeniedException"):
                        continue
                    raise

                sse = desc.get("SSEDescription")

                if sse is None:
                    # AWS-owned default key - encrypted but opaque
                    result.findings.append(
                        Finding(
                            check_id="aws-ddb-001",
                            title=f"DynamoDB table '{name}' uses AWS-owned encryption (no audit visibility)",
                            severity=Severity.LOW,
                            category=Category.SECURITY,
                            resource_type="AWS::DynamoDB::Table",
                            resource_id=name,
                            region=region,
                            description=(
                                f"Table '{name}' uses the AWS-owned default key. Data is encrypted, "
                                "but the key is held outside your account - there are no CloudTrail "
                                "KMS events, no rotation evidence, and no way to revoke decrypt access "
                                "in an incident. Compliance audits (SOC 2, HIPAA, ISO 27001) typically "
                                "require an AWS-managed KMS key or a customer-managed CMK so the "
                                "encryption is auditable."
                            ),
                            recommendation=(
                                "Promote to AWS-managed KMS (alias/aws/dynamodb) or a customer-managed CMK."
                            ),
                            remediation=_ddb_encryption_remediation(name, region),
                            compliance_refs=["SOC2 CC6.1", "HIPAA 164.312(a)(2)(iv)", "ISO27001 A.8.24"],
                        )
                    )
                elif sse.get("InaccessibleEncryptionDateTime"):
                    # CMK was disabled or access revoked - 7-day clock to archival
                    result.findings.append(
                        Finding(
                            check_id="aws-ddb-001",
                            title=(f"DynamoDB table '{name}' encryption key is inaccessible - table will be archived"),
                            severity=Severity.CRITICAL,
                            category=Category.SECURITY,
                            resource_type="AWS::DynamoDB::Table",
                            resource_id=name,
                            region=region,
                            description=(
                                f"Table '{name}' references a CMK that has been disabled, deleted, or "
                                "had access revoked. AWS will mark the table "
                                "INACCESSIBLE_ENCRYPTION_CREDENTIALS and archive it after 7 days, at "
                                "which point data is unrecoverable. Restore key access immediately."
                            ),
                            recommendation=(
                                "Restore key access immediately, then verify the table status returns to ACTIVE."
                            ),
                            remediation=_ddb_encryption_remediation(name, region),
                            compliance_refs=["SOC2 A1.2", "HIPAA 164.312(c)", "ISO27001 A.8.24"],
                        )
                    )
                elif sse.get("Status") != "ENABLED":
                    result.findings.append(
                        Finding(
                            check_id="aws-ddb-001",
                            title=(f"DynamoDB table '{name}' encryption status is {sse.get('Status', 'UNKNOWN')}"),
                            severity=Severity.HIGH,
                            category=Category.SECURITY,
                            resource_type="AWS::DynamoDB::Table",
                            resource_id=name,
                            region=region,
                            description=(
                                f"Table '{name}' has SSEDescription.Status = "
                                f"'{sse.get('Status', 'UNKNOWN')}', which is a transitional or disabled "
                                "state. Encryption may not be applied uniformly to all writes."
                            ),
                            recommendation=(
                                "Wait for encryption status to converge to ENABLED, or re-issue "
                                "update-table with the desired SSE specification."
                            ),
                            remediation=_ddb_encryption_remediation(name, region),
                            compliance_refs=["SOC2 CC6.1", "ISO27001 A.8.24"],
                        )
                    )
                # else: SSEDescription with Status='ENABLED' (AWS-managed or CMK) - no finding
    except Exception as e:
        result.error = str(e)

    return result


def check_pitr_enabled(provider: AWSProvider) -> CheckResult:
    """``aws-ddb-002`` - DynamoDB point-in-time recovery enabled.

    Maps to AWS Security Hub DynamoDB.2 (MEDIUM). Without PITR, accidental
    drops, ransomware-style mass overwrites, or bad conditional-update
    Lambdas leave the data unrecoverable except from on-demand backups
    (which require explicit scheduling). PITR provides 35-day continuous,
    any-second-granularity recovery at a storage cost of roughly
    $0.20/GB-month - cheap insurance against a delete-table fat finger.
    """
    result = CheckResult(check_id="aws-ddb-002", check_name="DynamoDB point-in-time recovery")

    try:
        for region in provider.regions:
            client = provider.session.client("dynamodb", region_name=region)
            try:
                tables = _list_tables(client)
            except ClientError as exc:
                error_code = exc.response.get("Error", {}).get("Code", "")
                if error_code in ("AccessDeniedException", "UnauthorizedOperation"):
                    continue
                raise

            for name in tables:
                result.resources_scanned += 1
                try:
                    cb = client.describe_continuous_backups(TableName=name)
                except ClientError as exc:
                    error_code = exc.response.get("Error", {}).get("Code", "")
                    if error_code in (
                        "ResourceNotFoundException",
                        "TableNotFoundException",
                        "AccessDeniedException",
                    ):
                        continue
                    raise

                desc = cb.get("ContinuousBackupsDescription", {})
                pitr = desc.get("PointInTimeRecoveryDescription", {})
                pitr_status = pitr.get("PointInTimeRecoveryStatus", "DISABLED")

                if pitr_status != "ENABLED":
                    result.findings.append(
                        Finding(
                            check_id="aws-ddb-002",
                            title=(f"DynamoDB table '{name}' does not have point-in-time recovery enabled"),
                            severity=Severity.MEDIUM,
                            category=Category.RELIABILITY,
                            resource_type="AWS::DynamoDB::Table",
                            resource_id=name,
                            region=region,
                            description=(
                                f"Table '{name}' has PITR status '{pitr_status}'. Without PITR, "
                                "accidental drops, ransomware-style overwrites, or mass "
                                "conditional-update bugs are unrecoverable except from on-demand "
                                "backups (which must be scheduled explicitly). PITR provides 35-day "
                                "continuous recovery at roughly $0.20 per GB-month."
                            ),
                            recommendation="Enable point-in-time recovery via update-continuous-backups.",
                            remediation=_ddb_pitr_remediation(name, region),
                            compliance_refs=["SOC2 A1.2", "ISO27001 A.8.13", "AWS FSBP DynamoDB.2"],
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def check_autoscaling_enabled(provider: AWSProvider) -> CheckResult:
    """``aws-ddb-003`` - DynamoDB autoscaling on PROVISIONED billing tables.

    Maps to AWS Security Hub DynamoDB.1 (MEDIUM). PROVISIONED billing with
    manual capacity either over-provisions (cost waste, billed 24/7) or
    under-provisions (ProvisionedThroughputExceededException, client retries
    amplifying load, lost revenue). Tables in ``PAY_PER_REQUEST`` mode are
    skipped - on-demand pricing has no autoscaling concept and is itself a
    valid resolution for the underlying control.

    A table with autoscaling on only one of read/write is flagged separately
    so the user knows which dimension needs attention.
    """
    result = CheckResult(check_id="aws-ddb-003", check_name="DynamoDB autoscaling")

    try:
        for region in provider.regions:
            client = provider.session.client("dynamodb", region_name=region)
            try:
                tables = _list_tables(client)
            except ClientError as exc:
                error_code = exc.response.get("Error", {}).get("Code", "")
                if error_code in ("AccessDeniedException", "UnauthorizedOperation"):
                    continue
                raise

            targets = _get_scalable_targets(provider, region)

            for name in tables:
                result.resources_scanned += 1
                try:
                    desc = client.describe_table(TableName=name)["Table"]
                except ClientError as exc:
                    error_code = exc.response.get("Error", {}).get("Code", "")
                    if error_code in ("ResourceNotFoundException", "AccessDeniedException"):
                        continue
                    raise

                # Legacy tables without BillingModeSummary are PROVISIONED
                billing = desc.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED")
                if billing == "PAY_PER_REQUEST":
                    continue

                resource_id = f"table/{name}"
                has_read = (resource_id, "dynamodb:table:ReadCapacityUnits") in targets
                has_write = (resource_id, "dynamodb:table:WriteCapacityUnits") in targets

                if not has_read and not has_write:
                    title = f"DynamoDB table '{name}' uses PROVISIONED billing without autoscaling"
                    description = (
                        f"Table '{name}' is in PROVISIONED billing mode with no Application Auto "
                        "Scaling registered on either read or write capacity. Traffic spikes "
                        "produce ProvisionedThroughputExceededException; over-provisioning wastes "
                        "money 24/7."
                    )
                elif not has_read:
                    title = f"DynamoDB table '{name}' has no autoscaling on read capacity"
                    description = (
                        f"Table '{name}' has autoscaling registered for write capacity but not "
                        "read. Read-heavy spikes will throttle."
                    )
                elif not has_write:
                    title = f"DynamoDB table '{name}' has no autoscaling on write capacity"
                    description = (
                        f"Table '{name}' has autoscaling registered for read capacity but not "
                        "write. Write-heavy spikes will throttle."
                    )
                else:
                    continue  # Both dimensions have autoscaling - no finding

                result.findings.append(
                    Finding(
                        check_id="aws-ddb-003",
                        title=title,
                        severity=Severity.MEDIUM,
                        category=Category.RELIABILITY,
                        resource_type="AWS::DynamoDB::Table",
                        resource_id=name,
                        region=region,
                        description=description,
                        recommendation=(
                            "Register Application Auto Scaling targets for read and write capacity, "
                            "or switch to PAY_PER_REQUEST billing if traffic is unpredictable."
                        ),
                        remediation=_ddb_autoscaling_remediation(name, region),
                        compliance_refs=["AWS FSBP DynamoDB.1", "ISO27001 A.8.6"],
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all DynamoDB checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_encryption_at_rest, provider, check_id="aws-ddb-001", category=Category.SECURITY),
        make_check(check_pitr_enabled, provider, check_id="aws-ddb-002", category=Category.RELIABILITY),
        make_check(
            check_autoscaling_enabled,
            provider,
            check_id="aws-ddb-003",
            category=Category.RELIABILITY,
        ),
    ]
