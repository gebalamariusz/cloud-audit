"""RDS security and reliability checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_rds_public_access(provider: AWSProvider) -> CheckResult:
    """Check for RDS instances that are publicly accessible."""
    result = CheckResult(check_id="aws-rds-001", check_name="Public RDS instances")

    try:
        for region in provider.regions:
            rds = provider.session.client("rds", region_name=region)
            paginator = rds.get_paginator("describe_db_instances")

            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    result.resources_scanned += 1
                    db_id = db["DBInstanceIdentifier"]

                    if db.get("PubliclyAccessible", False):
                        result.findings.append(
                            Finding(
                                check_id="aws-rds-001",
                                title=f"RDS instance '{db_id}' is publicly accessible",
                                severity=Severity.CRITICAL,
                                category=Category.SECURITY,
                                resource_type="AWS::RDS::DBInstance",
                                resource_id=db_id,
                                region=region,
                                description=f"RDS instance '{db_id}' ({db['Engine']}) has PubliclyAccessible=true.",
                                recommendation="Disable public access and use private subnets. Connect via VPN or bastion host.",
                                remediation=Remediation(
                                    cli=(
                                        f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                                        f"--no-publicly-accessible --apply-immediately --region {region}"
                                    ),
                                    terraform=(
                                        f'resource "aws_db_instance" "{db_id}" {{\n'
                                        f"  # ...\n"
                                        f"  publicly_accessible = false\n"
                                        f"}}"
                                    ),
                                    doc_url="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_RDS_Configuring.html",
                                    effort=Effort.LOW,
                                ),
                            )
                        )
    except Exception as e:
        result.error = str(e)

    return result


def check_rds_encryption(provider: AWSProvider) -> CheckResult:
    """Check for RDS instances without encryption at rest."""
    result = CheckResult(check_id="aws-rds-002", check_name="RDS encryption at rest")

    try:
        for region in provider.regions:
            rds = provider.session.client("rds", region_name=region)
            paginator = rds.get_paginator("describe_db_instances")

            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    result.resources_scanned += 1
                    db_id = db["DBInstanceIdentifier"]

                    if not db.get("StorageEncrypted", False):
                        result.findings.append(
                            Finding(
                                check_id="aws-rds-002",
                                title=f"RDS instance '{db_id}' is not encrypted at rest",
                                severity=Severity.HIGH,
                                category=Category.SECURITY,
                                resource_type="AWS::RDS::DBInstance",
                                resource_id=db_id,
                                region=region,
                                description=f"RDS instance '{db_id}' does not have storage encryption enabled.",
                                recommendation="Enable encryption at rest. Note: existing instances must be migrated via snapshot restore.",
                                remediation=Remediation(
                                    cli=(
                                        f"# RDS encryption cannot be enabled on existing instances.\n"
                                        f"# Migrate via snapshot:\n"
                                        f"aws rds create-db-snapshot --db-instance-identifier {db_id} "
                                        f"--db-snapshot-identifier {db_id}-pre-encrypt --region {region}\n"
                                        f"aws rds copy-db-snapshot --source-db-snapshot-identifier {db_id}-pre-encrypt "
                                        f"--target-db-snapshot-identifier {db_id}-encrypted --kms-key-id alias/aws/rds --region {region}\n"
                                        f"aws rds restore-db-instance-from-db-snapshot --db-instance-identifier {db_id}-new "
                                        f"--db-snapshot-identifier {db_id}-encrypted --region {region}"
                                    ),
                                    terraform=(
                                        f'resource "aws_db_instance" "{db_id}" {{\n'
                                        f"  # ...\n"
                                        f"  storage_encrypted = true\n"
                                        f"  kms_key_id        = aws_kms_key.rds.arn  # optional\n"
                                        f"}}"
                                    ),
                                    doc_url="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
                                    effort=Effort.HIGH,
                                ),
                            )
                        )
    except Exception as e:
        result.error = str(e)

    return result


def check_rds_multi_az(provider: AWSProvider) -> CheckResult:
    """Check for production RDS instances without Multi-AZ."""
    result = CheckResult(check_id="aws-rds-003", check_name="RDS Multi-AZ")

    try:
        for region in provider.regions:
            rds = provider.session.client("rds", region_name=region)
            paginator = rds.get_paginator("describe_db_instances")

            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    result.resources_scanned += 1
                    db_id = db["DBInstanceIdentifier"]

                    if not db.get("MultiAZ", False):
                        # Only flag non-micro/small instances (likely production)
                        instance_class = db.get("DBInstanceClass", "")
                        if "micro" in instance_class or "small" in instance_class:
                            continue

                        result.findings.append(
                            Finding(
                                check_id="aws-rds-003",
                                title=f"RDS instance '{db_id}' is not Multi-AZ",
                                severity=Severity.MEDIUM,
                                category=Category.RELIABILITY,
                                resource_type="AWS::RDS::DBInstance",
                                resource_id=db_id,
                                region=region,
                                description=f"RDS instance '{db_id}' ({instance_class}) does not have Multi-AZ failover enabled.",
                                recommendation="Enable Multi-AZ for production databases to provide automatic failover.",
                                remediation=Remediation(
                                    cli=(
                                        f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                                        f"--multi-az --apply-immediately --region {region}"
                                    ),
                                    terraform=(
                                        f'resource "aws_db_instance" "{db_id}" {{\n  # ...\n  multi_az = true\n}}'
                                    ),
                                    doc_url="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html",
                                    effort=Effort.MEDIUM,
                                ),
                            )
                        )
    except Exception as e:
        result.error = str(e)

    return result


def check_rds_auto_minor_upgrade(provider: AWSProvider) -> CheckResult:
    """Check for RDS instances with automatic minor version upgrade disabled."""
    result = CheckResult(check_id="aws-rds-004", check_name="RDS auto minor upgrade")

    try:
        for region in provider.regions:
            rds = provider.session.client("rds", region_name=region)
            paginator = rds.get_paginator("describe_db_instances")

            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    result.resources_scanned += 1
                    db_id = db["DBInstanceIdentifier"]

                    if not db.get("AutoMinorVersionUpgrade", True):
                        result.findings.append(
                            Finding(
                                check_id="aws-rds-004",
                                title=f"RDS instance '{db_id}' has auto minor upgrade disabled",
                                severity=Severity.LOW,
                                category=Category.RELIABILITY,
                                resource_type="AWS::RDS::DBInstance",
                                resource_id=db_id,
                                region=region,
                                description=f"RDS instance '{db_id}' will not automatically receive minor engine version upgrades with security patches.",
                                recommendation="Enable auto minor version upgrade to receive security patches automatically.",
                                remediation=Remediation(
                                    cli=(
                                        f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                                        f"--auto-minor-version-upgrade --apply-immediately --region {region}"
                                    ),
                                    terraform=(
                                        f'resource "aws_db_instance" "{db_id}" {{\n'
                                        f"  # ...\n"
                                        f"  auto_minor_version_upgrade = true\n"
                                        f"}}"
                                    ),
                                    doc_url="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Upgrading.html",
                                    effort=Effort.LOW,
                                ),
                            )
                        )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all RDS checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_rds_public_access, provider, check_id="aws-rds-001", category=Category.SECURITY),
        make_check(check_rds_encryption, provider, check_id="aws-rds-002", category=Category.SECURITY),
        make_check(check_rds_multi_az, provider, check_id="aws-rds-003", category=Category.RELIABILITY),
        make_check(check_rds_auto_minor_upgrade, provider, check_id="aws-rds-004", category=Category.RELIABILITY),
    ]
