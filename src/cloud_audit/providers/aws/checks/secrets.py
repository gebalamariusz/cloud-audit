"""Secrets Manager checks."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_secret_rotation(provider: AWSProvider) -> CheckResult:
    """Check for secrets without rotation or rotated more than 90 days ago."""
    result = CheckResult(check_id="aws-sm-001", check_name="Secrets Manager rotation")

    try:
        now = datetime.now(timezone.utc)
        max_age_days = 90

        for region in provider.regions:
            sm = provider.session.client("secretsmanager", region_name=region)
            paginator = sm.get_paginator("list_secrets")
            for page in paginator.paginate():
                for secret in page["SecretList"]:
                    result.resources_scanned += 1
                    name = secret["Name"]
                    arn = secret["ARN"]

                    rotation_enabled = secret.get("RotationEnabled", False)
                    last_rotated = secret.get("LastRotatedDate")

                    if not rotation_enabled:
                        result.findings.append(
                            Finding(
                                check_id="aws-sm-001",
                                title=f"Secret '{name}' has no automatic rotation configured",
                                severity=Severity.MEDIUM,
                                category=Category.SECURITY,
                                resource_type="AWS::SecretsManager::Secret",
                                resource_id=arn,
                                region=region,
                                description=f"Secret '{name}' does not have automatic rotation enabled. Stale secrets increase the window of compromise.",
                                recommendation="Enable automatic rotation with an appropriate rotation Lambda function.",
                                remediation=Remediation(
                                    cli=(
                                        f"aws secretsmanager rotate-secret --secret-id {name} "
                                        f"--rotation-lambda-arn arn:aws:lambda:{region}:ACCOUNT:function:rotation-fn "
                                        f"--rotation-rules AutomaticallyAfterDays=90 --region {region}"
                                    ),
                                    terraform=(
                                        f'resource "aws_secretsmanager_secret_rotation" "{name}" {{\n'
                                        f"  secret_id           = aws_secretsmanager_secret.{name}.id\n"
                                        f"  rotation_lambda_arn = aws_lambda_function.rotation.arn\n"
                                        f"  rotation_rules {{\n"
                                        f"    automatically_after_days = 90\n"
                                        f"  }}\n"
                                        f"}}"
                                    ),
                                    doc_url="https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html",
                                    effort=Effort.MEDIUM,
                                ),
                            )
                        )
                    elif last_rotated:
                        days_since = (now - last_rotated).days
                        if days_since > max_age_days:
                            result.findings.append(
                                Finding(
                                    check_id="aws-sm-001",
                                    title=f"Secret '{name}' last rotated {days_since} days ago",
                                    severity=Severity.MEDIUM,
                                    category=Category.SECURITY,
                                    resource_type="AWS::SecretsManager::Secret",
                                    resource_id=arn,
                                    region=region,
                                    description=f"Secret '{name}' has rotation enabled but was last rotated {days_since} days ago (threshold: {max_age_days}).",
                                    recommendation="Investigate why rotation is not running. Check the rotation Lambda function logs.",
                                    remediation=Remediation(
                                        cli=(
                                            f"# Trigger immediate rotation:\n"
                                            f"aws secretsmanager rotate-secret --secret-id {name} --region {region}"
                                        ),
                                        terraform=(
                                            "# Rotation is managed by the rotation Lambda.\n"
                                            "# Check CloudWatch logs for the rotation function."
                                        ),
                                        doc_url="https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html",
                                        effort=Effort.LOW,
                                    ),
                                )
                            )
    except Exception as e:
        result.error = str(e)

    return result


def check_unused_secret(provider: AWSProvider) -> CheckResult:
    """Check for secrets not accessed in 90+ days."""
    result = CheckResult(check_id="aws-sm-002", check_name="Unused secrets")

    try:
        now = datetime.now(timezone.utc)
        max_unused_days = 90

        for region in provider.regions:
            sm = provider.session.client("secretsmanager", region_name=region)
            paginator = sm.get_paginator("list_secrets")
            for page in paginator.paginate():
                for secret in page["SecretList"]:
                    result.resources_scanned += 1
                    name = secret["Name"]
                    arn = secret["ARN"]
                    last_accessed = secret.get("LastAccessedDate")

                    if last_accessed:
                        days_unused = (now - last_accessed).days
                        if days_unused > max_unused_days:
                            result.findings.append(
                                Finding(
                                    check_id="aws-sm-002",
                                    title=f"Secret '{name}' not accessed for {days_unused} days",
                                    severity=Severity.LOW,
                                    category=Category.COST,
                                    resource_type="AWS::SecretsManager::Secret",
                                    resource_id=arn,
                                    region=region,
                                    description=f"Secret '{name}' was last accessed {days_unused} days ago. Unused secrets cost $0.40/month and may indicate forgotten credentials.",
                                    recommendation="Delete the secret if no longer needed, or verify it's still required.",
                                    remediation=Remediation(
                                        cli=(
                                            f"# Schedule deletion (30-day recovery window):\n"
                                            f"aws secretsmanager delete-secret --secret-id {name} "
                                            f"--recovery-window-in-days 30 --region {region}"
                                        ),
                                        terraform=(
                                            "# Remove the aws_secretsmanager_secret resource from Terraform config\n"
                                            "# and run terraform apply."
                                        ),
                                        doc_url="https://docs.aws.amazon.com/secretsmanager/latest/userguide/manage_delete-secret.html",
                                        effort=Effort.LOW,
                                    ),
                                )
                            )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all Secrets Manager checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_secret_rotation, provider, check_id="aws-sm-001", category=Category.SECURITY),
        make_check(check_unused_secret, provider, check_id="aws-sm-002", category=Category.COST),
    ]
