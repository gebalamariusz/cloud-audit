"""IAM security checks."""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_root_mfa(provider: AWSProvider) -> CheckResult:
    """Check if the root account has MFA enabled."""
    iam = provider.session.client("iam")
    result = CheckResult(check_id="aws-iam-001", check_name="Root account MFA")

    try:
        summary = iam.get_account_summary()["SummaryMap"]
        result.resources_scanned = 1
        if summary.get("AccountMFAEnabled", 0) == 0:
            result.findings.append(
                Finding(
                    check_id="aws-iam-001",
                    title="Root account does not have MFA enabled",
                    severity=Severity.CRITICAL,
                    category=Category.SECURITY,
                    resource_type="AWS::IAM::Root",
                    resource_id="root",
                    description="The root account has no MFA device configured. Root has unrestricted access to all resources.",
                    recommendation="Enable MFA on the root account immediately. Use a hardware MFA device for best security.",
                    remediation=Remediation(
                        cli=(
                            "# Root MFA must be configured via AWS Console\n"
                            "# 1. Sign in as root: https://console.aws.amazon.com/\n"
                            "# 2. Go to: IAM > Security credentials > Multi-factor authentication\n"
                            "# 3. Assign MFA device (hardware TOTP recommended)"
                        ),
                        terraform=(
                            "# Root MFA cannot be managed via Terraform.\n"
                            "# Use AWS Console or aws-vault for root account protection."
                        ),
                        doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user_manage_mfa.html",
                        effort=Effort.LOW,
                    ),
                    compliance_refs=["CIS 1.5"],
                )
            )
    except Exception as e:
        result.error = str(e)

    return result


def check_users_mfa(provider: AWSProvider) -> CheckResult:
    """Check if all IAM users with console access have MFA enabled."""
    iam = provider.session.client("iam")
    result = CheckResult(check_id="aws-iam-002", check_name="IAM users MFA")

    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                result.resources_scanned += 1
                username = user["UserName"]

                # Check if user has console access (login profile)
                try:
                    iam.get_login_profile(UserName=username)
                except iam.exceptions.NoSuchEntityException:
                    continue  # No console access - MFA not required

                # User has console access - check MFA
                mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
                if not mfa_devices:
                    result.findings.append(
                        Finding(
                            check_id="aws-iam-002",
                            title=f"IAM user '{username}' has console access without MFA",
                            severity=Severity.HIGH,
                            category=Category.SECURITY,
                            resource_type="AWS::IAM::User",
                            resource_id=username,
                            description=f"User '{username}' can log in to the AWS Console but has no MFA device configured.",
                            recommendation=f"Enable MFA for user '{username}' or remove console access if not needed.",
                            remediation=Remediation(
                                cli=(
                                    f"# Enable virtual MFA for user '{username}':\n"
                                    f"aws iam create-virtual-mfa-device "
                                    f"--virtual-mfa-device-name {username}-mfa "
                                    f"--outfile /tmp/{username}-qr.png --bootstrap-method QRCodePNG\n"
                                    f"# Then activate with two consecutive TOTP codes:\n"
                                    f"aws iam enable-mfa-device --user-name {username} "
                                    f"--serial-number arn:aws:iam::ACCOUNT_ID:mfa/{username}-mfa "
                                    f"--authentication-code1 CODE1 --authentication-code2 CODE2"
                                ),
                                terraform=(
                                    f'resource "aws_iam_virtual_mfa_device" "{username}_mfa" {{\n'
                                    f'  virtual_mfa_device_name = "{username}-mfa"\n'
                                    f"}}"
                                ),
                                doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html",
                                effort=Effort.LOW,
                            ),
                            compliance_refs=["CIS 1.4"],
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def check_access_keys_rotation(provider: AWSProvider) -> CheckResult:
    """Check if access keys are older than 90 days."""
    iam = provider.session.client("iam")
    result = CheckResult(check_id="aws-iam-003", check_name="Access key rotation")

    try:
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        max_age_days = 90
        paginator = iam.get_paginator("list_users")

        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

                for key in keys:
                    result.resources_scanned += 1
                    if key["Status"] != "Active":
                        continue

                    created = key["CreateDate"]
                    age_days = (now - created).days

                    if age_days > max_age_days:
                        key_id = key["AccessKeyId"]
                        result.findings.append(
                            Finding(
                                check_id="aws-iam-003",
                                title=f"Access key for '{username}' is {age_days} days old",
                                severity=Severity.MEDIUM,
                                category=Category.SECURITY,
                                resource_type="AWS::IAM::AccessKey",
                                resource_id=key_id,
                                description=f"Access key {key_id} for user '{username}' was created {age_days} days ago (limit: {max_age_days}).",
                                recommendation="Rotate the access key. Create a new key, update all services using it, then deactivate the old one.",
                                remediation=Remediation(
                                    cli=(
                                        f"# Rotate access key for user '{username}':\n"
                                        f"aws iam create-access-key --user-name {username}\n"
                                        f"# Update all services using the old key, then:\n"
                                        f"aws iam update-access-key --user-name {username} "
                                        f"--access-key-id {key_id} --status Inactive\n"
                                        f"aws iam delete-access-key --user-name {username} "
                                        f"--access-key-id {key_id}"
                                    ),
                                    terraform=(
                                        "# Access keys should be managed outside Terraform.\n"
                                        "# Use aws-vault or SSO for credential management.\n"
                                        f'resource "aws_iam_access_key" "{username}" {{\n'
                                        f'  user = "{username}"\n'
                                        f"}}"
                                    ),
                                    doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey",
                                    effort=Effort.LOW,
                                ),
                                compliance_refs=["CIS 1.14"],
                            )
                        )
    except Exception as e:
        result.error = str(e)

    return result


def check_unused_access_keys(provider: AWSProvider) -> CheckResult:
    """Check for access keys that haven't been used in 30+ days."""
    iam = provider.session.client("iam")
    result = CheckResult(check_id="aws-iam-004", check_name="Unused access keys")

    try:
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        max_unused_days = 30
        paginator = iam.get_paginator("list_users")

        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

                for key in keys:
                    if key["Status"] != "Active":
                        continue
                    result.resources_scanned += 1
                    key_id = key["AccessKeyId"]

                    _remediation = Remediation(
                        cli=(
                            f"aws iam update-access-key --user-name {username} "
                            f"--access-key-id {key_id} --status Inactive\n"
                            f"# After confirming no impact:\n"
                            f"aws iam delete-access-key --user-name {username} "
                            f"--access-key-id {key_id}"
                        ),
                        terraform=(
                            "# Remove the aws_iam_access_key resource from your Terraform config\n"
                            "# and run terraform apply to delete the unused key."
                        ),
                        doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
                        effort=Effort.LOW,
                    )

                    last_used_resp = iam.get_access_key_last_used(AccessKeyId=key_id)
                    last_used_info = last_used_resp["AccessKeyLastUsed"]

                    if "LastUsedDate" not in last_used_info:
                        result.findings.append(
                            Finding(
                                check_id="aws-iam-004",
                                title=f"Access key for '{username}' has never been used",
                                severity=Severity.MEDIUM,
                                category=Category.SECURITY,
                                resource_type="AWS::IAM::AccessKey",
                                resource_id=key_id,
                                description=f"Active access key {key_id} for user '{username}' has never been used.",
                                recommendation="Deactivate or delete unused access keys to reduce attack surface.",
                                remediation=_remediation,
                                compliance_refs=["CIS 1.12"],
                            )
                        )
                    else:
                        days_unused = (now - last_used_info["LastUsedDate"]).days
                        if days_unused > max_unused_days:
                            result.findings.append(
                                Finding(
                                    check_id="aws-iam-004",
                                    title=f"Access key for '{username}' unused for {days_unused} days",
                                    severity=Severity.LOW,
                                    category=Category.SECURITY,
                                    resource_type="AWS::IAM::AccessKey",
                                    resource_id=key_id,
                                    description=f"Access key {key_id} last used {days_unused} days ago.",
                                    recommendation="Review if this key is still needed. Deactivate unused keys.",
                                    remediation=_remediation,
                                    compliance_refs=["CIS 1.12"],
                                )
                            )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all IAM checks bound to the provider."""
    checks: list[CheckFn] = [
        partial(check_root_mfa, provider),
        partial(check_users_mfa, provider),
        partial(check_access_keys_rotation, provider),
        partial(check_unused_access_keys, provider),
    ]
    for fn in checks:
        fn.category = Category.SECURITY
    return checks
