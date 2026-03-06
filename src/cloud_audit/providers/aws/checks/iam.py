"""IAM security checks."""

from __future__ import annotations

import json
from datetime import datetime, timezone
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


def check_overly_permissive_policy(provider: AWSProvider) -> CheckResult:
    """Check for IAM policies with overly permissive actions (Action: * on Resource: *)."""
    iam = provider.session.client("iam")
    result = CheckResult(check_id="aws-iam-005", check_name="Overly permissive IAM policies")

    try:
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                result.resources_scanned += 1
                arn = policy["Arn"]
                name = policy["PolicyName"]

                try:
                    version_id = policy["DefaultVersionId"]
                    doc = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)["PolicyVersion"]["Document"]
                    if isinstance(doc, str):
                        doc = json.loads(doc)

                    statements = doc.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]

                    for stmt in statements:
                        if stmt.get("Effect") != "Allow":
                            continue
                        actions = stmt.get("Action", [])
                        resources = stmt.get("Resource", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        if isinstance(resources, str):
                            resources = [resources]
                        if "*" in actions and "*" in resources:
                            result.findings.append(
                                Finding(
                                    check_id="aws-iam-005",
                                    title=f"IAM policy '{name}' grants full admin access (Action: *, Resource: *)",
                                    severity=Severity.CRITICAL,
                                    category=Category.SECURITY,
                                    resource_type="AWS::IAM::Policy",
                                    resource_id=arn,
                                    description=f"Policy '{name}' has a statement with Action: * and Resource: *. This grants unrestricted access to all AWS services.",
                                    recommendation="Follow least-privilege principle. Replace wildcard actions with specific service actions.",
                                    remediation=Remediation(
                                        cli=(
                                            f"# Review and restrict the policy:\n"
                                            f"aws iam get-policy-version --policy-arn {arn} --version-id {version_id}\n"
                                            f"# Create a new version with least-privilege permissions:\n"
                                            f"aws iam create-policy-version --policy-arn {arn} "
                                            f"--policy-document file://restricted-policy.json --set-as-default"
                                        ),
                                        terraform=(
                                            f"# Replace wildcard policy with specific permissions:\n"
                                            f'resource "aws_iam_policy" "{name}" {{\n'
                                            f'  name = "{name}"\n'
                                            f"  policy = jsonencode({{\n"
                                            f'    Version = "2012-10-17"\n'
                                            f"    Statement = [{{\n"
                                            f'      Effect   = "Allow"\n'
                                            f'      Action   = ["s3:GetObject", "s3:ListBucket"]  # specific actions\n'
                                            f'      Resource = ["arn:aws:s3:::my-bucket/*"]\n'
                                            f"    }}]\n"
                                            f"  }})\n"
                                            f"}}"
                                        ),
                                        doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
                                        effort=Effort.HIGH,
                                    ),
                                )
                            )
                            break  # One finding per policy is enough
                except Exception:
                    continue
    except Exception as e:
        result.error = str(e)

    return result


def check_weak_password_policy(provider: AWSProvider) -> CheckResult:
    """Check if the account password policy meets CIS requirements."""
    iam = provider.session.client("iam")
    result = CheckResult(check_id="aws-iam-006", check_name="Password policy strength")

    try:
        result.resources_scanned = 1
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
        except iam.exceptions.NoSuchEntityException:
            result.findings.append(
                Finding(
                    check_id="aws-iam-006",
                    title="No account password policy configured",
                    severity=Severity.MEDIUM,
                    category=Category.SECURITY,
                    resource_type="AWS::IAM::AccountPasswordPolicy",
                    resource_id="password-policy",
                    description="No custom password policy is set. The default AWS policy is very permissive (6 chars, no complexity).",
                    recommendation="Set a password policy with minimum 14 characters, requiring uppercase, lowercase, numbers, and symbols.",
                    remediation=Remediation(
                        cli=(
                            "aws iam update-account-password-policy "
                            "--minimum-password-length 14 "
                            "--require-symbols --require-numbers "
                            "--require-uppercase-characters --require-lowercase-characters "
                            "--max-password-age 90 --password-reuse-prevention 24"
                        ),
                        terraform=(
                            'resource "aws_iam_account_password_policy" "strict" {\n'
                            "  minimum_password_length        = 14\n"
                            "  require_lowercase_characters   = true\n"
                            "  require_uppercase_characters   = true\n"
                            "  require_numbers                = true\n"
                            "  require_symbols                = true\n"
                            "  max_password_age               = 90\n"
                            "  password_reuse_prevention      = 24\n"
                            "}"
                        ),
                        doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html",
                        effort=Effort.LOW,
                    ),
                    compliance_refs=["CIS 1.8"],
                )
            )
            return result

        issues = []
        if policy.get("MinimumPasswordLength", 0) < 14:
            issues.append(f"minimum length {policy.get('MinimumPasswordLength', 0)} (should be >= 14)")
        if not policy.get("RequireUppercaseCharacters", False):
            issues.append("uppercase not required")
        if not policy.get("RequireLowercaseCharacters", False):
            issues.append("lowercase not required")
        if not policy.get("RequireNumbers", False):
            issues.append("numbers not required")
        if not policy.get("RequireSymbols", False):
            issues.append("symbols not required")

        if issues:
            result.findings.append(
                Finding(
                    check_id="aws-iam-006",
                    title=f"Password policy is weak: {', '.join(issues)}",
                    severity=Severity.MEDIUM,
                    category=Category.SECURITY,
                    resource_type="AWS::IAM::AccountPasswordPolicy",
                    resource_id="password-policy",
                    description=f"Account password policy does not meet CIS requirements: {', '.join(issues)}.",
                    recommendation="Update the password policy to require minimum 14 characters with complexity requirements.",
                    remediation=Remediation(
                        cli=(
                            "aws iam update-account-password-policy "
                            "--minimum-password-length 14 "
                            "--require-symbols --require-numbers "
                            "--require-uppercase-characters --require-lowercase-characters "
                            "--max-password-age 90 --password-reuse-prevention 24"
                        ),
                        terraform=(
                            'resource "aws_iam_account_password_policy" "strict" {\n'
                            "  minimum_password_length        = 14\n"
                            "  require_lowercase_characters   = true\n"
                            "  require_uppercase_characters   = true\n"
                            "  require_numbers                = true\n"
                            "  require_symbols                = true\n"
                            "  max_password_age               = 90\n"
                            "  password_reuse_prevention      = 24\n"
                            "}"
                        ),
                        doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html",
                        effort=Effort.LOW,
                    ),
                    compliance_refs=["CIS 1.8"],
                )
            )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all IAM checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_root_mfa, provider, check_id="aws-iam-001", category=Category.SECURITY),
        make_check(check_users_mfa, provider, check_id="aws-iam-002", category=Category.SECURITY),
        make_check(check_access_keys_rotation, provider, check_id="aws-iam-003", category=Category.SECURITY),
        make_check(check_unused_access_keys, provider, check_id="aws-iam-004", category=Category.SECURITY),
        make_check(check_overly_permissive_policy, provider, check_id="aws-iam-005", category=Category.SECURITY),
        make_check(check_weak_password_policy, provider, check_id="aws-iam-006", category=Category.SECURITY),
    ]
