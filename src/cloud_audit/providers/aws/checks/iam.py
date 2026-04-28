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
    iam = provider.client("iam")
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


def check_root_access_keys(provider: AWSProvider) -> CheckResult:
    """Check if the root account has access keys (CIS 1.4)."""
    iam = provider.client("iam")
    result = CheckResult(check_id="aws-iam-008", check_name="Root account access keys")

    try:
        summary = iam.get_account_summary()["SummaryMap"]
        result.resources_scanned = 1
        if summary.get("AccountAccessKeysPresent", 0) > 0:
            result.findings.append(
                Finding(
                    check_id="aws-iam-008",
                    title="Root account has active access keys",
                    severity=Severity.CRITICAL,
                    category=Category.SECURITY,
                    resource_type="AWS::IAM::Root",
                    resource_id="root",
                    description=(
                        "The root account has access keys configured. "
                        "Root access keys grant unrestricted access to all AWS resources "
                        "and cannot be restricted by IAM policies. If compromised, "
                        "an attacker has full control over the account."
                    ),
                    recommendation="Delete root access keys immediately. Use IAM users or roles for programmatic access.",
                    remediation=Remediation(
                        cli=(
                            "# Root access keys must be deleted via AWS Console:\n"
                            "# 1. Sign in as root: https://console.aws.amazon.com/\n"
                            "# 2. Go to: IAM > Security credentials > Access keys\n"
                            "# 3. Delete all access keys\n"
                            "# Alternatively, use CLI if you have the root key (not recommended):\n"
                            "# aws iam delete-access-key --access-key-id AKIAXXXXXXXXXXXXXXXX"
                        ),
                        terraform=(
                            "# Root access keys cannot be managed via Terraform.\n"
                            "# Delete them via AWS Console and use IAM roles instead:\n"
                            'resource "aws_iam_role" "admin" {\n'
                            '  name = "admin-role"\n'
                            "  # Use this role instead of root access keys\n"
                            "}"
                        ),
                        doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user_manage_delete-key.html",
                        effort=Effort.LOW,
                    ),
                    compliance_refs=["CIS 1.4"],
                )
            )
    except Exception as e:
        result.error = str(e)

    return result


def check_users_mfa(provider: AWSProvider) -> CheckResult:
    """Check if all IAM users with console access have MFA enabled."""
    iam = provider.client("iam")
    result = CheckResult(check_id="aws-iam-002", check_name="IAM users MFA")

    try:
        account_id = provider.get_account_id()
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
                                    f"--serial-number arn:aws:iam::{account_id}:mfa/{username}-mfa "
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
                            compliance_refs=["CIS 1.10"],
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def check_access_keys_rotation(provider: AWSProvider) -> CheckResult:
    """Check if access keys are older than 90 days."""
    iam = provider.client("iam")
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
    """Check for access keys that haven't been used in 45+ days (CIS 1.12)."""
    iam = provider.client("iam")
    result = CheckResult(check_id="aws-iam-004", check_name="Unused access keys")

    try:
        now = datetime.now(timezone.utc)
        max_unused_days = 45  # CIS 1.12 requires 45 days
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
    iam = provider.client("iam")
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
    iam = provider.client("iam")
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
                    compliance_refs=["CIS 1.8", "CIS 1.9"],
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
        if policy.get("PasswordReusePrevention", 0) < 24:
            reuse_val = policy.get("PasswordReusePrevention", 0)
            issues.append(f"password reuse prevention {reuse_val} (should be >= 24)")

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
                    compliance_refs=["CIS 1.8", "CIS 1.9"],
                )
            )
    except Exception as e:
        result.error = str(e)

    return result


_OIDC_PROVIDER_NAMES: dict[str, str] = {
    "token.actions.githubusercontent.com": "GitHub Actions",
    "gitlab.com": "GitLab CI/CD",
    "oidc.circleci.com": "CircleCI",
    "app.terraform.io": "Terraform Cloud",
}


def _extract_oidc_url(federated_value: str) -> str | None:
    """Extract OIDC provider URL from a Federated principal ARN.

    Handles: arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com
    Returns the provider URL portion, or None if not an OIDC provider.
    """
    if ":oidc-provider/" in federated_value:
        return federated_value.split(":oidc-provider/", 1)[1]
    return None


def _get_provider_display_name(oidc_url: str) -> str:
    """Return human-readable name for a known OIDC provider, or the URL itself."""
    for prefix, name in _OIDC_PROVIDER_NAMES.items():
        if oidc_url == prefix or oidc_url.startswith(prefix + "/"):
            return name
    return oidc_url


def _has_sub_condition(condition: dict[str, object], provider_url: str) -> bool:
    """Check if any condition operator restricts the 'sub' claim for this OIDC provider."""
    sub_key = f"{provider_url}:sub"
    return any(isinstance(values, dict) and sub_key in values for _operator, values in condition.items())


def check_oidc_trust_policy(provider: AWSProvider) -> CheckResult:
    """Check IAM roles with OIDC federation for missing 'sub' condition.

    Roles federated with OIDC providers (GitHub Actions, GitLab CI, etc.) that only
    validate the 'aud' claim but not 'sub' allow ANY repository on the platform to
    assume the role. Google's UNC6426 threat actor exploited this exact pattern.
    """
    iam = provider.client("iam")
    result = CheckResult(check_id="aws-iam-007", check_name="OIDC trust policy without sub condition")

    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                role_name = role["RoleName"]
                role_arn = role["Arn"]

                trust_policy = role.get("AssumeRolePolicyDocument", {})
                if isinstance(trust_policy, str):
                    trust_policy = json.loads(trust_policy)

                statements = trust_policy.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                for stmt in statements:
                    if stmt.get("Effect") != "Allow":
                        continue

                    principal = stmt.get("Principal", {})
                    if isinstance(principal, str):
                        continue

                    federated = principal.get("Federated", [])
                    if isinstance(federated, str):
                        federated = [federated]

                    for fed_value in federated:
                        oidc_url = _extract_oidc_url(fed_value)
                        if oidc_url is None:
                            continue

                        result.resources_scanned += 1
                        display_name = _get_provider_display_name(oidc_url)
                        condition = stmt.get("Condition", {})

                        if not _has_sub_condition(condition, oidc_url):
                            result.findings.append(
                                Finding(
                                    check_id="aws-iam-007",
                                    title=f"Role '{role_name}' allows any {display_name} repo to assume it",
                                    severity=Severity.CRITICAL,
                                    category=Category.SECURITY,
                                    resource_type="AWS::IAM::Role",
                                    resource_id=role_arn,
                                    description=(
                                        f"Role '{role_name}' trusts OIDC provider {display_name} "
                                        f"({oidc_url}) without restricting the 'sub' claim. "
                                        f"Any repository on the platform can assume this role and "
                                        f"access all attached permissions. "
                                        f"Google documented threat actor UNC6426 exploiting this "
                                        f"pattern to escalate from npm package compromise to full "
                                        f"AWS admin access."
                                    ),
                                    recommendation=(
                                        f"Add a '{oidc_url}:sub' condition to the trust policy "
                                        f"restricting access to specific repositories and branches."
                                    ),
                                    remediation=Remediation(
                                        cli=(
                                            f"# 1. Get current trust policy:\n"
                                            f"aws iam get-role --role-name {role_name} "
                                            f"--query 'Role.AssumeRolePolicyDocument' > trust-policy.json\n"
                                            f"# 2. Add to Condition.StringEquals (or StringLike for wildcards):\n"
                                            f'#    "{oidc_url}:sub": '
                                            f'"repo:YOUR_ORG/YOUR_REPO:ref:refs/heads/main"\n'
                                            f"# 3. Apply:\n"
                                            f"aws iam update-assume-role-policy "
                                            f"--role-name {role_name} "
                                            f"--policy-document file://trust-policy.json"
                                        ),
                                        terraform=(
                                            f"# Add 'sub' condition to restrict OIDC federation:\n"
                                            f'resource "aws_iam_role" "{role_name}" {{\n'
                                            f'  name = "{role_name}"\n'
                                            f"\n"
                                            f"  assume_role_policy = jsonencode({{\n"
                                            f'    Version = "2012-10-17"\n'
                                            f"    Statement = [{{\n"
                                            f'      Effect = "Allow"\n'
                                            f"      Principal = {{\n"
                                            f'        Federated = "{fed_value}"\n'
                                            f"      }}\n"
                                            f'      Action = "sts:AssumeRoleWithWebIdentity"\n'
                                            f"      Condition = {{\n"
                                            f"        StringEquals = {{\n"
                                            f'          "{oidc_url}:aud" = "sts.amazonaws.com"\n'
                                            f'          "{oidc_url}:sub" = '
                                            f'"repo:YOUR_ORG/YOUR_REPO:ref:refs/heads/main"\n'
                                            f"        }}\n"
                                            f"      }}\n"
                                            f"    }}]\n"
                                            f"  }})\n"
                                            f"}}"
                                        ),
                                        doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html",
                                        effort=Effort.LOW,
                                    ),
                                )
                            )
    except Exception as e:
        result.error = str(e)

    return result


def check_multiple_active_keys(provider: AWSProvider) -> CheckResult:
    """Check if any IAM user has more than one active access key (CIS 1.13)."""
    iam = provider.client("iam")
    result = CheckResult(check_id="aws-iam-009", check_name="Multiple active access keys")

    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                try:
                    keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
                except Exception:
                    continue
                active_keys = [k for k in keys if k["Status"] == "Active"]
                result.resources_scanned += 1

                if len(active_keys) > 1:
                    key_ids = ", ".join(k["AccessKeyId"] for k in active_keys)
                    result.findings.append(
                        Finding(
                            check_id="aws-iam-009",
                            title=f"User '{username}' has {len(active_keys)} active access keys",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            resource_type="AWS::IAM::User",
                            resource_id=username,
                            description=(
                                f"User '{username}' has {len(active_keys)} active access keys ({key_ids}). "
                                f"Multiple active keys increase the attack surface and make key management harder."
                            ),
                            recommendation="Deactivate the older access key after confirming the newer one is in use.",
                            remediation=Remediation(
                                cli=(
                                    f"# Deactivate the older key (keep the newer one):\n"
                                    f"aws iam update-access-key --user-name {username} "
                                    f"--access-key-id {active_keys[0]['AccessKeyId']} --status Inactive"
                                ),
                                terraform=(
                                    "# Manage access keys in Terraform to enforce single-key policy:\n"
                                    f'resource "aws_iam_access_key" "{username}" {{\n'
                                    f'  user = "{username}"\n'
                                    f"}}"
                                ),
                                doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
                                effort=Effort.LOW,
                            ),
                            compliance_refs=["CIS 1.13"],
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def check_user_direct_policies(provider: AWSProvider) -> CheckResult:
    """Check if IAM users have policies attached directly instead of through groups (CIS 1.15)."""
    iam = provider.client("iam")
    result = CheckResult(check_id="aws-iam-010", check_name="Direct user policies")

    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                result.resources_scanned += 1

                inline_policies = iam.list_user_policies(UserName=username)["PolicyNames"]
                attached_policies = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]

                if inline_policies or attached_policies:
                    policy_names = [*inline_policies, *(p["PolicyName"] for p in attached_policies)]
                    result.findings.append(
                        Finding(
                            check_id="aws-iam-010",
                            title=f"User '{username}' has {len(policy_names)} direct policy attachment(s)",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            resource_type="AWS::IAM::User",
                            resource_id=username,
                            description=(
                                f"User '{username}' has policies attached directly: {', '.join(policy_names)}. "
                                f"Direct policy attachments bypass group-based access control and make "
                                f"permission auditing difficult."
                            ),
                            recommendation="Move policies to IAM groups and add users to appropriate groups instead.",
                            remediation=Remediation(
                                cli=(
                                    "# Detach policies from user and attach to a group:\n"
                                    + (
                                        "\n".join(
                                            f"aws iam detach-user-policy --user-name {username} --policy-arn {p['PolicyArn']}"
                                            for p in attached_policies
                                        )
                                        if attached_policies
                                        else "# No attached policies to detach"
                                    )
                                    + "\n"
                                    + (
                                        "\n".join(
                                            f"aws iam delete-user-policy --user-name {username} --policy-name {p}"
                                            for p in inline_policies
                                        )
                                        if inline_policies
                                        else "# No inline policies to delete"
                                    )
                                    + f"\n# Then add user to appropriate group:\n"
                                    f"aws iam add-user-to-group --user-name {username} --group-name APPROPRIATE_GROUP"
                                ),
                                terraform=(
                                    f"# Use group membership instead of direct policy attachment:\n"
                                    f'resource "aws_iam_group_membership" "{username}" {{\n'
                                    f'  name  = "{username}-membership"\n'
                                    f'  users = ["{username}"]\n'
                                    f"  group = aws_iam_group.developers.name\n"
                                    f"}}"
                                ),
                                doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#use-groups-for-permissions",
                                effort=Effort.MEDIUM,
                            ),
                            compliance_refs=["CIS 1.15"],
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def check_support_role(provider: AWSProvider) -> CheckResult:
    """Check if a support role with AWSSupportAccess policy exists (CIS 1.17)."""
    iam = provider.client("iam")
    result = CheckResult(check_id="aws-iam-011", check_name="Support role exists")

    try:
        account_id = provider.get_account_id()
        result.resources_scanned = 1
        support_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
        try:
            entities = iam.list_entities_for_policy(PolicyArn=support_arn)
            has_role = len(entities.get("PolicyRoles", [])) > 0
            has_user = len(entities.get("PolicyUsers", [])) > 0
            has_group = len(entities.get("PolicyGroups", [])) > 0
        except Exception as exc:
            error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if error_code in ("AccessDenied", "AccessDeniedException"):
                result.error = "Missing permission: iam:ListEntitiesForPolicy"
                return result
            has_role = False
            has_user = False
            has_group = False

        if not (has_role or has_user or has_group):
            result.findings.append(
                Finding(
                    check_id="aws-iam-011",
                    title="No IAM entity has AWSSupportAccess policy attached",
                    severity=Severity.MEDIUM,
                    category=Category.SECURITY,
                    resource_type="AWS::IAM::Policy",
                    resource_id="AWSSupportAccess",
                    description=(
                        "No IAM role, user, or group has the AWSSupportAccess managed policy attached. "
                        "This means no one can manage incidents through AWS Support."
                    ),
                    recommendation="Create a support role and attach the AWSSupportAccess policy.",
                    remediation=Remediation(
                        cli=(
                            "aws iam create-role --role-name aws-support-role "
                            f'--assume-role-policy-document \'{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{account_id}:root"}},"Action":"sts:AssumeRole"}}]}}\'\n'
                            "aws iam attach-role-policy --role-name aws-support-role "
                            "--policy-arn arn:aws:iam::aws:policy/AWSSupportAccess"
                        ),
                        terraform=(
                            'resource "aws_iam_role" "support" {\n'
                            '  name = "aws-support-role"\n'
                            "  assume_role_policy = jsonencode({\n"
                            '    Version = "2012-10-17"\n'
                            "    Statement = [{\n"
                            '      Effect    = "Allow"\n'
                            '      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }\n'
                            '      Action    = "sts:AssumeRole"\n'
                            "    }]\n"
                            "  })\n"
                            "}\n\n"
                            'resource "aws_iam_role_policy_attachment" "support" {\n'
                            "  role       = aws_iam_role.support.name\n"
                            '  policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"\n'
                            "}"
                        ),
                        doc_url="https://docs.aws.amazon.com/awssupport/latest/user/getting-started.html",
                        effort=Effort.LOW,
                    ),
                    compliance_refs=["CIS 1.17"],
                )
            )
    except Exception as e:
        result.error = str(e)

    return result


def check_iam_access_analyzer(provider: AWSProvider) -> CheckResult:
    """Check if IAM Access Analyzer is enabled in all regions (CIS 1.20)."""
    result = CheckResult(check_id="aws-iam-012", check_name="IAM Access Analyzer enabled")

    try:
        for region in provider.regions:
            result.resources_scanned += 1
            try:
                aa = provider.client("accessanalyzer", region_name=region)
                analyzers = aa.list_analyzers(type="ACCOUNT")["analyzers"]
                active_analyzers = [a for a in analyzers if a.get("status") == "ACTIVE"]
            except Exception as exc:
                error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if error_code in ("AccessDenied", "AccessDeniedException"):
                    result.error = "Missing permission: access-analyzer:ListAnalyzers"
                    return result
                active_analyzers = []

            if not active_analyzers:
                result.findings.append(
                    Finding(
                        check_id="aws-iam-012",
                        title=f"IAM Access Analyzer not enabled in {region}",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        resource_type="AWS::AccessAnalyzer::Analyzer",
                        resource_id=region,
                        region=region,
                        description=(
                            f"No active IAM Access Analyzer found in {region}. "
                            f"Access Analyzer identifies resources shared with external entities "
                            f"(S3 buckets, IAM roles, KMS keys, Lambda functions, SQS queues)."
                        ),
                        recommendation=f"Enable IAM Access Analyzer in {region}.",
                        remediation=Remediation(
                            cli=(
                                f"aws accessanalyzer create-analyzer "
                                f"--analyzer-name account-analyzer "
                                f"--type ACCOUNT "
                                f"--region {region}"
                            ),
                            terraform=(
                                'resource "aws_accessanalyzer_analyzer" "account" {\n'
                                '  analyzer_name = "account-analyzer"\n'
                                '  type          = "ACCOUNT"\n'
                                "}"
                            ),
                            doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html",
                            effort=Effort.LOW,
                        ),
                        compliance_refs=["CIS 1.20"],
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def check_expired_certificates(provider: AWSProvider) -> CheckResult:
    """Check for expired SSL/TLS certificates in IAM (CIS 1.19)."""
    iam = provider.client("iam")
    result = CheckResult(check_id="aws-iam-013", check_name="Expired SSL/TLS certificates")

    try:
        now = datetime.now(timezone.utc)
        paginator = iam.get_paginator("list_server_certificates")

        for page in paginator.paginate():
            for cert in page["ServerCertificateMetadataList"]:
                result.resources_scanned += 1
                cert_name = cert["ServerCertificateName"]
                cert_id = cert["ServerCertificateId"]
                expiration = cert["Expiration"]

                if expiration < now:
                    days_expired = (now - expiration).days
                    result.findings.append(
                        Finding(
                            check_id="aws-iam-013",
                            title=f"SSL/TLS certificate '{cert_name}' expired {days_expired} days ago",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            resource_type="AWS::IAM::ServerCertificate",
                            resource_id=cert_id,
                            description=(
                                f"Certificate '{cert_name}' expired on {expiration.strftime('%Y-%m-%d')}. "
                                f"Expired certificates should be removed to avoid accidental use."
                            ),
                            recommendation="Delete the expired certificate and replace with a valid one (prefer ACM).",
                            remediation=Remediation(
                                cli=f"aws iam delete-server-certificate --server-certificate-name {cert_name}",
                                terraform=(
                                    "# Use ACM instead of IAM certificates:\n"
                                    'resource "aws_acm_certificate" "cert" {\n'
                                    '  domain_name       = "example.com"\n'
                                    '  validation_method  = "DNS"\n'
                                    "}"
                                ),
                                doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html",
                                effort=Effort.LOW,
                            ),
                            compliance_refs=["CIS 1.19"],
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def check_root_hardware_mfa(provider: AWSProvider) -> CheckResult:
    """Check if root account uses hardware MFA (not virtual) (CIS 1.6)."""
    iam = provider.client("iam")
    result = CheckResult(check_id="aws-iam-015", check_name="Root hardware MFA")

    try:
        summary = iam.get_account_summary()["SummaryMap"]
        result.resources_scanned = 1

        # If root has no MFA at all, iam-001 handles that
        if summary.get("AccountMFAEnabled", 0) == 0:
            return result

        # Root has MFA - check if it's virtual
        mfa_devices = iam.list_virtual_mfa_devices()["VirtualMFADevices"]
        root_virtual_mfa = any(d.get("SerialNumber", "").endswith(":mfa/root-account-mfa-device") for d in mfa_devices)

        if root_virtual_mfa:
            result.findings.append(
                Finding(
                    check_id="aws-iam-015",
                    title="Root account uses virtual MFA instead of hardware MFA",
                    severity=Severity.MEDIUM,
                    category=Category.SECURITY,
                    resource_type="AWS::IAM::Root",
                    resource_id="root",
                    description=(
                        "The root account uses a virtual MFA device (software authenticator). "
                        "Hardware MFA devices (YubiKey, Gemalto) provide stronger protection "
                        "against phishing and device compromise."
                    ),
                    recommendation="Replace the virtual MFA with a hardware MFA device for the root account.",
                    remediation=Remediation(
                        cli=(
                            "# 1. Purchase a hardware MFA device (FIDO2 or TOTP)\n"
                            "# 2. Sign in as root to AWS Console\n"
                            "# 3. Go to: IAM > Security credentials > MFA\n"
                            "# 4. Remove current virtual MFA\n"
                            "# 5. Assign hardware MFA device"
                        ),
                        terraform=(
                            "# Root MFA cannot be managed via Terraform.\n# Use AWS Console to configure hardware MFA."
                        ),
                        doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html",
                        effort=Effort.MEDIUM,
                    ),
                    compliance_refs=["CIS 1.6"],
                )
            )
    except Exception as e:
        result.error = str(e)

    return result


def check_ec2_instance_roles(provider: AWSProvider) -> CheckResult:
    """Check if EC2 instances have IAM instance profiles (CIS 1.18)."""
    result = CheckResult(check_id="aws-iam-016", check_name="EC2 instance IAM roles")

    try:
        for region in provider.regions:
            ec2 = provider.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_instances")

            for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        instance_id = instance["InstanceId"]
                        result.resources_scanned += 1

                        if not instance.get("IamInstanceProfile"):
                            name_tag = next(
                                (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"),
                                instance_id,
                            )
                            result.findings.append(
                                Finding(
                                    check_id="aws-iam-016",
                                    title=f"EC2 instance '{name_tag}' has no IAM instance profile",
                                    severity=Severity.MEDIUM,
                                    category=Category.SECURITY,
                                    resource_type="AWS::EC2::Instance",
                                    resource_id=instance_id,
                                    region=region,
                                    description=(
                                        f"Instance {instance_id} ({name_tag}) in {region} does not have an "
                                        f"IAM instance profile attached. Without a role, applications on "
                                        f"this instance must use long-lived access keys instead of "
                                        f"temporary role credentials."
                                    ),
                                    recommendation="Attach an IAM instance profile with least-privilege permissions.",
                                    remediation=Remediation(
                                        cli=(
                                            f"# Create instance profile and attach to instance:\n"
                                            f"aws iam create-instance-profile --instance-profile-name {instance_id}-profile\n"
                                            f"aws iam add-role-to-instance-profile "
                                            f"--instance-profile-name {instance_id}-profile --role-name YOUR_ROLE\n"
                                            f"aws ec2 associate-iam-instance-profile "
                                            f"--instance-id {instance_id} "
                                            f"--iam-instance-profile Name={instance_id}-profile "
                                            f"--region {region}"
                                        ),
                                        terraform=(
                                            f'resource "aws_iam_instance_profile" "ec2" {{\n'
                                            f'  name = "{instance_id}-profile"\n'
                                            f"  role = aws_iam_role.ec2.name\n"
                                            f"}}\n\n"
                                            f'resource "aws_instance" "this" {{\n'
                                            f"  # ...\n"
                                            f"  iam_instance_profile = aws_iam_instance_profile.ec2.name\n"
                                            f"}}"
                                        ),
                                        doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html",
                                        effort=Effort.MEDIUM,
                                    ),
                                    compliance_refs=["CIS 1.18"],
                                )
                            )
    except Exception as e:
        result.error = str(e)

    return result


def check_cloudshell_access(provider: AWSProvider) -> CheckResult:
    """Check if AWSCloudShellFullAccess is attached to any entity (CIS 1.22)."""
    iam = provider.client("iam")
    result = CheckResult(check_id="aws-iam-014", check_name="CloudShell full access restricted")

    try:
        result.resources_scanned = 1
        cloudshell_arn = "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"
        try:
            entities = iam.list_entities_for_policy(PolicyArn=cloudshell_arn)
            attached_roles = entities.get("PolicyRoles", [])
            attached_users = entities.get("PolicyUsers", [])
            attached_groups = entities.get("PolicyGroups", [])
            total_attached = len(attached_roles) + len(attached_users) + len(attached_groups)
        except Exception as exc:
            error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if error_code in ("AccessDenied", "AccessDeniedException"):
                result.error = "Missing permission: iam:ListEntitiesForPolicy"
                return result
            total_attached = 0

        if total_attached > 0:
            entity_names = (
                [f"role:{r['RoleName']}" for r in attached_roles]
                + [f"user:{u['UserName']}" for u in attached_users]
                + [f"group:{g['GroupName']}" for g in attached_groups]
            )
            result.findings.append(
                Finding(
                    check_id="aws-iam-014",
                    title=f"AWSCloudShellFullAccess attached to {total_attached} entity/entities",
                    severity=Severity.MEDIUM,
                    category=Category.SECURITY,
                    resource_type="AWS::IAM::Policy",
                    resource_id="AWSCloudShellFullAccess",
                    description=(
                        f"AWSCloudShellFullAccess is attached to: {', '.join(entity_names)}. "
                        f"CloudShell provides a browser-based shell with your IAM credentials. "
                        f"Full access allows file upload/download which could be used for data exfiltration."
                    ),
                    recommendation="Replace AWSCloudShellFullAccess with a custom policy that restricts file transfer.",
                    remediation=Remediation(
                        cli=(
                            "# Detach AWSCloudShellFullAccess and use a restricted policy:\n"
                            + "\n".join(
                                [
                                    f"aws iam detach-role-policy --role-name {r['RoleName']} --policy-arn {cloudshell_arn}"
                                    for r in attached_roles
                                ]
                                + [
                                    f"aws iam detach-user-policy --user-name {u['UserName']} --policy-arn {cloudshell_arn}"
                                    for u in attached_users
                                ]
                                + [
                                    f"aws iam detach-group-policy --group-name {g['GroupName']} --policy-arn {cloudshell_arn}"
                                    for g in attached_groups
                                ]
                            )
                        ),
                        terraform=(
                            "# Use a restricted CloudShell policy instead:\n"
                            'resource "aws_iam_policy" "cloudshell_restricted" {\n'
                            '  name = "CloudShellRestricted"\n'
                            "  policy = jsonencode({\n"
                            '    Version = "2012-10-17"\n'
                            "    Statement = [\n"
                            '      { Effect = "Allow", Action = ["cloudshell:CreateEnvironment", "cloudshell:GetEnvironmentStatus"], Resource = "*" },\n'
                            '      { Effect = "Deny", Action = ["cloudshell:PutCredentials", "cloudshell:CreateSession"], Resource = "*" }\n'
                            "    ]\n"
                            "  })\n"
                            "}"
                        ),
                        doc_url="https://docs.aws.amazon.com/cloudshell/latest/userguide/sec-auth-with-identities.html",
                        effort=Effort.LOW,
                    ),
                    compliance_refs=["CIS 1.22"],
                )
            )
    except Exception as e:
        result.error = str(e)

    return result


def check_role_max_session_duration(provider: AWSProvider) -> CheckResult:
    """Check for IAM roles with MaxSessionDuration exceeding 1 hour."""
    iam = provider.client("iam")
    result = CheckResult(check_id="aws-iam-017", check_name="IAM role max session duration")

    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                role_name = role["RoleName"]
                role_path = role.get("Path", "/")

                # Skip service-linked roles
                if role_path.startswith("/aws-service-role/"):
                    continue

                result.resources_scanned += 1
                max_duration = role.get("MaxSessionDuration", 3600)

                if max_duration > 3600:
                    hours = max_duration / 3600
                    result.findings.append(
                        Finding(
                            check_id="aws-iam-017",
                            title=f"Role '{role_name}' has MaxSessionDuration of {hours:.0f}h ({max_duration}s)",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            resource_type="AWS::IAM::Role",
                            resource_id=role_name,
                            description=(
                                f"IAM role '{role_name}' has MaxSessionDuration set to "
                                f"{max_duration} seconds ({hours:.0f} hours). The default is "
                                f"1 hour (3600s). Extended session durations increase the window "
                                f"of opportunity for an attacker using stolen temporary credentials."
                            ),
                            recommendation="Reduce MaxSessionDuration to 3600 seconds (1 hour) unless a longer session is specifically required.",
                            remediation=Remediation(
                                cli=(
                                    f"aws iam update-role \\\n"
                                    f"  --role-name {role_name} \\\n"
                                    f"  --max-session-duration 3600"
                                ),
                                terraform=(
                                    'resource "aws_iam_role" "this" {\n'
                                    f'  name                 = "{role_name}"\n'
                                    "  max_session_duration = 3600  # 1 hour\n"
                                    "  assume_role_policy   = data.aws_iam_policy_document.trust.json\n"
                                    "}"
                                ),
                                doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html#id_roles_use_view-role-max-session",
                                effort=Effort.LOW,
                            ),
                            compliance_refs=[],
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def check_privilege_escalation(provider: AWSProvider) -> CheckResult:
    """Check for IAM privilege escalation paths across users and roles."""
    result = CheckResult(check_id="aws-iam-018", check_name="IAM privilege escalation paths")

    try:
        from cloud_audit.providers.aws.iam_analyzer import analyze_escalation

        paths = analyze_escalation(provider)
        result.resources_scanned = 1  # Single API call scans entire account

        for path in paths:
            # Build remediation based on category
            if path.category.value == "passrole_service":
                cli_fix = (
                    f"# Remove iam:PassRole from {path.principal_type.lower()} '{path.principal_name}':\n"
                    f"# Review attached policies and remove or scope iam:PassRole to specific role ARNs."
                )
                tf_fix = (
                    '# Scope iam:PassRole to specific roles:\n# Resource = ["arn:aws:iam::ACCOUNT:role/specific-role"]'
                )
            elif path.category.value == "iam_self_mutation":
                cli_fix = (
                    f"# Remove {path.required_actions[0]} from {path.principal_type.lower()} "
                    f"'{path.principal_name}':\n"
                    f"# Review and restrict attached policies."
                )
                tf_fix = (
                    f"# Deny dangerous IAM mutations via SCP or permission boundary:\n"
                    f'# Action = ["{path.required_actions[0]}"]\n'
                    f'# Effect = "Deny"'
                )
            elif path.category.value == "resource_policy_abuse":
                cli_fix = (
                    f"# Restrict {path.required_actions[0]} for {path.principal_type.lower()} "
                    f"'{path.principal_name}':\n"
                    f"# Resource policy modifications enable cross-account/cross-principal abuse.\n"
                    f"# Scope this action to specific function/layer ARNs or remove entirely."
                )
                tf_fix = (
                    f"# Deny resource policy abuse via SCP or permission boundary:\n"
                    f'# Action = ["{path.required_actions[0]}"]\n'
                    f'# Effect = "Deny"'
                )
            elif path.category.value == "compute_hijack":
                cli_fix = (
                    f"# Restrict {', '.join(path.required_actions)} for "
                    f"{path.principal_type.lower()} '{path.principal_name}':\n"
                    f"# These actions allow taking over existing compute that holds a privileged role.\n"
                    f"# Scope to specific instance/project/service ARNs and require MFA where possible."
                )
                tf_fix = (
                    f"# Limit compute-hijack actions via permission boundary or SCP:\n"
                    f"# Action = {path.required_actions}\n"
                    f'# Effect = "Deny"\n'
                    f'# Condition = {{ Bool = {{ "aws:MultiFactorAuthPresent" = "false" }} }}'
                )
            elif path.category.value == "lateral_assume_role":
                cli_fix = (
                    f"# Tighten trust policy on role '{path.principal_name}':\n"
                    f"# 1. Replace wildcard/root principals with specific ARNs.\n"
                    f"# 2. Add sts:ExternalId condition for cross-account roles.\n"
                    f"# 3. Require aws:MultiFactorAuthPresent = true for sensitive roles.\n"
                    f"# Update via: aws iam update-assume-role-policy "
                    f"--role-name {path.principal_name} --policy-document file://trust-policy.json"
                )
                tf_fix = (
                    "# Example hardened trust policy (replace with concrete principals):\n"
                    'data "aws_iam_policy_document" "assume_role" {\n'
                    "  statement {\n"
                    '    effect = "Allow"\n'
                    "    principals {\n"
                    '      type        = "AWS"\n'
                    '      identifiers = ["arn:aws:iam::ACCOUNT:role/specific-caller"]\n'
                    "    }\n"
                    '    actions = ["sts:AssumeRole"]\n'
                    "    condition {\n"
                    '      test     = "StringEquals"\n'
                    '      variable = "sts:ExternalId"\n'
                    '      values   = ["unique-shared-secret"]\n'
                    "    }\n"
                    "    condition {\n"
                    '      test     = "Bool"\n'
                    '      variable = "aws:MultiFactorAuthPresent"\n'
                    '      values   = ["true"]\n'
                    "    }\n"
                    "  }\n"
                    "}"
                )
            else:
                cli_fix = (
                    f"# Remove {', '.join(path.required_actions)} from "
                    f"{path.principal_type.lower()} '{path.principal_name}'."
                )
                tf_fix = f"# Restrict or remove actions: {', '.join(path.required_actions)}"

            result.findings.append(
                Finding(
                    check_id="aws-iam-018",
                    title=(f"{path.principal_type} '{path.principal_name}' can escalate via {path.method}"),
                    severity=path.severity,
                    category=Category.SECURITY,
                    resource_type=f"AWS::IAM::{path.principal_type}",
                    resource_id=path.principal_arn,
                    description=(
                        f"{path.principal_type} '{path.principal_name}' has permissions to "
                        f"escalate privileges via {path.method}: {path.target_privilege}. "
                        f"Required actions: {', '.join(path.required_actions)}."
                    ),
                    recommendation=(
                        f"Remove or restrict {', '.join(path.required_actions)} for "
                        f"{path.principal_type.lower()} '{path.principal_name}'. "
                        f"Use permission boundaries or SCPs to prevent escalation."
                    ),
                    remediation=Remediation(
                        cli=cli_fix,
                        terraform=tf_fix,
                        doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html",
                        effort=Effort.MEDIUM,
                    ),
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
        make_check(check_root_access_keys, provider, check_id="aws-iam-008", category=Category.SECURITY),
        make_check(check_users_mfa, provider, check_id="aws-iam-002", category=Category.SECURITY),
        make_check(check_access_keys_rotation, provider, check_id="aws-iam-003", category=Category.SECURITY),
        make_check(check_unused_access_keys, provider, check_id="aws-iam-004", category=Category.SECURITY),
        make_check(check_overly_permissive_policy, provider, check_id="aws-iam-005", category=Category.SECURITY),
        make_check(check_weak_password_policy, provider, check_id="aws-iam-006", category=Category.SECURITY),
        make_check(check_oidc_trust_policy, provider, check_id="aws-iam-007", category=Category.SECURITY),
        make_check(check_multiple_active_keys, provider, check_id="aws-iam-009", category=Category.SECURITY),
        make_check(check_user_direct_policies, provider, check_id="aws-iam-010", category=Category.SECURITY),
        make_check(check_support_role, provider, check_id="aws-iam-011", category=Category.SECURITY),
        make_check(check_iam_access_analyzer, provider, check_id="aws-iam-012", category=Category.SECURITY),
        make_check(check_expired_certificates, provider, check_id="aws-iam-013", category=Category.SECURITY),
        make_check(check_cloudshell_access, provider, check_id="aws-iam-014", category=Category.SECURITY),
        make_check(check_root_hardware_mfa, provider, check_id="aws-iam-015", category=Category.SECURITY),
        make_check(check_ec2_instance_roles, provider, check_id="aws-iam-016", category=Category.SECURITY),
        make_check(check_role_max_session_duration, provider, check_id="aws-iam-017", category=Category.SECURITY),
        make_check(check_privilege_escalation, provider, check_id="aws-iam-018", category=Category.SECURITY),
    ]
