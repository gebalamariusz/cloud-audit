"""KMS security checks."""

from __future__ import annotations

import json
from functools import partial
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_kms_key_rotation(provider: AWSProvider) -> CheckResult:
    """Check if customer-managed KMS keys have automatic rotation enabled."""
    result = CheckResult(check_id="aws-kms-001", check_name="KMS key rotation")

    try:
        for region in provider.regions:
            kms = provider.session.client("kms", region_name=region)
            paginator = kms.get_paginator("list_keys")

            for page in paginator.paginate():
                for key_entry in page["Keys"]:
                    key_id = key_entry["KeyId"]

                    # Get key metadata to filter out AWS-managed keys
                    try:
                        key_meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                    except Exception:
                        continue

                    # Skip AWS-managed keys and keys pending deletion
                    manager = key_meta.get("KeyManager", "")
                    state = key_meta.get("KeyState", "")
                    if manager != "CUSTOMER" or state != "Enabled":
                        continue

                    # Skip asymmetric keys (rotation only applies to symmetric)
                    spec = key_meta.get("KeySpec", "SYMMETRIC_DEFAULT")
                    if spec != "SYMMETRIC_DEFAULT":
                        continue

                    result.resources_scanned += 1
                    key_arn = key_meta.get("Arn", key_id)

                    try:
                        rotation = kms.get_key_rotation_status(KeyId=key_id)
                        rotation_enabled = rotation.get("KeyRotationEnabled", False)
                    except Exception:
                        rotation_enabled = False

                    if not rotation_enabled:
                        result.findings.append(
                            Finding(
                                check_id="aws-kms-001",
                                title=f"KMS key rotation disabled for {key_id[:12]}...",
                                severity=Severity.MEDIUM,
                                category=Category.SECURITY,
                                resource_type="AWS::KMS::Key",
                                resource_id=key_arn,
                                region=region,
                                description=(
                                    f"Customer-managed KMS key {key_id} in {region} "
                                    "does not have automatic key rotation enabled."
                                ),
                                recommendation="Enable automatic key rotation.",
                                remediation=Remediation(
                                    cli=f"aws kms enable-key-rotation --key-id {key_id} --region {region}",
                                    terraform=(
                                        'resource "aws_kms_key" "example" {\n  # ...\n  enable_key_rotation = true\n}'
                                    ),
                                    doc_url="https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
                                    effort=Effort.LOW,
                                ),
                                compliance_refs=["CIS 3.6"],
                            )
                        )
    except Exception as e:
        result.error = str(e)

    return result


def check_kms_key_policy(provider: AWSProvider) -> CheckResult:
    """Check for KMS keys with overly permissive key policies (wildcard principal)."""
    result = CheckResult(check_id="aws-kms-002", check_name="KMS key policy")

    try:
        for region in provider.regions:
            kms = provider.session.client("kms", region_name=region)
            paginator = kms.get_paginator("list_keys")

            for page in paginator.paginate():
                for key_entry in page["Keys"]:
                    key_id = key_entry["KeyId"]

                    try:
                        key_meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                    except Exception:
                        continue

                    # Skip AWS-managed keys
                    if key_meta.get("KeyManager") != "CUSTOMER":
                        continue
                    if key_meta.get("KeyState") != "Enabled":
                        continue

                    result.resources_scanned += 1
                    key_arn = key_meta.get("Arn", key_id)

                    try:
                        policy_str = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
                        policy = json.loads(policy_str)
                    except Exception:
                        continue

                    # Check for wildcard principal in any statement
                    for stmt in policy.get("Statement", []):
                        if stmt.get("Effect") != "Allow":
                            continue
                        principal = stmt.get("Principal", {})
                        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                            # Check if condition limits access
                            if stmt.get("Condition"):
                                continue  # Has conditions, probably OK
                            result.findings.append(
                                Finding(
                                    check_id="aws-kms-002",
                                    title=f"KMS key {key_id[:12]}... has wildcard principal in policy",
                                    severity=Severity.HIGH,
                                    category=Category.SECURITY,
                                    resource_type="AWS::KMS::Key",
                                    resource_id=key_arn,
                                    region=region,
                                    description=(
                                        f"KMS key {key_id} in {region} has a key policy statement "
                                        "with Principal: '*' (no conditions). "
                                        "Any AWS principal can use this key."
                                    ),
                                    recommendation=("Restrict the key policy to specific accounts, roles, or users."),
                                    remediation=Remediation(
                                        cli=(
                                            f"# Get current policy:\n"
                                            f"aws kms get-key-policy --key-id {key_id} "
                                            f"--policy-name default --region {region} "
                                            f"--output text > policy.json\n"
                                            f"# Edit policy.json to replace '*' with specific ARNs\n"
                                            f"aws kms put-key-policy --key-id {key_id} "
                                            f"--policy-name default "
                                            f"--policy file://policy.json "
                                            f"--region {region}"
                                        ),
                                        terraform=(
                                            'resource "aws_kms_key" "example" {\n'
                                            "  policy = jsonencode({\n"
                                            "    Statement = [{\n"
                                            '      Effect    = "Allow"\n'
                                            "      Principal = {\n"
                                            '        AWS = "arn:aws:iam::ACCOUNT_ID:root"\n'
                                            "      }\n"
                                            '      Action   = "kms:*"\n'
                                            '      Resource = "*"\n'
                                            "    }]\n"
                                            "  })\n"
                                            "}"
                                        ),
                                        doc_url="https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html",
                                        effort=Effort.MEDIUM,
                                    ),
                                )
                            )
                            break  # One finding per key is enough
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all KMS checks bound to the provider."""
    checks: list[CheckFn] = [
        partial(check_kms_key_rotation, provider),
        partial(check_kms_key_policy, provider),
    ]
    for fn in checks:
        fn.category = Category.SECURITY
    return checks
