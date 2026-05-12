"""TF-003: AWSCompromisedKeyQuarantineV3 attached to principal.

AWS automatically attaches AWSCompromisedKeyQuarantineV3 to IAM users/roles when
its credential-exposure detection identifies leaked access keys (most commonly
from public GitHub commits). The policy explicitly denies dangerous actions
(IAM, EC2 launch, Lambda create, organizations changes) to limit blast radius
while the account owner rotates the keys.

Presence of this policy = AWS has CONFIRMED a credential leak. The account is
already in active incident-response state. cloud-audit surfaces this as CRITICAL
because operators frequently miss the email notification or assume it's a false
alarm.

References:
    - https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantineV3.html
    - https://permiso.io/blog/introducing-detention-dodger
    - https://aws.amazon.com/blogs/security/aws-credential-compromise-best-practices/
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


PATTERN_ID = "TF-003-quarantine-policy"
CHECK_ID = "aws-tf-003"
PATTERN_NAME = "AWS-attached credential quarantine policy"
PATTERN_SEVERITY = Severity.CRITICAL
DOC_URL = "https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantineV3.html"

# AWS attaches v1, v2, or v3 depending on detection vintage. v3 is current (2024+).
# v1/v2 may still appear on long-quarantined principals.
_QUARANTINE_POLICY_ARNS = frozenset(
    {
        "arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantine",
        "arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantineV2",
        "arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantineV3",
    }
)

_REFERENCES = [
    "https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantineV3.html",
    "https://permiso.io/blog/introducing-detention-dodger",
]


def _build_finding(
    principal_arn: str,
    principal_name: str,
    principal_type: str,
    quarantine_arn: str,
) -> Finding:
    policy_version = quarantine_arn.rsplit("/", 1)[-1]
    return Finding(
        check_id=CHECK_ID,
        title=f"{principal_type} '{principal_name}' has AWS credential quarantine policy attached",
        severity=PATTERN_SEVERITY,
        category=Category.THREAT,
        resource_type=f"AWS::IAM::{principal_type}",
        resource_id=principal_arn,
        region="global",
        description=(
            f"AWS has attached {policy_version} to {principal_type.lower()} '{principal_name}'. "
            "This is an automated response by AWS Trust & Safety when credential exposure is "
            "detected (typically a public GitHub commit, leaked log, or shared snapshot). "
            "The policy denies high-risk actions to contain blast radius, but the underlying "
            "credentials are STILL ACTIVE and may have been used by an attacker before quarantine."
        ),
        recommendation=(
            "Treat as confirmed credential compromise. (1) Immediately rotate all access keys "
            "for this principal. (2) Audit CloudTrail for unauthorized activity in the 24h "
            "preceding the policy attachment. (3) Review IAM Access Analyzer findings. "
            "(4) After remediation, detach the quarantine policy via the IAM console or CLI."
        ),
        remediation=Remediation(
            cli=(
                f"# 1) List active access keys (and deactivate any unknown):\n"
                f"aws iam list-access-keys --user-name {principal_name}\n"
                f"aws iam update-access-key --user-name {principal_name} \\\n"
                f"  --access-key-id <AKIA...> --status Inactive\n"
                f"\n# 2) Review CloudTrail for the last 24h of this principal's activity:\n"
                f"aws cloudtrail lookup-events \\\n"
                f"  --lookup-attributes AttributeKey=Username,AttributeValue={principal_name}\n"
                f"\n# 3) After rotation + audit, detach the quarantine policy:\n"
                f"aws iam detach-{principal_type.lower()}-policy \\\n"
                f"  --{principal_type.lower()}-name {principal_name} \\\n"
                f"  --policy-arn {quarantine_arn}"
            ),
            terraform=(
                "# Quarantine policy is attached BY AWS, not Terraform.\n"
                "# After incident response, remove any aws_iam_*_policy_attachment\n"
                "# referencing this policy from your state.\n"
                "# Terraform will NOT detach managed-by-AWS attachments - use AWS CLI."
            ),
            doc_url=DOC_URL,
            effort=Effort.HIGH,
        ),
        threat_pattern_id=PATTERN_ID,
        references=_REFERENCES,
    )


def _check_attached_policies(
    attached: list[dict[str, Any]],
    principal_arn: str,
    principal_name: str,
    principal_type: str,
) -> list[Finding]:
    findings: list[Finding] = []
    for policy in attached:
        arn = policy.get("PolicyArn", "")
        if arn in _QUARANTINE_POLICY_ARNS:
            findings.append(
                _build_finding(
                    principal_arn=principal_arn,
                    principal_name=principal_name,
                    principal_type=principal_type,
                    quarantine_arn=arn,
                )
            )
    return findings


def detect(provider: AWSProvider) -> CheckResult:
    """Scan all IAM users and roles for AWSCompromisedKeyQuarantine* policies.

    IAM is global - we use one client, no region iteration. Pagination is
    required (large accounts have >100 users/roles).
    """
    result = CheckResult(check_id=CHECK_ID, check_name=PATTERN_NAME)

    try:
        iam = provider.client("iam")

        # Users - paginated
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                user_arn = user["Arn"]
                result.resources_scanned += 1
                try:
                    attached = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
                    result.findings.extend(
                        _check_attached_policies(
                            attached=attached,
                            principal_arn=user_arn,
                            principal_name=username,
                            principal_type="User",
                        )
                    )
                except Exception as exc:
                    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                    if code in ("AccessDenied", "NoSuchEntity"):
                        continue
                    raise

        # Roles - paginated, skip service-linked roles (AWSServiceRole*) for noise reduction
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                role_name = role["RoleName"]
                if role_name.startswith("AWSServiceRole"):
                    continue
                role_arn = role["Arn"]
                result.resources_scanned += 1
                try:
                    attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
                    result.findings.extend(
                        _check_attached_policies(
                            attached=attached,
                            principal_arn=role_arn,
                            principal_name=role_name,
                            principal_type="Role",
                        )
                    )
                except Exception as exc:
                    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                    if code in ("AccessDenied", "NoSuchEntity"):
                        continue
                    raise

    except Exception as e:
        result.error = str(e)

    return result
