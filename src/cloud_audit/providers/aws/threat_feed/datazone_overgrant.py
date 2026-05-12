"""TF-010: AmazonDataZoneFullAccess attached to non-admin principals.

Amazon DataZone became GA in 2023 and was significantly expanded across 2024-2026.
The AmazonDataZoneFullAccess managed policy grants broad access to data lakes,
Glue catalogs, and underlying S3 storage - far more than typical "data analyst"
or "data engineer" personas need.

Permiso and Datadog research consistently flag DataZone full-access attachments
to non-admin principals as a frequent over-permission - operators attach the
"easy" managed policy during onboarding and forget to scope it down. Because
DataZone bridges identity, data catalog, and storage layers, an unauthorized
data exfiltration path opens the moment such a principal is compromised.

References:
    - https://docs.aws.amazon.com/datazone/latest/userguide/security-iam.html
    - https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonDataZoneFullAccess.html
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


PATTERN_ID = "TF-010-datazone-overgrant"
CHECK_ID = "aws-tf-010"
PATTERN_NAME = "AmazonDataZoneFullAccess attached to non-admin principal"
PATTERN_SEVERITY = Severity.HIGH
DOC_URL = "https://docs.aws.amazon.com/datazone/latest/userguide/security-iam.html"

_DATAZONE_FULL_ACCESS = "arn:aws:iam::aws:policy/AmazonDataZoneFullAccess"
_ADMIN_POLICIES = frozenset(
    {
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/job-function/Administrator",
    }
)

_REFERENCES = [
    "https://docs.aws.amazon.com/datazone/latest/userguide/security-iam.html",
    "https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonDataZoneFullAccess.html",
]


def _build_finding(principal_arn: str, principal_name: str, principal_type: str) -> Finding:
    return Finding(
        check_id=CHECK_ID,
        title=f"{principal_type} '{principal_name}' has AmazonDataZoneFullAccess",
        severity=PATTERN_SEVERITY,
        category=Category.THREAT,
        resource_type=f"AWS::IAM::{principal_type}",
        resource_id=principal_arn,
        region="global",
        description=(
            f"{principal_type} '{principal_name}' is attached to AmazonDataZoneFullAccess. "
            "This managed policy grants broad rights across DataZone domains, projects, "
            "asset publishing, and the underlying Glue catalog + S3 storage. Combined with "
            "DataZone's role in bridging identity to data, this single attachment effectively "
            "puts the entire data plane within reach of a single principal compromise. "
            "Most analyst/engineer personas need scoped access (e.g. AmazonDataZoneFullUserAccess "
            "or per-project roles), not the full administrative variant."
        ),
        recommendation=(
            "Replace AmazonDataZoneFullAccess with the least-privilege variant for the "
            "principal's role: AmazonDataZoneFullUserAccess for end-users, or a custom "
            "policy scoped to specific DataZone domains. Reserve full access for DataZone "
            "platform admins only and gate it behind IAM Identity Center JIT elevation."
        ),
        remediation=Remediation(
            cli=(
                f"# 1) Detach the over-permissive managed policy:\n"
                f"aws iam detach-{principal_type.lower()}-policy \\\n"
                f"  --{principal_type.lower()}-name {principal_name} \\\n"
                f"  --policy-arn {_DATAZONE_FULL_ACCESS}\n"
                f"\n# 2) Attach the user-scoped variant instead (or a custom policy):\n"
                f"aws iam attach-{principal_type.lower()}-policy \\\n"
                f"  --{principal_type.lower()}-name {principal_name} \\\n"
                f"  --policy-arn arn:aws:iam::aws:policy/AmazonDataZoneFullUserAccess"
            ),
            terraform=(
                f"# Replace the full-access attachment with the user-scoped variant:\n"
                f'resource "aws_iam_{principal_type.lower()}_policy_attachment" '
                f'"{principal_name.replace("-", "_")}_datazone" {{\n'
                f'  {principal_type.lower()}       = "{principal_name}"\n'
                f'  policy_arn = "arn:aws:iam::aws:policy/AmazonDataZoneFullUserAccess"\n'
                f"}}"
            ),
            doc_url=DOC_URL,
            effort=Effort.LOW,
        ),
        threat_pattern_id=PATTERN_ID,
        references=_REFERENCES,
    )


def _scan_principals(
    iam: Any,
    *,
    list_op: str,
    list_attached_op: str,
    name_field: str,
    arn_field: str,
    principal_type: str,
    skip_service_linked: bool = False,
) -> tuple[int, list[Finding]]:
    findings: list[Finding] = []
    scanned = 0
    paginator = iam.get_paginator(list_op)
    list_attached = getattr(iam, list_attached_op)

    for page in paginator.paginate():
        for principal in page.get("Users" if principal_type == "User" else "Roles", []):
            name = principal[name_field]
            if skip_service_linked and name.startswith("AWSServiceRole"):
                continue
            arn = principal[arn_field]
            scanned += 1
            try:
                attached = list_attached(**{f"{principal_type}Name": name}).get("AttachedPolicies", [])
            except Exception as exc:
                code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if code in ("AccessDenied", "NoSuchEntity"):
                    continue
                raise

            arns = {p.get("PolicyArn", "") for p in attached}
            if _DATAZONE_FULL_ACCESS not in arns:
                continue
            if arns & _ADMIN_POLICIES:
                # Already an admin - DataZone full access is redundant noise, not over-permission
                continue

            findings.append(_build_finding(principal_arn=arn, principal_name=name, principal_type=principal_type))

    return scanned, findings


def detect(provider: AWSProvider) -> CheckResult:
    """Scan IAM users + roles for AmazonDataZoneFullAccess on non-admin principals."""
    result = CheckResult(check_id=CHECK_ID, check_name=PATTERN_NAME)

    try:
        iam = provider.client("iam")

        scanned_users, user_findings = _scan_principals(
            iam,
            list_op="list_users",
            list_attached_op="list_attached_user_policies",
            name_field="UserName",
            arn_field="Arn",
            principal_type="User",
        )
        scanned_roles, role_findings = _scan_principals(
            iam,
            list_op="list_roles",
            list_attached_op="list_attached_role_policies",
            name_field="RoleName",
            arn_field="Arn",
            principal_type="Role",
            skip_service_linked=True,
        )

        result.resources_scanned = scanned_users + scanned_roles
        result.findings = user_findings + role_findings

    except Exception as e:
        result.error = str(e)

    return result
