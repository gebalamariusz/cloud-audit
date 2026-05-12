"""TF-005: Recently-created IAM role with cryptomining-style compute access.

The November-December 2025 cryptomining campaign documented across The Hacker
News + The Register + Dark Reading shared a consistent IAM footprint: after
stealing credentials, attackers create a NEW IAM role within hours, attach
a broad EC2/PowerUser policy (so they can launch GPU instances or Lambdas
in any region), and then use it to spin up the actual mining workloads.

The campaign-specific signal is the SAME role having both EC2/Lambda compute
access AND the freshness window (created in the last 24-48 hours). Mature
operations rarely create admin-class roles ad-hoc; attacker post-credential-
theft scripts always do.

We flag at HIGH when a NEW role (CreateDate within last 48h) carries any of
the broad compute managed policies. We escalate to CRITICAL when the same
role ALSO has SES sending permissions (cryptomining + email spam combo
observed in the same campaign cluster).

References:
    - https://thehackernews.com/2025/12/compromised-iam-credentials-power-large.html
    - https://www.theregister.com/2025/12/18/crypto_crooks_use_stolen_aws/
    - https://www.darkreading.com/cloud-security/attackers-use-stolen-aws-credentials-cryptomining
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


PATTERN_ID = "TF-005-cryptomining-role"
CHECK_ID = "aws-tf-005"
PATTERN_NAME = "Recently-created IAM role with cryptomining-style compute access"
PATTERN_SEVERITY = Severity.HIGH
DOC_URL = "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"

_REFERENCES = [
    "https://thehackernews.com/2025/12/compromised-iam-credentials-power-large.html",
    "https://www.theregister.com/2025/12/18/crypto_crooks_use_stolen_aws/",
    "https://www.darkreading.com/cloud-security/attackers-use-stolen-aws-credentials-cryptomining",
]

_FRESHNESS_HOURS = 48
"""How recently the role must have been created to fit the campaign profile."""

_BROAD_COMPUTE_POLICIES = frozenset(
    {
        "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
        "arn:aws:iam::aws:policy/PowerUserAccess",
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/AmazonECS_FullAccess",
        "arn:aws:iam::aws:policy/AWSLambda_FullAccess",
    }
)

_SES_POLICIES = frozenset(
    {
        "arn:aws:iam::aws:policy/AmazonSESFullAccess",
        "arn:aws:iam::aws:policy/AdministratorAccess",  # admin includes SES
    }
)


def _build_finding(
    role_name: str,
    role_arn: str,
    created_at: datetime,
    matched_compute_policy: str,
    has_ses: bool,
) -> Finding:
    age_hours = int((datetime.now(timezone.utc) - created_at).total_seconds() // 3600)
    severity = Severity.CRITICAL if has_ses else PATTERN_SEVERITY
    ses_note = (
        " It also has SES sending permissions - matching the cryptomining-plus-email-spam "
        "combination observed in the same campaign cluster (mining for revenue + phishing "
        "from the compromised account in parallel)."
        if has_ses
        else ""
    )
    return Finding(
        check_id=CHECK_ID,
        title=f"Fresh IAM role '{role_name}' has broad compute access ({age_hours}h old)",
        severity=severity,
        category=Category.THREAT,
        resource_type="AWS::IAM::Role",
        resource_id=role_arn,
        region="global",
        description=(
            f"Role '{role_name}' was created {age_hours} hours ago and carries "
            f"{matched_compute_policy.rsplit('/', 1)[-1]}. The November-December 2025 "
            "cryptomining campaign (documented by The Hacker News, The Register, Dark "
            "Reading) followed this exact pattern: stolen credentials -> create new role "
            "with broad compute -> launch GPU instances / Lambda mining workloads in "
            f"every region.{ses_note} Investigate whether the role was created by an "
            "authorized operator. Mature CI/CD roles are rarely created with this scope ad-hoc."
        ),
        recommendation=(
            "(1) Confirm with your team that this role was created intentionally. (2) If "
            "unauthorized: detach the broad compute policy IMMEDIATELY (or delete the role), "
            "then audit CloudTrail for ec2:RunInstances, lambda:CreateFunction, ecs:RunTask "
            "events with this role as the principal in the same time window - those are "
            "your mining workloads to terminate. (3) Rotate the credentials of the principal "
            "that created the role (look up CreateRole in CloudTrail). (4) After containment, "
            "use AWS Cost Anomaly Detection to spot the mining spend spike."
        ),
        remediation=Remediation(
            cli=(
                f"# 1) Find what this role has been doing:\n"
                f"aws cloudtrail lookup-events \\\n"
                f"  --lookup-attributes AttributeKey=Username,AttributeValue={role_name}\n"
                f"\n# 2) Detach the broad policy:\n"
                f"aws iam detach-role-policy --role-name {role_name} \\\n"
                f"  --policy-arn {matched_compute_policy}\n"
                f"\n# 3) If the role itself is unauthorized, delete it:\n"
                f"#    (you must first detach all policies and remove from instance profiles)\n"
                f"aws iam delete-role --role-name {role_name}\n"
                f"\n# 4) Find who created it:\n"
                f"aws cloudtrail lookup-events \\\n"
                f"  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateRole \\\n"
                f"  --lookup-attributes AttributeKey=ResourceName,AttributeValue={role_name}"
            ),
            terraform=(
                "# If the role IS in your Terraform state but with surprising scope:\n"
                "#   1. Open the resource block, restrict the attached managed policy to\n"
                "#      a custom least-privilege policy, terraform plan + apply.\n"
                "# If the role is NOT in your Terraform state:\n"
                "#   1. Likely created out-of-band (legitimate emergency OR attacker).\n"
                "#   2. Confirm with your team. If unauthorized, delete via CLI above."
            ),
            doc_url=DOC_URL,
            effort=Effort.MEDIUM,
        ),
        threat_pattern_id=PATTERN_ID,
        references=_REFERENCES,
    )


def detect(provider: AWSProvider) -> CheckResult:
    """Scan IAM roles for the cryptomining-campaign profile: fresh + broad compute."""
    result = CheckResult(check_id=CHECK_ID, check_name=PATTERN_NAME)

    try:
        iam = provider.client("iam")
        cutoff = datetime.now(timezone.utc) - timedelta(hours=_FRESHNESS_HOURS)
        paginator = iam.get_paginator("list_roles")

        for page in paginator.paginate():
            for role in page.get("Roles", []):
                role_name = role["RoleName"]
                if role_name.startswith("AWSServiceRole"):
                    continue
                created_at = role.get("CreateDate")
                if not isinstance(created_at, datetime):
                    continue
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
                if created_at < cutoff:
                    continue  # Not fresh

                result.resources_scanned += 1
                try:
                    attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
                except Exception as exc:
                    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                    if code in ("AccessDenied", "NoSuchEntity"):
                        continue
                    raise

                arns = {p.get("PolicyArn", "") for p in attached}
                broad = next((a for a in arns if a in _BROAD_COMPUTE_POLICIES), None)
                if not broad:
                    continue

                has_ses = bool(arns & _SES_POLICIES)

                result.findings.append(
                    _build_finding(
                        role_name=role_name,
                        role_arn=role["Arn"],
                        created_at=created_at,
                        matched_compute_policy=broad,
                        has_ses=has_ses,
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result
