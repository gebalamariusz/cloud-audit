"""TF-001: SES phishing setup precursors.

The SES abuse campaigns documented by Wiz (May 2025) and BleepingComputer
(May 2026) follow a consistent pattern: an attacker compromises AWS
credentials, calls GetSendQuota to confirm out-of-sandbox status, verifies
a fresh email or domain identity (often a typosquat of a trusted brand),
and blasts phishing through SES so messages arrive with the trust signal
of AWS-IP-sourced delivery.

We surface the precursor that is visible from the control plane: SES email
identities verified RECENTLY in an account that has production sending
enabled. We do not have visibility into whether the identity is benign
(legitimate marketing setup) or malicious - we flag at MEDIUM and let the
operator triage.

Two stronger sub-signals raise severity to HIGH when present:
- Identity is an email address that doesn't match a domain identity in the
  same account (typosquats / one-off addresses are red flags)
- Account has elevated send quota (production sending out of sandbox)

References:
    - https://www.wiz.io/blog/wiz-discovers-cloud-email-abuse-campaign
    - https://www.bleepingcomputer.com/news/security/researchers-report-amazon-ses-abused-in-phishing-to-evade-detection/
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


PATTERN_ID = "TF-001-ses-phishing-setup"
CHECK_ID = "aws-tf-001"
PATTERN_NAME = "SES recently verified identity (phishing setup precursor)"
PATTERN_SEVERITY = Severity.MEDIUM
DOC_URL = "https://docs.aws.amazon.com/ses/latest/dg/sending-authorization.html"

_REFERENCES = [
    "https://www.wiz.io/blog/wiz-discovers-cloud-email-abuse-campaign",
    "https://www.bleepingcomputer.com/news/security/researchers-report-amazon-ses-abused-in-phishing-to-evade-detection/",
]

_RECENT_DAYS = 14
"""Verification considered 'recent' if created within this window.

14 days catches campaign-style bursts without flagging legitimate identities
that have been around for months."""


def _build_finding(
    identity_name: str,
    identity_type: str,
    region: str,
    created_at: datetime | None,
    out_of_sandbox: bool,
    is_email_no_matching_domain: bool,
) -> Finding:
    severity = Severity.HIGH if (out_of_sandbox and is_email_no_matching_domain) else PATTERN_SEVERITY
    age_str = "unknown age"
    if created_at:
        age_days = (datetime.now(timezone.utc) - created_at).days
        age_str = f"verified {age_days} days ago"

    sandbox_note = (
        " The account has production sending enabled (out of SES sandbox), so messages "
        "from this identity reach external recipients without the per-recipient "
        "verify-first restriction."
        if out_of_sandbox
        else " The account is still in SES sandbox - external impact limited."
    )
    typosquat_note = (
        " The identity is an EMAIL address with no matching DOMAIN identity in the same "
        "account - a common typosquat / one-off setup pattern in attacker-driven SES "
        "abuse campaigns."
        if is_email_no_matching_domain
        else ""
    )
    return Finding(
        check_id=CHECK_ID,
        title=f"SES {identity_type} identity '{identity_name}' verified recently in {region}",
        severity=severity,
        category=Category.THREAT,
        resource_type=f"AWS::SES::{identity_type.capitalize()}Identity",
        resource_id=f"ses:{region}:{identity_name}",
        region=region,
        description=(
            f"SES identity '{identity_name}' ({age_str}) is verified in {region}. The Wiz "
            "May 2025 research and BleepingComputer May 2026 follow-up document a "
            "consistent SES abuse pattern in stolen-credential incidents: attackers verify "
            "a fresh identity to send phishing through SES so messages carry AWS IP "
            f"reputation.{sandbox_note}{typosquat_note} Confirm the identity was created "
            "by an authorized operator."
        ),
        recommendation=(
            "(1) Confirm the verification was authorized by your team. (2) If unexpected, "
            "delete the identity (`aws sesv2 delete-email-identity`) and audit CloudTrail "
            "for VerifyEmailIdentity / CreateEmailIdentity events to identify the source "
            "principal. (3) Rotate any IAM credentials that have ses:Verify*, "
            "ses:CreateEmailIdentity, ses:SendEmail permissions. (4) Add a "
            "CloudWatch alarm on the SES Bounces and Complaints metrics."
        ),
        remediation=Remediation(
            cli=(
                f"# 1) Inspect the identity:\n"
                f"aws sesv2 get-email-identity --email-identity {identity_name} \\\n"
                f"  --region {region}\n"
                f"\n# 2) If unexpected, delete it:\n"
                f"aws sesv2 delete-email-identity --email-identity {identity_name} \\\n"
                f"  --region {region}\n"
                f"\n# 3) Find who verified it:\n"
                f"aws cloudtrail lookup-events \\\n"
                f"  --lookup-attributes AttributeKey=ResourceName,AttributeValue={identity_name} \\\n"
                f"  --region {region}"
            ),
            terraform=(
                "# SES identities are typically managed in code, not detached.\n"
                "# If this identity is unauthorized:\n"
                "#  1. Remove the matching aws_ses_email_identity / aws_sesv2_email_identity\n"
                "#     resource from your Terraform OR\n"
                "#  2. Run: terraform import to bring it under control + delete via plan."
            ),
            doc_url=DOC_URL,
            effort=Effort.LOW,
        ),
        threat_pattern_id=PATTERN_ID,
        references=_REFERENCES,
    )


def _is_email(identity: str) -> bool:
    return "@" in identity


def _scan_region(provider: AWSProvider, region: str) -> tuple[int, list[Finding]]:
    findings: list[Finding] = []
    scanned = 0

    try:
        ses = provider.client("sesv2", region_name=region)
    except Exception:
        return 0, []

    # Out-of-sandbox check: get_account once
    out_of_sandbox = False
    try:
        account = ses.get_account()
        out_of_sandbox = bool(account.get("ProductionAccessEnabled", False))
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if code in ("AccessDeniedException", "UnrecognizedClientException", "ValidationException"):
            return 0, []

    try:
        identities = ses.list_email_identities().get("EmailIdentities", [])
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if code in ("AccessDeniedException", "UnrecognizedClientException", "ValidationException"):
            return 0, []
        raise

    # Build set of verified domains (for typosquat detection)
    verified_domains = {i.get("IdentityName", "") for i in identities if i.get("IdentityType") == "DOMAIN"}

    cutoff = datetime.now(timezone.utc) - timedelta(days=_RECENT_DAYS)

    for identity in identities:
        scanned += 1
        name = identity.get("IdentityName", "")
        if not name:
            continue
        identity_type = identity.get("IdentityType", "EMAIL_ADDRESS")  # EMAIL_ADDRESS or DOMAIN
        if not identity.get("VerifiedForSendingStatus", False):
            continue  # Pending/failed identities aren't usable for phishing

        # Look up details for created timestamp
        try:
            detail = ses.get_email_identity(EmailIdentity=name)
        except Exception:
            continue
        created_at = detail.get("CreatedTimestamp")
        if not isinstance(created_at, datetime):
            # Some boto3 versions return raw datetime, others may return a string.
            # If we can't parse, skip rather than over-flag.
            continue
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        if created_at < cutoff:
            continue  # Not recent

        is_email_no_match = False
        if _is_email(name):
            domain_part = name.rsplit("@", 1)[-1]
            is_email_no_match = domain_part not in verified_domains

        findings.append(
            _build_finding(
                identity_name=name,
                identity_type="email" if _is_email(name) else "domain",
                region=region,
                created_at=created_at,
                out_of_sandbox=out_of_sandbox,
                is_email_no_matching_domain=is_email_no_match,
            )
        )

    return scanned, findings


def detect(provider: AWSProvider) -> CheckResult:
    """Scan all regions for recently-verified SES identities (phishing setup precursor)."""
    result = CheckResult(check_id=CHECK_ID, check_name=PATTERN_NAME)

    try:
        for region in provider.regions:
            scanned, findings = _scan_region(provider, region)
            result.resources_scanned += scanned
            result.findings.extend(findings)
    except Exception as e:
        result.error = str(e)

    return result
