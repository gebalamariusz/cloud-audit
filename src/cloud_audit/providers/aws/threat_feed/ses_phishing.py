"""TF-001: SES phishing setup precursors.

The SES abuse campaigns documented by Wiz (September 2025) and BleepingComputer
(May 2026) follow a consistent pattern: an attacker compromises AWS
credentials, calls GetSendQuota to confirm out-of-sandbox status, then -
per Wiz's direct quote - "adds multiple domains as verified identities
using the CreateEmailIdentity API" so they can blast phishing through SES
from common prefixes (admin@, billing@, sales@, noreply@) on those domains.

We surface the precursor that is visible from the control plane: SES email
or domain identities verified RECENTLY. We do not have visibility into
whether the identity is benign (legitimate marketing setup) or malicious -
we flag at MEDIUM and let the operator triage.

Severity escalates to HIGH when BOTH of these are true:
- The account has production sending enabled (out of SES sandbox), so
  abuse would reach external recipients without the per-recipient
  verify-first restriction.
- The account has TWO OR MORE identities verified in the recent window
  (the "burst" pattern Wiz documented - attackers add multiple domains
  in quick succession, not one).

Severity does NOT escalate on "email identity without matching domain"
(an earlier draft of this detector used that signal - it was wrong;
Wiz documented attackers verifying domains, not single-email typosquats).

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

_BURST_THRESHOLD = 2
"""Number of recent verifications that triggers HIGH severity escalation.

Wiz documented attackers "adding multiple domains as verified identities"
in quick succession. Two or more recent verifications in the same account
matches that burst signature."""


def _build_finding(
    identity_name: str,
    identity_type: str,
    region: str,
    created_at: datetime,
    out_of_sandbox: bool,
    recent_burst_count: int,
) -> Finding:
    is_burst = recent_burst_count >= _BURST_THRESHOLD
    severity = Severity.HIGH if (out_of_sandbox and is_burst) else PATTERN_SEVERITY
    age_days = (datetime.now(timezone.utc) - created_at).days

    sandbox_note = (
        " The account has production sending enabled (out of SES sandbox), so messages "
        "from this identity reach external recipients without the per-recipient "
        "verify-first restriction."
        if out_of_sandbox
        else " The account is still in SES sandbox - external impact limited."
    )
    burst_note = (
        f" {recent_burst_count} identities have been verified in this account in the last "
        f"{_RECENT_DAYS} days - a burst pattern matching Wiz's documented incident where "
        "attackers added multiple domains as verified identities in quick succession."
        if is_burst
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
            f"SES identity '{identity_name}' was verified {age_days} days ago in {region}. "
            "The Wiz September 2025 research and BleepingComputer May 2026 follow-up "
            "document a consistent SES abuse pattern in stolen-credential incidents: "
            "attackers verify SES identities and blast phishing through SES so messages "
            f"carry AWS IP reputation.{sandbox_note}{burst_note} Confirm the verification "
            "was performed by an authorized operator."
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

    cutoff = datetime.now(timezone.utc) - timedelta(days=_RECENT_DAYS)

    # First pass: collect every recently-verified identity with its CreatedTimestamp.
    # The burst count is the SAME for every finding emitted from a single account scan -
    # it reflects the total recent activity in the SES inventory, which is the signature
    # Wiz documented (attackers add multiple identities, not one). We must count first
    # so that the count is correct on every emitted finding.
    recent_entries: list[tuple[str, datetime]] = []
    for identity in identities:
        scanned += 1
        name = identity.get("IdentityName", "")
        if not name:
            continue
        if not identity.get("VerifiedForSendingStatus", False):
            continue
        try:
            detail = ses.get_email_identity(EmailIdentity=name)
        except Exception:
            continue
        created_at = detail.get("CreatedTimestamp")
        if not isinstance(created_at, datetime):
            continue
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        if created_at < cutoff:
            continue
        recent_entries.append((name, created_at))

    recent_burst_count = len(recent_entries)
    if recent_burst_count == 0:
        return scanned, []

    for name, created_at in recent_entries:
        findings.append(
            _build_finding(
                identity_name=name,
                identity_type="email" if _is_email(name) else "domain",
                region=region,
                created_at=created_at,
                out_of_sandbox=out_of_sandbox,
                recent_burst_count=recent_burst_count,
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
