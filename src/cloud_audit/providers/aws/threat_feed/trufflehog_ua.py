"""TF-004: leaked-creds-discovery scanner user-agent in CloudTrail.

When credentials leak to public sources (GitHub commits, paste sites,
shipping logs), automated discovery tools immediately scrape and validate
them. The most common validation is `aws sts get-caller-identity` because
it requires zero permissions to call but tells the attacker who the
credentials belong to.

TruffleHog, gitleaks, NoseyParker and similar OFFENSIVE leaked-credentials
scanners *can* leave a recognisable user-agent substring when their HTTP
clients are invoked with a custom UA (e.g. TruffleHog's `--user-agent-suffix`
flag). TF-004 catches those cases.

DETECTION LIMITATION (be honest with yourself): when these scanners use the
stock AWS SDK / boto3 / aws-cli default user-agent, their calls look
identical to legitimate traffic and TF-004 will NOT flag them. Absence of a
hit does not mean nothing scanned your keys; presence of a hit is a strong
signal that something did. Pair this with TF-003 (quarantine policy) and
behavioural CloudTrail monitoring (e.g. Prowler's
`cloudtrail_threat_detection_enumeration`) for fuller coverage.

We deliberately exclude DEFENSIVE tools like Permiso's CloudGrappler and
DetentionDodger from the signature list - those running against your account
are your own (or your auditor's) and should not generate findings.

Seeing such a UA in CloudTrail = your credentials were likely validated by
an external offensive scanner = treat as confirmed exposure. We surface
CRITICAL because the next step in the attack chain is typically
CreateFunction / RunInstances / VerifyEmailIdentity within minutes.

References:
    - https://www.bleepingcomputer.com/news/security/researchers-report-amazon-ses-abused-in-phishing-to-evade-detection/
    - https://permiso.io/blog/introducing-detention-dodger
    - https://github.com/trufflesecurity/trufflehog
    - https://github.com/Cybr-Inc/fwdcloudsec-2025-summaries
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


PATTERN_ID = "TF-004-trufflehog-ua-cloudtrail"
CHECK_ID = "aws-tf-004"
PATTERN_NAME = "Leaked-credentials scanner user-agent observed in CloudTrail"
PATTERN_SEVERITY = Severity.CRITICAL
DOC_URL = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-record-contents.html"

_REFERENCES = [
    "https://www.bleepingcomputer.com/news/security/researchers-report-amazon-ses-abused-in-phishing-to-evade-detection/",
    "https://permiso.io/blog/introducing-detention-dodger",
    "https://github.com/trufflesecurity/trufflehog",
]

# Substrings (case-insensitive) in CloudTrail userAgent that indicate an
# OFFENSIVE leaked-credentials discovery scanner. DEFENSIVE tools
# (CloudGrappler, DetentionDodger) are intentionally excluded - operators
# running them against their own account are not the threat. Easy to extend
# as new offensive tools surface; resist the urge to add defensive ones.
_SCANNER_UA_SIGNATURES = (
    "trufflehog",
    "gitleaks",
    "noseyparker",
    "secretscanner",
)

# How far back to look. CloudTrail lookup_events keeps 90 days; we cap at 24h
# to keep the call lightweight and to focus on the actionable window
# (post-leak validation typically happens minutes after the credential leaks).
_LOOKBACK_HOURS = 24


def _build_finding(
    user_agent: str,
    principal_arn: str,
    event_time: datetime,
    region: str,
    source_ip: str,
) -> Finding:
    matched_sig = next((s for s in _SCANNER_UA_SIGNATURES if s in user_agent.lower()), "scanner")
    return Finding(
        check_id=CHECK_ID,
        title=f"Leaked-creds scanner ({matched_sig}) called sts:GetCallerIdentity as {principal_arn.rsplit('/', 1)[-1]}",
        severity=PATTERN_SEVERITY,
        category=Category.THREAT,
        resource_type="AWS::IAM::Principal",
        resource_id=principal_arn,
        region=region,
        description=(
            f"On {event_time.isoformat()} a CloudTrail event recorded a sts:GetCallerIdentity "
            f"call from user-agent '{user_agent}' (matches signature '{matched_sig}') "
            f"using credentials of {principal_arn}. Source IP: {source_ip}. The matching "
            "user-agent is the canonical signature of an automated leaked-credentials "
            "discovery scanner (TruffleHog and friends). This means your credentials are "
            "validated as live by an external automated tool - the next attack chain step "
            "(RunInstances, VerifyEmailIdentity, CreateFunction) typically follows within "
            "minutes."
        ),
        recommendation=(
            "TREAT AS CONFIRMED CREDENTIAL COMPROMISE. (1) Immediately rotate / deactivate "
            "the access keys for this principal. (2) Audit CloudTrail for ALL activity by "
            "this principal in the last 24 hours - assume any IAM/EC2/Lambda/SES action "
            "may have been the attacker. (3) Once contained, hunt for the leak source: "
            "inspect public GitHub commits, container image registries, CI logs, and "
            "shared snapshots for the exposed key. (4) Set up github push protection / "
            "secret-scanning to prevent re-leak."
        ),
        remediation=Remediation(
            cli=(
                "# 1) Identify and deactivate the principal's access keys:\n"
                "#    (replace USER with the username extracted from the ARN above)\n"
                "aws iam list-access-keys --user-name USER\n"
                "aws iam update-access-key --user-name USER \\\n"
                "  --access-key-id <AKIA...> --status Inactive\n"
                "\n# 2) Get the full activity timeline for this principal:\n"
                "aws cloudtrail lookup-events \\\n"
                "  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<AKIA...>"
            ),
            terraform=(
                "# Credential rotation lives outside Terraform. Once contained,\n"
                "# update your aws_iam_access_key resources OR move the principal\n"
                "# to short-lived credentials via IAM Identity Center / OIDC."
            ),
            doc_url=DOC_URL,
            effort=Effort.HIGH,
        ),
        threat_pattern_id=PATTERN_ID,
        references=_REFERENCES,
    )


def _ua_is_scanner(user_agent: str) -> bool:
    if not user_agent:
        return False
    ua_lower = user_agent.lower()
    return any(sig in ua_lower for sig in _SCANNER_UA_SIGNATURES)


def _scan_region(provider: AWSProvider, region: str, since: datetime) -> tuple[int, list[Finding]]:
    findings: list[Finding] = []
    scanned = 0

    try:
        ct = provider.client("cloudtrail", region_name=region)
    except Exception:
        return 0, []

    paginator = ct.get_paginator("lookup_events")

    try:
        pages = paginator.paginate(
            LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "GetCallerIdentity"}],
            StartTime=since,
        )
        # Convert to list to materialize errors during paginate, not later
        page_list = list(pages)
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if code in ("AccessDeniedException", "UnrecognizedClientException", "ValidationException"):
            return 0, []
        raise

    import json as _json

    for page in page_list:
        for event in page.get("Events", []):
            scanned += 1
            try:
                cloudtrail_event = _json.loads(event.get("CloudTrailEvent", "{}"))
            except Exception:
                continue
            user_agent = cloudtrail_event.get("userAgent", "")
            if not _ua_is_scanner(user_agent):
                continue

            user_identity = cloudtrail_event.get("userIdentity", {})
            principal_arn = user_identity.get("arn") or user_identity.get("principalId") or "unknown"
            event_time_raw = cloudtrail_event.get("eventTime", "")
            try:
                event_time = datetime.fromisoformat(event_time_raw.replace("Z", "+00:00"))
            except Exception:
                event_time = since
            source_ip = cloudtrail_event.get("sourceIPAddress", "unknown")

            findings.append(
                _build_finding(
                    user_agent=user_agent,
                    principal_arn=principal_arn,
                    event_time=event_time,
                    region=region,
                    source_ip=source_ip,
                )
            )

    return scanned, findings


def detect(provider: AWSProvider) -> CheckResult:
    """Scan CloudTrail across regions for leaked-credentials scanner user-agents in the last 24h."""
    result = CheckResult(check_id=CHECK_ID, check_name=PATTERN_NAME)
    since = datetime.now(timezone.utc) - timedelta(hours=_LOOKBACK_HOURS)

    try:
        for region in provider.regions:
            scanned, findings = _scan_region(provider, region, since)
            result.resources_scanned += scanned
            result.findings.extend(findings)
    except Exception as e:
        result.error = str(e)

    return result
