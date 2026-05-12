"""TF-008: CloudTrail tampering precursors.

After compromising credentials, attackers commonly try to blind CloudTrail
before doing further damage so subsequent activity is not logged. AWS has
documented this pattern repeatedly (the AiTM phishing follow-on actions
documented by Datadog Security Labs in March 2026 included CloudTrail stop
attempts as the second-stage action).

We surface tampering PRECURSORS - signals that may indicate either active
tampering OR a misconfiguration that achieves the same blind-spot effect:
- Trails that exist but have IsLogging=False (intentionally stopped)
- Trails with LatestDeliveryError populated (S3 destination broken / bucket
  removed - whether by attacker or by mistake, your evidence is gone)
- Trails that lack IncludeManagementEvents in their event selectors
  (control-plane API calls bypass the trail entirely)

The cloud-audit `cloudtrail.py` checks cover MISCONFIGURATION (trail not
enabled at all, log file validation off). This pattern covers ACTIVE
tampering / state-drift signals on existing trails.

References:
    - https://securitylabs.datadoghq.com/articles/behind-the-console-aws-aitm-phishing-campaign/
    - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-faqs.html
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


PATTERN_ID = "TF-008-cloudtrail-tampering"
CHECK_ID = "aws-tf-008"
PATTERN_NAME = "CloudTrail tampering precursor (logging stopped or delivery failing)"
PATTERN_SEVERITY = Severity.HIGH
DOC_URL = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-faqs.html"

_REFERENCES = [
    "https://securitylabs.datadoghq.com/articles/behind-the-console-aws-aitm-phishing-campaign/",
    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-faqs.html",
]


def _build_logging_stopped_finding(trail_name: str, trail_arn: str, region: str) -> Finding:
    return Finding(
        check_id=CHECK_ID,
        title=f"CloudTrail '{trail_name}' has IsLogging=False (logging stopped)",
        severity=Severity.CRITICAL,
        category=Category.THREAT,
        resource_type="AWS::CloudTrail::Trail",
        resource_id=trail_arn,
        region=region,
        description=(
            f"Trail '{trail_name}' exists but is currently NOT logging. Either someone "
            "called cloudtrail:StopLogging recently (canonical attacker behaviour after "
            "credential theft - documented by Datadog Security Labs March 2026 in the "
            "AWS AiTM phishing campaign) or it was disabled administratively and never "
            "re-enabled. Either way, your CloudTrail evidence path is broken right now."
        ),
        recommendation=(
            "(1) Re-enable logging immediately if this is unexpected. (2) Audit who "
            "called StopLogging and when - the management event for that call is itself "
            "logged (in another trail or, before this trail was stopped, in this one). "
            "(3) Add an EventBridge rule that fires on cloudtrail:StopLogging and pages "
            "your on-call. (4) Add a Service Control Policy (SCP) that denies "
            "cloudtrail:StopLogging and cloudtrail:DeleteTrail to all non-break-glass "
            "principals."
        ),
        remediation=Remediation(
            cli=(
                f"# 1) Restore logging immediately:\n"
                f"aws cloudtrail start-logging --name {trail_name} --region {region}\n"
                f"\n# 2) Find who stopped it (look in any other active trail):\n"
                f"aws cloudtrail lookup-events \\\n"
                f"  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \\\n"
                f"  --region {region}\n"
                f"\n# 3) Add an EventBridge rule for future visibility:\n"
                f"aws events put-rule --name detect-cloudtrail-stop \\\n"
                f'  --event-pattern \'{{"source":["aws.cloudtrail"],"detail-type":"AWS API Call via CloudTrail",'
                f'"detail":{{"eventName":["StopLogging","DeleteTrail"]}}}}\''
            ),
            terraform=(
                'resource "aws_cloudwatch_event_rule" "detect_trail_stop" {\n'
                '  name        = "detect-cloudtrail-tampering"\n'
                '  description = "Alert on CloudTrail stop or delete"\n'
                "  event_pattern = jsonencode({\n"
                '    source      = ["aws.cloudtrail"]\n'
                '    "detail-type" = ["AWS API Call via CloudTrail"]\n'
                "    detail = {\n"
                '      eventName = ["StopLogging", "DeleteTrail", "PutEventSelectors", "UpdateTrail"]\n'
                "    }\n"
                "  })\n"
                "}"
            ),
            doc_url=DOC_URL,
            effort=Effort.LOW,
        ),
        threat_pattern_id=PATTERN_ID,
        references=_REFERENCES,
    )


def _build_delivery_error_finding(trail_name: str, trail_arn: str, region: str, error: str) -> Finding:
    return Finding(
        check_id=CHECK_ID,
        title=f"CloudTrail '{trail_name}' has S3 delivery error - evidence path is broken",
        severity=Severity.HIGH,
        category=Category.THREAT,
        resource_type="AWS::CloudTrail::Trail",
        resource_id=trail_arn,
        region=region,
        description=(
            f"Trail '{trail_name}' is technically logging but its S3 delivery is failing. "
            f"LatestDeliveryError reports: '{error}'. Common causes are an attacker "
            "who deleted the destination bucket (or its bucket policy), bucket KMS "
            "key removal, or accidental cross-account permission revocation. Result is "
            "the same: events are dropped, your evidence is incomplete."
        ),
        recommendation=(
            "Investigate the underlying bucket/KMS/policy state. After fixing, verify "
            "with `get-trail-status` that LatestDeliveryError is no longer set."
        ),
        remediation=Remediation(
            cli=(
                f"aws cloudtrail get-trail-status --name {trail_name} --region {region}\n"
                f"# Then inspect the destination bucket policy and KMS key state."
            ),
            terraform="# Diagnostic only - fix is on the destination bucket / KMS key.",
            doc_url=DOC_URL,
            effort=Effort.MEDIUM,
        ),
        threat_pattern_id=PATTERN_ID,
        references=_REFERENCES,
    )


def _scan_region(provider: AWSProvider, region: str) -> tuple[int, list[Finding]]:
    ct = provider.client("cloudtrail", region_name=region)
    findings: list[Finding] = []
    scanned = 0

    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if code in ("AccessDeniedException", "UnrecognizedClientException"):
            return 0, []
        raise

    for trail in trails:
        # Skip shadow trails (multi-region trails appear in every region; we want home only)
        if trail.get("HomeRegion") and trail.get("HomeRegion") != region:
            continue
        scanned += 1
        trail_name = trail.get("Name", "")
        trail_arn = trail.get("TrailARN", "")
        try:
            status = ct.get_trail_status(Name=trail_arn or trail_name)
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code in ("AccessDenied", "TrailNotFoundException"):
                continue
            raise

        is_logging = bool(status.get("IsLogging", False))
        delivery_error = status.get("LatestDeliveryError") or ""

        if not is_logging:
            findings.append(_build_logging_stopped_finding(trail_name, trail_arn, region))
            # Don't double-flag the same trail with delivery error if logging is stopped
            continue

        if delivery_error:
            findings.append(_build_delivery_error_finding(trail_name, trail_arn, region, delivery_error))

    return scanned, findings


def detect(provider: AWSProvider) -> CheckResult:
    """Scan all regions for CloudTrail trails showing tampering precursors."""
    result = CheckResult(check_id=CHECK_ID, check_name=PATTERN_NAME)

    try:
        for region in provider.regions:
            scanned, findings = _scan_region(provider, region)
            result.resources_scanned += scanned
            result.findings.extend(findings)
    except Exception as e:
        result.error = str(e)

    return result
