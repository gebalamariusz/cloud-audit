"""GuardDuty visibility checks."""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_guardduty_enabled(provider: AWSProvider) -> CheckResult:
    """Check if GuardDuty is enabled in each region."""
    result = CheckResult(check_id="aws-gd-001", check_name="GuardDuty enabled")

    try:
        for region in provider.regions:
            gd = provider.session.client("guardduty", region_name=region)
            result.resources_scanned += 1

            detectors = gd.list_detectors().get("DetectorIds", [])
            if not detectors:
                result.findings.append(
                    Finding(
                        check_id="aws-gd-001",
                        title=f"GuardDuty is not enabled in {region}",
                        severity=Severity.HIGH,
                        category=Category.SECURITY,
                        resource_type="AWS::GuardDuty::Detector",
                        resource_id=f"guardduty-{region}",
                        region=region,
                        description=(
                            f"GuardDuty is not enabled in {region}. "
                            "No threat detection for malicious activity or unauthorized behavior."
                        ),
                        recommendation="Enable GuardDuty in all active regions.",
                        remediation=Remediation(
                            cli=(f"aws guardduty create-detector --enable --region {region}"),
                            terraform=('resource "aws_guardduty_detector" "main" {\n  enable = true\n}'),
                            doc_url="https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html",
                            effort=Effort.LOW,
                        ),
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result


def check_guardduty_findings(provider: AWSProvider) -> CheckResult:
    """Check for unresolved GuardDuty findings older than 30 days."""
    result = CheckResult(check_id="aws-gd-002", check_name="GuardDuty unresolved findings")

    try:
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)

        for region in provider.regions:
            gd = provider.session.client("guardduty", region_name=region)
            detectors = gd.list_detectors().get("DetectorIds", [])

            for detector_id in detectors:
                result.resources_scanned += 1

                # Get active (non-archived) findings
                finding_ids = gd.list_findings(
                    DetectorId=detector_id,
                    FindingCriteria={
                        "Criterion": {
                            "service.archived": {"Eq": ["false"]},
                        }
                    },
                    MaxResults=50,
                ).get("FindingIds", [])

                if not finding_ids:
                    continue

                findings_detail = gd.get_findings(
                    DetectorId=detector_id,
                    FindingIds=finding_ids,
                ).get("Findings", [])

                old_findings = []
                for f in findings_detail:
                    created = f.get("CreatedAt", "")
                    if created:
                        try:
                            created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                            age_days = (now - created_dt).days
                            if age_days > 30:
                                old_findings.append((f, age_days))
                        except (ValueError, TypeError):
                            continue

                if old_findings:
                    severity_counts: dict[str, int] = {}
                    for f, _ in old_findings:
                        sev = f.get("Severity", 0)
                        if sev >= 7:
                            severity_counts["HIGH"] = severity_counts.get("HIGH", 0) + 1
                        elif sev >= 4:
                            severity_counts["MEDIUM"] = severity_counts.get("MEDIUM", 0) + 1
                        else:
                            severity_counts["LOW"] = severity_counts.get("LOW", 0) + 1

                    sev_str = ", ".join(f"{k}: {v}" for k, v in sorted(severity_counts.items()))
                    result.findings.append(
                        Finding(
                            check_id="aws-gd-002",
                            title=f"{len(old_findings)} unresolved GuardDuty finding(s) in {region} older than 30 days",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            resource_type="AWS::GuardDuty::Detector",
                            resource_id=detector_id,
                            region=region,
                            description=(
                                f"GuardDuty has {len(old_findings)} unresolved finding(s) older than 30 days "
                                f"in {region} ({sev_str}). Unresolved findings indicate potential threats "
                                "that have not been investigated."
                            ),
                            recommendation="Review and resolve GuardDuty findings. Archive investigated findings.",
                            remediation=Remediation(
                                cli=(
                                    f"# List active findings:\n"
                                    f"aws guardduty list-findings "
                                    f"--detector-id {detector_id} "
                                    f"--region {region}\n"
                                    f"# Archive after investigation:\n"
                                    f"aws guardduty archive-findings "
                                    f"--detector-id {detector_id} "
                                    f"--finding-ids FINDING_ID "
                                    f"--region {region}"
                                ),
                                terraform=(
                                    "# GuardDuty findings are operational, not managed by Terraform.\n"
                                    "# Use AWS Console or CLI to review and archive findings."
                                ),
                                doc_url="https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html",
                                effort=Effort.MEDIUM,
                            ),
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all GuardDuty checks bound to the provider."""
    checks: list[CheckFn] = [
        partial(check_guardduty_enabled, provider),
        partial(check_guardduty_findings, provider),
    ]
    for fn in checks:
        fn.category = Category.SECURITY
    return checks
