"""HTML report generator using Jinja2."""

from __future__ import annotations

import base64
import logging
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

from jinja2 import Environment, FileSystemLoader

from cloud_audit.models import Severity

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from cloud_audit.models import Finding, ScanReport

TEMPLATE_DIR = Path(__file__).parent / "templates"
LOGO_PATH = Path(__file__).parent.parent.parent.parent / "assets" / "logo-nobg.png"


def _build_executive_summary(sorted_findings: list[Finding], checks_passed: int) -> str:
    """Build a 2-3 sentence executive summary for non-technical readers."""
    if not sorted_findings:
        return f"No security issues detected. All {checks_passed} checks passed."

    critical = [f for f in sorted_findings if f.severity == Severity.CRITICAL]
    high = [f for f in sorted_findings if f.severity == Severity.HIGH]
    medium = [f for f in sorted_findings if f.severity == Severity.MEDIUM]

    if critical:
        most_urgent = critical[0]
        parts = [
            f"This account has {len(critical)} critical security"
            f" {'issue' if len(critical) == 1 else 'issues'} requiring immediate attention.",
            f"The most urgent: {most_urgent.title}.",
        ]
        extras = []
        if high:
            extras.append(f"{len(high)} high-severity")
        if medium:
            extras.append(f"{len(medium)} medium-severity")
        if extras:
            extra_count = len(high) + len(medium)
            verb = "issue was" if extra_count == 1 else "issues were"
            parts.append(f"An additional {' and '.join(extras)} {verb} found.")
        return " ".join(parts)

    if high:
        most_urgent = high[0]
        parts = [
            f"This account has {len(high)} high-severity"
            f" {'issue' if len(high) == 1 else 'issues'} that should be addressed this week.",
            f"The most important: {most_urgent.title}.",
        ]
        if medium:
            med_verb = "issue was" if len(medium) == 1 else "issues were"
            parts.append(f"An additional {len(medium)} medium-severity {med_verb} found.")
        return " ".join(parts)

    total = len(sorted_findings)
    noun = "issue" if total == 1 else "issues"
    return f"This account has {total} {noun} to review. No critical or high-severity problems were found."


def _build_priority_groups(sorted_findings: list[Finding]) -> list[dict[str, Any]]:
    """Group findings by urgency: Fix Now, Fix This Week, Plan for Next Sprint."""
    fix_now = [f for f in sorted_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    fix_this_week = [f for f in sorted_findings if f.severity == Severity.MEDIUM]
    plan_for_sprint = [f for f in sorted_findings if f.severity in (Severity.LOW, Severity.INFO)]

    groups = []
    if fix_now:
        groups.append(
            {
                "key": "fix_now",
                "label": "Fix Now",
                "description": "Critical and high-severity issues requiring immediate action",
                "color_class": "priority-critical",
                "findings": fix_now,
            }
        )
    if fix_this_week:
        groups.append(
            {
                "key": "fix_this_week",
                "label": "Fix This Week",
                "description": "Medium-severity issues to address soon",
                "color_class": "priority-medium",
                "findings": fix_this_week,
            }
        )
    if plan_for_sprint:
        groups.append(
            {
                "key": "plan_for_sprint",
                "label": "Plan for Next Sprint",
                "description": "Low-severity improvements and best practices",
                "color_class": "priority-low",
                "findings": plan_for_sprint,
            }
        )
    return groups


def _build_cis_status(all_findings: list[Finding], cis_controls: list[str]) -> list[dict[str, str]]:
    """Build pass/fail status for each CIS control."""
    failed_refs: set[str] = set()
    for f in all_findings:
        for ref in f.compliance_refs:
            if ref.startswith("CIS"):
                failed_refs.add(ref)

    return [{"ref": ref, "status": "fail" if ref in failed_refs else "pass"} for ref in cis_controls]


def _load_logo_base64() -> str | None:
    """Read logo.png from repo root and return base64 string, or None if missing."""
    try:
        if LOGO_PATH.is_file():
            return base64.b64encode(LOGO_PATH.read_bytes()).decode("ascii")
    except Exception:
        logger.debug("Could not load logo from %s", LOGO_PATH)
    return None


def render_html(report: ScanReport) -> str:
    """Render a ScanReport to a self-contained HTML string."""
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("report.html.j2")

    # Sort findings by severity for display
    severity_order = list(Severity)
    sorted_findings = sorted(report.all_findings, key=lambda f: severity_order.index(f.severity))

    # Group findings by category (kept for backwards compat)
    by_category: dict[str, list[object]] = defaultdict(list)
    for f in sorted_findings:
        by_category[f.category.value].append(f)

    # Collect unique CIS references across all findings
    cis_controls: list[str] = sorted(
        {ref for f in report.all_findings for ref in f.compliance_refs if ref.startswith("CIS")}
    )

    # Executive summary
    executive_summary = _build_executive_summary(sorted_findings, report.summary.checks_passed)

    # Priority groups
    priority_groups = _build_priority_groups(sorted_findings)

    # CIS pass/fail status
    cis_status = _build_cis_status(report.all_findings, cis_controls)

    # Logo (base64-embedded for self-contained HTML)
    logo_base64 = _load_logo_base64()

    return template.render(
        report=report,
        sorted_findings=sorted_findings,
        by_category=dict(by_category),
        severity_order=severity_order,
        cis_controls=cis_controls,
        executive_summary=executive_summary,
        priority_groups=priority_groups,
        cis_status=cis_status,
        attack_chains=report.attack_chains,
        root_causes=report.root_causes,
        logo_base64=logo_base64,
    )
