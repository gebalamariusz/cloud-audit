"""Markdown report generator for CI/CD and PR comments."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloud_audit.models import ScanReport

_SEVERITY_MARKERS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


def generate_markdown(report: ScanReport) -> str:
    """Generate a Markdown report string from a ScanReport."""
    from cloud_audit.models import Severity

    lines: list[str] = []
    s = report.summary

    # Header
    lines.append("# cloud-audit scan report")
    lines.append("")
    lines.append(f"**Provider:** {report.provider.upper()}")
    lines.append(f"**Account:** {report.account_id or 'unknown'}")
    if report.regions:
        lines.append(f"**Regions:** {', '.join(report.regions)}")
    lines.append(f"**Duration:** {report.duration_seconds:.1f}s")
    lines.append(f"**Health Score:** {s.score}/100")
    if s.total_risk_exposure and s.total_risk_exposure.high_usd > 0:
        lines.append(f"**Estimated Risk Exposure:** {s.total_risk_exposure.display}")
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Resources scanned | {s.resources_scanned} |")
    lines.append(f"| Checks passed | {s.checks_passed} |")
    lines.append(f"| Checks failed | {s.checks_failed} |")
    if s.checks_errored:
        lines.append(f"| Checks errored | {s.checks_errored} |")
    if s.coverage_gaps:
        lines.append(f"| Coverage gaps (reads denied, not assessed) | {s.coverage_gaps} |")
    lines.append(f"| Total findings | {s.total_findings} |")
    lines.append("")

    # Findings by severity
    if s.by_severity:
        lines.append("## Findings by severity")
        lines.append("")
        for sev in Severity:
            count = s.by_severity.get(sev, 0)
            if count:
                lines.append(f"- **{sev.value.upper()}:** {count}")
        lines.append("")

    # Attack chains
    if report.attack_chains:
        lines.append(f"## Attack Chains ({len(report.attack_chains)} detected)")
        lines.append("")
        lines.append("| Severity | Chain | Risk | Priority Fix |")
        lines.append("|----------|-------|------|--------------|")
        for chain in report.attack_chains:
            chain_sev = chain.severity.value.upper()
            name = chain.name.replace("|", "\\|").replace("\n", " ")
            cost = chain.cost_estimate.display if chain.cost_estimate and chain.cost_estimate.high_usd > 0 else "-"
            fix = chain.priority_fix.replace("|", "\\|").replace("\n", " ")
            lines.append(f"| **{chain_sev}** | {name} | {cost} | {fix} |")
        lines.append("")

    # Findings table
    findings = report.all_findings
    if findings:
        severity_order = list(Severity)
        sorted_findings = sorted(findings, key=lambda f: severity_order.index(f.severity))

        lines.append("## Findings")
        lines.append("")
        has_costs = any(f.cost_estimate for f in sorted_findings)

        if has_costs:
            lines.append("| Severity | Check | Resource | Title | Risk |")
            lines.append("|----------|-------|----------|-------|------|")
        else:
            lines.append("| Severity | Check | Region | Resource | Title |")
            lines.append("|----------|-------|--------|----------|-------|")

        for f in sorted_findings:
            marker = _SEVERITY_MARKERS.get(f.severity.value, f.severity.value)
            resource = f.resource_id[:40] + "..." if len(f.resource_id) > 40 else f.resource_id
            title = f.title[:50] + "..." if len(f.title) > 50 else f.title
            check_id = f.check_id.replace("|", "\\|").replace("\n", " ")
            region = f.region.replace("|", "\\|").replace("\n", " ")
            resource = resource.replace("|", "\\|").replace("\n", " ")
            title = title.replace("|", "\\|").replace("\n", " ")
            if has_costs and f.cost_estimate and f.cost_estimate.source_url:
                cost = f"[{f.cost_estimate.display}]({f.cost_estimate.source_url})"
                lines.append(f"| **{marker}** | {check_id} | `{resource}` | {title} | {cost} |")
            elif has_costs:
                lines.append(f"| **{marker}** | {check_id} | `{resource}` | {title} | - |")
            else:
                lines.append(f"| **{marker}** | {check_id} | {region} | `{resource}` | {title} |")

        lines.append("")
    else:
        lines.append("## Findings")
        lines.append("")
        lines.append("No issues found.")
        lines.append("")

    # CIS references
    cis_refs = sorted({ref for f in findings for ref in f.compliance_refs if ref.startswith("CIS")})
    if cis_refs:
        lines.append("## CIS Benchmark coverage")
        lines.append("")
        lines.append(f"Controls checked: {', '.join(cis_refs)}")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append("*Generated by [cloud-audit](https://github.com/gebalamariusz/cloud-audit)*")
    lines.append("")

    return "\n".join(lines)
