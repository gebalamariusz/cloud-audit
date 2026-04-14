"""Compliance assessment engine.

Maps scan findings to compliance framework controls and generates
compliance-specific reports with per-control evidence and remediation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from cloud_audit.compliance import load_framework
from cloud_audit.models import AttackChain, Finding, ScanReport  # noqa: TC001


@dataclass
class ControlResult:
    """Assessment result for a single compliance control."""

    control_id: str
    title: str
    section: str
    level: str  # "L1", "L2", ""
    assessment: str  # "Automated", "Manual", ""

    # Mapping
    check_ids: list[str]  # cloud-audit check IDs mapped to this control
    status: Literal["PASS", "FAIL", "PARTIAL", "NOT_ASSESSED"] = "NOT_ASSESSED"

    # Results
    findings: list[Finding] = field(default_factory=list)
    checks_passed: int = 0
    checks_failed: int = 0
    checks_total: int = 0

    # Compliance-specific output
    evidence_statement: str = ""
    manual_steps: str = ""
    cis_description: str = ""

    # Attack chain violations
    violated_by_chains: list[str] = field(default_factory=list)


@dataclass
class ComplianceReport:
    """Full compliance assessment for a framework."""

    framework_id: str
    framework_name: str
    version: str
    source_url: str
    disclaimer: str

    # Underlying scan
    scan_report: ScanReport

    # Metadata
    status: str = "stable"

    # Per-control results
    controls: list[ControlResult] = field(default_factory=list)

    # Summary
    controls_assessed: int = 0
    controls_passing: int = 0
    controls_failing: int = 0
    controls_partial: int = 0
    controls_not_assessed: int = 0

    # Attack chain context
    chain_violations: list[tuple[AttackChain, list[str]]] = field(default_factory=list)

    @property
    def readiness_score(self) -> float:
        """Percentage of assessed controls that pass."""
        if self.controls_assessed == 0:
            return 0.0
        return (self.controls_passing / self.controls_assessed) * 100

    @property
    def total_controls(self) -> int:
        return len(self.controls)


def build_compliance_report(
    framework_id: str,
    scan_report: ScanReport,
    attack_chains: list[AttackChain] | None = None,
) -> ComplianceReport:
    """Build a compliance report by mapping scan results to framework controls.

    Args:
        framework_id: Framework identifier (e.g., "cis_aws_v3")
        scan_report: The completed scan report
        attack_chains: Detected attack chains (optional, for chain-to-control mapping)

    Returns:
        ComplianceReport with per-control assessment
    """
    fw = load_framework(framework_id)

    report = ComplianceReport(
        framework_id=fw["framework_id"],
        framework_name=fw["framework_name"],
        version=fw.get("version", ""),
        source_url=fw.get("source_url", ""),
        disclaimer=fw.get("disclaimer", ""),
        status=fw.get("status", "stable"),
        scan_report=scan_report,
    )

    # Index scan findings by check_id
    findings_by_check: dict[str, list[Finding]] = {}
    for result in scan_report.results:
        for finding in result.findings:
            findings_by_check.setdefault(finding.check_id, []).append(finding)

    # Set of check_ids that were actually executed (even if they found nothing)
    executed_checks: set[str] = set()
    for result in scan_report.results:
        executed_checks.add(result.check_id)

    # Index attack chains
    chain_control_map: dict[str, list[str]] = {}
    if attack_chains:
        for chain_id, control_ids in fw.get("attack_chain_mappings", {}).items():
            chain_control_map[chain_id] = control_ids

    # Build per-control results
    controls_data: dict[str, Any] = fw.get("controls", {})
    for control_id, control_def in controls_data.items():
        check_ids = control_def.get("checks", [])

        cr = ControlResult(
            control_id=control_id,
            title=control_def.get("title", ""),
            section=control_def.get("section", ""),
            level=control_def.get("level", ""),
            assessment=control_def.get("assessment", ""),
            check_ids=check_ids,
            manual_steps=control_def.get("manual_steps", ""),
            cis_description=control_def.get("description", ""),
        )

        if not check_ids:
            # No automated checks for this control
            cr.status = "NOT_ASSESSED"
            cr.evidence_statement = (
                f"Control {control_id} requires manual assessment. No automated checks are available for this control."
            )
        else:
            # Check which mapped checks were executed and what they found
            mapped_findings: list[Finding] = []
            checks_executed = 0
            checks_with_findings = 0
            checks_errored = 0

            for cid in check_ids:
                if cid in executed_checks:
                    checks_executed += 1
                    # Check if the check errored (has error but no findings)
                    check_result = next((r for r in scan_report.results if r.check_id == cid), None)
                    if check_result and check_result.error:
                        checks_errored += 1
                        continue
                    check_findings = findings_by_check.get(cid, [])
                    if check_findings:
                        checks_with_findings += 1
                        mapped_findings.extend(check_findings)

            cr.findings = mapped_findings
            cr.checks_total = len(check_ids)
            cr.checks_passed = checks_executed - checks_with_findings - checks_errored
            cr.checks_failed = checks_with_findings

            if checks_executed == 0:
                cr.status = "NOT_ASSESSED"
                cr.evidence_statement = (
                    f"Control {control_id} has {len(check_ids)} automated check(s) mapped "
                    f"but none were executed in this scan."
                )
            elif checks_with_findings == 0:
                cr.status = "PASS"
                cr.evidence_statement = _generate_evidence(
                    control_id, cr.title, cr.checks_passed, cr.checks_total, [], control_def
                )
            elif checks_with_findings < checks_executed:
                cr.status = "PARTIAL"
                cr.evidence_statement = _generate_evidence(
                    control_id, cr.title, cr.checks_passed, cr.checks_total, mapped_findings, control_def
                )
            else:
                cr.status = "FAIL"
                cr.evidence_statement = _generate_evidence(
                    control_id, cr.title, cr.checks_passed, cr.checks_total, mapped_findings, control_def
                )

        # Map attack chain violations to this control
        if attack_chains:
            for chain in attack_chains:
                violated_controls = chain_control_map.get(chain.chain_id, [])
                if control_id in violated_controls:
                    cr.violated_by_chains.append(chain.chain_id)
                    seen_chains = {c.chain_id for c, _ in report.chain_violations}
                    if chain.chain_id not in seen_chains:
                        report.chain_violations.append((chain, violated_controls))

        report.controls.append(cr)

    # Compute summary
    for cr in report.controls:
        if cr.status == "PASS":
            report.controls_passing += 1
            report.controls_assessed += 1
        elif cr.status == "FAIL":
            report.controls_failing += 1
            report.controls_assessed += 1
        elif cr.status == "PARTIAL":
            report.controls_partial += 1
            report.controls_assessed += 1
        else:
            report.controls_not_assessed += 1

    return report


def _generate_evidence(
    control_id: str,
    title: str,
    passed: int,
    total: int,
    findings: list[Finding],
    control_def: dict[str, Any],
) -> str:
    """Generate an evidence statement for a control."""
    template = control_def.get("evidence_template", "")
    if template:
        try:
            findings_summary = ""
            if findings:
                finding_descs = [f"{f.severity.value}: {f.title}" for f in findings[:5]]
                findings_summary = "; ".join(finding_descs)
                if len(findings) > 5:
                    findings_summary += f" (+{len(findings) - 5} more)"
            return str(
                template.format(
                    pass_count=passed,
                    total_count=total,
                    fail_count=total - passed,
                    findings_summary=findings_summary,
                    resource_count=sum(1 for f in findings),
                )
            )
        except (KeyError, IndexError):
            pass

    # Fallback evidence
    if not findings:
        return (
            f"Control {control_id} ({title}) was assessed. "
            f"{passed}/{total} automated check(s) passed. No findings detected."
        )
    return (
        f"Control {control_id} ({title}) was assessed. "
        f"{passed}/{total} automated check(s) passed. "
        f"{len(findings)} finding(s) detected requiring remediation."
    )
