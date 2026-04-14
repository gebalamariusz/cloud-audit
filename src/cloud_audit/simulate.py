"""What-If Remediation Simulator.

Simulates the impact of applying a fix (removing all findings for a check_id)
on attack chains, health score, and risk exposure — without changing anything in AWS.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cloud_audit.models import (
    AttackChain,
    CheckResult,
    CostEstimateData,
    Finding,
    RootCauseFix,
    ScanReport,
    Severity,
)

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


@dataclass
class SimulationResult:
    """Before/after comparison of applying one or more fixes."""

    fix_check_ids: list[str]
    fix_titles: list[str]

    # Before
    score_before: int
    chains_before: int
    risk_before: CostEstimateData | None
    findings_before: int

    # After
    score_after: int
    chains_after: int
    risk_after: CostEstimateData | None
    findings_after: int

    # Delta
    chains_broken: list[AttackChain] = field(default_factory=list)
    chains_remaining: list[AttackChain] = field(default_factory=list)

    # Next recommendation
    next_fix: RootCauseFix | None = None

    @property
    def score_delta(self) -> int:
        return self.score_after - self.score_before

    @property
    def chains_delta(self) -> int:
        return self.chains_after - self.chains_before

    @property
    def risk_reduction_pct(self) -> float:
        if not self.risk_before or self.risk_before.high_usd == 0:
            return 0.0
        after_high = self.risk_after.high_usd if self.risk_after else 0
        return (1.0 - after_high / self.risk_before.high_usd) * 100


def simulate_fix(report: ScanReport, check_ids: list[str]) -> SimulationResult:
    """Simulate removing all findings for given check_ids and recompute chains/score.

    This is a pure in-memory operation — no AWS API calls, no side effects.
    """
    from cloud_audit.root_cause import _FIX_TITLES

    fix_titles = [_FIX_TITLES.get(cid, cid) for cid in check_ids]
    check_id_set = set(check_ids)

    # Before state
    score_before = report.summary.score
    chains_before = len(report.attack_chains)
    risk_before = report.summary.total_risk_exposure
    findings_before = report.summary.total_findings

    # Build reduced findings list (remove findings for target check_ids)
    reduced_findings: list[Finding] = [f for f in report.all_findings if f.check_id not in check_id_set]

    # Build reduced CheckResults for score calculation
    reduced_results: list[CheckResult] = []
    for cr in report.results:
        kept = [f for f in cr.findings if f.check_id not in check_id_set]
        reduced_results.append(
            CheckResult(
                check_id=cr.check_id,
                check_name=cr.check_name,
                findings=kept,
                resources_scanned=cr.resources_scanned,
                error=cr.error,
            )
        )

    # Recompute attack chains on reduced findings
    try:
        from cloud_audit.correlate import detect_attack_chains

        # No relationship data needed for re-detection — use findings-only mode
        after_chains = detect_attack_chains(reduced_findings, None)
    except Exception:
        after_chains = []

    # Compute after score
    penalty = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in reduced_findings)
    score_after = max(0, 100 - penalty)

    # Compute after risk
    risk_after = _compute_total_risk(after_chains)

    # Determine which chains were broken
    after_chain_ids = {c.chain_id for c in after_chains}
    chains_broken = [c for c in report.attack_chains if c.chain_id not in after_chain_ids]

    # Compute next recommended fix from remaining chains
    next_fix = _compute_next_fix(reduced_findings, after_chains)

    return SimulationResult(
        fix_check_ids=check_ids,
        fix_titles=fix_titles,
        score_before=score_before,
        chains_before=chains_before,
        risk_before=risk_before,
        findings_before=findings_before,
        score_after=score_after,
        chains_after=len(after_chains),
        risk_after=risk_after,
        findings_after=len(reduced_findings),
        chains_broken=chains_broken,
        chains_remaining=after_chains,
        next_fix=next_fix,
    )


def _compute_total_risk(chains: list[AttackChain]) -> CostEstimateData | None:
    """Sum risk across all chains."""
    total_low = 0
    total_high = 0
    has_any = False
    for c in chains:
        if c.cost_estimate and c.cost_estimate.high_usd > 0:
            total_low += c.cost_estimate.low_usd
            total_high += c.cost_estimate.high_usd
            has_any = True
    if not has_any:
        return None
    return CostEstimateData(
        low_usd=total_low,
        high_usd=total_high,
        display=_format_usd(total_low, total_high),
        rationale="Remaining risk after simulated fix",
    )


def _compute_next_fix(findings: list[Finding], chains: list[AttackChain]) -> RootCauseFix | None:
    """Find the highest-impact remaining fix after simulation."""
    if not chains:
        return None
    try:
        from cloud_audit.root_cause import compute_root_causes

        remaining_causes = compute_root_causes(findings, chains)
        return remaining_causes[0] if remaining_causes else None
    except Exception:
        return None


def _format_usd(low: int, high: int) -> str:
    """Format a USD range like '$800K - $2.1M'."""

    def _fmt(v: int) -> str:
        if v >= 1_000_000:
            m = v / 1_000_000
            return f"${m:.1f}M" if m != int(m) else f"${int(m)}M"
        if v >= 1_000:
            k = v / 1_000
            return f"${k:.0f}K" if k == int(k) else f"${k:.1f}K"
        return f"${v}"

    return f"{_fmt(low)} - {_fmt(high)}"
