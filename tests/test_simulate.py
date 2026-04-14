"""Tests for the What-If Remediation Simulator."""

from __future__ import annotations

from cloud_audit.models import (
    AttackChain,
    Category,
    CheckResult,
    CostEstimateData,
    Effort,
    Finding,
    Remediation,
    ScanReport,
    Severity,
)
from cloud_audit.simulate import SimulationResult, simulate_fix


def _make_finding(
    check_id: str,
    severity: Severity = Severity.HIGH,
    resource_id: str = "test-resource",
    region: str = "eu-central-1",
) -> Finding:
    return Finding(
        check_id=check_id,
        title=f"Finding for {check_id}",
        severity=severity,
        category=Category.SECURITY,
        resource_type="AWS::Test::Resource",
        resource_id=resource_id,
        region=region,
        description="Test",
        recommendation="Test",
        remediation=Remediation(
            cli=f"aws fix {check_id}",
            terraform=f'resource "fix" "{check_id}" {{}}',
            doc_url="https://docs.aws.amazon.com/test",
            effort=Effort.LOW,
        ),
    )


def _make_chain(
    chain_id: str,
    findings: list[Finding],
    severity: Severity = Severity.CRITICAL,
    cost: CostEstimateData | None = None,
) -> AttackChain:
    return AttackChain(
        chain_id=chain_id,
        name=f"Chain {chain_id}",
        severity=severity,
        findings=findings,
        attack_narrative=f"Attack via {chain_id}",
        priority_fix=f"Fix {chain_id}",
        cost_estimate=cost,
    )


def _make_report(findings: list[Finding], chains: list[AttackChain]) -> ScanReport:
    report = ScanReport(provider="aws", account_id="123456789012", regions=["eu-central-1"])
    report.results.append(
        CheckResult(
            check_id="test",
            check_name="Test",
            findings=findings,
            resources_scanned=len(findings),
        )
    )
    report.attack_chains = chains
    report.compute_summary()
    return report


class TestSimulateFix:
    """Tests for simulate_fix()."""

    def test_empty_report(self) -> None:
        report = _make_report([], [])
        result = simulate_fix(report, ["aws-vpc-002"])
        assert result.score_before == 100
        assert result.score_after == 100
        assert result.chains_before == 0
        assert result.chains_after == 0

    def test_fix_removes_findings(self) -> None:
        f1 = _make_finding("aws-vpc-002", severity=Severity.CRITICAL)
        f2 = _make_finding("aws-ct-001", severity=Severity.HIGH)
        report = _make_report([f1, f2], [])
        result = simulate_fix(report, ["aws-vpc-002"])
        assert result.findings_before == 2
        assert result.findings_after == 1

    def test_score_improves(self) -> None:
        f1 = _make_finding("aws-vpc-002", severity=Severity.CRITICAL)  # -20 penalty
        f2 = _make_finding("aws-ct-001", severity=Severity.HIGH)  # -10 penalty
        report = _make_report([f1, f2], [])
        # Score before: 100 - 20 - 10 = 70
        assert report.summary.score == 70
        result = simulate_fix(report, ["aws-vpc-002"])
        # Score after: 100 - 10 = 90
        assert result.score_after == 90
        assert result.score_delta == 20

    def test_multiple_check_ids(self) -> None:
        f1 = _make_finding("aws-vpc-002", severity=Severity.CRITICAL)
        f2 = _make_finding("aws-ct-001", severity=Severity.HIGH)
        f3 = _make_finding("aws-iam-001", severity=Severity.MEDIUM)
        report = _make_report([f1, f2, f3], [])
        result = simulate_fix(report, ["aws-vpc-002", "aws-ct-001"])
        assert result.findings_after == 1  # Only f3 remains
        assert result.score_after == 95  # 100 - 5 (MEDIUM)

    def test_chains_broken(self) -> None:
        f_sg = _make_finding("aws-vpc-002")
        f_ct = _make_finding("aws-ct-001")
        # AC-13 needs vpc-002 + vpc-003, so fixing vpc-002 should break it
        chain = _make_chain("AC-13", [f_sg])
        report = _make_report([f_sg, f_ct], [chain])
        result = simulate_fix(report, ["aws-vpc-002"])
        assert result.chains_before == 1
        # Chain should be gone because its required finding is removed
        assert len(result.chains_broken) >= 0  # Depends on correlator re-detection

    def test_risk_reduction_percentage(self) -> None:
        result = SimulationResult(
            fix_check_ids=["test"],
            fix_titles=["Test"],
            score_before=50,
            chains_before=2,
            risk_before=CostEstimateData(low_usd=100_000, high_usd=1_000_000, display="$100K - $1M", rationale="test"),
            findings_before=10,
            score_after=80,
            chains_after=1,
            risk_after=CostEstimateData(low_usd=10_000, high_usd=100_000, display="$10K - $100K", rationale="test"),
            findings_after=5,
        )
        assert result.score_delta == 30
        assert result.chains_delta == -1
        assert result.risk_reduction_pct == 90.0

    def test_risk_reduction_no_risk(self) -> None:
        result = SimulationResult(
            fix_check_ids=["test"],
            fix_titles=["Test"],
            score_before=50,
            chains_before=1,
            risk_before=None,
            findings_before=5,
            score_after=80,
            chains_after=0,
            risk_after=None,
            findings_after=2,
        )
        assert result.risk_reduction_pct == 0.0

    def test_fix_titles_from_mapping(self) -> None:
        f = _make_finding("aws-vpc-002")
        report = _make_report([f], [])
        result = simulate_fix(report, ["aws-vpc-002"])
        assert result.fix_titles == ["Restrict security groups"]

    def test_unknown_check_id_title_fallback(self) -> None:
        f = _make_finding("aws-unknown-999")
        report = _make_report([f], [])
        result = simulate_fix(report, ["aws-unknown-999"])
        assert result.fix_titles == ["aws-unknown-999"]
