"""Tests for root-cause grouping (Sprint 2)."""

from __future__ import annotations

from cloud_audit.models import (
    AttackChain,
    Category,
    CostEstimateData,
    Effort,
    Finding,
    Remediation,
    RootCauseFix,
    Severity,
)
from cloud_audit.root_cause import CHECK_TO_CHAINS, compute_root_causes


def _make_finding(check_id: str, severity: Severity = Severity.HIGH, effort: Effort = Effort.LOW) -> Finding:
    """Create a minimal Finding for testing."""
    return Finding(
        check_id=check_id,
        title=f"Test finding for {check_id}",
        severity=severity,
        category=Category.SECURITY,
        resource_type="AWS::Test::Resource",
        resource_id=f"test-{check_id}",
        description="Test description",
        recommendation="Test recommendation",
        remediation=Remediation(
            cli=f"aws fix {check_id}",
            terraform=f'resource "fix" "{check_id}" {{}}',
            doc_url="https://docs.aws.amazon.com/test",
            effort=effort,
        ),
    )


def _make_chain(chain_id: str, findings: list[Finding], cost: CostEstimateData | None = None) -> AttackChain:
    """Create a minimal AttackChain for testing."""
    return AttackChain(
        chain_id=chain_id,
        name=f"Test chain {chain_id}",
        severity=Severity.CRITICAL,
        findings=findings,
        attack_narrative=f"Attacker exploits {chain_id}",
        priority_fix=f"Fix {chain_id}",
        cost_estimate=cost,
    )


class TestComputeRootCauses:
    """Tests for compute_root_causes()."""

    def test_empty_chains_returns_empty(self) -> None:
        findings = [_make_finding("aws-vpc-002")]
        result = compute_root_causes(findings, [])
        assert result == []

    def test_single_check_single_chain(self) -> None:
        f1 = _make_finding("aws-iam-008")
        # AC-25 requires aws-iam-008 + aws-ct-001
        chain = _make_chain("AC-25", [f1])
        result = compute_root_causes([f1], [chain])

        assert len(result) == 1
        assert result[0].check_id == "aws-iam-008"
        assert result[0].chains_broken == ["AC-25"]
        assert result[0].findings_closed == 1

    def test_vpc_002_breaks_most_chains(self) -> None:
        """aws-vpc-002 participates in 7 chains — should rank first if all are detected."""
        f_sg = _make_finding("aws-vpc-002", severity=Severity.CRITICAL)
        f_flow = _make_finding("aws-vpc-003", severity=Severity.MEDIUM)

        chains = [
            _make_chain("AC-01", [f_sg]),
            _make_chain("AC-02", [f_sg]),
            _make_chain("AC-13", [f_sg, f_flow]),
            _make_chain("AC-14", [f_sg, f_flow]),
            _make_chain("AC-31", [f_sg, f_flow]),
            _make_chain("AC-33", [f_sg, f_flow]),
        ]

        result = compute_root_causes([f_sg, f_flow], chains)
        assert len(result) >= 2
        # vpc-002 should be first (breaks more chains)
        assert result[0].check_id == "aws-vpc-002"
        assert len(result[0].chains_broken) >= 6

    def test_only_detected_chains_counted(self) -> None:
        """Static mapping says aws-ct-001 -> 5 chains, but only count actually detected ones."""
        f_ct = _make_finding("aws-ct-001")
        # Only AC-09 was detected (not AC-10, AC-11, AC-17, AC-25)
        chains = [_make_chain("AC-09", [f_ct])]
        result = compute_root_causes([f_ct], chains)

        assert len(result) == 1
        assert result[0].check_id == "aws-ct-001"
        assert result[0].chains_broken == ["AC-09"]
        assert len(result[0].chains_broken) == 1  # NOT 5

    def test_findings_not_in_mapping_are_excluded(self) -> None:
        """Checks not in CHECK_TO_CHAINS should not appear in root causes."""
        f = _make_finding("aws-ec2-005")  # termination protection - not in any chain
        chains = [_make_chain("AC-01", [f])]
        result = compute_root_causes([f], chains)
        assert result == []

    def test_multiple_findings_same_check(self) -> None:
        """Multiple findings for same check_id -> findings_closed counts all."""
        f1 = _make_finding("aws-vpc-002")
        f2 = _make_finding("aws-vpc-002")
        f2.resource_id = "sg-different"
        chain = _make_chain("AC-13", [f1])
        result = compute_root_causes([f1, f2], [chain])

        assert len(result) == 1
        assert result[0].findings_closed == 2

    def test_sort_order_chains_desc(self) -> None:
        """Sort by chains_broken descending, then severity, then effort."""
        f_sg = _make_finding("aws-vpc-002", severity=Severity.CRITICAL)
        f_iam = _make_finding("aws-iam-008", severity=Severity.CRITICAL)

        chains = [
            _make_chain("AC-01", [f_sg]),
            _make_chain("AC-02", [f_sg]),
            _make_chain("AC-25", [f_iam]),
        ]

        result = compute_root_causes([f_sg, f_iam], chains)
        assert result[0].check_id == "aws-vpc-002"  # 2 chains > 1 chain
        assert result[1].check_id == "aws-iam-008"  # 1 chain

    def test_risk_aggregation(self) -> None:
        """Risk reduced should sum across broken chains."""
        cost1 = CostEstimateData(low_usd=100_000, high_usd=500_000, display="$100K - $500K", rationale="test")
        cost2 = CostEstimateData(low_usd=200_000, high_usd=1_000_000, display="$200K - $1M", rationale="test")
        f = _make_finding("aws-vpc-002")
        chains = [
            _make_chain("AC-01", [f], cost=cost1),
            _make_chain("AC-02", [f], cost=cost2),
        ]

        result = compute_root_causes([f], chains)
        assert result[0].total_risk_reduced is not None
        assert result[0].total_risk_reduced.low_usd == 300_000
        assert result[0].total_risk_reduced.high_usd == 1_500_000

    def test_no_risk_when_chains_have_no_cost(self) -> None:
        f = _make_finding("aws-iam-008")
        chains = [_make_chain("AC-25", [f], cost=None)]
        result = compute_root_causes([f], chains)
        assert result[0].total_risk_reduced is None

    def test_effort_from_remediation(self) -> None:
        """Effort should come from the finding's remediation."""
        f = _make_finding("aws-ct-008", effort=Effort.MEDIUM)
        chains = [_make_chain("AC-32", [f])]
        result = compute_root_causes([f], chains)
        assert result[0].effort == Effort.MEDIUM

    def test_finding_without_remediation_defaults_effort(self) -> None:
        """Finding with remediation=None should default to MEDIUM effort."""
        f = Finding(
            check_id="aws-vpc-002",
            title="Open SG",
            severity=Severity.CRITICAL,
            category=Category.SECURITY,
            resource_type="AWS::EC2::SecurityGroup",
            resource_id="sg-test",
            description="Test",
            recommendation="Test",
            remediation=None,
        )
        chain = _make_chain("AC-01", [f])
        result = compute_root_causes([f], [chain])
        assert len(result) == 1
        assert result[0].effort == Effort.MEDIUM
        assert result[0].remediation is None

    def test_chains_broken_are_sorted(self) -> None:
        """chains_broken list should be sorted alphabetically."""
        f = _make_finding("aws-vpc-002")
        chains = [
            _make_chain("AC-33", [f]),
            _make_chain("AC-01", [f]),
            _make_chain("AC-13", [f]),
        ]
        result = compute_root_causes([f], chains)
        assert result[0].chains_broken == ["AC-01", "AC-13", "AC-33"]


class TestCheckToChainsMapping:
    """Validate the static CHECK_TO_CHAINS mapping."""

    def test_all_chain_ids_are_valid_format(self) -> None:
        for check_id, chain_ids in CHECK_TO_CHAINS.items():
            for cid in chain_ids:
                assert cid.startswith("AC-"), f"{check_id} references invalid chain {cid}"
                assert cid[3:].isdigit(), f"{check_id} references invalid chain {cid}"

    def test_vpc_002_has_most_chains(self) -> None:
        """aws-vpc-002 should be in the most chains (7)."""
        assert len(CHECK_TO_CHAINS["aws-vpc-002"]) == 7

    def test_ct_001_has_5_chains(self) -> None:
        assert len(CHECK_TO_CHAINS["aws-ct-001"]) == 5

    def test_iam_007_has_4_chains(self) -> None:
        assert len(CHECK_TO_CHAINS["aws-iam-007"]) == 4

    def test_no_duplicate_chain_ids_per_check(self) -> None:
        for check_id, chain_ids in CHECK_TO_CHAINS.items():
            assert len(chain_ids) == len(set(chain_ids)), f"{check_id} has duplicate chain IDs"


class TestRootCauseFixModel:
    """Tests for the RootCauseFix Pydantic model."""

    def test_model_serialization(self) -> None:
        fix = RootCauseFix(
            check_id="aws-vpc-002",
            fix_title="Restrict security groups",
            effort=Effort.LOW,
            findings_closed=5,
            chains_broken=["AC-01", "AC-02"],
        )
        data = fix.model_dump()
        assert data["check_id"] == "aws-vpc-002"
        assert data["effort"] == "low"
        assert data["chains_broken"] == ["AC-01", "AC-02"]

    def test_model_json_roundtrip(self) -> None:
        fix = RootCauseFix(
            check_id="aws-ct-001",
            fix_title="Enable CloudTrail",
            effort=Effort.MEDIUM,
            findings_closed=3,
            chains_broken=["AC-09", "AC-10"],
        )
        json_str = fix.model_dump_json()
        restored = RootCauseFix.model_validate_json(json_str)
        assert restored.check_id == "aws-ct-001"
        assert restored.chains_broken == ["AC-09", "AC-10"]
