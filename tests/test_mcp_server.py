"""Tests for the MCP server module."""

from __future__ import annotations

import json

import pytest

try:
    import mcp  # noqa: F401

    HAS_MCP = True
except ImportError:
    HAS_MCP = False

pytestmark = pytest.mark.skipif(not HAS_MCP, reason="mcp package not installed")

from cloud_audit.models import (
    AttackChain,
    Category,
    CheckResult,
    CostEstimateData,
    Finding,
    Remediation,
    ScanReport,
    Severity,
)


def _make_report_json() -> dict:
    """Create a sample report dict for testing MCP tools."""
    finding = Finding(
        check_id="aws-iam-001",
        title="Root account without MFA",
        severity=Severity.CRITICAL,
        category=Category.SECURITY,
        resource_type="AWS::IAM::User",
        resource_id="arn:aws:iam::123456789012:root",
        description="Root account has no MFA enabled",
        recommendation="Enable MFA on root",
        remediation=Remediation(
            cli="aws iam create-virtual-mfa-device --virtual-mfa-device-name root-mfa",
            terraform='resource "aws_iam_virtual_mfa_device" "root" {}',
            doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html",
            effort="low",
        ),
        cost_estimate=CostEstimateData(
            low_usd=50_000, high_usd=500_000, display="$50K - $500K", rationale="Root compromise"
        ),
    )

    chain = AttackChain(
        chain_id="AC-09",
        name="Unmonitored Admin Access",
        severity=Severity.CRITICAL,
        findings=[finding],
        attack_narrative="Root has no MFA and CloudTrail is off.",
        priority_fix="Enable CloudTrail first.",
        mitre_refs=["T1078.004"],
        resources=["root", "cloudtrail"],
        cost_estimate=CostEstimateData(
            low_usd=125_000, high_usd=1_250_000, display="$125K - $1.3M", rationale="Compound"
        ),
    )

    report = ScanReport(
        provider="aws",
        account_id="123456789012",
        regions=["eu-central-1"],
        results=[
            CheckResult(
                check_id="aws-iam-001",
                check_name="Root MFA",
                findings=[finding],
                resources_scanned=1,
            ),
        ],
        attack_chains=[chain],
    )
    report.compute_summary()
    report.summary.total_risk_exposure = CostEstimateData(
        low_usd=50_000, high_usd=500_000, display="$50K - $500K", rationale="Total"
    )

    return json.loads(report.model_dump_json())


class TestMcpTools:
    """Test MCP server tool functions directly (no MCP transport)."""

    def test_get_findings_no_report(self) -> None:
        import cloud_audit.mcp_server as mcp_mod

        mcp_mod._last_report_json = None
        with pytest.raises(ValueError, match="No scan results"):
            mcp_mod.get_findings()

    def test_get_findings_with_report(self) -> None:
        import cloud_audit.mcp_server as mcp_mod

        mcp_mod._last_report_json = _make_report_json()
        result = json.loads(mcp_mod.get_findings())
        assert len(result) == 1
        assert result[0]["check_id"] == "aws-iam-001"
        assert result[0]["risk"] == "$50K - $500K"

    def test_get_findings_severity_filter(self) -> None:
        import cloud_audit.mcp_server as mcp_mod

        mcp_mod._last_report_json = _make_report_json()
        result = json.loads(mcp_mod.get_findings(severity="low"))
        assert len(result) == 0  # No LOW findings in test data

    def test_get_findings_service_filter(self) -> None:
        import cloud_audit.mcp_server as mcp_mod

        mcp_mod._last_report_json = _make_report_json()
        result = json.loads(mcp_mod.get_findings(service="iam"))
        assert len(result) == 1

    def test_get_attack_chains(self) -> None:
        import cloud_audit.mcp_server as mcp_mod

        mcp_mod._last_report_json = _make_report_json()
        result = json.loads(mcp_mod.get_attack_chains())
        assert len(result) == 1
        assert result[0]["chain_id"] == "AC-09"
        assert result[0]["risk"] == "$125K - $1.3M"

    def test_get_remediation(self) -> None:
        import cloud_audit.mcp_server as mcp_mod

        mcp_mod._last_report_json = _make_report_json()
        result = json.loads(mcp_mod.get_remediation(check_id="aws-iam-001"))
        assert "cli_command" in result
        assert "terraform_hcl" in result
        assert "mfa" in result["cli_command"]

    def test_get_remediation_not_found(self) -> None:
        import cloud_audit.mcp_server as mcp_mod

        mcp_mod._last_report_json = _make_report_json()
        result = json.loads(mcp_mod.get_remediation(check_id="aws-unknown-999"))
        assert "error" in result

    def test_get_health_score(self) -> None:
        import cloud_audit.mcp_server as mcp_mod

        mcp_mod._last_report_json = _make_report_json()
        result = json.loads(mcp_mod.get_health_score())
        assert result["health_score"] == 80  # 100 - 20 (CRITICAL)
        assert result["risk_exposure"] == "$50K - $500K"

    def test_list_checks(self) -> None:
        import cloud_audit.mcp_server as mcp_mod

        result = json.loads(mcp_mod.list_checks())
        assert len(result) >= 45  # At least 45 checks
        # Verify structure
        assert "check_id" in result[0]
        assert "name" in result[0]
        assert "service" in result[0]
        assert "category" in result[0]


class TestAgentBlastTool:
    """get_agent_blast composes the agent-blast engine over the cached report."""

    def test_no_report_raises(self) -> None:
        import cloud_audit.mcp_server as mcp_mod

        mcp_mod._last_report_json = None
        with pytest.raises(ValueError, match="No scan results"):
            mcp_mod.get_agent_blast()

    def test_no_agents_in_report(self) -> None:
        import cloud_audit.mcp_server as mcp_mod

        mcp_mod._last_report_json = _make_report_json()
        assert "No AI agents" in mcp_mod.get_agent_blast()

    def test_all_agents_markdown(self) -> None:
        import cloud_audit.mcp_server as mcp_mod
        from cloud_audit.demo_data import build_demo_report

        mcp_mod._last_report_json = json.loads(build_demo_report().model_dump_json())
        out = mcp_mod.get_agent_blast()
        assert "# agent-blast: support-bot" in out
        assert "# agent-blast: tools-gw" in out
        assert "PassRole+Lambda" in out

    def test_agent_filter_and_unknown(self) -> None:
        import cloud_audit.mcp_server as mcp_mod
        from cloud_audit.demo_data import build_demo_report

        mcp_mod._last_report_json = json.loads(build_demo_report().model_dump_json())
        only = mcp_mod.get_agent_blast("planner")
        assert "# agent-blast: planner" in only
        assert "support-bot" not in only.split("\n")[0]
        missing = mcp_mod.get_agent_blast("nope")
        assert missing.startswith("No agent matches")
        assert "support-bot" in missing
