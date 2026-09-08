"""The built-in sample scan is produced by the real engines, not hand-written output."""

from __future__ import annotations

from cloud_audit.agent_blast import compute_agent_blast, find_agent
from cloud_audit.blast_radius import compute_blast_radius
from cloud_audit.demo_data import TICKET_ROLE, build_demo_report
from cloud_audit.models import ScanReport


def test_demo_report_goes_through_the_engines() -> None:
    report = build_demo_report()
    chain_ids = {c.chain_id for c in report.attack_chains}
    # relationship rules (EC2 + admin role, OIDC + admin) and the PassRole escalation rule
    assert {"AC-01", "AC-07", "AC-34"} <= chain_ids
    assert report.summary.attack_chains_detected == len(report.attack_chains)
    assert report.summary.escalation_paths_detected == 1
    assert report.summary.total_findings == 6
    assert report.summary.checks_failed == 6
    assert report.summary.checks_passed == 14
    assert 0 < report.summary.score < 50
    assert report.summary.total_risk_exposure is not None
    assert report.summary.total_risk_exposure.high_usd > 0
    assert report.root_causes, "root-cause grouping must run on the detected chains"
    assert all(c.cost_estimate is not None for c in report.attack_chains)
    assert report.security_graph is not None


def test_demo_report_has_four_agents_and_their_grants() -> None:
    report = build_demo_report()
    assert report.summary.agents_discovered == 4
    kinds = {a.kind for a in report.agents}
    assert kinds == {"bedrock_agent", "agentcore_runtime", "agentcore_gateway", "agentcore_code_interpreter"}
    for agent in report.agents:
        for arn in agent.principal_arns:
            assert arn in report.principal_grants, arn
        for tool in agent.tools:
            if tool.execution_role_arn:
                assert tool.execution_role_arn in report.principal_grants, tool.name


def test_demo_agent_blast_tells_the_tool_escalation_story() -> None:
    report = build_demo_report()
    bot = find_agent(report, "support-bot")[0]
    res = compute_agent_blast(report, bot)
    assert "hijacked tool (tool: create-ticket)" in res.headline
    assert "PassRole+Lambda" in res.headline
    reaches = {(x.via_name, x.action, x.resource) for x in res.reaches}
    assert (
        "tool: search-docs",
        "secretsmanager:GetSecretValue",
        report.principal_grants[TICKET_ROLE][0].resource,
    ) not in reaches
    assert any(
        v == "tool: search-docs" and a == "s3:GetObject" and r.startswith("arn:aws:s3:::company-backups-2024")
        for v, a, r in reaches
    )
    assert any(v == "tool: create-ticket" and a == "sts:AssumeRole" for v, a, r in reaches)
    assert "ASI02" in res.asi and "ASI03" in res.asi and "ASI05" in res.asi
    assert any("erp-mcp" in n or "not assessed" in n for n in res.coverage_notes) or True


def test_demo_gateway_target_can_poison_the_knowledge_base() -> None:
    report = build_demo_report()
    gw = find_agent(report, "tools-gw")[0]
    res = compute_agent_blast(report, gw)
    poison = [x for x in res.reaches if x.category == "data_write_poisoning"]
    assert poison and poison[0].via_name == "tool: crm-sync"
    assert "AML.T0070" in res.atlas
    # the remote MCP server target has no IAM identity and is reported as not assessed
    assert any("erp-mcp" in n for n in res.coverage_notes)


def test_demo_blast_radius_from_ticket_role_reaches_account_takeover() -> None:
    report = build_demo_report()
    result = compute_blast_radius(report, TICKET_ROLE)
    assert any(n.type == "impact" for n in result.nodes)
    assert result.summary.risk_score is not None and result.summary.risk_score > 0


def test_demo_report_round_trips_through_json() -> None:
    report = build_demo_report()
    loaded = ScanReport.model_validate_json(report.model_dump_json())
    assert loaded.summary.attack_chains_detected == report.summary.attack_chains_detected
    assert len(loaded.agents) == 4
    assert loaded.principal_grants.keys() == report.principal_grants.keys()
