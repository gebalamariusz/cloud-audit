"""CLI: cloud-audit agent-blast."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from cloud_audit.cli import app
from cloud_audit.models import AgentIdentity, AgentTool, PolicyGrant, ScanReport

runner = CliRunner()
ACCOUNT = "123456789012"
AGENT_ROLE = f"arn:aws:iam::{ACCOUNT}:role/agent-role"
TOOL_ROLE = f"arn:aws:iam::{ACCOUNT}:role/tool-role"


def _report_file(tmp_path: Path, with_agents: bool = True, gaps: list[str] | None = None) -> Path:
    report = ScanReport(provider="aws", account_id=ACCOUNT, regions=["eu-central-1"])
    if with_agents:
        report.agents = [
            AgentIdentity(
                agent_id="AG1",
                name="support-bot",
                kind="bedrock_agent",
                region="eu-central-1",
                principal_arns=[AGENT_ROLE],
                tools=[AgentTool(name="search", kind="action_group_lambda", execution_role_arn=TOOL_ROLE)],
                data_sources=["arn:aws:s3:::kb-docs"],
            ),
            AgentIdentity(
                agent_id="RT1",
                name="planner",
                kind="agentcore_runtime",
                region="eu-central-1",
                principal_arns=[AGENT_ROLE],
            ),
        ]
        report.principal_grants = {
            AGENT_ROLE: [PolicyGrant(action="s3:GetObject", resource="*", effect="Allow")],
            TOOL_ROLE: [PolicyGrant(action="s3:PutObject", resource="arn:aws:s3:::kb-docs/*", effect="Allow")],
        }
    report.agent_inventory_gaps = gaps or []
    report.compute_summary()
    path = tmp_path / "scan.json"
    path.write_text(report.model_dump_json(), encoding="utf-8")
    return path


def test_tree_for_all_agents(tmp_path: Path) -> None:
    result = runner.invoke(app, ["agent-blast", "--report", str(_report_file(tmp_path))])
    assert result.exit_code == 0, result.output
    assert "support-bot" in result.output
    assert "planner" in result.output
    assert "Behaviour takeover" in result.output
    assert "poisoning" in result.output  # single token: Rich wraps tree lines at the terminal width


def test_select_agent_by_substring_and_json(tmp_path: Path) -> None:
    result = runner.invoke(app, ["agent-blast", "--report", str(_report_file(tmp_path)), "-a", "support", "-f", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert len(payload) == 1
    assert payload[0]["agent"]["name"] == "support-bot"
    assert payload[0]["reaches"]
    assert payload[0]["identity_takeover"][0]["blast"]["schema_version"] == "1.0"


def test_unknown_agent_lists_available(tmp_path: Path) -> None:
    result = runner.invoke(app, ["agent-blast", "--report", str(_report_file(tmp_path)), "-a", "nope"])
    assert result.exit_code == 2
    assert "planner" in result.output and "support-bot" in result.output


def test_markdown_to_file(tmp_path: Path) -> None:
    out = tmp_path / "blast.md"
    result = runner.invoke(
        app, ["agent-blast", "--report", str(_report_file(tmp_path)), "-f", "markdown", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    text = out.read_text(encoding="utf-8")
    assert "# agent-blast: support-bot" in text
    assert "# agent-blast: planner" in text


def test_tree_refuses_output_file(tmp_path: Path) -> None:
    result = runner.invoke(app, ["agent-blast", "--report", str(_report_file(tmp_path)), "-o", str(tmp_path / "x.txt")])
    assert result.exit_code == 2


def test_no_agents_exit_1_and_explains(tmp_path: Path) -> None:
    result = runner.invoke(app, ["agent-blast", "--report", str(_report_file(tmp_path, with_agents=False))])
    assert result.exit_code == 1
    assert "No AI agents" in result.output


def test_no_agents_but_denied_inventory_shows_gaps(tmp_path: Path) -> None:
    path = _report_file(tmp_path, with_agents=False, gaps=["us-east-1: ListAgents denied (AccessDeniedException)"])
    result = runner.invoke(app, ["agent-blast", "--report", str(path)])
    assert result.exit_code == 1
    assert "denied a read" in result.output
    assert "ListAgents" in result.output


def test_missing_report_exit_2(tmp_path: Path) -> None:
    result = runner.invoke(app, ["agent-blast", "--report", str(tmp_path / "missing.json")])
    assert result.exit_code == 2


def test_bad_format_exit_2(tmp_path: Path) -> None:
    result = runner.invoke(app, ["agent-blast", "--report", str(_report_file(tmp_path)), "-f", "mermaid"])
    assert result.exit_code == 2


def test_demo_mode_needs_no_report() -> None:
    result = runner.invoke(app, ["agent-blast", "--demo"])
    assert result.exit_code == 0, result.output
    assert "support-bot" in result.output
    assert "tools-gw" in result.output
    assert "create-ticket" in result.output


def test_demo_mode_json_is_valid_and_verify_is_ignored() -> None:
    result = runner.invoke(app, ["agent-blast", "--demo", "--verify", "-a", "support-bot", "-f", "json"])
    assert result.exit_code == 0, result.output
    # the warning line precedes the JSON payload
    body = result.output[result.output.index("[") :]
    payload = json.loads(body)
    assert payload[0]["agent"]["name"] == "support-bot"
    assert payload[0]["verified"] is False


def test_demo_save_writes_a_loadable_report(tmp_path: Path) -> None:
    out = tmp_path / "demo.json"
    result = runner.invoke(app, ["demo", "--save", str(out)])
    assert result.exit_code == 0, result.output
    report = ScanReport.model_validate_json(out.read_text(encoding="utf-8"))
    assert report.summary.attack_chains_detected >= 3
    assert len(report.agents) == 4
    follow = runner.invoke(app, ["agent-blast", "--report", str(out), "-a", "planner", "-f", "markdown"])
    assert follow.exit_code == 0, follow.output
    assert "# agent-blast: planner" in follow.output
