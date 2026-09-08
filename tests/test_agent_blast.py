"""agent-blast: composition of inventory, blast radius, grants and Proof Mode for one agent."""

from __future__ import annotations

from typing import Any

from cloud_audit.agent_blast import (
    AgentBlastResult,
    compute_agent_blast,
    find_agent,
    to_markdown,
    to_tree,
    verify_agent_blast,
    verify_report_agents,
)
from cloud_audit.models import (
    AgentIdentity,
    AgentTool,
    EscalationCategory,
    EscalationPath,
    PolicyGrant,
    ScanReport,
    Severity,
)

ACCOUNT = "123456789012"
AGENT_ROLE = f"arn:aws:iam::{ACCOUNT}:role/agent-role"
TOOL_ROLE = f"arn:aws:iam::{ACCOUNT}:role/tool-role"
KB_BUCKET = "arn:aws:s3:::kb-docs"
HR_SECRET = f"arn:aws:secretsmanager:eu-central-1:{ACCOUNT}:secret:hr/payroll-AbCdEf"
LATERAL = f"arn:aws:iam::{ACCOUNT}:role/data-admin"


def _grant(
    action: str, resource: str = "*", effect: str = "Allow", cond: bool = False, source: str = "inline:p"
) -> PolicyGrant:
    return PolicyGrant(action=action, resource=resource, effect=effect, has_condition=cond, source=source)


def _agent(
    kind: str = "bedrock_agent", tools: list[AgentTool] | None = None, roles: list[str] | None = None
) -> AgentIdentity:
    return AgentIdentity(
        agent_id="AG1",
        name="support-bot",
        kind=kind,
        arn=f"arn:aws:bedrock:eu-central-1:{ACCOUNT}:agent/AG1",
        region="eu-central-1",
        principal_arns=[AGENT_ROLE] if roles is None else roles,
        tools=tools
        if tools is not None
        else [
            AgentTool(
                name="search",
                kind="action_group_lambda",
                target_arn=f"arn:aws:lambda:eu-central-1:{ACCOUNT}:function:search",
                execution_role_arn=TOOL_ROLE,
                region="eu-central-1",
                detail="2 OpenAPI path(s)",
            ),
            AgentTool(
                name="ask-user", kind="action_group_custom_control", region="eu-central-1", detail="RETURN_CONTROL"
            ),
        ],
        data_sources=[KB_BUCKET],
        foundation_model="anthropic.claude-3-5-sonnet",
        guardrail_attached=True,
    )


def _escalation(
    principal: str, method: str = "CreatePolicyVersion", actions: list[str] | None = None
) -> EscalationPath:
    return EscalationPath(
        principal_arn=principal,
        principal_name=principal.rsplit("/", 1)[-1],
        principal_type="Role",
        method=method,
        category=EscalationCategory.IAM_SELF_MUTATION,
        required_actions=actions or ["iam:CreatePolicyVersion"],
        target_privilege="Admin via new policy version",
        severity=Severity.CRITICAL,
    )


def _report(
    agent: AgentIdentity | None = None,
    grants: dict[str, list[PolicyGrant]] | None = None,
    escalations: list[EscalationPath] | None = None,
    gaps: list[str] | None = None,
) -> ScanReport:
    report = ScanReport(provider="aws", account_id=ACCOUNT, regions=["eu-central-1"])
    report.agents = [agent or _agent()]
    report.principal_grants = grants if grants is not None else {AGENT_ROLE: [], TOOL_ROLE: []}
    report.escalation_paths = escalations or []
    report.agent_inventory_gaps = gaps or []
    report.compute_summary()
    return report


# ---------------------------------------------------------------------------
# Composition
# ---------------------------------------------------------------------------


def test_two_threat_models_from_identity_and_tool_roles() -> None:
    report = _report()
    res = compute_agent_blast(report, report.agents[0])
    assert [r.principal_arn for r in res.identity_takeover] == [AGENT_ROLE]
    assert [r.principal_arn for r in res.behaviour_takeover] == [TOOL_ROLE]
    assert res.behaviour_takeover[0].via_name == "tool: search"
    assert res.identity_takeover[0].via == "identity"
    assert all(r.has_policy_data for r in res.identity_takeover + res.behaviour_takeover)
    # a tool without an IAM identity is reported as not assessed, never silently dropped
    assert any("ask-user" in n and "not assessed" in n for n in res.coverage_notes)


def test_knowledge_base_bucket_becomes_concrete_reach_even_under_wildcard() -> None:
    grants = {AGENT_ROLE: [_grant("s3:GetObject", "*")], TOOL_ROLE: [_grant("s3:*", "*")]}
    res = compute_agent_blast(_report(grants=grants), _report().agents[0])
    kb = [x for x in res.reaches if x.resource == f"{KB_BUCKET}/*"]
    assert {(x.via, x.action) for x in kb} == {
        ("identity", "s3:GetObject"),
        ("tool", "s3:GetObject"),
        ("tool", "s3:PutObject"),
    }
    poison = next(x for x in kb if x.action == "s3:PutObject")
    assert poison.category == "data_write_poisoning"
    assert "ASI06" in poison.asi
    assert "AML.T0070" in poison.atlas
    assert "ASI02" in poison.asi  # via tool
    assert "AML.T0053" in poison.atlas
    assert poison.scope == "specific"
    # the wildcard grants also show up as wildcard reaches
    assert any(x.scope == "wildcard" and x.action == "s3:GetObject" and x.via == "identity" for x in res.reaches)


def test_headline_prefers_admin_escalation_on_own_role() -> None:
    report = _report(escalations=[_escalation(AGENT_ROLE), _escalation(AGENT_ROLE, method="AttachRolePolicy")])
    res = compute_agent_blast(report, report.agents[0])
    assert res.headline.startswith("Identity takeover of agent-role reaches account admin via AttachRolePolicy")
    assert "+1 more" in res.headline
    assert res.identity_takeover[0].escalation_methods == ["AttachRolePolicy", "CreatePolicyVersion"]
    assert "ASI03" in res.asi


def test_headline_tool_escalation_then_poisoning_then_counts() -> None:
    tool_esc = _report(escalations=[_escalation(TOOL_ROLE)])
    assert "hijacked tool (tool: search)" in compute_agent_blast(tool_esc, tool_esc.agents[0]).headline

    poison = _report(grants={AGENT_ROLE: [], TOOL_ROLE: [_grant("s3:PutObject", f"{KB_BUCKET}/*")]})
    assert (
        "write into the agent's knowledge base (RAG poisoning)"
        in compute_agent_blast(poison, poison.agents[0]).headline
    )

    counts = _report(
        grants={
            AGENT_ROLE: [_grant("secretsmanager:GetSecretValue", HR_SECRET), _grant("sts:AssumeRole", LATERAL)],
            TOOL_ROLE: [_grant("dynamodb:Scan", f"arn:aws:dynamodb:eu-central-1:{ACCOUNT}:table/customers")],
        }
    )
    head = compute_agent_blast(counts, counts.agents[0]).headline
    assert "1 data read(s), 1 secret read(s), 1 lateral hop(s)" in head
    assert "1 through tools" in head

    empty = _report()
    assert "No data, secret, lateral or admin reach" in compute_agent_blast(empty, empty.agents[0]).headline


def test_explicit_deny_removes_reach_and_conditional_deny_annotates() -> None:
    grants = {
        AGENT_ROLE: [
            _grant("s3:GetObject", "*"),
            _grant("s3:*", "arn:aws:s3:::hr-files/*", effect="Deny"),
            _grant("secretsmanager:GetSecretValue", HR_SECRET),
            _grant("secretsmanager:*", "*", effect="Deny", cond=True),
        ],
        TOOL_ROLE: [],
    }
    res = compute_agent_blast(_report(grants=grants), _report().agents[0])
    # kb bucket read survives (deny is on hr-files), secret survives with a note
    assert any(x.resource == f"{KB_BUCKET}/*" and x.action == "s3:GetObject" for x in res.reaches)
    secret = next(x for x in res.reaches if x.action == "secretsmanager:GetSecretValue")
    assert "conditional Deny" in secret.note
    # a hard deny on the exact resource kills the reach
    hard = {AGENT_ROLE: [_grant("s3:GetObject", "*"), _grant("s3:GetObject", "*", effect="Deny")], TOOL_ROLE: []}
    res2 = compute_agent_blast(_report(grants=hard), _report().agents[0])
    assert not any(x.action == "s3:GetObject" for x in res2.reaches)


def test_not_action_grant_reaches_everything_except_listed() -> None:
    grants = {
        AGENT_ROLE: [PolicyGrant(action="NotAction:iam:*,sts:*", resource="*", effect="Allow", not_action=True)],
        TOOL_ROLE: [],
    }
    res = compute_agent_blast(_report(grants=grants), _report().agents[0])
    actions = {x.action for x in res.reaches if x.via == "identity"}
    assert "s3:GetObject" in actions
    assert "secretsmanager:GetSecretValue" in actions
    assert "sts:AssumeRole" not in actions


def test_conditional_allow_is_flagged_not_dropped() -> None:
    grants = {AGENT_ROLE: [_grant("s3:GetObject", f"{KB_BUCKET}/*", cond=True)], TOOL_ROLE: []}
    res = compute_agent_blast(_report(grants=grants), _report().agents[0])
    kb = next(x for x in res.reaches if x.resource == f"{KB_BUCKET}/*")
    assert kb.conditional is True


def test_missing_policy_data_is_a_coverage_note() -> None:
    report = _report(grants={})
    res = compute_agent_blast(report, report.agents[0])
    assert not res.identity_takeover[0].has_policy_data
    assert any("no policy data for" in n for n in res.coverage_notes)
    assert res.reaches == []


def test_inventory_gaps_propagate_and_sandbox_gets_escape_tag() -> None:
    sandbox = _agent(kind="agentcore_code_interpreter", tools=[], roles=[f"arn:aws:iam::{ACCOUNT}:role/ci-role"])
    report = _report(
        agent=sandbox, grants={f"arn:aws:iam::{ACCOUNT}:role/ci-role": []}, gaps=["us-east-1: ListAgents denied"]
    )
    res = compute_agent_blast(report, sandbox)
    assert "us-east-1: ListAgents denied" in res.coverage_notes
    assert "AML.T0105" in res.atlas


def test_managed_sandbox_without_role_headline() -> None:
    sandbox = _agent(kind="agentcore_browser", tools=[], roles=[])
    res = compute_agent_blast(_report(agent=sandbox, grants={}), sandbox)
    assert "AWS-managed sandbox without an execution role" in res.headline
    assert res.identity_takeover == []


def test_find_agent_exact_then_substring() -> None:
    report = _report()
    assert find_agent(report, "support-bot")[0].agent_id == "AG1"
    assert find_agent(report, "AG1")[0].name == "support-bot"
    assert find_agent(report, "SUPPORT")[0].name == "support-bot"
    assert find_agent(report, "nope") == []


# ---------------------------------------------------------------------------
# Proof Mode
# ---------------------------------------------------------------------------


class _Sim:
    def __init__(self, decisions: dict[str, str]) -> None:
        self.decisions = decisions
        self.calls: list[dict[str, Any]] = []

    def __call__(
        self,
        principal_arn: str,
        action_names: list[str],
        resource_arns: list[str] | None = None,
        context_entries: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        self.calls.append(
            {"principal": principal_arn, "actions": action_names, "resources": resource_arns, "ctx": context_entries}
        )
        out: list[dict[str, Any]] = []
        for action in action_names:
            for arn in resource_arns or ["*"]:
                out.append(
                    {
                        "EvalActionName": action,
                        "EvalDecision": self.decisions.get(arn, "implicitDeny"),
                        "EvalResourceName": arn,
                    }
                )
        return out


def test_verify_probes_kb_bucket_with_concrete_object_and_records_proof() -> None:
    grants = {
        AGENT_ROLE: [_grant("s3:GetObject", "*"), _grant("secretsmanager:GetSecretValue", HR_SECRET)],
        TOOL_ROLE: [],
    }
    res = compute_agent_blast(_report(grants=grants), _report().agents[0])
    probe = f"{KB_BUCKET}/cloud-audit-agent-blast-probe"
    sim = _Sim({probe: "allowed", HR_SECRET: "explicitDeny"})
    allowed = verify_agent_blast(res, sim)
    assert allowed == 1
    assert res.verified is True
    kb = next(x for x in res.reaches if x.resource == f"{KB_BUCKET}/*")
    assert kb.proof is not None and kb.proof.allowed is True
    secret = next(x for x in res.reaches if x.resource == HR_SECRET)
    assert secret.proof is not None and secret.proof.allowed is False
    wildcard = next(x for x in res.reaches if x.scope == "wildcard")
    assert wildcard.proof is not None and wildcard.proof.allowed is None
    assert "not simulated" in wildcard.proof.detail
    # attacker context supplied by default, probe object used instead of the "/*" pattern
    assert all(c["ctx"] for c in sim.calls)
    assert any(probe in (c["resources"] or []) for c in sim.calls)
    assert not any(f"{KB_BUCKET}/*" in (c["resources"] or []) for c in sim.calls)


def test_verify_report_agents_also_verifies_escalation_paths() -> None:
    report = _report(grants={AGENT_ROLE: [], TOOL_ROLE: []}, escalations=[_escalation(AGENT_ROLE)])
    res = compute_agent_blast(report, report.agents[0])
    sim = _Sim({"*": "allowed"})
    verify_report_agents(report, [res], sim)
    assert report.escalation_paths[0].verified is True
    assert res.identity_takeover[0].escalation_verified == 1


def test_verify_simulator_failure_never_raises() -> None:
    grants = {AGENT_ROLE: [_grant("secretsmanager:GetSecretValue", HR_SECRET)], TOOL_ROLE: []}
    res = compute_agent_blast(_report(grants=grants), _report().agents[0])

    def _boom(*_a: Any, **_k: Any) -> list[dict[str, Any]]:
        raise RuntimeError("throttled")

    assert verify_agent_blast(res, _boom) == 0
    secret = next(x for x in res.reaches if x.resource == HR_SECRET)
    assert secret.proof is not None and secret.proof.allowed is None
    assert "throttled" in secret.proof.detail


# ---------------------------------------------------------------------------
# Rendering and serialization
# ---------------------------------------------------------------------------


def test_markdown_and_tree_render_all_sections() -> None:
    grants = {AGENT_ROLE: [_grant("s3:GetObject", "*")], TOOL_ROLE: [_grant("s3:PutObject", f"{KB_BUCKET}/*")]}
    report = _report(grants=grants, escalations=[_escalation(AGENT_ROLE)])
    res = compute_agent_blast(report, report.agents[0])
    md = to_markdown(res)
    for section in (
        "# agent-blast: support-bot",
        "## Identity takeover",
        "## Behaviour takeover",
        "## Reach",
        "## Tags",
        "does not prove",
    ):
        assert section in md
    assert "CreatePolicyVersion" in md
    assert "ASI06" in md and "AML.T0070" in md
    tree = to_tree(res)
    assert tree.label  # renders without raising
    from rich.console import Console

    console = Console(record=True, width=160, force_terminal=False)
    console.print(tree)
    text = console.export_text()
    assert "support-bot" in text
    assert "Behaviour takeover" in text
    assert "poisoning" in text  # a single token: Rich may wrap the line at any space


def test_tree_keeps_secret_arns_literal_no_emoji() -> None:
    """Rich would turn ':secret:' inside an ARN into an emoji (and crash cp1250 consoles)."""
    grants = {AGENT_ROLE: [_grant("secretsmanager:GetSecretValue", HR_SECRET)], TOOL_ROLE: []}
    res = compute_agent_blast(_report(grants=grants), _report().agents[0])
    from rich.console import Console

    console = Console(record=True, width=200, force_terminal=False, emoji=True)
    console.print(to_tree(res))
    text = console.export_text()
    assert ":secret:hr/payroll" in text
    assert "㊙" not in text


def test_json_round_trip() -> None:
    report = _report(grants={AGENT_ROLE: [_grant("s3:GetObject", "*")], TOOL_ROLE: []})
    res = compute_agent_blast(report, report.agents[0])
    loaded = AgentBlastResult.model_validate_json(res.to_json_str())
    assert loaded.agent.name == "support-bot"
    assert loaded.identity_takeover[0].blast.schema_version == "1.0"
    assert loaded.reaches[0].asi
