"""Tests for the AI agent identity inventory (agent_inventory.py).

moto implements only a slice of bedrock-agent and nothing of
bedrock-agentcore-control, so fake clients feed controlled list/get responses.
Field names and operations match the live boto3 service model (verified at
design time); the fakes record call kwargs so required parameters are pinned.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from cloud_audit.models import ScanReport
from cloud_audit.providers.aws.agent_inventory import discover_agents, principal_arns_for

ACCOUNT = "123456789012"
AGENT_ROLE = f"arn:aws:iam::{ACCOUNT}:role/agent-resource-role"
TOOL_ROLE = f"arn:aws:iam::{ACCOUNT}:role/tool-lambda-role"
KB_ROLE = f"arn:aws:iam::{ACCOUNT}:role/kb-role"
LAMBDA_ARN = f"arn:aws:lambda:eu-central-1:{ACCOUNT}:function:search-docs"
RUNTIME_ROLE = f"arn:aws:iam::{ACCOUNT}:role/agentcore-runtime-role"
GATEWAY_ROLE = f"arn:aws:iam::{ACCOUNT}:role/agentcore-gateway-role"
CI_ROLE = f"arn:aws:iam::{ACCOUNT}:role/code-interpreter-role"


class _FakePaginator:
    def __init__(self, pages: list[dict[str, Any]], record: list[dict[str, Any]], method: str) -> None:
        self._pages = pages
        self._record = record
        self._method = method

    def paginate(self, **kwargs: Any) -> list[dict[str, Any]]:
        self._record.append({"op": self._method, **kwargs})
        return self._pages


class _FakeClient:
    """Stand-in for a boto3 client: canned list pages, canned get responses, injected errors."""

    def __init__(
        self,
        *,
        lists: dict[str, list[dict[str, Any]]] | None = None,
        gets: dict[str, dict[str, Any] | Any] | None = None,
        errors: dict[str, Exception] | None = None,
    ) -> None:
        self._lists = lists or {}
        self._gets = gets or {}
        self._errors = errors or {}
        self.calls: list[dict[str, Any]] = []

    def get_paginator(self, method: str) -> _FakePaginator:
        if method in self._errors:
            raise self._errors[method]
        return _FakePaginator(self._lists.get(method, [{}]), self.calls, method)

    def __getattr__(self, name: str) -> Any:
        def _call(**kwargs: Any) -> dict[str, Any]:
            self.calls.append({"op": name, **kwargs})
            if name in self._errors:
                raise self._errors[name]
            value = self._gets.get(name, {})
            return value(**kwargs) if callable(value) else value

        return _call


class _FakeProvider:
    def __init__(self, clients: dict[str, _FakeClient], regions: tuple[str, ...] = ("eu-central-1",)) -> None:
        self._clients = clients
        self.regions = list(regions)

    def client(self, service: str, region_name: str | None = None) -> _FakeClient:
        return self._clients.setdefault(service, _FakeClient())


def _denied(op: str) -> ClientError:
    return ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, op)


def _absent(op: str) -> ClientError:
    return ClientError({"Error": {"Code": "UnrecognizedClientException", "Message": "n/a"}}, op)


def _bedrock_agent_client() -> _FakeClient:
    return _FakeClient(
        lists={
            "list_agents": [
                {"agentSummaries": [{"agentId": "AG1", "agentName": "support-bot", "agentStatus": "PREPARED"}]}
            ],
            "list_agent_action_groups": [
                {
                    "actionGroupSummaries": [
                        {"actionGroupId": "G1", "actionGroupName": "search", "actionGroupState": "ENABLED"},
                        {"actionGroupId": "G2", "actionGroupName": "ask-user", "actionGroupState": "ENABLED"},
                    ]
                }
            ],
            "list_agent_knowledge_bases": [{"agentKnowledgeBaseSummaries": [{"knowledgeBaseId": "KB1"}]}],
            "list_data_sources": [{"dataSourceSummaries": [{"dataSourceId": "DS1"}]}],
        },
        gets={
            "get_agent": {
                "agent": {
                    "agentId": "AG1",
                    "agentArn": f"arn:aws:bedrock:eu-central-1:{ACCOUNT}:agent/AG1",
                    "agentName": "support-bot",
                    "agentResourceRoleArn": AGENT_ROLE,
                    "foundationModel": "anthropic.claude-3-5-sonnet",
                    "guardrailConfiguration": {"guardrailIdentifier": "gr-1", "guardrailVersion": "1"},
                    "agentStatus": "PREPARED",
                }
            },
            "get_agent_action_group": lambda **kw: {
                "agentActionGroup": (
                    {
                        "actionGroupName": "search",
                        "actionGroupState": "ENABLED",
                        "actionGroupExecutor": {"lambda": LAMBDA_ARN},
                        "apiSchema": {"payload": '{"openapi":"3.0.0","paths":{"/search":{},"/fetch":{}}}'},
                    }
                    if kw["actionGroupId"] == "G1"
                    else {
                        "actionGroupName": "ask-user",
                        "actionGroupState": "ENABLED",
                        "actionGroupExecutor": {"customControl": "RETURN_CONTROL"},
                        "functionSchema": {"functions": [{"name": "ask"}]},
                    }
                )
            },
            "get_knowledge_base": {
                "knowledgeBase": {
                    "knowledgeBaseId": "KB1",
                    "name": "docs",
                    "knowledgeBaseArn": f"arn:aws:bedrock:eu-central-1:{ACCOUNT}:knowledge-base/KB1",
                    "roleArn": KB_ROLE,
                }
            },
            "get_data_source": {
                "dataSource": {
                    "dataSourceConfiguration": {"type": "S3", "s3Configuration": {"bucketArn": "arn:aws:s3:::kb-docs"}}
                }
            },
        },
    )


def _lambda_client() -> _FakeClient:
    return _FakeClient(gets={"get_function_configuration": {"FunctionArn": LAMBDA_ARN, "Role": TOOL_ROLE}})


def _agentcore_client() -> _FakeClient:
    return _FakeClient(
        lists={
            "list_agent_runtimes": [{"agentRuntimes": [{"agentRuntimeId": "RT1", "agentRuntimeName": "planner"}]}],
            "list_gateways": [{"items": [{"gatewayId": "GW1", "name": "tools-gw", "authorizerType": "CUSTOM_JWT"}]}],
            "list_gateway_targets": [
                {"items": [{"targetId": "T1", "name": "crm"}, {"targetId": "T2", "name": "remote-mcp"}]}
            ],
            "list_code_interpreters": [
                {"codeInterpreterSummaries": [{"codeInterpreterId": "CI1", "name": "py-sandbox"}]}
            ],
            "list_browsers": [{"browserSummaries": []}],
        },
        gets={
            "get_agent_runtime": {
                "agentRuntimeId": "RT1",
                "agentRuntimeArn": f"arn:aws:bedrock-agentcore:eu-central-1:{ACCOUNT}:runtime/RT1",
                "agentRuntimeName": "planner",
                "roleArn": RUNTIME_ROLE,
                "networkConfiguration": {"networkMode": "PUBLIC"},
            },
            "get_gateway": {
                "gatewayId": "GW1",
                "gatewayArn": f"arn:aws:bedrock-agentcore:eu-central-1:{ACCOUNT}:gateway/GW1",
                "name": "tools-gw",
                "roleArn": GATEWAY_ROLE,
                "authorizerType": "CUSTOM_JWT",
                "policyEngineConfiguration": {},
            },
            "get_gateway_target": lambda **kw: (
                {
                    "targetId": "T1",
                    "name": "crm",
                    "targetConfiguration": {"mcp": {"lambda": {"lambdaArn": LAMBDA_ARN, "toolSchema": {}}}},
                    "credentialProviderConfigurations": [{"credentialProviderType": "GATEWAY_IAM_ROLE"}],
                }
                if kw["targetId"] == "T1"
                else {
                    "targetId": "T2",
                    "name": "remote-mcp",
                    "targetConfiguration": {"mcp": {"mcpServer": {"endpoint": "https://mcp.example.com/mcp"}}},
                    "credentialProviderConfigurations": [{"credentialProviderType": "OAUTH"}],
                }
            ),
            "get_code_interpreter": {
                "codeInterpreterId": "CI1",
                "codeInterpreterArn": f"arn:aws:bedrock-agentcore:eu-central-1:{ACCOUNT}:code-interpreter/CI1",
                "name": "py-sandbox",
                "executionRoleArn": CI_ROLE,
                "networkConfiguration": {"networkMode": "SANDBOX"},
            },
        },
    )


# ---------------------------------------------------------------------------
# Bedrock Agents
# ---------------------------------------------------------------------------


def test_bedrock_agent_identity_tools_and_data() -> None:
    prov = _FakeProvider(
        {
            "bedrock-agent": _bedrock_agent_client(),
            "lambda": _lambda_client(),
            "bedrock-agentcore-control": _FakeClient(),
        }
    )
    agents, gaps = discover_agents(prov)  # type: ignore[arg-type]
    assert gaps == []
    bots = [a for a in agents if a.kind == "bedrock_agent"]
    assert len(bots) == 1
    bot = bots[0]
    assert bot.name == "support-bot"
    assert bot.principal_arns == [AGENT_ROLE]
    assert bot.foundation_model == "anthropic.claude-3-5-sonnet"
    assert bot.guardrail_attached is True
    assert "status: PREPARED" in bot.notes

    kinds = {t.name: t for t in bot.tools}
    assert kinds["search"].kind == "action_group_lambda"
    assert kinds["search"].target_arn == LAMBDA_ARN
    assert kinds["search"].execution_role_arn == TOOL_ROLE
    assert "2 OpenAPI path(s)" in kinds["search"].detail
    assert kinds["ask-user"].kind == "action_group_custom_control"
    assert kinds["ask-user"].execution_role_arn == ""
    assert "RETURN_CONTROL" in kinds["ask-user"].detail
    assert kinds["docs"].kind == "knowledge_base"
    assert kinds["docs"].execution_role_arn == KB_ROLE
    assert bot.data_sources == ["arn:aws:s3:::kb-docs"]

    own, tools = principal_arns_for(bot)
    assert own == [AGENT_ROLE]
    assert tools == [TOOL_ROLE, KB_ROLE]


def test_bedrock_agent_reads_draft_version() -> None:
    client = _bedrock_agent_client()
    prov = _FakeProvider({"bedrock-agent": client, "lambda": _lambda_client()})
    discover_agents(prov)  # type: ignore[arg-type]
    versions = {
        c.get("agentVersion")
        for c in client.calls
        if c["op"] in {"list_agent_action_groups", "get_agent_action_group", "list_agent_knowledge_bases"}
    }
    assert versions == {"DRAFT"}


def test_lambda_role_lookup_failure_leaves_role_empty() -> None:
    lam = _FakeClient(errors={"get_function_configuration": _denied("GetFunctionConfiguration")})
    prov = _FakeProvider({"bedrock-agent": _bedrock_agent_client(), "lambda": lam})
    agents, gaps = discover_agents(prov)  # type: ignore[arg-type]
    search = next(t for t in agents[0].tools if t.name == "search")
    assert search.execution_role_arn == ""
    assert gaps == []  # a Lambda read failure degrades the tool, it is not an inventory gap


def test_lambda_role_is_cached_per_function() -> None:
    lam = _lambda_client()
    client = _bedrock_agent_client()
    client._lists["list_agent_action_groups"] = [
        {
            "actionGroupSummaries": [
                {"actionGroupId": "G1", "actionGroupName": "search"},
                {"actionGroupId": "G1b", "actionGroupName": "search2"},
            ]
        }
    ]
    client._gets["get_agent_action_group"] = {
        "agentActionGroup": {"actionGroupName": "x", "actionGroupExecutor": {"lambda": LAMBDA_ARN}}
    }
    prov = _FakeProvider({"bedrock-agent": client, "lambda": lam})
    discover_agents(prov)  # type: ignore[arg-type]
    assert sum(1 for c in lam.calls if c["op"] == "get_function_configuration") == 1


# ---------------------------------------------------------------------------
# AgentCore
# ---------------------------------------------------------------------------


def test_agentcore_runtime_gateway_targets_and_sandbox() -> None:
    prov = _FakeProvider(
        {"bedrock-agent": _FakeClient(), "lambda": _lambda_client(), "bedrock-agentcore-control": _agentcore_client()}
    )
    agents, gaps = discover_agents(prov)  # type: ignore[arg-type]
    assert gaps == []
    by_kind = {a.kind: a for a in agents}
    assert set(by_kind) == {"agentcore_runtime", "agentcore_gateway", "agentcore_code_interpreter"}

    rt = by_kind["agentcore_runtime"]
    assert rt.principal_arns == [RUNTIME_ROLE]
    assert "network mode: PUBLIC" in rt.notes
    assert "inbound auth: IAM (SigV4)" in rt.notes

    gw = by_kind["agentcore_gateway"]
    assert gw.principal_arns == [GATEWAY_ROLE]
    assert "inbound authorizer: CUSTOM_JWT" in gw.notes
    assert "policy engine: none" in gw.notes
    tools = {t.name: t for t in gw.tools}
    assert tools["crm"].kind == "gateway_target_lambda"
    assert tools["crm"].execution_role_arn == TOOL_ROLE
    assert "GATEWAY_IAM_ROLE" in tools["crm"].detail
    assert tools["remote-mcp"].kind == "gateway_target_mcp_server"
    assert tools["remote-mcp"].target_arn == "https://mcp.example.com/mcp"
    assert tools["remote-mcp"].execution_role_arn == ""  # OAuth, not an IAM identity

    ci = by_kind["agentcore_code_interpreter"]
    assert ci.principal_arns == [CI_ROLE]
    assert "network mode: SANDBOX" in ci.notes


def test_gateway_policy_engine_mode_is_reported() -> None:
    client = _agentcore_client()
    client._gets["get_gateway"] = {
        **client._gets["get_gateway"],
        "policyEngineConfiguration": {"arn": "arn:x", "mode": "ENFORCE"},
    }
    prov = _FakeProvider({"bedrock-agentcore-control": client, "lambda": _lambda_client()})
    agents, _ = discover_agents(prov)  # type: ignore[arg-type]
    gw = next(a for a in agents if a.kind == "agentcore_gateway")
    assert "policy engine: ENFORCE" in gw.notes


def test_system_sandbox_without_role_is_noted() -> None:
    client = _agentcore_client()
    client._gets["get_code_interpreter"] = {"codeInterpreterId": "CI1", "name": "aws-managed"}
    prov = _FakeProvider({"bedrock-agentcore-control": client})
    agents, _ = discover_agents(prov)  # type: ignore[arg-type]
    ci = next(a for a in agents if a.kind == "agentcore_code_interpreter")
    assert ci.principal_arns == []
    assert any("no execution role" in n for n in ci.notes)


# ---------------------------------------------------------------------------
# Availability, denial and gaps
# ---------------------------------------------------------------------------


def test_region_without_services_is_silent() -> None:
    prov = _FakeProvider(
        {
            "bedrock-agent": _FakeClient(errors={"list_agents": _absent("ListAgents")}),
            "bedrock-agentcore-control": _FakeClient(errors={"list_agent_runtimes": _absent("ListAgentRuntimes")}),
        }
    )
    agents, gaps = discover_agents(prov)  # type: ignore[arg-type]
    assert agents == []
    assert gaps == []


def test_access_denied_is_a_coverage_gap_not_an_empty_inventory() -> None:
    prov = _FakeProvider(
        {
            "bedrock-agent": _FakeClient(errors={"list_agents": _denied("ListAgents")}),
            "bedrock-agentcore-control": _FakeClient(errors={"list_agent_runtimes": _denied("ListAgentRuntimes")}),
        },
        regions=("us-east-1",),
    )
    agents, gaps = discover_agents(prov)  # type: ignore[arg-type]
    assert agents == []
    assert len(gaps) == 2
    assert all(g.startswith("us-east-1: ") for g in gaps)
    assert any("ListAgents" in g for g in gaps)
    assert any("ListAgentRuntimes" in g for g in gaps)


def test_partial_denial_keeps_the_agent_and_records_gap() -> None:
    client = _bedrock_agent_client()
    client._errors["list_agent_action_groups"] = _denied("ListAgentActionGroups")
    prov = _FakeProvider({"bedrock-agent": client, "lambda": _lambda_client()})
    agents, gaps = discover_agents(prov)  # type: ignore[arg-type]
    assert len(agents) == 1
    assert agents[0].principal_arns == [AGENT_ROLE]
    assert [t.kind for t in agents[0].tools] == ["knowledge_base"]  # action groups unreadable, KB still read
    assert len(gaps) == 1
    assert "ListAgentActionGroups" in gaps[0]


def test_unexpected_error_propagates() -> None:
    err = ClientError({"Error": {"Code": "ThrottlingException", "Message": "slow"}}, "ListAgents")
    prov = _FakeProvider({"bedrock-agent": _FakeClient(errors={"list_agents": err})})
    try:
        discover_agents(prov)  # type: ignore[arg-type]
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ThrottlingException"
    else:
        raise AssertionError("throttling must propagate so the scanner can report it")


def test_multi_region_inventory_tags_region() -> None:
    prov = _FakeProvider(
        {"bedrock-agent": _bedrock_agent_client(), "lambda": _lambda_client()}, regions=("eu-central-1", "us-east-1")
    )
    agents, _ = discover_agents(prov)  # type: ignore[arg-type]
    assert [a.region for a in agents if a.kind == "bedrock_agent"] == ["eu-central-1", "us-east-1"]


# ---------------------------------------------------------------------------
# Report model
# ---------------------------------------------------------------------------


def test_report_carries_agents_and_gaps_through_json() -> None:
    prov = _FakeProvider({"bedrock-agent": _bedrock_agent_client(), "lambda": _lambda_client()})
    agents, _gaps = discover_agents(prov)  # type: ignore[arg-type]
    report = ScanReport(
        provider="aws",
        account_id=ACCOUNT,
        regions=["eu-central-1"],
        agents=agents,
        agent_inventory_gaps=["us-east-1: ListAgents denied"],
    )
    report.compute_summary()
    assert report.summary.agents_discovered == 1
    assert report.summary.coverage_gaps == 1
    loaded = ScanReport.model_validate_json(report.model_dump_json())
    assert loaded.agents[0].tools[0].execution_role_arn == TOOL_ROLE
    assert loaded.agent_inventory_gaps == ["us-east-1: ListAgents denied"]


def test_old_reports_without_agents_still_load() -> None:
    loaded = ScanReport.model_validate_json('{"provider": "aws", "account_id": "1", "results": []}')
    assert loaded.agents == []
    assert loaded.agent_inventory_gaps == []
    loaded.compute_summary()
    assert loaded.summary.agents_discovered == 0
