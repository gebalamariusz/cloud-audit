"""AI agent identity inventory (read-only): who your agents ARE in IAM terms.

Bedrock Agents and AgentCore resources each act through IAM roles: the agent's own
resource role, the execution roles of the Lambda functions behind its tools, the
roles of Knowledge Bases, Gateways, code interpreters and browsers. A hijacked
agent (prompt injection, tool abuse, sandbox escape) acts with *those* identities.
This module lists them so ``agent-blast`` can seed the blast-radius engine with
each one and Proof Mode can simulate concrete actions against concrete resources.

Two threat models, both need this inventory:

- **identity takeover** - the attacker obtains the role's credentials (code
  interpreter escape, metadata-service read): blast radius is the full role;
- **behaviour takeover** - the attacker steers the agent (prompt injection):
  blast radius is bounded by the tools and *their* execution roles.

Read-only: ``bedrock-agent`` and ``bedrock-agentcore-control`` list/get calls plus
``lambda:GetFunctionConfiguration`` to resolve a tool's execution role. No per-call
charge. Regions without the services are skipped silently; access denials are
returned as coverage gaps, because the account may well have agents there.

Bedrock Agents are read at their ``DRAFT`` version (the working copy). Aliases can
pin older numbered versions; a difference between DRAFT and a deployed alias is
a config-drift question, not an identity one, and is out of scope here.

Field names and operations verified against the boto3 1.42 service models.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from cloud_audit.models import AgentIdentity, AgentTool
from cloud_audit.providers.aws.checks.agentcore import _ACCESS_DENIED_CODES, _is_unavailable

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider

_BEDROCK_AGENT = "bedrock-agent"
_AGENTCORE = "bedrock-agentcore-control"
_DRAFT = "DRAFT"


def _paginate(client: Any, method: str, result_key: str, **params: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    paginator = client.get_paginator(method)
    for page in paginator.paginate(**params):
        items.extend(page.get(result_key, []))
    return items


def _skip_or_gap(gaps: list[str], region: str, service: str, exc: Exception) -> bool:
    """True when the caller should skip; records a coverage gap on access denial.

    Mirrors ``checks.agentcore._skip_or_gap``: a region without the service is a
    silent skip, an access denial is "not assessed here".
    """
    if not _is_unavailable(exc):
        return False
    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
    if code in _ACCESS_DENIED_CODES:
        op = getattr(exc, "operation_name", None) or service
        gap = f"{region}: {op} denied ({code}) - AI agent inventory not assessed in this region"
        if gap not in gaps:
            gaps.append(gap)
    return True


def _lambda_role(provider: AWSProvider, region: str, function_arn: str, cache: dict[str, str]) -> str:
    """Resolve a Lambda function's execution role ARN (cached; empty string on any failure)."""
    if not function_arn:
        return ""
    if function_arn in cache:
        return cache[function_arn]
    role = ""
    try:
        cfg = provider.client("lambda", region_name=region).get_function_configuration(FunctionName=function_arn)
        role = str(cfg.get("Role") or "")
    except Exception:
        role = ""
    cache[function_arn] = role
    return role


def _schema_detail(action_group: dict[str, Any]) -> str:
    """Short, honest description of how many operations an action group exposes."""
    fn_schema = action_group.get("functionSchema") or {}
    functions = fn_schema.get("functions")
    if isinstance(functions, list) and functions:
        return f"{len(functions)} function(s) in functionSchema"
    api_schema = action_group.get("apiSchema") or {}
    payload = api_schema.get("payload")
    if isinstance(payload, str) and payload.strip():
        try:
            doc = json.loads(payload)
            paths = doc.get("paths") if isinstance(doc, dict) else None
            if isinstance(paths, dict):
                return f"{len(paths)} OpenAPI path(s) in apiSchema"
        except ValueError:
            pass
        return "OpenAPI schema (inline, not parsed)"
    if api_schema.get("s3"):
        return "OpenAPI schema stored in S3 (not fetched)"
    return "no schema"


# ---------------------------------------------------------------------------
# Bedrock Agents
# ---------------------------------------------------------------------------


def _discover_bedrock_agents(provider: AWSProvider, region: str, gaps: list[str]) -> list[AgentIdentity]:
    agents: list[AgentIdentity] = []
    lambda_cache: dict[str, str] = {}
    try:
        client = provider.client(_BEDROCK_AGENT, region_name=region)
        summaries = _paginate(client, "list_agents", "agentSummaries")
    except Exception as exc:
        if _skip_or_gap(gaps, region, _BEDROCK_AGENT, exc):
            return agents
        raise

    for summary in summaries:
        agent_id = summary.get("agentId")
        if not agent_id:
            continue
        try:
            detail = client.get_agent(agentId=agent_id).get("agent", {})
        except Exception as exc:
            if _skip_or_gap(gaps, region, _BEDROCK_AGENT, exc):
                continue
            raise

        role_arn = str(detail.get("agentResourceRoleArn") or "")
        identity = AgentIdentity(
            agent_id=str(agent_id),
            name=str(detail.get("agentName") or summary.get("agentName") or agent_id),
            kind="bedrock_agent",
            arn=str(detail.get("agentArn") or ""),
            region=region,
            principal_arns=[role_arn] if role_arn else [],
            foundation_model=str(detail.get("foundationModel") or ""),
            guardrail_attached=bool(detail.get("guardrailConfiguration")),
        )
        status = detail.get("agentStatus") or summary.get("agentStatus")
        if status:
            identity.notes.append(f"status: {status}")

        # Tools: action groups -> Lambda executor -> execution role
        try:
            groups = _paginate(
                client, "list_agent_action_groups", "actionGroupSummaries", agentId=agent_id, agentVersion=_DRAFT
            )
        except Exception as exc:
            if not _skip_or_gap(gaps, region, _BEDROCK_AGENT, exc):
                raise
            groups = []
        for group in groups:
            group_id = group.get("actionGroupId")
            if not group_id:
                continue
            try:
                ag = client.get_agent_action_group(agentId=agent_id, agentVersion=_DRAFT, actionGroupId=group_id).get(
                    "agentActionGroup", {}
                )
            except Exception as exc:
                if _skip_or_gap(gaps, region, _BEDROCK_AGENT, exc):
                    continue
                raise
            executor = ag.get("actionGroupExecutor") or {}
            lambda_arn = str(executor.get("lambda") or "")
            name = str(ag.get("actionGroupName") or group.get("actionGroupName") or group_id)
            state = ag.get("actionGroupState") or group.get("actionGroupState") or ""
            detail_note = _schema_detail(ag)
            if state:
                detail_note = f"{detail_note}; state {state}"
            if lambda_arn:
                identity.tools.append(
                    AgentTool(
                        name=name,
                        kind="action_group_lambda",
                        target_arn=lambda_arn,
                        execution_role_arn=_lambda_role(provider, region, lambda_arn, lambda_cache),
                        region=region,
                        detail=detail_note,
                    )
                )
            else:
                identity.tools.append(
                    AgentTool(
                        name=name,
                        kind="action_group_custom_control",
                        region=region,
                        detail=f"{detail_note}; RETURN_CONTROL (executed by the caller, not by AWS)",
                    )
                )

        # Data: knowledge bases -> S3 data sources (+ the KB's own role)
        try:
            kbs = _paginate(
                client,
                "list_agent_knowledge_bases",
                "agentKnowledgeBaseSummaries",
                agentId=agent_id,
                agentVersion=_DRAFT,
            )
        except Exception as exc:
            if not _skip_or_gap(gaps, region, _BEDROCK_AGENT, exc):
                raise
            kbs = []
        for kb_summary in kbs:
            kb_id = kb_summary.get("knowledgeBaseId")
            if not kb_id:
                continue
            try:
                kb = client.get_knowledge_base(knowledgeBaseId=kb_id).get("knowledgeBase", {})
                sources = _paginate(client, "list_data_sources", "dataSourceSummaries", knowledgeBaseId=kb_id)
            except Exception as exc:
                if _skip_or_gap(gaps, region, _BEDROCK_AGENT, exc):
                    continue
                raise
            buckets: list[str] = []
            for src in sources:
                ds_id = src.get("dataSourceId")
                if not ds_id:
                    continue
                try:
                    ds = client.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id).get("dataSource", {})
                except Exception as exc:
                    if _skip_or_gap(gaps, region, _BEDROCK_AGENT, exc):
                        continue
                    raise
                s3 = (ds.get("dataSourceConfiguration") or {}).get("s3Configuration") or {}
                bucket_arn = str(s3.get("bucketArn") or "")
                if bucket_arn:
                    buckets.append(bucket_arn)
            for bucket_arn in buckets:
                if bucket_arn not in identity.data_sources:
                    identity.data_sources.append(bucket_arn)
            identity.tools.append(
                AgentTool(
                    name=str(kb.get("name") or kb_id),
                    kind="knowledge_base",
                    target_arn=str(kb.get("knowledgeBaseArn") or ""),
                    execution_role_arn=str(kb.get("roleArn") or ""),
                    region=region,
                    detail=f"{len(buckets)} S3 data source(s)" if buckets else "no S3 data source",
                )
            )
        agents.append(identity)
    return agents


# ---------------------------------------------------------------------------
# AgentCore: runtimes, gateways (+ targets), code interpreters, browsers
# ---------------------------------------------------------------------------


def _gateway_target_tool(
    provider: AWSProvider, region: str, gateway_role: str, target: dict[str, Any], cache: dict[str, str]
) -> AgentTool:
    mcp = (target.get("targetConfiguration") or {}).get("mcp") or {}
    name = str(target.get("name") or target.get("targetId") or "target")
    providers = target.get("credentialProviderConfigurations") or []
    cred_types = sorted({str(p.get("credentialProviderType") or "") for p in providers if isinstance(p, dict)} - {""})
    cred_note = f"credential provider: {', '.join(cred_types)}" if cred_types else "credential provider: not set"
    # A GATEWAY_IAM_ROLE credential provider means the gateway's own role calls the backend.
    gateway_identity = gateway_role if "GATEWAY_IAM_ROLE" in cred_types else ""

    if "lambda" in mcp:
        lambda_arn = str((mcp.get("lambda") or {}).get("lambdaArn") or "")
        return AgentTool(
            name=name,
            kind="gateway_target_lambda",
            target_arn=lambda_arn,
            execution_role_arn=_lambda_role(provider, region, lambda_arn, cache),
            region=region,
            detail=cred_note,
        )
    if "mcpServer" in mcp:
        endpoint = str((mcp.get("mcpServer") or {}).get("endpoint") or "")
        return AgentTool(
            name=name,
            kind="gateway_target_mcp_server",
            target_arn=endpoint,
            execution_role_arn=gateway_identity,
            region=region,
            detail=f"remote MCP server; {cred_note}",
        )
    if "apiGateway" in mcp:
        api = mcp.get("apiGateway") or {}
        return AgentTool(
            name=name,
            kind="gateway_target_api_gateway",
            target_arn=f"api-gateway:{api.get('restApiId', '')}/{api.get('stage', '')}",
            execution_role_arn=gateway_identity,
            region=region,
            detail=cred_note,
        )
    if "openApiSchema" in mcp:
        return AgentTool(
            name=name,
            kind="gateway_target_openapi",
            execution_role_arn=gateway_identity,
            region=region,
            detail=f"OpenAPI target; {cred_note}",
        )
    if "smithyModel" in mcp:
        return AgentTool(
            name=name,
            kind="gateway_target_smithy",
            execution_role_arn=gateway_identity,
            region=region,
            detail=f"Smithy (AWS service) target; {cred_note}",
        )
    return AgentTool(
        name=name, kind="gateway_target_openapi", execution_role_arn=gateway_identity, region=region, detail=cred_note
    )


def _discover_agentcore(provider: AWSProvider, region: str, gaps: list[str]) -> list[AgentIdentity]:
    agents: list[AgentIdentity] = []
    lambda_cache: dict[str, str] = {}
    try:
        client = provider.client(_AGENTCORE, region_name=region)
        runtimes = _paginate(client, "list_agent_runtimes", "agentRuntimes")
    except Exception as exc:
        if _skip_or_gap(gaps, region, _AGENTCORE, exc):
            return agents
        raise

    for rt in runtimes:
        rt_id = rt.get("agentRuntimeId")
        if not rt_id:
            continue
        try:
            detail = client.get_agent_runtime(agentRuntimeId=rt_id)
        except Exception as exc:
            if _skip_or_gap(gaps, region, _AGENTCORE, exc):
                continue
            raise
        role_arn = str(detail.get("roleArn") or "")
        identity = AgentIdentity(
            agent_id=str(rt_id),
            name=str(detail.get("agentRuntimeName") or rt.get("agentRuntimeName") or rt_id),
            kind="agentcore_runtime",
            arn=str(detail.get("agentRuntimeArn") or rt.get("agentRuntimeArn") or ""),
            region=region,
            principal_arns=[role_arn] if role_arn else [],
        )
        mode = (detail.get("networkConfiguration") or {}).get("networkMode")
        if mode:
            identity.notes.append(f"network mode: {mode}")
        auth = detail.get("authorizerConfiguration")
        identity.notes.append("inbound auth: custom JWT authorizer" if auth else "inbound auth: IAM (SigV4)")
        agents.append(identity)

    # Gateways and their targets
    try:
        gateways = _paginate(client, "list_gateways", "items")
    except Exception as exc:
        if not _skip_or_gap(gaps, region, _AGENTCORE, exc):
            raise
        gateways = []
    for gw in gateways:
        gw_id = gw.get("gatewayId")
        if not gw_id:
            continue
        try:
            detail = client.get_gateway(gatewayIdentifier=gw_id)
        except Exception as exc:
            if _skip_or_gap(gaps, region, _AGENTCORE, exc):
                continue
            raise
        role_arn = str(detail.get("roleArn") or "")
        identity = AgentIdentity(
            agent_id=str(gw_id),
            name=str(detail.get("name") or gw.get("name") or gw_id),
            kind="agentcore_gateway",
            arn=str(detail.get("gatewayArn") or ""),
            region=region,
            principal_arns=[role_arn] if role_arn else [],
        )
        authorizer = detail.get("authorizerType") or gw.get("authorizerType")
        if authorizer:
            identity.notes.append(f"inbound authorizer: {authorizer}")
        policy = detail.get("policyEngineConfiguration") or {}
        identity.notes.append(
            f"policy engine: {policy.get('mode') or 'attached'}" if policy.get("arn") else "policy engine: none"
        )
        try:
            targets = _paginate(client, "list_gateway_targets", "items", gatewayIdentifier=gw_id)
        except Exception as exc:
            if not _skip_or_gap(gaps, region, _AGENTCORE, exc):
                raise
            targets = []
        for tgt in targets:
            tgt_id = tgt.get("targetId")
            if not tgt_id:
                continue
            try:
                full = client.get_gateway_target(gatewayIdentifier=gw_id, targetId=tgt_id)
            except Exception as exc:
                if _skip_or_gap(gaps, region, _AGENTCORE, exc):
                    continue
                raise
            identity.tools.append(_gateway_target_tool(provider, region, role_arn, full, lambda_cache))
        agents.append(identity)

    # Sandboxes with their own execution roles
    for list_op, list_key, get_op, id_key, arn_key, kind in (
        (
            "list_code_interpreters",
            "codeInterpreterSummaries",
            "get_code_interpreter",
            "codeInterpreterId",
            "codeInterpreterArn",
            "agentcore_code_interpreter",
        ),
        ("list_browsers", "browserSummaries", "get_browser", "browserId", "browserArn", "agentcore_browser"),
    ):
        try:
            items = _paginate(client, list_op, list_key)
        except Exception as exc:
            if not _skip_or_gap(gaps, region, _AGENTCORE, exc):
                raise
            continue
        for item in items:
            item_id = item.get(id_key)
            if not item_id:
                continue
            try:
                detail = getattr(client, get_op)(**{id_key: item_id})
            except Exception as exc:
                if _skip_or_gap(gaps, region, _AGENTCORE, exc):
                    continue
                raise
            role_arn = str(detail.get("executionRoleArn") or "")
            identity = AgentIdentity(
                agent_id=str(item_id),
                name=str(detail.get("name") or item.get("name") or item_id),
                kind=kind,
                arn=str(detail.get(arn_key) or item.get(arn_key) or ""),
                region=region,
                principal_arns=[role_arn] if role_arn else [],
            )
            mode = (detail.get("networkConfiguration") or {}).get("networkMode")
            if mode:
                identity.notes.append(f"network mode: {mode}")
            if not role_arn:
                identity.notes.append("no execution role (AWS-managed system sandbox)")
            agents.append(identity)
    return agents


def discover_agents(provider: AWSProvider) -> tuple[list[AgentIdentity], list[str]]:
    """Inventory AI agents and agent sandboxes across the provider's regions.

    Returns ``(agents, coverage_gaps)``. Never raises for a region that lacks the
    services or denies the read; other errors propagate to the caller, which
    decides whether the scan can continue without the inventory.
    """
    agents: list[AgentIdentity] = []
    gaps: list[str] = []
    for region in provider.regions:
        agents.extend(_discover_bedrock_agents(provider, region, gaps))
        agents.extend(_discover_agentcore(provider, region, gaps))
    return agents, gaps


def principal_arns_for(agent: AgentIdentity) -> tuple[list[str], list[str]]:
    """Split an agent's IAM identities into (own roles, tool execution roles), deduplicated, order kept."""
    own = list(dict.fromkeys(a for a in agent.principal_arns if a))
    tools = list(dict.fromkeys(t.execution_role_arn for t in agent.tools if t.execution_role_arn))
    return own, tools
