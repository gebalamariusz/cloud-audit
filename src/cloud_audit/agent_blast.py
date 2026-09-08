"""agent-blast: what can a hijacked AI agent reach in your AWS account, and can you prove it?

Composes engines cloud-audit already has - the agent identity inventory, the
blast-radius BFS (IAM escalation, AssumeRole hops), raw policy grants and Proof
Mode - into one answer per agent, under two threat models:

- **identity takeover**: the attacker holds the credentials of a role the agent
  runs as (sandbox escape, metadata-service read, leaked session). Reach = the
  full role: escalation methods, lateral AssumeRole hops, data.
- **behaviour takeover**: the attacker steers the agent through prompt injection
  and never sees a credential. Reach = what the agent's tools can do, bounded by
  the tools' own execution roles. The tool role is an upper bound; what the tool
  *code* does with its parameters is narrower and cannot be read from IAM.

Everything is computed offline from a saved scan. ``--verify`` adds read-only
``iam:SimulatePrincipalPolicy`` calls per concrete (principal, action, resource)
so "can read bucket X" becomes "the IAM policy simulator allowed s3:GetObject on
bucket X for this role" (simulated, not executed; see ``proof`` for the exact
scope of that claim).

Tags map each reach to OWASP Top 10 for Agentic Applications (2026) and MITRE
ATLAS (v2026.08) identifiers so the output slots into an auditor's vocabulary.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, Field

from cloud_audit.blast_radius import BlastRadiusResult, compute_blast_radius, disable_emoji
from cloud_audit.models import AgentIdentity, PolicyGrant, ScanReport
from cloud_audit.proof import ATTACKER_CONTEXT_ENTRIES, verify_escalation_paths, verify_resource_access
from cloud_audit.providers.aws.agent_inventory import principal_arns_for

if TYPE_CHECKING:
    from rich.tree import Tree

# ---------------------------------------------------------------------------
# Tag catalogue. Only the identifiers used below; names as published.
# OWASP Top 10 for Agentic Applications, 2026 edition (released 2025-12-09).
# MITRE ATLAS v2026.08 technique ids.
# ---------------------------------------------------------------------------
ASI_NAMES: dict[str, str] = {
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory and Context Poisoning",
}
ATLAS_NAMES: dict[str, str] = {
    "AML.T0034": "Cost Harvesting",
    "AML.T0040": "AI Model Inference API Access",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0070": "RAG Poisoning",
    "AML.T0086": "Exfiltration via AI Agent Tool Invocation",
    "AML.T0105": "Escape to Host",
}

ReachCategory = Literal[
    "secrets", "data_write_poisoning", "lateral", "code_execution", "data_write", "data_read", "model_invocation"
]
# Display order: what an attacker would go for first.
_CATEGORY_ORDER: dict[str, int] = {
    "secrets": 0,
    "data_write_poisoning": 1,
    "lateral": 2,
    "code_execution": 3,
    "data_write": 4,
    "data_read": 5,
    "model_invocation": 6,
}
Scope = Literal["specific", "wildcard"]
Via = Literal["identity", "tool"]

# (action, category, human label, ARN family prefix used to recognise a matching resource pattern)
_REACH_RULES: list[tuple[str, ReachCategory, str, str]] = [
    ("s3:GetObject", "data_read", "read S3 objects", "arn:aws:s3:::"),
    ("s3:PutObject", "data_write", "write S3 objects", "arn:aws:s3:::"),
    ("secretsmanager:GetSecretValue", "secrets", "read secret values", "arn:aws:secretsmanager:"),
    ("ssm:GetParameter", "secrets", "read SSM parameters", "arn:aws:ssm:"),
    ("ssm:GetParameters", "secrets", "read SSM parameters", "arn:aws:ssm:"),
    ("ssm:GetParametersByPath", "secrets", "read SSM parameter trees", "arn:aws:ssm:"),
    ("dynamodb:Scan", "data_read", "scan DynamoDB tables", "arn:aws:dynamodb:"),
    ("dynamodb:Query", "data_read", "query DynamoDB tables", "arn:aws:dynamodb:"),
    ("dynamodb:GetItem", "data_read", "read DynamoDB items", "arn:aws:dynamodb:"),
    ("dynamodb:BatchGetItem", "data_read", "read DynamoDB items", "arn:aws:dynamodb:"),
    ("rds-data:ExecuteStatement", "data_read", "run SQL via RDS Data API", "arn:aws:rds:"),
    ("kms:Decrypt", "secrets", "decrypt with KMS keys", "arn:aws:kms:"),
    ("sqs:ReceiveMessage", "data_read", "read queue messages", "arn:aws:sqs:"),
    ("lambda:InvokeFunction", "code_execution", "invoke Lambda functions", "arn:aws:lambda:"),
    ("lambda:UpdateFunctionCode", "code_execution", "replace Lambda code", "arn:aws:lambda:"),
    (
        "bedrock-agentcore:InvokeCodeInterpreter",
        "code_execution",
        "run code in AgentCore interpreters",
        "arn:aws:bedrock-agentcore:",
    ),
    ("sts:AssumeRole", "lateral", "assume IAM roles", "arn:aws:iam::"),
    ("bedrock:InvokeModel", "model_invocation", "invoke Bedrock models", "arn:aws:bedrock:"),
    (
        "bedrock:InvokeModelWithResponseStream",
        "model_invocation",
        "invoke Bedrock models (streaming)",
        "arn:aws:bedrock:",
    ),
]

_CATEGORY_TAGS: dict[str, tuple[list[str], list[str]]] = {
    # category -> (ASI codes, ATLAS ids) applied on top of the via-based tags
    "data_read": ([], ["AML.T0086"]),
    "data_write": ([], []),
    "data_write_poisoning": (["ASI06"], ["AML.T0070"]),
    "secrets": ([], ["AML.T0086"]),
    "code_execution": (["ASI05"], []),
    "lateral": (["ASI03"], []),
    "model_invocation": ([], ["AML.T0040", "AML.T0034"]),
}
_VIA_TAGS: dict[str, tuple[list[str], list[str]]] = {
    "identity": (["ASI03"], []),
    "tool": (["ASI02"], ["AML.T0053"]),
}
_SANDBOX_KINDS = {"agentcore_code_interpreter", "agentcore_browser"}


class ResourceProofModel(BaseModel):
    """Serializable twin of ``proof.ResourceProof``."""

    decision: str
    allowed: bool | None
    detail: str


class AgentReach(BaseModel):
    """One thing a hijacked agent could do, with the identity it would use and the proof status."""

    principal_arn: str
    via: Via = Field(description="'identity' = the agent's own role; 'tool' = a tool's execution role")
    via_name: str = Field(description="Agent role name or 'tool: <name>'")
    action: str
    resource: str = Field(description="Concrete ARN, ARN pattern, or '*'")
    scope: Scope
    category: ReachCategory
    label: str
    conditional: bool = Field(default=False, description="Allow carries a Condition that was not evaluated statically")
    note: str = ""
    asi: list[str] = Field(default_factory=list)
    atlas: list[str] = Field(default_factory=list)
    proof: ResourceProofModel | None = None


class PrincipalRadius(BaseModel):
    """Blast radius of one IAM identity the agent acts through."""

    principal_arn: str
    via: Via
    via_name: str
    escalation_methods: list[str] = Field(default_factory=list)
    escalation_verified: int = Field(default=0, description="Escalation paths confirmed by the IAM simulator")
    blast: BlastRadiusResult
    has_policy_data: bool = Field(description="False when the scan carries no policy grants for this principal")


class AgentBlastResult(BaseModel):
    """agent-blast output for one agent."""

    agent: AgentIdentity
    headline: str
    identity_takeover: list[PrincipalRadius] = Field(default_factory=list)
    behaviour_takeover: list[PrincipalRadius] = Field(default_factory=list)
    reaches: list[AgentReach] = Field(default_factory=list)
    asi: list[str] = Field(default_factory=list)
    atlas: list[str] = Field(default_factory=list)
    coverage_notes: list[str] = Field(default_factory=list)
    verified: bool = Field(default=False, description="True when --verify ran the IAM simulator for this result")

    def to_json_str(self, indent: int = 2) -> str:
        return self.model_dump_json(indent=indent)


# ---------------------------------------------------------------------------
# Grant matching (static, conservative: patterns compared, conditions flagged)
# ---------------------------------------------------------------------------


def _pattern_matches(pattern: str, value: str) -> bool:
    return fnmatch.fnmatchcase(value.lower(), pattern.lower())


def _grant_allows_action(grant: PolicyGrant, action: str) -> bool:
    if grant.not_action:
        patterns = grant.action.split(":", 1)[1].split(",") if grant.action.startswith("NotAction:") else []
        return not any(_pattern_matches(p, action) for p in patterns)
    return _pattern_matches(grant.action, action)


def _grant_resource_scope(grant: PolicyGrant, family_prefix: str) -> tuple[Scope, str] | None:
    """Return (scope, resource) when the grant's resource can name a resource of this family."""
    if grant.not_resource:
        # "Everything except X" reaches this family unless X excludes the whole family; treat as wildcard.
        return "wildcard", "*"
    resource = grant.resource
    if resource == "*":
        return "wildcard", "*"
    # Family check on the literal prefix (before any wildcard), e.g. arn:aws:s3:::bucket/* vs arn:aws:s3:::
    literal = resource.split("*", 1)[0]
    if literal.startswith(family_prefix) or family_prefix.startswith(literal):
        return ("wildcard", resource) if literal == family_prefix else ("specific", resource)
    return None


def _denied(grants: list[PolicyGrant], action: str, resource: str) -> tuple[bool, bool]:
    """(hard_deny, conditional_deny) for an action on a resource under this principal's Deny grants."""
    hard = False
    conditional = False
    for g in grants:
        if g.effect != "Deny" or not _grant_allows_action(g, action):
            continue
        if g.not_resource or g.resource == "*" or _pattern_matches(g.resource, resource) or resource == "*":
            if g.has_condition:
                conditional = True
            else:
                hard = True
    return hard, conditional


def _reaches_for_principal(
    principal_arn: str,
    via: Via,
    via_name: str,
    grants: list[PolicyGrant],
    kb_buckets: dict[str, str],
    agent_name: str,
) -> list[AgentReach]:
    reaches: dict[tuple[str, str], AgentReach] = {}
    allows = [g for g in grants if g.effect == "Allow"]

    def _add(
        action: str, resource: str, scope: Scope, category: ReachCategory, label: str, conditional: bool, note: str
    ) -> None:
        key = (action.lower(), resource.lower())
        hard, cond_deny = _denied(grants, action, resource)
        if hard:
            return
        if cond_deny:
            note = (note + "; " if note else "") + "a conditional Deny also applies (not evaluated)"
        asi = list(dict.fromkeys(list(_VIA_TAGS[via][0]) + list(_CATEGORY_TAGS[category][0])))
        atlas = list(dict.fromkeys(list(_VIA_TAGS[via][1]) + list(_CATEGORY_TAGS[category][1])))
        existing = reaches.get(key)
        if existing is not None:
            existing.conditional = existing.conditional and conditional
            # The knowledge-base pass carries the more specific story (and tags) for the same pair.
            if "knowledge base" in label and "knowledge base" not in existing.label:
                existing.label, existing.note, existing.category = label, note, category
                existing.asi, existing.atlas = asi, atlas
            return
        reaches[key] = AgentReach(
            principal_arn=principal_arn,
            via=via,
            via_name=via_name,
            action=action,
            resource=resource,
            scope=scope,
            category=category,
            label=label,
            conditional=conditional,
            note=note,
            asi=asi,
            atlas=atlas,
        )

    for action, category, label, family in _REACH_RULES:
        for g in allows:
            if not _grant_allows_action(g, action):
                continue
            scoped = _grant_resource_scope(g, family)
            if scoped is None:
                continue
            scope, resource = scoped
            _add(action, resource, scope, category, label, g.has_condition, f"from {g.source}" if g.source else "")

    # Knowledge-base buckets are concrete targets even under wildcard grants. Any agent's
    # bucket counts: a gateway tool writing into another agent's knowledge base is still
    # RAG poisoning, just cross-agent.
    for bucket_arn, owner in kb_buckets.items():
        object_arn = f"{bucket_arn}/*"
        whose = "the agent's" if owner == agent_name else f"agent '{owner}'"
        for action, category, label in (
            ("s3:GetObject", "data_read", f"read {whose} knowledge base"),
            ("s3:PutObject", "data_write_poisoning", f"write into {whose} knowledge base (RAG poisoning)"),
        ):
            for g in allows:
                if not _grant_allows_action(g, action):
                    continue
                if g.not_resource or g.resource == "*" or _pattern_matches(g.resource, object_arn):
                    _add(
                        action,
                        object_arn,
                        "specific",
                        category,
                        label,
                        g.has_condition,
                        f"knowledge base data source of agent '{owner}'",
                    )
                    break
    return list(reaches.values())


# ---------------------------------------------------------------------------
# Composition
# ---------------------------------------------------------------------------


def _radius_for(
    report: ScanReport, principal_arn: str, via: Via, via_name: str, max_depth: int, max_nodes: int
) -> PrincipalRadius:
    paths = [p for p in report.escalation_paths if p.principal_arn.lower() == principal_arn.lower()]
    blast = compute_blast_radius(report, principal_arn, max_depth=max_depth, max_nodes=max_nodes)
    return PrincipalRadius(
        principal_arn=principal_arn,
        via=via,
        via_name=via_name,
        escalation_methods=sorted({p.method for p in paths}),
        escalation_verified=sum(1 for p in paths if p.verified is True),
        blast=blast,
        has_policy_data=principal_arn in report.principal_grants,
    )


def _headline(
    agent: AgentIdentity, identity: list[PrincipalRadius], tools: list[PrincipalRadius], reaches: list[AgentReach]
) -> str:
    for r in identity:
        if r.escalation_methods:
            return (
                f"Identity takeover of {r.via_name} reaches account admin via "
                f"{r.escalation_methods[0]}"
                f"{' (+' + str(len(r.escalation_methods) - 1) + ' more)' if len(r.escalation_methods) > 1 else ''}"
            )
    for r in tools:
        if r.escalation_methods:
            return f"A hijacked tool ({r.via_name}) can escalate to account admin via {r.escalation_methods[0]}"
    poison = [x for x in reaches if x.category == "data_write_poisoning"]
    if poison:
        return f"{poison[0].via_name} can {poison[0].label}: {poison[0].resource}"
    secrets = [x for x in reaches if x.category == "secrets"]
    data = [x for x in reaches if x.category == "data_read"]
    lateral = [x for x in reaches if x.category == "lateral"]
    if secrets or data or lateral:
        via_tool = sum(1 for x in reaches if x.via == "tool")
        return (
            f"{len(data)} data read(s), {len(secrets)} secret read(s), {len(lateral)} lateral hop(s) reachable; "
            f"{via_tool} through tools (prompt injection alone)"
        )
    if agent.kind in _SANDBOX_KINDS and not agent.principal_arns:
        return "AWS-managed sandbox without an execution role: no IAM reach of its own"
    return "No data, secret, lateral or admin reach found in scan data (check coverage notes)"


def compute_agent_blast(
    report: ScanReport, agent: AgentIdentity, max_depth: int = 5, max_nodes: int = 50
) -> AgentBlastResult:
    """Compute both threat models for one agent from a saved scan. No AWS API calls."""
    own_roles, tool_roles = principal_arns_for(agent)
    notes: list[str] = list(report.agent_inventory_gaps)
    if not report.escalation_paths and not report.principal_grants:
        notes.append(
            "scan carries no IAM escalation paths or policy grants: "
            "run a full scan (IAM check enabled) before agent-blast"
        )

    identity = [_radius_for(report, arn, "identity", arn.rsplit("/", 1)[-1], max_depth, max_nodes) for arn in own_roles]
    tools: list[PrincipalRadius] = []
    tool_role_names: dict[str, str] = {}
    for tool in agent.tools:
        if tool.execution_role_arn:
            tool_role_names.setdefault(tool.execution_role_arn, f"tool: {tool.name}")
        else:
            notes.append(
                f"tool '{tool.name}' ({tool.kind}): backend identity unknown, not assessed - "
                f"{tool.detail or 'no IAM role'}"
            )
    for arn in tool_roles:
        tools.append(_radius_for(report, arn, "tool", tool_role_names.get(arn, "tool"), max_depth, max_nodes))

    # Every knowledge-base bucket in the account, with the agent it feeds.
    kb_buckets: dict[str, str] = {}
    for other in report.agents:
        for bucket in other.data_sources:
            kb_buckets.setdefault(bucket, other.name)
    for bucket in agent.data_sources:
        kb_buckets[bucket] = agent.name

    reaches: list[AgentReach] = []
    for r in identity + tools:
        grants = report.principal_grants.get(r.principal_arn)
        if grants is None:
            notes.append(
                f"no policy data for {r.principal_arn}: data reach not assessed (scan predates v2.5 or IAM read denied)"
            )
            continue
        reaches.extend(_reaches_for_principal(r.principal_arn, r.via, r.via_name, grants, kb_buckets, agent.name))

    asi = sorted(
        {code for x in reaches for code in x.asi} | {"ASI03" for r in identity + tools if r.escalation_methods}
    )
    atlas = sorted(
        {code for x in reaches for code in x.atlas}
        | ({"AML.T0105"} if agent.kind in _SANDBOX_KINDS and own_roles else set())
    )
    return AgentBlastResult(
        agent=agent,
        headline=_headline(agent, identity, tools, reaches),
        identity_takeover=identity,
        behaviour_takeover=tools,
        reaches=reaches,
        asi=asi,
        atlas=atlas,
        coverage_notes=list(dict.fromkeys(notes)),
    )


def find_agent(report: ScanReport, needle: str) -> list[AgentIdentity]:
    """Match agents by exact id, exact name, or case-insensitive substring of either."""
    n = needle.strip().lower()
    exact = [a for a in report.agents if a.agent_id.lower() == n or a.name.lower() == n or a.arn.lower() == n]
    if exact:
        return exact
    return [a for a in report.agents if n in a.name.lower() or n in a.agent_id.lower() or n in a.arn.lower()]


# ---------------------------------------------------------------------------
# Proof Mode for agent-blast
# ---------------------------------------------------------------------------

SimulateFn = Callable[..., list[dict[str, Any]]]


def verify_agent_blast(
    result: AgentBlastResult,
    simulate_fn: SimulateFn,
    context_entries: list[dict[str, Any]] | None = None,
) -> int:
    """Run the IAM policy simulator over every concrete reach and every escalation path.

    Returns the number of reaches the simulator allowed. Wildcard reaches are left
    unproven (a '*' simulation cannot name the resource); the agent's knowledge-base
    buckets are always concrete and therefore always provable.
    """
    ctx = ATTACKER_CONTEXT_ENTRIES if context_entries is None else context_entries
    allowed = 0
    groups: dict[tuple[str, str], list[AgentReach]] = {}
    for reach in result.reaches:
        if reach.scope != "specific" or "*" in reach.resource.removesuffix("/*"):
            reach.proof = ResourceProofModel(
                decision="unknown",
                allowed=None,
                detail="wildcard or pattern resource: not simulated (name a concrete ARN)",
            )
            continue
        groups.setdefault((reach.principal_arn, reach.action), []).append(reach)
    for (principal, action), items in groups.items():
        # A bucket-wide grant is proven on a synthetic object key: the simulator
        # accepts resources that do not exist, and "bucket/*" is a pattern, not an ARN.
        sim_resources = [_probe_arn(i.resource) for i in items]
        proofs = verify_resource_access(principal, action, sim_resources, simulate_fn, ctx)
        by_arn = {p.resource_arn: p for p in proofs}
        for item, sim_resource in zip(items, sim_resources, strict=True):
            p = by_arn.get(sim_resource)
            if p is None:
                item.proof = ResourceProofModel(decision="unknown", allowed=None, detail="no simulator result")
                continue
            item.proof = ResourceProofModel(decision=p.decision, allowed=p.allowed, detail=p.detail)
            if p.allowed is True:
                allowed += 1
    result.verified = True
    return allowed


PROBE_OBJECT_KEY = "cloud-audit-agent-blast-probe"


def _probe_arn(resource: str) -> str:
    """Turn a trailing-wildcard object pattern into a concrete (nonexistent) object ARN for the simulator."""
    return f"{resource[:-2]}/{PROBE_OBJECT_KEY}" if resource.endswith("/*") else resource


def verify_report_agents(report: ScanReport, results: list[AgentBlastResult], simulate_fn: SimulateFn) -> int:
    """Verify reaches for several agents and the escalation paths of their principals in one pass."""
    principals = {r.principal_arn for res in results for r in res.identity_takeover + res.behaviour_takeover}
    paths = [p for p in report.escalation_paths if p.principal_arn in principals]
    if paths:
        verify_escalation_paths(paths, simulate_fn)
        for res in results:
            for radius in res.identity_takeover + res.behaviour_takeover:
                radius.escalation_verified = sum(
                    1 for p in paths if p.principal_arn == radius.principal_arn and p.verified is True
                )
    return sum(verify_agent_blast(res, simulate_fn) for res in results)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_SCOPE_OF_CLAIM = (
    "Simulated, not executed: identity policies, the attached permissions boundary and SCPs are evaluated by "
    "the IAM policy simulator; resource-based policies of the targets, RCPs and VPC endpoint policies are not. "
    "Tool reach is an upper bound set by the tool's role; what the tool code does with its inputs is narrower."
)


def _radius_summary(r: PrincipalRadius, result: AgentBlastResult) -> str:
    """One display line per identity. The engine's own headline stays untouched in JSON."""
    impact = [n for n in r.blast.nodes if n.type == "impact"]
    if impact:
        hops = max(n.bfsStep for n in impact)
        via = ", ".join(r.escalation_methods) or "reachable identities"
        return f"reaches Account Takeover in {hops} hop(s) via {via}"
    if r.escalation_methods:
        return "escalation path: " + ", ".join(r.escalation_methods)
    own = [x for x in result.reaches if x.principal_arn == r.principal_arn]
    if own:
        named = sum(1 for x in own if x.scope == "specific")
        return f"no escalation path; {len(own)} reach(es) from policy grants, {named} on named resources (see Reach)"
    if not r.has_policy_data:
        return "no policy data in scan"
    return "no escalation path and no data reach found"


def _proof_mark(reach: AgentReach) -> str:
    if reach.proof is None:
        return "[dim]unverified[/dim]"
    if reach.proof.allowed is True:
        return "[bold green]PROVEN (simulator: allowed)[/bold green]"
    if reach.proof.allowed is False:
        return "[bold red]DENIED by simulator[/bold red]"
    return "[yellow]not asserted[/yellow]"


def to_tree(result: AgentBlastResult) -> Tree:
    from rich.markup import escape
    from rich.tree import Tree

    a = result.agent
    root = Tree(f"[bold magenta]{escape(a.name)}[/bold magenta] [dim]({escape(a.kind)}, {escape(a.region)})[/dim]")
    root.add(f"[bold]{escape(result.headline)}[/bold]")
    if a.notes:
        root.add("[dim]" + "; ".join(escape(n) for n in a.notes) + "[/dim]")

    ident = root.add("[bold]Identity takeover[/bold] [dim](attacker holds the role's credentials)[/dim]")
    if not result.identity_takeover:
        ident.add("[dim]no IAM role of its own[/dim]")
    for r in result.identity_takeover:
        node = ident.add(f"[magenta]{escape(r.via_name)}[/magenta] [dim]{escape(r.principal_arn)}[/dim]")
        node.add(
            f"{escape(_radius_summary(r, result))} "
            f"[dim](risk {r.blast.summary.risk_score}/100, {r.blast.summary.nodes_reachable} nodes)[/dim]"
        )
        if r.escalation_methods:
            node.add(
                f"[red]escalation: {escape(', '.join(r.escalation_methods))}[/red]"
                + (f" [green]({r.escalation_verified} confirmed by simulator)[/green]" if r.escalation_verified else "")
            )
        if not r.has_policy_data:
            node.add("[yellow]no policy data in scan: data reach not assessed[/yellow]")

    beh = root.add("[bold]Behaviour takeover[/bold] [dim](prompt injection: the agent's tools, their roles)[/dim]")
    if not a.tools:
        beh.add("[dim]no tools[/dim]")
    for tool in a.tools:
        line = f"[cyan]{escape(tool.name)}[/cyan] [dim]{escape(tool.kind)}[/dim]"
        if tool.execution_role_arn:
            line += f" -> [magenta]{escape(tool.execution_role_arn.rsplit('/', 1)[-1])}[/magenta]"
        else:
            line += " [yellow](no IAM identity known)[/yellow]"
        tnode = beh.add(line)
        if tool.detail:
            tnode.add(f"[dim]{escape(tool.detail)}[/dim]")
        for r in result.behaviour_takeover:
            if r.principal_arn == tool.execution_role_arn:
                tnode.add(f"{escape(_radius_summary(r, result))} [dim](risk {r.blast.summary.risk_score}/100)[/dim]")
                if r.escalation_methods:
                    tnode.add(f"[red]escalation: {escape(', '.join(r.escalation_methods))}[/red]")

    reach = root.add(f"[bold]Reach[/bold] [dim]({len(result.reaches)} action/resource pairs)[/dim]")
    for x in sorted(result.reaches, key=lambda y: (_CATEGORY_ORDER.get(y.category, 99), y.via, y.action, y.resource)):
        cond = " [yellow](conditional)[/yellow]" if x.conditional else ""
        reach.add(
            f"[{'cyan' if x.via == 'tool' else 'magenta'}]{escape(x.via_name)}[/] {escape(x.action)} on "
            f"[green]{escape(x.resource)}[/green]{cond} {_proof_mark(x)} [dim]{escape(x.label)}[/dim]"
        )

    tags = root.add("[bold]Tags[/bold]")
    tags.add("OWASP Agentic: " + (", ".join(f"{c} {ASI_NAMES.get(c, '')}" for c in result.asi) or "none"))
    tags.add("MITRE ATLAS: " + (", ".join(f"{c} {ATLAS_NAMES.get(c, '')}" for c in result.atlas) or "none"))

    if result.coverage_notes:
        cov = root.add("[bold yellow]Coverage notes[/bold yellow]")
        for n in result.coverage_notes:
            cov.add(f"[yellow]{escape(n)}[/yellow]")
    root.add(f"[dim]{escape(_SCOPE_OF_CLAIM)}[/dim]")
    disable_emoji(root)  # ARNs such as ...:secret:... must never turn into emoji
    return root


def to_markdown(result: AgentBlastResult) -> str:
    a = result.agent
    lines = [
        f"# agent-blast: {a.name}",
        "",
        f"**Kind:** {a.kind}  ",
        f"**Region:** {a.region}  ",
        f"**ARN:** `{a.arn}`  " if a.arn else "",
        f"**Headline:** {result.headline}",
        "",
    ]
    if a.notes:
        lines += ["**Config notes:** " + "; ".join(a.notes), ""]
    lines += [
        "## Identity takeover",
        "",
        "| Role | Blast headline | Risk | Escalation | Simulator-confirmed |",
        "|---|---|---|---|---|",
    ]
    for r in result.identity_takeover:
        lines.append(
            f"| `{r.principal_arn}` | {_radius_summary(r, result)} | {r.blast.summary.risk_score}/100 | "
            f"{', '.join(r.escalation_methods) or 'none'} | {r.escalation_verified if result.verified else 'n/a'} |"
        )
    if not result.identity_takeover:
        lines.append("| (no IAM role of its own) | | | | |")
    lines += [
        "",
        "## Behaviour takeover (tools)",
        "",
        "| Tool | Kind | Backend | Execution role | Blast headline |",
        "|---|---|---|---|---|",
    ]
    radius_by_arn = {r.principal_arn: r for r in result.behaviour_takeover}
    for t in a.tools:
        radius = radius_by_arn.get(t.execution_role_arn)
        lines.append(
            f"| {t.name} | {t.kind} | `{t.target_arn}` | `{t.execution_role_arn or 'unknown'}` | "
            f"{_radius_summary(radius, result) if radius else 'not assessed'} |"
        )
    if not a.tools:
        lines.append("| (no tools) | | | | |")
    lines += ["", "## Reach", "", "| Via | Action | Resource | Scope | Category | Proof |", "|---|---|---|---|---|---|"]
    for x in sorted(result.reaches, key=lambda y: (_CATEGORY_ORDER.get(y.category, 99), y.via, y.action, y.resource)):
        proof = (
            "unverified"
            if x.proof is None
            else ("PROVEN" if x.proof.allowed is True else ("DENIED" if x.proof.allowed is False else "not asserted"))
        )
        cond = " (conditional)" if x.conditional else ""
        lines.append(f"| {x.via_name} | `{x.action}` | `{x.resource}`{cond} | {x.scope} | {x.category} | {proof} |")
    if not result.reaches:
        lines.append("| (none found in scan data) | | | | | |")
    lines += ["", "## Tags", ""]
    lines.append(
        "- OWASP Top 10 for Agentic Applications: "
        + (", ".join(f"{c} ({ASI_NAMES.get(c, '')})" for c in result.asi) or "none")
    )
    lines.append("- MITRE ATLAS: " + (", ".join(f"{c} ({ATLAS_NAMES.get(c, '')})" for c in result.atlas) or "none"))
    if result.coverage_notes:
        lines += ["", "## Coverage notes", ""]
        lines += [f"- {n}" for n in result.coverage_notes]
    lines += ["", "## What this proves and does not prove", "", _SCOPE_OF_CLAIM, ""]
    return "\n".join(line for line in lines if line is not None)
