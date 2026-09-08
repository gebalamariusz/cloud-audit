"""MCP Server for cloud-audit - exposes AWS security scanning to AI assistants.

Enables AI agents (Claude Code, Cursor, VS Code Copilot) to scan AWS accounts,
query findings, explore attack chains, and get remediation guidance.

Usage:
    # Add to Claude Code:
    claude mcp add cloud-audit -- python -m cloud_audit.mcp_server

    # Or run directly:
    python -m cloud_audit.mcp_server
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "cloud-audit",
    instructions=(
        "Open-source AWS security scanner. "
        "Scan your AWS account for misconfigurations, detect attack chains, "
        "and get copy-paste remediation (CLI + Terraform)."
    ),
)

# In-memory cache for the last scan report
_last_report_json: dict[str, Any] | None = None


def _report_or_error() -> dict[str, Any]:
    if _last_report_json is None:
        msg = "No scan results available. Run the scan_aws tool first."
        raise ValueError(msg)
    return _last_report_json


def _all_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in report.get("results", []):
        findings.extend(result.get("findings", []))
    return findings


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def scan_aws(
    profile: str = "default",
    regions: str = "",
    min_severity: str = "",
) -> str:
    """Run an AWS security scan and return a summary.

    Scans your AWS account for security misconfigurations, detects
    attack chains, and estimates breach cost risk.

    Args:
        profile: AWS CLI profile name (default: "default")
        regions: Comma-separated AWS regions to scan (default: profile region)
        min_severity: Minimum finding severity: critical, high, medium, low
    """
    global _last_report_json

    from cloud_audit.config import CloudAuditConfig
    from cloud_audit.models import Severity
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.scanner import run_scan

    region_list = [r.strip() for r in regions.split(",") if r.strip()] or None
    provider = AWSProvider(profile=profile, regions=region_list)

    config = CloudAuditConfig()
    if min_severity:
        try:
            config.min_severity = Severity(min_severity.lower())
        except ValueError:
            valid = ", ".join(s.value for s in Severity)
            return json.dumps({"error": f"Invalid min_severity '{min_severity}'. Valid: {valid}"})

    report, suppressed = run_scan(provider=provider, config=config, quiet=True)

    # Cache the full report as dict for subsequent tool calls
    _last_report_json = json.loads(report.model_dump_json())

    s = report.summary
    result: dict[str, Any] = {
        "account_id": report.account_id,
        "regions": report.regions,
        "health_score": s.score,
        "total_findings": s.total_findings,
        "attack_chains": s.attack_chains_detected,
        "by_severity": {k.value: v for k, v in s.by_severity.items()},
        "checks_passed": s.checks_passed,
        "checks_failed": s.checks_failed,
        "duration_seconds": report.duration_seconds,
    }

    if s.total_risk_exposure:
        result["risk_exposure"] = s.total_risk_exposure.display

    if suppressed:
        result["findings_suppressed"] = suppressed

    return json.dumps(result, indent=2)


@mcp.tool()
def get_findings(
    severity: str = "",
    service: str = "",
    limit: int = 20,
) -> str:
    """Get findings from the last scan, optionally filtered.

    Each finding includes check ID, severity, resource, description,
    and estimated breach cost.

    Args:
        severity: Filter by severity (critical, high, medium, low)
        service: Filter by AWS service prefix (e.g. "iam", "s3", "ec2", "vpc")
        limit: Maximum number of findings to return (default: 20)
    """
    report = _report_or_error()
    findings = _all_findings(report)

    if severity:
        sev_lower = severity.lower()
        findings = [f for f in findings if f.get("severity") == sev_lower]
    if service:
        svc_lower = service.lower()
        findings = [f for f in findings if f.get("check_id", "").split("-")[1] == svc_lower]

    findings = findings[:limit]

    # Return compact representation
    output = []
    for f in findings:
        item: dict[str, Any] = {
            "check_id": f.get("check_id"),
            "severity": f.get("severity"),
            "title": f.get("title"),
            "resource_id": f.get("resource_id"),
            "region": f.get("region"),
            "description": f.get("description"),
            "recommendation": f.get("recommendation"),
        }
        cost = f.get("cost_estimate")
        if cost:
            item["risk"] = cost.get("display")
        output.append(item)

    return json.dumps(output, indent=2)


@mcp.tool()
def get_attack_chains() -> str:
    """Get all detected attack chains from the last scan.

    Attack chains are correlated findings that form exploitable attack
    paths. Each chain includes a narrative, priority fix, and breach
    cost estimate.
    """
    report = _report_or_error()
    chains = report.get("attack_chains", [])

    output = []
    for c in chains:
        item: dict[str, Any] = {
            "chain_id": c.get("chain_id"),
            "name": c.get("name"),
            "severity": c.get("severity"),
            "attack_narrative": c.get("attack_narrative"),
            "priority_fix": c.get("priority_fix"),
            "resources": c.get("resources"),
            "finding_count": len(c.get("findings", [])),
        }
        cost = c.get("cost_estimate")
        if cost:
            item["risk"] = cost.get("display")
        output.append(item)

    return json.dumps(output, indent=2)


@mcp.tool()
def get_remediation(check_id: str) -> str:
    """Get remediation details (CLI command + Terraform code) for a specific check.

    Returns copy-paste ready AWS CLI command and Terraform HCL snippet
    to fix the finding.

    Args:
        check_id: The check ID (e.g. "aws-iam-001", "aws-s3-001", "aws-vpc-002")
    """
    report = _report_or_error()
    findings = _all_findings(report)

    for f in findings:
        if f.get("check_id") == check_id and f.get("remediation"):
            rem = f["remediation"]
            result: dict[str, Any] = {
                "check_id": f.get("check_id"),
                "title": f.get("title"),
                "resource_id": f.get("resource_id"),
                "cli_command": rem.get("cli"),
                "terraform_hcl": rem.get("terraform"),
                "doc_url": rem.get("doc_url"),
                "effort": rem.get("effort"),
            }
            cost = f.get("cost_estimate")
            if cost:
                result["risk"] = cost.get("display")
            return json.dumps(result, indent=2)

    return json.dumps({"error": f"No remediation found for check_id: {check_id}"})


@mcp.tool()
def get_health_score() -> str:
    """Get the current health score and risk exposure summary.

    Returns the 0-100 health score, finding counts by severity,
    attack chain count, and total estimated risk exposure in USD.
    """
    report = _report_or_error()
    summary = report.get("summary", {})

    result: dict[str, Any] = {
        "health_score": summary.get("score"),
        "total_findings": summary.get("total_findings"),
        "attack_chains": summary.get("attack_chains_detected"),
        "by_severity": summary.get("by_severity"),
        "checks_passed": summary.get("checks_passed"),
        "checks_failed": summary.get("checks_failed"),
    }

    exposure = summary.get("total_risk_exposure")
    if exposure:
        result["risk_exposure"] = exposure.get("display")
        result["risk_rationale"] = exposure.get("rationale")

    return json.dumps(result, indent=2)


@mcp.tool()
def list_checks() -> str:
    """List all available security checks (no AWS credentials needed).

    Returns check IDs with their categories and services.
    """
    from cloud_audit.providers.aws.provider import _CHECK_MODULES

    checks_list: list[dict[str, str]] = []
    _sentinel = type("_Sentinel", (), {})()

    for module in _CHECK_MODULES:
        service = module.__name__.rsplit(".", 1)[-1].rstrip("_")
        try:
            checks = module.get_checks(_sentinel)
        except Exception:  # noqa: S112
            continue

        for check_fn in checks:
            category = getattr(check_fn, "category", "unknown")
            check_id = getattr(check_fn, "check_id", "unknown")
            func_name = getattr(check_fn, "func", check_fn).__name__
            readable = func_name.replace("check_", "").replace("_", " ").title()

            checks_list.append(
                {
                    "check_id": str(check_id),
                    "name": readable,
                    "service": service.upper(),
                    "category": str(getattr(category, "value", category)),
                }
            )

    return json.dumps(checks_list, indent=2)


@mcp.tool()
def get_agent_blast(agent: str = "") -> str:
    """What can a hijacked AI agent reach in this AWS account?

    For every Bedrock Agent, AgentCore runtime, gateway or sandbox found by the
    last scan (or the one matching ``agent`` by name, id or ARN substring),
    returns a Markdown report under two threat models: identity takeover (the
    attacker holds the agent role's credentials) and behaviour takeover (prompt
    injection steering the agent's tools, bounded by the tools' execution
    roles), with data, secret, lateral and code-execution reach and OWASP
    Agentic / MITRE ATLAS tags. Computed from the saved scan, no AWS calls.
    """
    from cloud_audit.agent_blast import compute_agent_blast, find_agent, to_markdown
    from cloud_audit.models import ScanReport

    report = ScanReport.model_validate(_report_or_error())
    if not report.agents:
        gaps = report.agent_inventory_gaps
        if gaps:
            return "No AI agents in the last scan, but the inventory was denied a read: " + "; ".join(gaps)
        return "No AI agents (Bedrock Agents / AgentCore) in the last scan."
    targets = report.agents if not agent.strip() else find_agent(report, agent)
    if not targets:
        names = ", ".join(sorted({a.name for a in report.agents}))
        return f"No agent matches '{agent}'. Available: {names}"
    return "\n\n".join(to_markdown(compute_agent_blast(report, a)) for a in targets)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
