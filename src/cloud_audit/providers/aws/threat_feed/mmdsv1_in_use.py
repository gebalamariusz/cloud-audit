"""TF-006: MMDSv1 still in use on EC2 (and Bedrock AgentCore agents).

EC2 Instance Metadata Service v1 (IMDSv1, also called MMDSv1) is the
session-token-less metadata endpoint that has powered every AWS SSRF + cred-theft
campaign of the last decade (Capital One 2019, Bedrock AgentCore Feb 2026
regression, the long-running cryptomining campaigns). IMDSv2 mandates a
PUT-then-GET handshake with a session token that defeats SSRF.

AWS announced on 2026-02-14 that NEW Bedrock AgentCore agents default to MMDSv2,
but agents created before that date may still be on v1 unless explicitly
upgraded. Coverage of the EC2 surface is also far from universal - Datadog's
2025 State of Cloud Security report shows only 50% of EC2 instances enforce
IMDSv2 (and many that do enforce it have HttpTokens=optional, allowing v1
fallback).

We flag:
- EC2 instances where MetadataOptions.HttpTokens != "required" (v1 still callable)
- Bedrock AgentCore agents where MMDSv2 is not enforced (when API surface available)

References:
    - https://www.datadoghq.com/blog/cloud-security-study-learnings-2025/
    - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
    - https://aws.amazon.com/blogs/security/get-the-full-benefits-of-imdsv2-and-disable-imdsv1-across-your-aws-infrastructure/
    - https://unit42.paloaltonetworks.com/bypass-of-aws-sandbox-network-isolation-mode/
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


PATTERN_ID = "TF-006-mmdsv1-in-use"
CHECK_ID = "aws-tf-006"
PATTERN_NAME = "EC2/AgentCore using IMDSv1 (MMDSv1) - SSRF/credential theft vector"
PATTERN_SEVERITY = Severity.HIGH
DOC_URL = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"

_REFERENCES = [
    "https://www.datadoghq.com/blog/cloud-security-study-learnings-2025/",
    "https://aws.amazon.com/blogs/security/get-the-full-benefits-of-imdsv2-and-disable-imdsv1-across-your-aws-infrastructure/",
    "https://unit42.paloaltonetworks.com/bypass-of-aws-sandbox-network-isolation-mode/",
]


def _build_ec2_finding(instance_id: str, region: str, hop_limit: int, http_endpoint: str) -> Finding:
    hop_note = (
        " HttpPutResponseHopLimit > 1 also means IMDS is reachable from containers "
        "on the host - a Capital-One-style SSRF in any pod can reach the underlying "
        "instance role credentials."
        if hop_limit > 1
        else ""
    )
    endpoint_note = (
        " (IMDS is currently disabled entirely; no immediate exposure but verify the "
        "configuration is intentional - re-enabling without setting HttpTokens=required "
        "re-introduces v1.)"
        if http_endpoint == "disabled"
        else ""
    )
    return Finding(
        check_id=CHECK_ID,
        title=f"EC2 instance {instance_id} allows IMDSv1 (HttpTokens != required)",
        severity=PATTERN_SEVERITY,
        category=Category.THREAT,
        resource_type="AWS::EC2::Instance",
        resource_id=instance_id,
        region=region,
        description=(
            f"Instance {instance_id} in {region} has MetadataOptions.HttpTokens set to "
            f"'optional' (or unset). The IMDSv1 endpoint is callable - any SSRF in code "
            f"running on the instance can fetch IAM role credentials without a session "
            f"token. This is the persistent #1 cred-theft vector tracked across cloud "
            f"breaches since 2019.{hop_note}{endpoint_note}"
        ),
        recommendation=(
            "Enforce IMDSv2 on the instance: set HttpTokens=required and "
            "HttpPutResponseHopLimit=1. After enforcing, monitor "
            "MetadataNoToken CloudWatch metric for 24-48h to catch any application "
            "that still calls v1 (typically old SDK versions)."
        ),
        remediation=Remediation(
            cli=(
                f"# Enforce IMDSv2 on a running instance (no reboot required):\n"
                f"aws ec2 modify-instance-metadata-options \\\n"
                f"  --instance-id {instance_id} \\\n"
                f"  --http-tokens required \\\n"
                f"  --http-put-response-hop-limit 1 \\\n"
                f"  --http-endpoint enabled \\\n"
                f"  --region {region}"
            ),
            terraform=(
                'resource "aws_instance" "this" {\n'
                "  # ... your existing config ...\n"
                "  metadata_options {\n"
                '    http_endpoint               = "enabled"\n'
                '    http_tokens                 = "required"  # IMDSv2 only\n'
                "    http_put_response_hop_limit = 1\n"
                "  }\n"
                "}"
            ),
            doc_url=DOC_URL,
            effort=Effort.LOW,
        ),
        threat_pattern_id=PATTERN_ID,
        references=_REFERENCES,
    )


def _build_agentcore_finding(agent_id: str, agent_name: str, region: str) -> Finding:
    return Finding(
        check_id=CHECK_ID,
        title=f"Bedrock AgentCore agent '{agent_name}' uses MMDSv1",
        severity=Severity.CRITICAL,  # AgentCore + MMDSv1 = active known-CVE
        category=Category.THREAT,
        resource_type="AWS::Bedrock::Agent",
        resource_id=agent_id,
        region=region,
        description=(
            f"Bedrock AgentCore agent '{agent_name}' in {region} is running with MMDSv1 "
            "session-tokenless metadata. Agents created before 2026-02-14 default to v1; "
            "the Unit 42 'Cracks in the Bedrock' research demonstrates active exploitation "
            "via DNS exfiltration in sandbox mode and SSRF regression. Treat as an "
            "exploitable production vulnerability until upgraded."
        ),
        recommendation=(
            "Upgrade the agent to MMDSv2 via the Bedrock AgentCore API (or recreate "
            "the agent - new agents default to v2 since 2026-02-14). For sandbox-mode "
            "agents, also restrict outbound DNS to a known allowlist."
        ),
        remediation=Remediation(
            cli=(
                f"# Inspect current MMDS configuration:\n"
                f"aws bedrock-agent get-agent --agent-id {agent_id} --region {region}\n"
                f"\n# Upgrade (the exact field name depends on your bedrock-agent CLI version;\n"
                f"# consult the AgentCore best-practices doc):\n"
                f"aws bedrock-agent update-agent --agent-id {agent_id} \\\n"
                f"  --metadata-version v2 --region {region}"
            ),
            terraform=(
                "# Bedrock AgentCore Terraform support is evolving - the metadata_version\n"
                "# attribute is a 2026 addition. Consult the AWS provider docs.\n"
                'resource "aws_bedrockagent_agent" "this" {\n'
                "  # ... your existing config ...\n"
                '  metadata_version = "v2"\n'
                "}"
            ),
            doc_url="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-security-best-practices.html",
            effort=Effort.LOW,
        ),
        threat_pattern_id=PATTERN_ID,
        references=[*_REFERENCES, "https://thehackernews.com/2026/03/ai-flaws-in-amazon-bedrock-langsmith.html"],
    )


def _scan_ec2_region(provider: AWSProvider, region: str) -> tuple[int, list[Finding]]:
    ec2 = provider.client("ec2", region_name=region)
    findings: list[Finding] = []
    scanned = 0

    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate(
        Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped", "stopping"]}]
    ):
        for reservation in page.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                scanned += 1
                instance_id = inst.get("InstanceId", "")
                metadata_options = inst.get("MetadataOptions") or {}
                http_tokens = metadata_options.get("HttpTokens", "optional")
                hop_limit = metadata_options.get("HttpPutResponseHopLimit", 1)
                http_endpoint = metadata_options.get("HttpEndpoint", "enabled")

                if http_tokens == "required":
                    continue  # IMDSv2 enforced - safe

                findings.append(
                    _build_ec2_finding(
                        instance_id=instance_id,
                        region=region,
                        hop_limit=hop_limit,
                        http_endpoint=http_endpoint,
                    )
                )
    return scanned, findings


def _scan_agentcore_region(provider: AWSProvider, region: str) -> tuple[int, list[Finding]]:
    """Scan Bedrock AgentCore agents. The metadata_version field is API-dependent;
    we look for it defensively and skip silently if the SDK does not expose it."""
    findings: list[Finding] = []
    scanned = 0
    try:
        bedrock = provider.client("bedrock-agent", region_name=region)
    except Exception:
        return 0, []

    try:
        paginator = bedrock.get_paginator("list_agents")
    except Exception:
        # bedrock-agent client without list_agents available in this region
        return 0, []

    try:
        pages = list(paginator.paginate())
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if code in ("AccessDeniedException", "UnrecognizedClientException", "ValidationException"):
            return 0, []
        raise

    for page in pages:
        for summary in page.get("agentSummaries", []):
            scanned += 1
            agent_id = summary.get("agentId", "")
            agent_name = summary.get("agentName", "")
            try:
                detail = bedrock.get_agent(agentId=agent_id).get("agent", {})
            except Exception:
                continue
            # The exact field name in the AgentCore API as of 2026-Q2 is
            # `metadataVersion`; we accept either spelling defensively.
            mmds_version = detail.get("metadataVersion") or detail.get("MetadataVersion") or "v1"
            if str(mmds_version).lower() in ("v2", "2"):
                continue
            findings.append(_build_agentcore_finding(agent_id=agent_id, agent_name=agent_name, region=region))

    return scanned, findings


def detect(provider: AWSProvider) -> CheckResult:
    """Scan EC2 (all regions) + AgentCore (all regions, best-effort) for MMDSv1 exposure."""
    result = CheckResult(check_id=CHECK_ID, check_name=PATTERN_NAME)

    try:
        for region in provider.regions:
            try:
                ec2_scanned, ec2_findings = _scan_ec2_region(provider, region)
                result.resources_scanned += ec2_scanned
                result.findings.extend(ec2_findings)
            except Exception as exc:
                code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if code in ("AccessDeniedException", "UnrecognizedClientException"):
                    pass  # region opt-in or no perms - skip silently
                else:
                    raise

            ac_scanned, ac_findings = _scan_agentcore_region(provider, region)
            result.resources_scanned += ac_scanned
            result.findings.extend(ac_findings)
    except Exception as e:
        result.error = str(e)

    return result
