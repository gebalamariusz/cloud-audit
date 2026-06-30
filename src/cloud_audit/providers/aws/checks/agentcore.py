"""Amazon Bedrock AgentCore security checks.

AgentCore (GA 2025-10) is AWS's managed platform for running AI agents (Runtime,
Code Interpreter, Memory, Gateway, Identity, Policy). Its security model is
"secure by AWS, misconfigured by customer": several attack surfaces are the
customer's responsibility and AWS does not fix them automatically. Palo Alto
Unit 42 ("Cracks in the Bedrock") documented IAM "God Mode", sandbox
network-isolation bypass / egress exfiltration, and related issues in 2026.

cloud-audit is the first OSS scanner with dedicated AgentCore checks. All checks
are read-only (``bedrock-agentcore-control`` list/get) with no per-call charge.
AgentCore is regional and not present in every region; regions/accounts without
the service are skipped silently.

Field names, operations and enum values used here were verified against the live
boto3 service model (boto3 1.42.x) - not assumed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn

_SERVICE = "bedrock-agentcore-control"

# Errors meaning "service/region not available or not permitted here" -> skip region.
_SKIP_ERROR_CODES = {
    "AccessDeniedException",
    "UnrecognizedClientException",
    "ResourceNotFoundException",
    "ValidationException",
    "OptInRequired",
    "InvalidAction",
    "NotImplementedException",
    "404",
}
_SKIP_ERROR_TYPES = {
    "EndpointConnectionError",
    "ConnectTimeoutError",
    "UnknownServiceError",
    "NoRegionError",
}

# Verified documentation sources.
_UNIT42_GODMODE = "https://unit42.paloaltonetworks.com/exploit-of-aws-agentcore-iam-god-mode/"
_UNIT42_SANDBOX = "https://unit42.paloaltonetworks.com/bypass-of-aws-sandbox-network-isolation-mode/"
_TF_RUNTIME = (
    "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/bedrockagentcore_agent_runtime"
)
_TF_GATEWAY = "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/bedrockagentcore_gateway"
_TF_MEMORY = "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/bedrockagentcore_memory"


def _is_unavailable(exc: Exception) -> bool:
    """True if the error means AgentCore is absent/unsupported/forbidden here (skip).

    AgentCore is a new, regional service. A region or account without it (or an
    older endpoint) surfaces as endpoint errors, access/validation errors, opt-in
    requirements, or "not implemented" / 404 responses - none of which should fail
    the scan. Anything else (e.g. throttling that survives retries) propagates.
    """
    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
    if code in _SKIP_ERROR_CODES:
        return True
    if type(exc).__name__ in _SKIP_ERROR_TYPES:
        return True
    msg = str(exc).lower()
    return "not implemented" in msg or "not supported" in msg


def _paginate(client: Any, method: str, result_key: str) -> list[dict[str, Any]]:
    """Collect all items from a paginated list operation."""
    items: list[dict[str, Any]] = []
    paginator = client.get_paginator(method)
    for page in paginator.paginate():
        items.extend(page.get(result_key, []))
    return items


def _agentcore_client(provider: AWSProvider, region: str) -> Any:
    """Build a read-only bedrock-agentcore-control client (cached, adaptive retry via provider.client)."""
    return provider.client(_SERVICE, region_name=region)


def check_code_interpreter_public_network(provider: AWSProvider) -> CheckResult:
    """Flag AgentCore Code Interpreters running in PUBLIC network mode."""
    result = CheckResult(check_id="aws-agc-001", check_name="AgentCore Code Interpreter public network mode")
    try:
        for region in provider.regions:
            try:
                client = _agentcore_client(provider, region)
                summaries = _paginate(client, "list_code_interpreters", "codeInterpreterSummaries")
            except Exception as exc:
                if _is_unavailable(exc):
                    continue
                raise

            for summary in summaries:
                ci_id = summary.get("codeInterpreterId")
                if not ci_id:
                    continue
                result.resources_scanned += 1
                try:
                    detail = client.get_code_interpreter(codeInterpreterId=ci_id)
                except Exception as exc:
                    if _is_unavailable(exc):
                        continue
                    raise

                if detail.get("networkConfiguration", {}).get("networkMode") != "PUBLIC":
                    continue
                name = detail.get("name", ci_id)
                result.findings.append(
                    Finding(
                        check_id="aws-agc-001",
                        title=f"AgentCore Code Interpreter '{name}' uses PUBLIC network mode in {region}",
                        severity=Severity.HIGH,
                        category=Category.SECURITY,
                        resource_type="AWS::BedrockAgentCore::CodeInterpreter",
                        resource_id=detail.get("codeInterpreterArn", ci_id),
                        region=region,
                        description=(
                            f"AgentCore Code Interpreter '{name}' runs in PUBLIC network mode, giving the "
                            "sandbox unrestricted outbound internet access. Code the agent executes - including "
                            "attacker-influenced or prompt-injected code - can exfiltrate data or reach external "
                            "command-and-control. Unit 42 documented sandbox network-isolation bypass and DNS "
                            "egress on this surface. PUBLIC mode is a customer configuration choice, not an AWS bug."
                        ),
                        recommendation=(
                            "Recreate the Code Interpreter in SANDBOX or VPC network mode and add Route 53 DNS "
                            "Firewall egress filtering for VPC."
                        ),
                        remediation=Remediation(
                            cli=(
                                "# networkMode is immutable - recreate with restricted egress, then delete the old one\n"
                                "aws bedrock-agentcore-control create-code-interpreter \\\n"
                                f"  --name {name} --execution-role-arn <ROLE_ARN> \\\n"
                                '  --network-configuration \'{"networkMode":"SANDBOX"}\' \\\n'
                                f"  --region {region}\n"
                                f"aws bedrock-agentcore-control delete-code-interpreter --code-interpreter-id {ci_id} "
                                f"--region {region}"
                            ),
                            terraform=(
                                "# aws-ia/agentcore module exposes network_mode for code interpreters\n"
                                'module "agentcore" {\n'
                                '  source = "aws-ia/agentcore/aws"\n'
                                "  code_interpreters = {\n"
                                f'    {name} = {{ network_mode = "SANDBOX" }}\n'
                                "  }\n"
                                "}"
                            ),
                            doc_url=_UNIT42_SANDBOX,
                            effort=Effort.MEDIUM,
                        ),
                    )
                )
    except Exception as e:
        result.error = str(e)
    return result


def check_runtime_public_network(provider: AWSProvider) -> CheckResult:
    """Flag AgentCore Agent Runtimes running in PUBLIC network mode."""
    result = CheckResult(check_id="aws-agc-002", check_name="AgentCore Runtime public network mode")
    try:
        for region in provider.regions:
            try:
                client = _agentcore_client(provider, region)
                summaries = _paginate(client, "list_agent_runtimes", "agentRuntimes")
            except Exception as exc:
                if _is_unavailable(exc):
                    continue
                raise

            for summary in summaries:
                rt_id = summary.get("agentRuntimeId")
                if not rt_id:
                    continue
                result.resources_scanned += 1
                try:
                    detail = client.get_agent_runtime(agentRuntimeId=rt_id)
                except Exception as exc:
                    if _is_unavailable(exc):
                        continue
                    raise

                if detail.get("networkConfiguration", {}).get("networkMode") != "PUBLIC":
                    continue
                name = detail.get("agentRuntimeName", rt_id)
                result.findings.append(
                    Finding(
                        check_id="aws-agc-002",
                        title=f"AgentCore Runtime '{name}' uses PUBLIC network mode in {region}",
                        severity=Severity.HIGH,
                        category=Category.SECURITY,
                        resource_type="AWS::BedrockAgentCore::Runtime",
                        resource_id=detail.get("agentRuntimeArn", rt_id),
                        region=region,
                        description=(
                            f"AgentCore Runtime '{name}' runs in PUBLIC network mode with unrestricted outbound "
                            "internet access. A compromised or prompt-injected agent can exfiltrate data and reach "
                            "external infrastructure. PUBLIC can be intentional for public-facing agents (pair it "
                            "with a JWT/IAM authorizer); the risk flagged here is the uncontrolled egress, not the "
                            "PUBLIC value itself. Run production agents in VPC mode so egress is controlled."
                        ),
                        recommendation="Move the runtime to VPC network mode with controlled egress (DNS Firewall).",
                        remediation=Remediation(
                            cli=(
                                "aws bedrock-agentcore-control update-agent-runtime \\\n"
                                f"  --agent-runtime-id {rt_id} \\\n"
                                '  --network-configuration \'{"networkMode":"VPC","networkModeConfig":'
                                '{"subnets":["subnet-xxx"],"securityGroups":["sg-xxx"]}}\' \\\n'
                                f"  --region {region}"
                            ),
                            terraform=(
                                'resource "aws_bedrockagentcore_agent_runtime" "this" {\n'
                                "  # ...\n"
                                "  network_configuration {\n"
                                '    network_mode = "VPC"\n'
                                "  }\n"
                                "}"
                            ),
                            doc_url=_TF_RUNTIME,
                            effort=Effort.MEDIUM,
                        ),
                    )
                )
    except Exception as e:
        result.error = str(e)
    return result


def check_runtime_imdsv2(provider: AWSProvider) -> CheckResult:
    """Flag AgentCore Runtimes that do not enforce MMDSv2 (metadata service v2)."""
    result = CheckResult(check_id="aws-agc-003", check_name="AgentCore Runtime MMDSv2 not enforced")
    try:
        for region in provider.regions:
            try:
                client = _agentcore_client(provider, region)
                summaries = _paginate(client, "list_agent_runtimes", "agentRuntimes")
            except Exception as exc:
                if _is_unavailable(exc):
                    continue
                raise

            for summary in summaries:
                rt_id = summary.get("agentRuntimeId")
                if not rt_id:
                    continue
                result.resources_scanned += 1
                try:
                    detail = client.get_agent_runtime(agentRuntimeId=rt_id)
                except Exception as exc:
                    if _is_unavailable(exc):
                        continue
                    raise

                # requireMMDSV2 must be explicitly True; absent or False = v1 allowed.
                if detail.get("metadataConfiguration", {}).get("requireMMDSV2") is True:
                    continue
                name = detail.get("agentRuntimeName", rt_id)
                result.findings.append(
                    Finding(
                        check_id="aws-agc-003",
                        title=f"AgentCore Runtime '{name}' does not enforce MMDSv2 in {region}",
                        severity=Severity.HIGH,
                        category=Category.SECURITY,
                        resource_type="AWS::BedrockAgentCore::Runtime",
                        resource_id=detail.get("agentRuntimeArn", rt_id),
                        region=region,
                        description=(
                            f"AgentCore Runtime '{name}' does not require MMDSv2 for its metadata service. With v1 "
                            "allowed, a server-side request forgery (SSRF) or prompt-injection that makes the agent "
                            "fetch a URL can read the metadata endpoint and steal the runtime's IAM credentials - "
                            "the same class of attack IMDSv2 hardens against on EC2."
                        ),
                        recommendation="Enforce MMDSv2 on the runtime (requireMMDSV2 = true).",
                        remediation=Remediation(
                            cli=(
                                "aws bedrock-agentcore-control update-agent-runtime \\\n"
                                f"  --agent-runtime-id {rt_id} \\\n"
                                "  --metadata-configuration '{\"requireMMDSV2\":true}' \\\n"
                                f"  --region {region}"
                            ),
                            terraform=(
                                "# As of 2026-06 the aws_bedrockagentcore_agent_runtime resource does not yet "
                                "expose MMDSv2\n# enforcement - apply the AWS CLI fix above, or use "
                                "aws_cloudcontrolapi_resource with\n# requireMMDSV2 in the desired_state JSON."
                            ),
                            doc_url=_UNIT42_GODMODE,
                            effort=Effort.LOW,
                        ),
                    )
                )
    except Exception as e:
        result.error = str(e)
    return result


def check_memory_encryption(provider: AWSProvider) -> CheckResult:
    """Flag AgentCore Memory stores without a customer-managed KMS key."""
    result = CheckResult(check_id="aws-agc-004", check_name="AgentCore Memory without customer-managed KMS")
    try:
        for region in provider.regions:
            try:
                client = _agentcore_client(provider, region)
                summaries = _paginate(client, "list_memories", "memories")
            except Exception as exc:
                if _is_unavailable(exc):
                    continue
                raise

            for summary in summaries:
                mem_id = summary.get("id")
                if not mem_id:
                    continue
                result.resources_scanned += 1
                try:
                    memory = client.get_memory(memoryId=mem_id).get("memory", {})
                except Exception as exc:
                    if _is_unavailable(exc):
                        continue
                    raise

                if memory.get("encryptionKeyArn"):
                    continue
                name = memory.get("name", mem_id)
                result.findings.append(
                    Finding(
                        check_id="aws-agc-004",
                        title=f"AgentCore Memory '{name}' has no customer-managed KMS key in {region}",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        resource_type="AWS::BedrockAgentCore::Memory",
                        resource_id=memory.get("arn", mem_id),
                        region=region,
                        description=(
                            f"AgentCore Memory '{name}' has no customer-managed KMS key (encryptionKeyArn unset), so "
                            "it falls back to an AWS-owned key. Agent memory persists conversation context and "
                            "extracted data; without a CMK there is no key-level audit trail, rotation control, or "
                            "incident-time revocation, and cross-account/shared-strategy access is harder to bound."
                        ),
                        recommendation="Recreate the memory store with a customer-managed KMS key (encryptionKeyArn).",
                        remediation=Remediation(
                            cli=(
                                "# encryption key is set at creation - recreate with a CMK\n"
                                "aws bedrock-agentcore-control create-memory \\\n"
                                f"  --name {name} --encryption-key-arn <KMS_KEY_ARN> \\\n"
                                f"  --region {region}"
                            ),
                            terraform=(
                                'resource "aws_bedrockagentcore_memory" "this" {\n'
                                "  # ...\n"
                                "  encryption_key_arn = aws_kms_key.agentcore.arn\n"
                                "}"
                            ),
                            doc_url=_TF_MEMORY,
                            effort=Effort.MEDIUM,
                        ),
                    )
                )
    except Exception as e:
        result.error = str(e)
    return result


def check_gateway_authorizer(provider: AWSProvider) -> CheckResult:
    """Flag AgentCore Gateways with no inbound authorizer (open tool access)."""
    result = CheckResult(check_id="aws-agc-005", check_name="AgentCore Gateway without inbound authorizer")
    try:
        for region in provider.regions:
            try:
                client = _agentcore_client(provider, region)
                summaries = _paginate(client, "list_gateways", "items")
            except Exception as exc:
                if _is_unavailable(exc):
                    continue
                raise

            for summary in summaries:
                gw_id = summary.get("gatewayId")
                if not gw_id:
                    continue
                result.resources_scanned += 1
                try:
                    detail = client.get_gateway(gatewayIdentifier=gw_id)
                except Exception as exc:
                    if _is_unavailable(exc):
                        continue
                    raise

                if detail.get("authorizerType") != "NONE":
                    continue
                name = detail.get("name", gw_id)
                result.findings.append(
                    Finding(
                        check_id="aws-agc-005",
                        title=f"AgentCore Gateway '{name}' has no inbound authorizer in {region}",
                        severity=Severity.HIGH,
                        category=Category.SECURITY,
                        resource_type="AWS::BedrockAgentCore::Gateway",
                        resource_id=detail.get("gatewayArn", gw_id),
                        region=region,
                        description=(
                            f"AgentCore Gateway '{name}' has authorizerType NONE - the gateway exposes its MCP tools "
                            "and targets without authenticating callers. Anyone able to reach the gateway URL can "
                            "invoke the connected tools and the IAM role behind them. Require CUSTOM_JWT or AWS_IAM."
                        ),
                        recommendation="Set an inbound authorizer (CUSTOM_JWT with scoped audience/clients, or AWS_IAM).",
                        remediation=Remediation(
                            cli=(
                                "aws bedrock-agentcore-control update-gateway \\\n"
                                f"  --gateway-identifier {gw_id} --authorizer-type AWS_IAM \\\n"
                                f"  --region {region}"
                            ),
                            terraform=(
                                'resource "aws_bedrockagentcore_gateway" "this" {\n'
                                "  # ...\n"
                                '  authorizer_type = "AWS_IAM"\n'
                                "}"
                            ),
                            doc_url=_TF_GATEWAY,
                            effort=Effort.MEDIUM,
                        ),
                    )
                )
    except Exception as e:
        result.error = str(e)
    return result


def check_gateway_policy_engine(provider: AWSProvider) -> CheckResult:
    """Flag AgentCore Gateways with no enforcing policy engine (Cedar) governance."""
    result = CheckResult(check_id="aws-agc-006", check_name="AgentCore Gateway policy engine not enforcing")
    try:
        for region in provider.regions:
            try:
                client = _agentcore_client(provider, region)
                summaries = _paginate(client, "list_gateways", "items")
            except Exception as exc:
                if _is_unavailable(exc):
                    continue
                raise

            for summary in summaries:
                gw_id = summary.get("gatewayId")
                if not gw_id:
                    continue
                result.resources_scanned += 1
                try:
                    detail = client.get_gateway(gatewayIdentifier=gw_id)
                except Exception as exc:
                    if _is_unavailable(exc):
                        continue
                    raise

                policy_engine = detail.get("policyEngineConfiguration") or {}
                mode = policy_engine.get("mode")
                if mode == "ENFORCE":
                    continue
                name = detail.get("name", gw_id)
                state = "log-only (not enforcing)" if mode == "LOG_ONLY" else "no policy engine attached"
                result.findings.append(
                    Finding(
                        check_id="aws-agc-006",
                        title=f"AgentCore Gateway '{name}' does not enforce a policy engine in {region}",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY,
                        resource_type="AWS::BedrockAgentCore::Gateway",
                        resource_id=detail.get("gatewayArn", gw_id),
                        region=region,
                        description=(
                            f"AgentCore Gateway '{name}' has {state}. Without an enforcing Cedar policy engine, "
                            "fine-grained authorization on which caller may invoke which tool is not applied - a "
                            "valid caller can reach every target the gateway exposes. LOG_ONLY records decisions "
                            "but does not block them."
                        ),
                        recommendation="Attach a policy engine in ENFORCE mode with least-privilege tool rules.",
                        remediation=Remediation(
                            cli=(
                                "aws bedrock-agentcore-control update-gateway \\\n"
                                f"  --gateway-identifier {gw_id} \\\n"
                                '  --policy-engine-configuration \'{"arn":"<POLICY_ENGINE_ARN>","mode":"ENFORCE"}\' \\\n'
                                f"  --region {region}"
                            ),
                            terraform=(
                                'resource "aws_bedrockagentcore_gateway" "this" {\n'
                                "  # ...\n"
                                "  policy_engine_configuration {\n"
                                '    mode = "ENFORCE"\n'
                                "  }\n"
                                "}"
                            ),
                            doc_url=_TF_GATEWAY,
                            effort=Effort.MEDIUM,
                        ),
                    )
                )
    except Exception as e:
        result.error = str(e)
    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all AgentCore checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_code_interpreter_public_network, provider, check_id="aws-agc-001", category=Category.SECURITY),
        make_check(check_runtime_public_network, provider, check_id="aws-agc-002", category=Category.SECURITY),
        make_check(check_runtime_imdsv2, provider, check_id="aws-agc-003", category=Category.SECURITY),
        make_check(check_memory_encryption, provider, check_id="aws-agc-004", category=Category.SECURITY),
        make_check(check_gateway_authorizer, provider, check_id="aws-agc-005", category=Category.SECURITY),
        make_check(check_gateway_policy_engine, provider, check_id="aws-agc-006", category=Category.SECURITY),
    ]
