"""Deterministic sample scan used by ``cloud-audit demo --save`` and ``agent-blast --demo``.

The findings, identities and agents are invented (account ``123456789012``,
region ``eu-central-1``), but everything derived from them is produced by the
real engines: attack-chain correlation, root-cause grouping, breach-cost
estimation, the security graph and the agent identity model. What you see in
the sample output is what a real scan with the same findings would produce.

No AWS API calls. Safe to run anywhere.
"""

from __future__ import annotations

from cloud_audit.correlate import ResourceRelationships, detect_attack_chains
from cloud_audit.cost_model import (
    CostEstimate,
    estimate_chain_cost,
    estimate_finding_cost,
    estimate_total_exposure,
)
from cloud_audit.graph import build_from_scan_artifacts
from cloud_audit.models import (
    AgentIdentity,
    AgentTool,
    Category,
    CheckResult,
    CostEstimateData,
    Effort,
    EscalationCategory,
    EscalationPath,
    Finding,
    PolicyGrant,
    Remediation,
    ScanReport,
    Severity,
)
from cloud_audit.root_cause import compute_root_causes

ACCOUNT = "123456789012"
REGION = "eu-central-1"
_ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _role(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT}:role/{name}"


def _lambda(name: str) -> str:
    return f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{name}"


# Identities the sample agents act through
AGENT_ROLE = _role("support-bot-agent-role")
SEARCH_ROLE = _role("support-bot-search-role")
TICKET_ROLE = _role("support-bot-ticket-role")
KB_ROLE = _role("support-bot-kb-role")
PLANNER_ROLE = _role("planner-runtime-role")
GATEWAY_ROLE = _role("tools-gateway-role")
CRM_SYNC_ROLE = _role("crm-sync-role")
SANDBOX_ROLE = _role("sandbox-exec-role")
KB_BUCKET = "arn:aws:s3:::kb-product-docs"
BACKUP_BUCKET = "arn:aws:s3:::company-backups-2024"
DB_SECRET = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:prod/db-credentials-Ab12Cd"
CRM_TOKEN = f"arn:aws:ssm:{REGION}:{ACCOUNT}:parameter/crm/api-token"
OPS_ADMIN_ROLE = _role("ops-admin")
TICKETS_TABLE = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/tickets"


def _rem(cli: str, terraform: str, doc_url: str, effort: Effort = Effort.LOW) -> Remediation:
    return Remediation(cli=cli, terraform=terraform, doc_url=doc_url, effort=effort)


def _finding(
    check_id: str,
    title: str,
    severity: Severity,
    resource_type: str,
    resource_id: str,
    description: str,
    recommendation: str,
    remediation: Remediation,
    region: str = "global",
    compliance_refs: list[str] | None = None,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        severity=severity,
        category=Category.SECURITY,
        resource_type=resource_type,
        resource_id=resource_id,
        region=region,
        description=description,
        recommendation=recommendation,
        remediation=remediation,
        compliance_refs=compliance_refs or [],
    )


def _sample_findings() -> dict[str, tuple[str, list[Finding]]]:
    """check_id -> (check name, findings). Order is the order shown in reports."""
    return {
        "aws-vpc-002": (
            "Security groups open to the world",
            [
                _finding(
                    "aws-vpc-002",
                    "Security group sg-0a1b2c3d4e5f67890 allows 0.0.0.0/0 on port 22",
                    Severity.CRITICAL,
                    "AWS::EC2::SecurityGroup",
                    "sg-0a1b2c3d4e5f67890",
                    "SSH is reachable from any IPv4 address. The group is attached to i-0abc123def456789.",
                    "Restrict ingress to known CIDRs or use SSM Session Manager instead of SSH.",
                    _rem(
                        "aws ec2 revoke-security-group-ingress --group-id sg-0a1b2c3d4e5f67890 "
                        "--protocol tcp --port 22 --cidr 0.0.0.0/0",
                        'resource "aws_security_group_rule" "ssh" {\n  type              = "ingress"\n'
                        '  security_group_id = "sg-0a1b2c3d4e5f67890"\n  from_port         = 22\n'
                        '  to_port           = 22\n  protocol          = "tcp"\n'
                        '  cidr_blocks       = ["10.0.0.0/8"]\n}',
                        "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",
                    ),
                    region=REGION,
                    compliance_refs=["CIS 5.2"],
                )
            ],
        ),
        "aws-iam-007": (
            "OIDC trust policies without subject condition",
            [
                _finding(
                    "aws-iam-007",
                    "Role 'github-deploy-role' trusts GitHub OIDC without a 'sub' condition",
                    Severity.CRITICAL,
                    "AWS::IAM::Role",
                    _role("github-deploy-role"),
                    "Any GitHub repository can present a token that satisfies this trust policy.",
                    "Add a token.actions.githubusercontent.com:sub condition naming the repository and branch.",
                    _rem(
                        "aws iam update-assume-role-policy --role-name github-deploy-role "
                        "--policy-document file://trust-with-sub.json",
                        'condition {\n  test     = "StringEquals"\n'
                        '  variable = "token.actions.githubusercontent.com:sub"\n'
                        '  values   = ["repo:acme/platform:ref:refs/heads/main"]\n}',
                        "https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/"
                        "configuring-openid-connect-in-amazon-web-services",
                    ),
                )
            ],
        ),
        "aws-iam-018": (
            "IAM privilege escalation paths",
            [
                _finding(
                    "aws-iam-018",
                    "Role 'support-bot-ticket-role' can escalate via PassRole+Lambda",
                    Severity.CRITICAL,
                    "AWS::IAM::Role",
                    TICKET_ROLE,
                    "Role 'support-bot-ticket-role' has permissions to escalate privileges via PassRole+Lambda: "
                    "Admin via Lambda with privileged role. Required actions: iam:PassRole, lambda:CreateFunction, "
                    "lambda:InvokeFunction.",
                    "Scope iam:PassRole to the one role the ticket function needs and drop lambda:CreateFunction.",
                    _rem(
                        "aws iam delete-role-policy --role-name support-bot-ticket-role --policy-name lambda-admin",
                        'resource "aws_iam_role_policy" "ticket" {\n  role   = "support-bot-ticket-role"\n'
                        '  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = ["dynamodb:PutItem"], '
                        f'Resource = "{TICKETS_TABLE}" }}] }})\n}}',
                        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html",
                        Effort.MEDIUM,
                    ),
                ),
            ],
        ),
        "aws-s3-001": (
            "S3 public access block",
            [
                _finding(
                    "aws-s3-001",
                    "Bucket 'company-backups-2024' has Block Public Access disabled",
                    Severity.HIGH,
                    "AWS::S3::Bucket",
                    BACKUP_BUCKET,
                    "All four public-access-block settings are off; a single ACL or policy change exposes the data.",
                    "Enable all four Block Public Access settings on the bucket.",
                    _rem(
                        "aws s3api put-public-access-block --bucket company-backups-2024 "
                        "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
                        "BlockPublicPolicy=true,RestrictPublicBuckets=true",
                        'resource "aws_s3_bucket_public_access_block" "backups" {\n  bucket                  = '
                        '"company-backups-2024"\n  block_public_acls       = true\n  block_public_policy     = true\n'
                        "  ignore_public_acls      = true\n  restrict_public_buckets = true\n}",
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                    ),
                    compliance_refs=["CIS 2.1.4"],
                )
            ],
        ),
        "aws-agc-002": (
            "AgentCore Runtime public network mode",
            [
                _finding(
                    "aws-agc-002",
                    f"AgentCore Runtime 'planner' runs in PUBLIC network mode in {REGION}",
                    Severity.MEDIUM,
                    "AWS::BedrockAgentCore::Runtime",
                    f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/planner-8XK2Q",
                    "The agent runtime has unrestricted internet egress: a prompt-injected agent can exfiltrate data.",
                    "Move the runtime to VPC network mode with an egress-filtering security group.",
                    _rem(
                        "aws bedrock-agentcore-control update-agent-runtime --agent-runtime-id planner-8XK2Q "
                        '--network-configuration \'{"networkMode":"VPC","networkModeConfig":{"subnets":["subnet-0a1"],'
                        '"securityGroups":["sg-0egress"]}}\'',
                        'resource "aws_bedrockagentcore_agent_runtime" "planner" {\n  network_configuration {\n'
                        '    network_mode = "VPC"\n  }\n}',
                        "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-vpc.html",
                        Effort.MEDIUM,
                    ),
                    region=REGION,
                )
            ],
        ),
        "aws-agc-005": (
            "AgentCore Gateway without inbound authorizer",
            [
                _finding(
                    "aws-agc-005",
                    f"AgentCore Gateway 'tools-gw' has no inbound authorizer in {REGION}",
                    Severity.HIGH,
                    "AWS::BedrockAgentCore::Gateway",
                    f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:gateway/tools-gw-M4N7P",
                    "authorizerType is NONE: anyone who can reach the gateway URL can call every tool behind it.",
                    "Attach a JWT authorizer (Cognito, Okta, Entra ID) or require IAM SigV4.",
                    _rem(
                        "aws bedrock-agentcore-control update-gateway --gateway-identifier tools-gw-M4N7P "
                        "--authorizer-type CUSTOM_JWT --authorizer-configuration file://jwt.json",
                        'resource "aws_bedrockagentcore_gateway" "tools" {\n  authorizer_type = "CUSTOM_JWT"\n}',
                        "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-inbound-auth.html",
                    ),
                    region=REGION,
                )
            ],
        ),
    }


_PASSING_CHECKS = [
    ("aws-iam-001", "Root account MFA"),
    ("aws-iam-003", "Access key rotation"),
    ("aws-rds-001", "Public RDS instances"),
    ("aws-ct-001", "CloudTrail enabled in all regions"),
    ("aws-ct-002", "CloudTrail log file validation"),
    ("aws-gd-001", "GuardDuty enabled"),
    ("aws-kms-001", "KMS key rotation"),
    ("aws-s3-002", "S3 default encryption"),
    ("aws-iam-002", "Users without MFA"),
    ("aws-iam-008", "Root access keys"),
    ("aws-cfg-001", "AWS Config enabled"),
    ("aws-lambda-001", "Public Lambda function URLs"),
    ("aws-agc-003", "AgentCore Runtime MMDSv2 not enforced"),
    ("aws-agc-001", "AgentCore Code Interpreter public network mode"),
]


def _escalation_paths() -> list[EscalationPath]:
    return [
        EscalationPath(
            principal_arn=TICKET_ROLE,
            principal_name="support-bot-ticket-role",
            principal_type="Role",
            method="PassRole+Lambda",
            category=EscalationCategory.PASSROLE_SERVICE,
            required_actions=["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
            target_privilege="Admin via Lambda with privileged role",
            severity=Severity.CRITICAL,
        ),
    ]


def _agents() -> list[AgentIdentity]:
    return [
        AgentIdentity(
            agent_id="SUPPORTBOT1",
            name="support-bot",
            kind="bedrock_agent",
            arn=f"arn:aws:bedrock:{REGION}:{ACCOUNT}:agent/SUPPORTBOT1",
            region=REGION,
            principal_arns=[AGENT_ROLE],
            tools=[
                AgentTool(
                    name="search-docs",
                    kind="action_group_lambda",
                    target_arn=_lambda("search-docs"),
                    execution_role_arn=SEARCH_ROLE,
                    region=REGION,
                    detail="3 OpenAPI path(s) in apiSchema; state ENABLED",
                ),
                AgentTool(
                    name="create-ticket",
                    kind="action_group_lambda",
                    target_arn=_lambda("create-ticket"),
                    execution_role_arn=TICKET_ROLE,
                    region=REGION,
                    detail="2 function(s) in functionSchema; state ENABLED",
                ),
                AgentTool(
                    name="product-docs",
                    kind="knowledge_base",
                    target_arn=f"arn:aws:bedrock:{REGION}:{ACCOUNT}:knowledge-base/KBPRODDOCS",
                    execution_role_arn=KB_ROLE,
                    region=REGION,
                    detail="1 S3 data source(s)",
                ),
            ],
            data_sources=[KB_BUCKET],
            foundation_model="anthropic.claude-3-5-sonnet-20241022-v2:0",
            guardrail_attached=False,
            notes=["status: PREPARED"],
        ),
        AgentIdentity(
            agent_id="planner-8XK2Q",
            name="planner",
            kind="agentcore_runtime",
            arn=f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/planner-8XK2Q",
            region=REGION,
            principal_arns=[PLANNER_ROLE],
            notes=["network mode: PUBLIC", "inbound auth: IAM (SigV4)"],
        ),
        AgentIdentity(
            agent_id="tools-gw-M4N7P",
            name="tools-gw",
            kind="agentcore_gateway",
            arn=f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:gateway/tools-gw-M4N7P",
            region=REGION,
            principal_arns=[GATEWAY_ROLE],
            tools=[
                AgentTool(
                    name="crm-sync",
                    kind="gateway_target_lambda",
                    target_arn=_lambda("crm-sync"),
                    execution_role_arn=CRM_SYNC_ROLE,
                    region=REGION,
                    detail="credential provider: GATEWAY_IAM_ROLE",
                ),
                AgentTool(
                    name="erp-mcp",
                    kind="gateway_target_mcp_server",
                    target_arn="https://erp.internal.example/mcp",
                    region=REGION,
                    detail="remote MCP server; credential provider: OAUTH",
                ),
            ],
            notes=["inbound authorizer: NONE", "policy engine: none"],
        ),
        AgentIdentity(
            agent_id="py-sandbox-Q9R1S",
            name="py-sandbox",
            kind="agentcore_code_interpreter",
            arn=f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:code-interpreter/py-sandbox-Q9R1S",
            region=REGION,
            principal_arns=[SANDBOX_ROLE],
            notes=["network mode: PUBLIC"],
        ),
    ]


def _grant(action: str, resource: str, source: str, effect: str = "Allow", cond: bool = False) -> PolicyGrant:
    return PolicyGrant(action=action, resource=resource, effect=effect, has_condition=cond, source=source)


def _principal_grants() -> dict[str, list[PolicyGrant]]:
    bedrock_policy = "inline:AmazonBedrockAgentBedrockFoundationModelPolicy"
    return {
        AGENT_ROLE: [
            _grant("bedrock:InvokeModel", "*", bedrock_policy),
            _grant("bedrock:InvokeModelWithResponseStream", "*", bedrock_policy),
            _grant(
                "bedrock:Retrieve", f"arn:aws:bedrock:{REGION}:{ACCOUNT}:knowledge-base/KBPRODDOCS", "inline:kb-access"
            ),
            _grant("s3:GetObject", f"{KB_BUCKET}/*", "inline:kb-access"),
        ],
        SEARCH_ROLE: [
            _grant("s3:GetObject", f"{KB_BUCKET}/*", "inline:search-docs"),
            _grant("s3:*", f"{BACKUP_BUCKET}/*", f"managed:arn:aws:iam::{ACCOUNT}:policy/legacy-backup-access"),
            _grant("secretsmanager:GetSecretValue", DB_SECRET, "inline:search-docs"),
            _grant("logs:*", "*", "managed:arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"),
        ],
        TICKET_ROLE: [
            _grant("dynamodb:PutItem", TICKETS_TABLE, "inline:tickets"),
            _grant("dynamodb:GetItem", TICKETS_TABLE, "inline:tickets"),
            _grant("dynamodb:Query", TICKETS_TABLE, "inline:tickets"),
            _grant("sts:AssumeRole", OPS_ADMIN_ROLE, "inline:tickets"),
            _grant("iam:PassRole", "*", "inline:lambda-admin"),
            _grant("lambda:CreateFunction", "*", "inline:lambda-admin"),
            _grant("lambda:InvokeFunction", "*", "inline:lambda-admin"),
        ],
        KB_ROLE: [
            _grant("s3:GetObject", f"{KB_BUCKET}/*", "inline:kb-ingest"),
            _grant("s3:ListBucket", KB_BUCKET, "inline:kb-ingest"),
            _grant(
                "bedrock:InvokeModel",
                f"arn:aws:bedrock:{REGION}::foundation-model/amazon.titan-embed-text-v2:0",
                "inline:kb-ingest",
            ),
        ],
        PLANNER_ROLE: [
            _grant("bedrock:InvokeModel", "*", "inline:planner"),
            _grant("bedrock-agentcore:InvokeCodeInterpreter", "*", "inline:planner"),
            _grant("s3:GetObject", "arn:aws:s3:::planner-scratch/*", "inline:planner"),
        ],
        GATEWAY_ROLE: [
            _grant("lambda:InvokeFunction", _lambda("crm-sync"), "inline:gateway-targets"),
        ],
        CRM_SYNC_ROLE: [
            _grant("s3:PutObject", f"{KB_BUCKET}/*", "inline:crm-sync"),
            _grant("dynamodb:*", f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/crm-cache", "inline:crm-sync"),
            _grant("ssm:GetParameter", CRM_TOKEN, "inline:crm-sync"),
        ],
        SANDBOX_ROLE: [
            _grant("s3:*", "*", "managed:arn:aws:iam::aws:policy/AmazonS3FullAccess"),
        ],
    }


def _to_data(est: CostEstimate) -> CostEstimateData:
    return CostEstimateData(
        low_usd=est.low, high_usd=est.high, display=est.display, rationale=est.rationale, source_url=est.source_url
    )


def build_demo_report() -> ScanReport:
    """Build the sample scan through the real post-scan engines. No AWS API calls."""
    report = ScanReport(provider="aws", account_id=ACCOUNT, regions=[REGION], duration_seconds=12.4)

    for check_id, (name, findings) in _sample_findings().items():
        report.results.append(
            CheckResult(check_id=check_id, check_name=name, findings=findings, resources_scanned=len(findings) + 3)
        )
    for check_id, name in _PASSING_CHECKS:
        report.results.append(CheckResult(check_id=check_id, check_name=name, resources_scanned=4))

    report.escalation_paths = _escalation_paths()
    report.agents = _agents()
    report.principal_grants = _principal_grants()

    relationships = ResourceRelationships(
        ec2_roles={"i-0abc123def456789": "prod-admin-role"},
        ec2_sgs={"i-0abc123def456789": ["sg-0a1b2c3d4e5f67890"]},
        lambda_roles={"search-docs": SEARCH_ROLE, "create-ticket": TICKET_ROLE, "crm-sync": CRM_SYNC_ROLE},
        role_policies={"prod-admin-role": {_ADMIN}, "github-deploy-role": {_ADMIN}},
        escalation_paths=list(report.escalation_paths),
    )

    report.compute_summary()
    report.attack_chains = detect_attack_chains(report.all_findings, relationships)
    report.summary.attack_chains_detected = len(report.attack_chains)
    report.summary.escalation_paths_detected = len(report.escalation_paths)

    for check_result in report.results:
        for finding in check_result.findings:
            est = estimate_finding_cost(finding)
            if est:
                finding.cost_estimate = _to_data(est)
    for chain in report.attack_chains:
        chain.cost_estimate = _to_data(estimate_chain_cost(chain))
    report.summary.total_risk_exposure = _to_data(estimate_total_exposure(report))

    report.root_causes = compute_root_causes(report.all_findings, report.attack_chains)
    report.security_graph = build_from_scan_artifacts(
        escalation_paths=report.escalation_paths,
        iam_trust_graph=None,
        resource_relationships=relationships,
        findings=report.all_findings,
    ).to_dict()
    return report
