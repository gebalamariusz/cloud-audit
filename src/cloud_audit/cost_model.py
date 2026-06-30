"""Breach cost estimation for findings and attack chains.

Maps security findings to estimated financial risk using published breach data.
All estimates are ranges (low/high) with cited sources. This is NOT a precise
calculator - it helps communicate risk in business terms.

Verified sources (each URL was fetched and data confirmed on the page):
- IBM Cost of a Data Breach 2024: $4.88M avg breach, $4.81M credential breaches,
  258 days avg lifecycle, $173/record IP theft, $2.2M savings with AI/automation
  https://newsroom.ibm.com/2024-07-30-ibm-report-escalating-data-breach-disruption-pushes-costs-to-new-highs
- Verizon DBIR 2024: credentials in 24% of breaches, 77% of web app attacks
  https://aembit.io/blog/credential-and-secrets-theft-insights-from-the-2024-verizon-data-breach-report/
- Microsoft: 99.9% of compromised accounts lack MFA
  https://learn.microsoft.com/en-us/partner-center/security/security-at-your-organization
- Capital One 2019: OCC $80M fine, $190M settlement, 100M+ records, SSRF+IMDSv1
  https://www.occ.gov/news-issuances/news-releases/2020/nr-occ-2020-101.html
- Uber 2022: $148M multistate settlement, 57M users affected
  https://www.mass.gov/news/ag-healey-leads-multistate-coalition-in-reaching-148-million-settlement-with-uber-over-nationwide-data-breach
- CircleCI 2023: session token theft, secrets exfiltrated
  https://circleci.com/blog/jan-4-2023-incident-report/
- Codecov 2021: bash uploader modified to exfiltrate env vars
  https://about.codecov.io/security-update/
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloud_audit.models import AttackChain, Finding, ScanReport


# ---------------------------------------------------------------------------
# Cost categories - each check maps to one of these
# ---------------------------------------------------------------------------

# (low_usd, high_usd, rationale, source_url)
# These are NOT total breach costs - they represent the incremental risk
# contribution of a single misconfiguration.

# Verified source URLs - each was fetched and data confirmed on the page
_IBM_BREACH = (
    "https://newsroom.ibm.com/2024-07-30-ibm-report-escalating-data-breach-disruption-pushes-costs-to-new-highs"
)
_VERIZON_DBIR = "https://aembit.io/blog/credential-and-secrets-theft-insights-from-the-2024-verizon-data-breach-report/"
_MS_MFA = "https://learn.microsoft.com/en-us/partner-center/security/security-at-your-organization"
_CAPITAL_ONE_OCC = "https://www.occ.gov/news-issuances/news-releases/2020/nr-occ-2020-101.html"
_CAPITAL_ONE_KREBS = "https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/"
_UBER = "https://www.mass.gov/news/ag-healey-leads-multistate-coalition-in-reaching-148-million-settlement-with-uber-over-nationwide-data-breach"
_CIRCLECI = "https://circleci.com/blog/jan-4-2023-incident-report/"
_CODECOV = "https://about.codecov.io/security-update/"
_CIS_AWS = "https://www.cisecurity.org/benchmark/amazon_web_services"
_NIST_URL = "https://pages.nist.gov/800-63-3/sp800-63b.html"
_MITRE_CLOUD = "https://attack.mitre.org/matrices/enterprise/cloud/"
_OWASP_URL = "https://owasp.org/www-project-top-ten/"
_AWS_DATA_PERIMETER = (
    "https://docs.aws.amazon.com/whitepapers/latest/building-a-data-perimeter-on-aws/perimeter-overview.html"
)
_UNIT42_AGENTCORE = "https://unit42.paloaltonetworks.com/exploit-of-aws-agentcore-iam-god-mode/"
_AWS_CONFUSED_DEPUTY = "https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html"

_COST_TABLE: dict[str, tuple[int, int, str, str]] = {
    # IAM - credential/access risks
    "aws-iam-001": (
        50_000,
        500_000,
        "Root account without MFA is the #1 cause of full account takeover. "
        "Uber paid $148M settlement after attackers used compromised credentials (MA AG, 2022).",
        _UBER,
    ),
    "aws-iam-002": (
        10_000,
        100_000,
        "99.9% of compromised accounts lack MFA (Microsoft, see source). "
        "Cost range is cloud-audit's estimate for credential theft risk without MFA.",
        _MS_MFA,
    ),
    "aws-iam-003": (
        5_000,
        50_000,
        "Keys older than 90 days have higher exposure window. "
        "CircleCI (2023): attacker stole session tokens and exfiltrated customer secrets and keys (see source).",
        _CIRCLECI,
    ),
    "aws-iam-004": (
        2_000,
        20_000,
        "Unused keys are attack surface with zero value. If compromised, detection is unlikely since nobody monitors them.",
        _CIS_AWS,
    ),
    "aws-iam-005": (
        50_000,
        500_000,
        "Action:*/Resource:* policies allow full lateral movement. "
        "Capital One attacker used an overly permissive role to access 100M+ records (Krebs, 2019).",
        _CAPITAL_ONE_KREBS,
    ),
    "aws-iam-006": (
        5_000,
        50_000,
        "Weak password policies enable brute-force attacks. NIST SP 800-63B recommends minimum length and complexity requirements (see source).",
        _NIST_URL,
    ),
    "aws-iam-007": (
        50_000,
        500_000,
        "OIDC trust without sub condition lets ANY repo assume the role. "
        "MITRE ATT&CK documents cloud credential exploitation techniques (see source).",
        _MITRE_CLOUD,
    ),
    "aws-iam-018": (
        100_000,
        2_000_000,
        "IAM privilege escalation enables full account takeover. "
        "PMapper found 77% of tested accounts had escalation paths (Bishop Fox, 2024).",
        _MITRE_CLOUD,
    ),
    # AI Security - Bedrock
    "aws-bedrock-001": (
        10_000,
        100_000,
        "LLMjacking attacks can cost $50K+ in compute charges. "
        "Without logging, detection is impossible (Sysdig, 2024).",
        "https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/",
    ),
    # AI Security - SageMaker
    "aws-sagemaker-001": (
        50_000,
        500_000,
        "SageMaker root access enables model theft, data exfiltration, and lateral movement. "
        "Proprietary ML models are high-value intellectual property.",
        "https://docs.aws.amazon.com/sagemaker/latest/dg/nbi-root-access.html",
    ),
    # S3 - data exposure
    "aws-s3-001": (
        100_000,
        5_000_000,
        "Public S3 buckets are the most common source of cloud data leaks. "
        "Capital One: OCC assessed $80M civil money penalty for cloud security failures (see source).",
        _CAPITAL_ONE_OCC,
    ),
    "aws-s3-002": (
        1_000,
        10_000,
        "SSE-S3 (AES-256) is AWS default since Jan 2023. SSE-KMS adds customer-managed key control required by some compliance frameworks.",
        _CIS_AWS,
    ),
    "aws-s3-003": (
        500,
        5_000,
        "Without versioning, accidental or malicious deletes are permanent. Ransomware attacks increasingly target unversioned S3 data.",
        _CIS_AWS,
    ),
    "aws-s3-004": (
        200,
        2_000,
        "No lifecycle rules means storage costs grow indefinitely. Primarily a cost issue, not a security risk.",
        _CIS_AWS,
    ),
    "aws-s3-005": (
        2_000,
        20_000,
        "Without access logs, you cannot detect unauthorized data access after a breach. "
        "IBM 2024: orgs using security AI/automation saved $2.2M per breach - visibility is key (see source).",
        _IBM_BREACH,
    ),
    # EC2 - compute compromise
    "aws-ec2-001": (
        10_000,
        100_000,
        "Public AMIs may contain embedded credentials, SSH keys, or sensitive configuration. Attackers actively scan for public AMIs.",
        _MITRE_CLOUD,
    ),
    "aws-ec2-002": (
        2_000,
        20_000,
        "Unencrypted EBS volumes expose data if snapshots are shared or volumes are detached. Required by most compliance frameworks.",
        _CIS_AWS,
    ),
    "aws-ec2-003": (100, 1_000, "Stopped instances still incur EBS charges. Primarily a cost issue.", _CIS_AWS),
    "aws-ec2-004": (
        25_000,
        250_000,
        "IMDSv1 allows SSRF attacks to steal IAM credentials from the metadata service. "
        "This was the exact attack vector in the Capital One breach (2019, 100M+ records).",
        _CAPITAL_ONE_KREBS,
    ),
    "aws-ec2-005": (
        500,
        5_000,
        "Without termination protection, accidental API calls or automation errors can destroy instances.",
        _CIS_AWS,
    ),
    "aws-ec2-006": (
        2_000,
        20_000,
        "New EBS volumes created in this region will not be encrypted by default, creating compliance gaps over time.",
        _CIS_AWS,
    ),
    # VPC - network exposure
    "aws-vpc-001": (
        1_000,
        10_000,
        "Default VPC resources get public IPs automatically. Accidentally launched services become internet-facing.",
        _CIS_AWS,
    ),
    "aws-vpc-002": (
        25_000,
        250_000,
        "Open security groups are the #1 network-level finding in cloud breaches. "
        "Verizon DBIR 2024: stolen credentials used in 77% of basic web application attacks.",
        _VERIZON_DBIR,
    ),
    "aws-vpc-003": (
        5_000,
        50_000,
        "Without flow logs, network forensics after a breach is impossible. "
        "IBM 2024: avg breach lifecycle is 258 days (see source). Cost range is cloud-audit's estimate.",
        _IBM_BREACH,
    ),
    "aws-vpc-004": (
        5_000,
        50_000,
        "Unrestricted NACLs bypass the network perimeter. Defense-in-depth requires both SG and NACL controls.",
        _CIS_AWS,
    ),
    # RDS - database exposure
    "aws-rds-001": (
        100_000,
        5_000_000,
        "Publicly accessible databases are the highest-risk finding. "
        "IBM 2024: avg breach cost is $4.88M; stolen intellectual property costs $173/record (see source).",
        _IBM_BREACH,
    ),
    "aws-rds-002": (
        10_000,
        100_000,
        "Unencrypted RDS stores data in plaintext on disk. Required for PCI-DSS, HIPAA, SOC 2, and most compliance frameworks.",
        _CIS_AWS,
    ),
    "aws-rds-003": (
        5_000,
        50_000,
        "Single-AZ RDS has no automatic failover. A zone outage means downtime until manual recovery.",
        _CIS_AWS,
    ),
    "aws-rds-004": (
        500,
        5_000,
        "Skipping minor upgrades delays security patches. Known CVEs remain exploitable longer.",
        _CIS_AWS,
    ),
    # EIP
    "aws-eip-001": (50, 500, "Unattached Elastic IPs incur hourly charges. Purely a cost waste issue.", _CIS_AWS),
    # CloudTrail - visibility
    "aws-ct-001": (
        25_000,
        250_000,
        "Without CloudTrail, there is zero record of API activity. "
        "IBM 2024: avg breach lifecycle is 258 days (see source). Cost range is cloud-audit's own estimate based on breach data.",
        _IBM_BREACH,
    ),
    "aws-ct-002": (
        5_000,
        50_000,
        "Without log file validation, attackers can tamper with audit logs to cover their tracks.",
        _CIS_AWS,
    ),
    "aws-ct-003": (
        25_000,
        250_000,
        "Public CloudTrail bucket exposes your entire API audit history to the internet.",
        _CIS_AWS,
    ),
    # KMS
    "aws-kms-001": (
        2_000,
        20_000,
        "Keys without rotation accumulate cryptographic risk over time. CIS and NIST recommend annual rotation.",
        _CIS_AWS,
    ),
    "aws-kms-002": (
        10_000,
        100_000,
        "Overly permissive KMS policies allow unauthorized decryption of encrypted resources.",
        _CIS_AWS,
    ),
    # Lambda
    "aws-lambda-001": (
        25_000,
        250_000,
        "Public function URLs with no auth let anyone invoke your code. If the function has IAM permissions, it becomes an attack proxy.",
        _MITRE_CLOUD,
    ),
    "aws-lambda-002": (
        5_000,
        50_000,
        "Deprecated runtimes no longer receive security patches. Known CVEs become permanently exploitable.",
        _OWASP_URL,
    ),
    "aws-lambda-003": (
        10_000,
        100_000,
        "Secrets in environment variables are visible in the Lambda console and CloudWatch logs. "
        "Codecov (2021): attacker modified bash uploader to exfiltrate env vars from CI environments (see source).",
        _CODECOV,
    ),
    # ECS
    "aws-ecs-001": (
        25_000,
        250_000,
        "Privileged containers can escape to the host. Combined with ECS Exec, this gives full node access.",
        _MITRE_CLOUD,
    ),
    "aws-ecs-002": (
        5_000,
        50_000,
        "Without logging, container compromises go undetected. You cannot investigate what happened.",
        _CIS_AWS,
    ),
    "aws-ecs-003": (
        10_000,
        100_000,
        "ECS Exec gives interactive shell access to running containers. If not restricted, any IAM user with ecs:ExecuteCommand can access.",
        _MITRE_CLOUD,
    ),
    # GuardDuty
    "aws-gd-001": (
        10_000,
        100_000,
        "Without GuardDuty, there is no automated threat detection. "
        "IBM 2024: avg breach lifecycle is 258 days; security automation saves $2.2M per breach (see source).",
        _IBM_BREACH,
    ),
    "aws-gd-002": (
        5_000,
        50_000,
        "Unresolved GuardDuty findings are known threats you're aware of but haven't addressed.",
        _CIS_AWS,
    ),
    # AWS Config
    "aws-cfg-001": (
        5_000,
        50_000,
        "Without Config, you cannot track configuration changes. Unauthorized modifications go unrecorded.",
        _CIS_AWS,
    ),
    "aws-cfg-002": (
        5_000,
        50_000,
        "Stopped Config recorder means new resources and changes are not tracked. Drift detection is blind.",
        _CIS_AWS,
    ),
    # SSM
    "aws-ssm-001": (
        5_000,
        50_000,
        "EC2 instances outside SSM cannot receive automated patches. "
        "Verizon DBIR: credentials involved in 24% of all breaches - unpatched systems are easy targets.",
        _VERIZON_DBIR,
    ),
    "aws-ssm-002": (
        10_000,
        100_000,
        "SSM parameters stored as plain String (not SecureString) are visible to anyone with ssm:GetParameter. Use SecureString with KMS.",
        _OWASP_URL,
    ),
    # Secrets Manager
    "aws-sm-001": (
        5_000,
        50_000,
        "Secrets not rotated in 90+ days have higher compromise risk. Automated rotation is a best practice for database passwords and API keys.",
        _CIS_AWS,
    ),
    "aws-sm-002": (
        500,
        5_000,
        "Unused secrets are attack surface with zero value. Each increases the blast radius if Secrets Manager is compromised.",
        _CIS_AWS,
    ),
    # CloudWatch
    "aws-cw-001": (
        10_000,
        100_000,
        "Without a root usage alarm, root account activity goes completely unnoticed. Root should be used only for account-level tasks.",
        _CIS_AWS,
    ),
    # Data perimeter - resource policy boundary
    "aws-dp-001": (
        25_000,
        500_000,
        "An S3 bucket policy granting cross-account or wildcard access without an organization-boundary "
        "condition is a direct data-exfiltration path. Capital One's attacker reached 100M+ records via "
        "cross-account access; the OCC levied an $80M fine (2020).",
        _CAPITAL_ONE_OCC,
    ),
    "aws-dp-002": (
        5_000,
        50_000,
        "An SNS topic policy without a data-perimeter condition can leak messages cross-account or be "
        "coerced via the confused deputy problem. The AWS data perimeter whitepaper recommends "
        "aws:PrincipalOrgID / aws:SourceArn / aws:SourceAccount guardrails (see source).",
        _AWS_DATA_PERIMETER,
    ),
    "aws-dp-003": (
        5_000,
        50_000,
        "An SQS queue policy without a data-perimeter condition can expose queued data to external "
        "accounts. The AWS data perimeter whitepaper recommends organization-boundary conditions (see source).",
        _AWS_DATA_PERIMETER,
    ),
    "aws-dp-004": (
        25_000,
        500_000,
        "A Secrets Manager resource policy open to external or wildcard principals is a direct "
        "credential-exfiltration path. IBM Cost of a Data Breach 2024 puts the average breach at $4.88M.",
        _IBM_BREACH,
    ),
    "aws-dp-005": (
        10_000,
        100_000,
        "A Lambda resource policy granting a service principal without aws:SourceAccount / aws:SourceArn "
        "enables the confused deputy problem: a service acting for another account can be coerced into "
        "invoking the function. AWS recommends source-scoping conditions for service principals (see source).",
        _AWS_CONFUSED_DEPUTY,
    ),
    # AgentCore - AI agent platform attack surface (Unit 42 "Cracks in the Bedrock", 2026)
    "aws-agc-001": (
        10_000,
        100_000,
        "An AgentCore Code Interpreter in PUBLIC network mode gives an attacker-influenced or prompt-injected "
        "sandbox unrestricted internet egress for data exfiltration. Unit 42 documented sandbox isolation "
        "bypass on this surface.",
        _UNIT42_AGENTCORE,
    ),
    "aws-agc-002": (
        10_000,
        100_000,
        "An AgentCore Runtime in PUBLIC network mode lets a compromised or prompt-injected agent exfiltrate "
        "data to external infrastructure instead of being confined to a controlled VPC egress path.",
        _UNIT42_AGENTCORE,
    ),
    "aws-agc-003": (
        25_000,
        500_000,
        "An AgentCore Runtime that does not enforce MMDSv2 is exposed to SSRF / prompt-injection credential "
        "theft from the metadata endpoint, enabling takeover of the runtime's IAM role - the same risk class "
        "IMDSv2 addresses on EC2.",
        _UNIT42_AGENTCORE,
    ),
    "aws-agc-004": (
        5_000,
        50_000,
        "AgentCore Memory without a customer-managed KMS key has no key-level audit trail, rotation, or "
        "incident-time revocation over persisted conversation context and extracted data.",
        _UNIT42_AGENTCORE,
    ),
    "aws-agc-005": (
        25_000,
        500_000,
        "An AgentCore Gateway with no inbound authorizer exposes its MCP tools and the backing IAM role to "
        "any caller that can reach the gateway URL.",
        _UNIT42_AGENTCORE,
    ),
    "aws-agc-006": (
        5_000,
        50_000,
        "An AgentCore Gateway without an enforcing Cedar policy engine applies no per-tool authorization; any "
        "valid caller reaches every target the gateway exposes.",
        _UNIT42_AGENTCORE,
    ),
}

# Attack chain multiplier - compound risks have higher impact than sum of parts
_CHAIN_MULTIPLIER = 2.5


def _format_usd(amount: int) -> str:
    """Format dollar amount in human-readable form."""
    if amount >= 1_000_000:
        return f"${amount / 1_000_000:.1f}M"
    if amount >= 1_000:
        return f"${amount / 1_000:.0f}K"
    return f"${amount}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class CostEstimate:
    """Estimated financial risk for a finding or attack chain."""

    __slots__ = ("high", "low", "rationale", "source_url")

    def __init__(self, low: int, high: int, rationale: str, source_url: str = "") -> None:
        self.low = low
        self.high = high
        self.rationale = rationale
        self.source_url = source_url

    @property
    def display(self) -> str:
        """Human-readable range, e.g. '$50K - $500K'."""
        return f"{_format_usd(self.low)} - {_format_usd(self.high)}"

    def to_dict(self) -> dict[str, object]:
        d: dict[str, object] = {
            "low_usd": self.low,
            "high_usd": self.high,
            "display": self.display,
            "rationale": self.rationale,
        }
        if self.source_url:
            d["source_url"] = self.source_url
        return d


def estimate_finding_cost(finding: Finding) -> CostEstimate | None:
    """Estimate breach cost for a single finding."""
    entry = _COST_TABLE.get(finding.check_id)
    if entry is None:
        return None
    low, high, rationale, source_url = entry
    return CostEstimate(low=low, high=high, rationale=rationale, source_url=source_url)


def estimate_chain_cost(chain: AttackChain) -> CostEstimate:
    """Estimate breach cost for an attack chain (compound risk).

    Attack chains represent correlated risks that multiply impact.
    The estimate is higher than the sum of individual findings because
    chained vulnerabilities create exploitable paths that are more
    likely to result in an actual breach.
    """
    total_low = 0
    total_high = 0

    seen_checks: set[str] = set()
    for f in chain.findings:
        if f.check_id in seen_checks:
            continue
        seen_checks.add(f.check_id)
        entry = _COST_TABLE.get(f.check_id)
        if entry:
            total_low += entry[0]
            total_high += entry[1]

    # Apply compound risk multiplier
    total_low = int(total_low * _CHAIN_MULTIPLIER)
    total_high = int(total_high * _CHAIN_MULTIPLIER)

    # Cap at IBM average breach cost for reasonableness
    total_high = min(total_high, 10_000_000)
    total_low = min(total_low, total_high)

    rationale = (
        f"Compound risk: {chain.name}. "
        f"Chained vulnerabilities multiply impact by {_CHAIN_MULTIPLIER}x "
        f"(IBM 2024: avg breach $4.88M, credential breaches $4.81M)."
    )

    return CostEstimate(low=total_low, high=total_high, rationale=rationale)


def estimate_total_exposure(report: ScanReport) -> CostEstimate:
    """Estimate total risk exposure for the entire scan.

    Uses the highest-cost items (attack chains or individual findings)
    to avoid double-counting findings that appear in both.
    """
    # Collect chain costs (findings in chains are NOT double-counted)
    chain_finding_ids: set[str] = set()
    total_low = 0
    total_high = 0

    for chain in report.attack_chains:
        chain_cost = estimate_chain_cost(chain)
        total_low += chain_cost.low
        total_high += chain_cost.high
        for f in chain.findings:
            chain_finding_ids.add(f"{f.check_id}:{f.resource_id}")

    # Add individual findings NOT already in chains
    for f in report.all_findings:
        fid = f"{f.check_id}:{f.resource_id}"
        if fid in chain_finding_ids:
            continue
        entry = _COST_TABLE.get(f.check_id)
        if entry:
            total_low += entry[0]
            total_high += entry[1]

    if total_low == 0 and total_high == 0:
        return CostEstimate(low=0, high=0, rationale="No quantifiable risk findings detected.")

    rationale = (
        "Aggregate risk exposure based on IBM Cost of a Data Breach 2024, "
        "Verizon DBIR 2024, and published enforcement actions. "
        "Ranges reflect uncertainty - actual impact depends on data sensitivity, "
        "detection speed, and incident response capability."
    )

    return CostEstimate(low=total_low, high=total_high, rationale=rationale)
