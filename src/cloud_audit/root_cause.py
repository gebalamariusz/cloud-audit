"""Root-cause grouping: map check fixes to attack chains they break.

Given a set of findings and detected attack chains, compute which single
fixes have the highest impact — breaking the most chains with the least effort.
"""

from __future__ import annotations

from cloud_audit.models import (
    AttackChain,
    CostEstimateData,
    Effort,
    Finding,
    RootCauseFix,
    Severity,
)

# Reverse mapping: check_id -> chain_ids that require this check.
# Derived from correlate.py chain detection functions.
CHECK_TO_CHAINS: dict[str, list[str]] = {
    # IAM
    "aws-iam-001": ["AC-09", "AC-10"],
    "aws-iam-002": ["AC-12", "AC-26"],
    "aws-iam-005": ["AC-12", "AC-26"],
    "aws-iam-007": ["AC-07", "AC-23", "AC-24", "AC-28"],
    "aws-iam-008": ["AC-25"],
    "aws-iam-012": ["AC-28"],
    # CloudTrail
    "aws-ct-001": ["AC-09", "AC-10", "AC-11", "AC-17", "AC-25"],
    "aws-ct-008": ["AC-32"],
    # GuardDuty
    "aws-gd-001": ["AC-10", "AC-11"],
    # Config
    "aws-cfg-001": ["AC-11"],
    # VPC / Network
    "aws-vpc-002": ["AC-01", "AC-02", "AC-13", "AC-14", "AC-29", "AC-31", "AC-33"],
    "aws-vpc-003": ["AC-13", "AC-14", "AC-27", "AC-31", "AC-33"],
    "aws-vpc-004": ["AC-14"],
    "aws-vpc-005": ["AC-27"],
    "aws-vpc-006": ["AC-33"],
    # EC2
    "aws-ec2-004": ["AC-02"],
    # Lambda
    "aws-lambda-001": ["AC-05"],
    "aws-lambda-003": ["AC-21"],
    # RDS
    "aws-rds-001": ["AC-17"],
    "aws-rds-002": ["AC-17"],
    # ECS
    "aws-ecs-001": ["AC-19"],
    "aws-ecs-002": ["AC-20"],
    "aws-ecs-003": ["AC-19", "AC-20"],
    # SSM
    "aws-ssm-002": ["AC-21"],
    "aws-ssm-003": ["AC-29", "AC-30"],
    # Inspector
    "aws-inspector-001": ["AC-30"],
    # WAF
    "aws-waf-001": ["AC-31"],
    # CloudWatch
    "aws-cw-001": ["AC-26", "AC-32"],
    # IAM Escalation
    "aws-iam-018": ["AC-34", "AC-35", "AC-36"],
    # AI Security (Bedrock + SageMaker)
    "aws-bedrock-001": ["AC-38"],
    "aws-bedrock-002": ["AC-38", "AC-39"],
    "aws-sagemaker-001": ["AC-37", "AC-39"],
    "aws-sagemaker-002": ["AC-37"],
    "aws-sagemaker-003": [],
}

# Human-readable fix titles for each check.
_FIX_TITLES: dict[str, str] = {
    "aws-iam-001": "Enable root account MFA",
    "aws-iam-002": "Enable MFA for IAM users",
    "aws-iam-005": "Remove overly permissive policies",
    "aws-iam-007": "Add OIDC 'sub' condition to trust policies",
    "aws-iam-008": "Delete root access keys",
    "aws-iam-012": "Enable IAM Access Analyzer",
    "aws-ct-001": "Enable CloudTrail (multi-region)",
    "aws-ct-008": "Deliver CloudTrail logs to CloudWatch",
    "aws-gd-001": "Enable GuardDuty",
    "aws-cfg-001": "Enable AWS Config",
    "aws-vpc-002": "Restrict security groups",
    "aws-vpc-003": "Enable VPC flow logs",
    "aws-vpc-004": "Restrict Network ACLs",
    "aws-vpc-005": "Restrict default security group",
    "aws-vpc-006": "Add private subnets for segmentation",
    "aws-ec2-004": "Enforce IMDSv2 on EC2 instances",
    "aws-lambda-001": "Restrict Lambda function URL auth",
    "aws-lambda-003": "Move secrets out of Lambda env vars",
    "aws-rds-001": "Disable public access on RDS",
    "aws-rds-002": "Enable RDS encryption",
    "aws-ecs-001": "Remove ECS privileged mode",
    "aws-ecs-002": "Add logging to ECS tasks",
    "aws-ecs-003": "Disable ECS Exec in production",
    "aws-ssm-002": "Use SecureString for secret parameters",
    "aws-ssm-003": "Apply missing patches",
    "aws-inspector-001": "Enable Inspector vulnerability scanning",
    "aws-waf-001": "Enable WAF on internet-facing resources",
    "aws-cw-001": "Create CloudWatch alarm for root usage",
    "aws-iam-018": "Remove IAM privilege escalation paths",
    "aws-bedrock-001": "Enable Bedrock model invocation logging",
    "aws-bedrock-002": "Configure Bedrock guardrails",
    "aws-sagemaker-001": "Disable SageMaker notebook root access",
    "aws-sagemaker-002": "Disable SageMaker direct internet access",
    "aws-sagemaker-003": "Enable SageMaker endpoint encryption",
}

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_EFFORT_ORDER = [Effort.LOW, Effort.MEDIUM, Effort.HIGH]


def compute_root_causes(
    findings: list[Finding],
    chains: list[AttackChain],
) -> list[RootCauseFix]:
    """Compute root-cause fixes sorted by impact (chains broken desc, severity desc, effort asc).

    For each unique check_id present in the findings, counts how many of the
    *actually detected* chains it participates in. Only chains that were fired
    are counted — theoretical chains from the static mapping are ignored.
    """
    if not chains:
        return []

    detected_chain_ids = {c.chain_id for c in chains}
    chain_cost_map: dict[str, CostEstimateData | None] = {c.chain_id: c.cost_estimate for c in chains}

    # Group findings by check_id
    by_check: dict[str, list[Finding]] = {}
    for f in findings:
        by_check.setdefault(f.check_id, []).append(f)

    results: list[RootCauseFix] = []

    for check_id, check_findings in by_check.items():
        potential_chains = CHECK_TO_CHAINS.get(check_id, [])
        # Only count chains that were actually detected in this scan
        broken = [cid for cid in potential_chains if cid in detected_chain_ids]
        if not broken:
            continue

        # Pick the first finding's remediation and effort as representative
        rep_finding = check_findings[0]
        effort = rep_finding.remediation.effort if rep_finding.remediation else Effort.MEDIUM
        remediation = rep_finding.remediation

        # Aggregate risk reduced across broken chains
        total_risk = _aggregate_risk(broken, chain_cost_map)

        results.append(
            RootCauseFix(
                check_id=check_id,
                fix_title=_FIX_TITLES.get(check_id, check_id),
                effort=effort,
                findings_closed=len(check_findings),
                chains_broken=sorted(broken),
                remediation=remediation,
                total_risk_reduced=total_risk,
            )
        )

    # Sort: most chains broken desc, then highest severity findings desc, then lowest effort
    results.sort(
        key=lambda r: (
            -len(r.chains_broken),
            _max_severity_rank(by_check.get(r.check_id, [])),
            _EFFORT_ORDER.index(r.effort) if r.effort in _EFFORT_ORDER else 1,
        )
    )

    return results


def _max_severity_rank(findings: list[Finding]) -> int:
    """Return negative severity rank (lower = more severe) for sorting."""
    if not findings:
        return 0
    best = min(_SEVERITY_ORDER.index(f.severity) for f in findings)
    return -len(_SEVERITY_ORDER) + best


def _aggregate_risk(
    chain_ids: list[str],
    chain_cost_map: dict[str, CostEstimateData | None],
) -> CostEstimateData | None:
    """Sum up risk estimates across a list of chains."""
    total_low = 0
    total_high = 0
    has_any = False

    for cid in chain_ids:
        cost = chain_cost_map.get(cid)
        if cost and cost.high_usd > 0:
            total_low += cost.low_usd
            total_high += cost.high_usd
            has_any = True

    if not has_any:
        return None

    return CostEstimateData(
        low_usd=total_low,
        high_usd=total_high,
        display=_format_usd_range(total_low, total_high),
        rationale="Aggregate risk across broken attack chains",
    )


def _format_usd_range(low: int, high: int) -> str:
    """Format a USD range like '$800K - $2.1M'."""

    def _fmt(v: int) -> str:
        if v >= 1_000_000:
            m = v / 1_000_000
            return f"${m:.1f}M" if m != int(m) else f"${int(m)}M"
        if v >= 1_000:
            k = v / 1_000
            return f"${k:.0f}K" if k == int(k) else f"${k:.1f}K"
        return f"${v}"

    return f"{_fmt(low)} - {_fmt(high)}"
