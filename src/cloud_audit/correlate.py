"""Attack chain detection - correlate findings into exploitable attack paths.

Analyzes individual scan findings to detect compound risk patterns where multiple
misconfigurations create an actually exploitable attack surface. Based on published
attack research from MITRE ATT&CK, Datadog pathfinding.cloud, and AWS CIRT.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cloud_audit.models import AttackChain, Finding, Severity, VizStep

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


# ---------------------------------------------------------------------------
# Resource relationship data (collected with lightweight API calls)
# ---------------------------------------------------------------------------


@dataclass
class ResourceRelationships:
    """Lightweight resource relationships needed for attack chain detection."""

    # EC2 instance_id -> IAM role name (from IamInstanceProfile)
    ec2_roles: dict[str, str] = field(default_factory=dict)
    # EC2 instance_id -> list of security group IDs
    ec2_sgs: dict[str, list[str]] = field(default_factory=dict)
    # Lambda function name -> IAM role ARN
    lambda_roles: dict[str, str] = field(default_factory=dict)
    # IAM role name -> set of attached managed policy ARNs
    role_policies: dict[str, set[str]] = field(default_factory=dict)
    # IAM escalation paths (populated from iam_analyzer cache)
    escalation_paths: list[object] = field(default_factory=list)


# Well-known AWS managed policy ARNs for permission classification
_ADMIN_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
}
_S3_POLICIES = {
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
}
_EC2_POLICIES = {
    "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
}


def _role_is_admin(rels: ResourceRelationships, role_name: str) -> bool:
    policies = rels.role_policies.get(role_name, set())
    return bool(policies & _ADMIN_POLICIES)


def _role_has_s3(rels: ResourceRelationships, role_name: str) -> bool:
    policies = rels.role_policies.get(role_name, set())
    return bool(policies & (_ADMIN_POLICIES | _S3_POLICIES))


def _role_has_ec2(rels: ResourceRelationships, role_name: str) -> bool:
    policies = rels.role_policies.get(role_name, set())
    return bool(policies & (_ADMIN_POLICIES | _EC2_POLICIES))


def _role_name_from_arn(arn: str) -> str:
    """Extract role name from instance profile ARN or role ARN."""
    # arn:aws:iam::123456789012:instance-profile/role-name
    if "/" in arn:
        return arn.rsplit("/", 1)[-1]
    return arn


# ---------------------------------------------------------------------------
# Relationship collectors (only called when relevant findings exist)
# ---------------------------------------------------------------------------


def collect_relationships(
    provider: AWSProvider,
    findings: list[Finding],
) -> ResourceRelationships:
    """Collect resource relationships needed for attack chain detection.

    Only makes API calls when relevant findings are present in the scan.
    """
    rels = ResourceRelationships()
    check_ids = {f.check_id for f in findings}

    # EC2 relationships: needed when we have public SG or IMDSv1 findings
    needs_ec2 = bool(check_ids & {"aws-vpc-002", "aws-ec2-004"})
    if needs_ec2:
        _collect_ec2_rels(provider, rels)

    # Lambda relationships: needed when we have public lambda findings
    needs_lambda = bool(check_ids & {"aws-lambda-001"})
    if needs_lambda:
        _collect_lambda_rels(provider, rels)

    # IAM role policies: needed for admin detection on EC2/Lambda/OIDC roles
    role_names: set[str] = set()
    if needs_ec2:
        role_names.update(rels.ec2_roles.values())
    if needs_lambda:
        for arn in rels.lambda_roles.values():
            role_names.add(_role_name_from_arn(arn))
    if "aws-iam-007" in check_ids:
        # OIDC roles - extract role name from finding resource_id (ARN)
        for f in findings:
            if f.check_id == "aws-iam-007":
                role_names.add(_role_name_from_arn(f.resource_id))

    if role_names:
        _collect_role_policies(provider, role_names, rels)

    return rels


def _collect_ec2_rels(provider: AWSProvider, rels: ResourceRelationships) -> None:
    """Collect EC2 instance -> IAM role and -> security group mappings."""
    for region in provider.regions:
        try:
            ec2 = provider.session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for inst in reservation.get("Instances", []):
                        iid = inst["InstanceId"]
                        rels.ec2_sgs[iid] = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]
                        profile = inst.get("IamInstanceProfile")
                        if profile:
                            rels.ec2_roles[iid] = _role_name_from_arn(profile.get("Arn", ""))
        except Exception:
            logger.debug("Failed to collect EC2 relationships in %s", region, exc_info=True)
            continue


def _collect_lambda_rels(provider: AWSProvider, rels: ResourceRelationships) -> None:
    """Collect Lambda function -> IAM role mappings."""
    for region in provider.regions:
        try:
            lam = provider.session.client("lambda", region_name=region)
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []):
                    name = fn["FunctionName"]
                    rels.lambda_roles[name] = fn.get("Role", "")
        except Exception:
            logger.debug("Failed to collect Lambda relationships in %s", region, exc_info=True)
            continue


def _collect_role_policies(
    provider: AWSProvider,
    role_names: set[str],
    rels: ResourceRelationships,
) -> None:
    """Collect attached managed policies for the given IAM roles."""
    iam = provider.session.client("iam")
    for role_name in role_names:
        try:
            paginator = iam.get_paginator("list_attached_role_policies")
            policies: set[str] = set()
            for page in paginator.paginate(RoleName=role_name):
                policies.update(p["PolicyArn"] for p in page.get("AttachedPolicies", []))
            rels.role_policies[role_name] = policies
        except Exception:
            logger.debug("Failed to collect policies for role %s", role_name, exc_info=True)
            continue


# ---------------------------------------------------------------------------
# Helper: index findings by check_id and region
# ---------------------------------------------------------------------------


def _findings_by_check(findings: list[Finding]) -> dict[str, list[Finding]]:
    idx: dict[str, list[Finding]] = {}
    for f in findings:
        idx.setdefault(f.check_id, []).append(f)
    return idx


def _region_overlap(
    by_check: dict[str, list[Finding]],
    *check_ids: str,
) -> list[tuple[str, list[Finding]]]:
    """Find regions where ALL check_ids have findings. Returns (region, [one finding per check_id])."""
    groups = [by_check.get(cid, []) for cid in check_ids]
    if not all(groups):
        return []
    region_sets = [{f.region for f in g} for g in groups]
    common = region_sets[0]
    for rs in region_sets[1:]:
        common &= rs
    results: list[tuple[str, list[Finding]]] = []
    for region in common:
        matched = [next(f for f in g if f.region == region) for g in groups]
        results.append((region, matched))
    return results


# ---------------------------------------------------------------------------
# ATTACK CHAIN RULES
# ---------------------------------------------------------------------------

# --- Tier 1: Internet Exposure + Privilege ---


def _detect_exposed_admin_instance(
    by_check: dict[str, list[Finding]],
    rels: ResourceRelationships,
) -> list[AttackChain]:
    """AC-01: Public SG + EC2 with admin IAM role."""
    chains: list[AttackChain] = []
    sg_findings = by_check.get("aws-vpc-002", [])
    if not sg_findings or not rels.ec2_sgs:
        return chains

    open_sgs = {f.resource_id for f in sg_findings}

    for instance_id, sgs in rels.ec2_sgs.items():
        exposed_sgs = set(sgs) & open_sgs
        if not exposed_sgs:
            continue
        role_name = rels.ec2_roles.get(instance_id, "")
        if not role_name or not _role_is_admin(rels, role_name):
            continue
        sg_finding = next(f for f in sg_findings if f.resource_id in exposed_sgs)
        chains.append(
            AttackChain(
                chain_id="AC-01",
                name="Internet-Exposed Admin Instance",
                severity=Severity.CRITICAL,
                findings=[sg_finding],
                attack_narrative=(
                    f"Instance {instance_id} is reachable from the internet via "
                    f"open security group and has admin IAM role '{role_name}'. "
                    f"An attacker can reach the instance, access IMDS credentials, "
                    f"and gain full admin access to the AWS account."
                ),
                priority_fix=f"Restrict security group {sg_finding.resource_id} to specific IPs (effort: LOW).",
                mitre_refs=["T1190", "T1552.005", "T1078.004"],
                resources=[instance_id, sg_finding.resource_id],
                viz_steps=[
                    VizStep(label="Internet", sub="Entry Point", type="internet", edge_label="scans ports"),
                    VizStep(
                        label=sg_finding.resource_id, sub="Security Group", type="network", edge_label="allows access"
                    ),
                    VizStep(label=instance_id, sub="EC2 Instance", type="compute", edge_label="IMDS creds"),
                    VizStep(label=role_name, sub="IAM Role (admin)", type="identity", edge_label="full access"),
                    VizStep(label="Account Takeover", sub="Full AWS Access", type="impact"),
                ],
            )
        )
    return chains


def _detect_ssrf_credential_theft(
    by_check: dict[str, list[Finding]],
    rels: ResourceRelationships,
) -> list[AttackChain]:
    """AC-02: Public SG + IMDSv1 on same instance."""
    chains: list[AttackChain] = []
    sg_findings = by_check.get("aws-vpc-002", [])
    imds_findings = by_check.get("aws-ec2-004", [])
    if not sg_findings or not imds_findings:
        return chains

    open_sgs = {f.resource_id for f in sg_findings}
    imds_instances = {f.resource_id for f in imds_findings}

    for instance_id in imds_instances:
        instance_sgs = set(rels.ec2_sgs.get(instance_id, []))
        if not instance_sgs & open_sgs:
            continue
        sg_f = next(f for f in sg_findings if f.resource_id in instance_sgs)
        imds_f = next(f for f in imds_findings if f.resource_id == instance_id)
        chains.append(
            AttackChain(
                chain_id="AC-02",
                name="SSRF to Credential Theft",
                severity=Severity.CRITICAL,
                findings=[sg_f, imds_f],
                attack_narrative=(
                    f"Instance {instance_id} is internet-facing and uses IMDSv1. "
                    f"An attacker can exploit SSRF to query the metadata service "
                    f"at 169.254.169.254 and steal IAM role credentials."
                ),
                priority_fix=f"Enforce IMDSv2 on {instance_id} (effort: LOW).",
                mitre_refs=["T1190", "T1552.005"],
                resources=[instance_id, sg_f.resource_id],
                viz_steps=[
                    VizStep(label="Internet", sub="Entry Point", type="internet", edge_label="SSRF attack"),
                    VizStep(label=sg_f.resource_id, sub="Security Group", type="network", edge_label="allows access"),
                    VizStep(label=instance_id, sub="EC2 (IMDSv1)", type="compute", edge_label="metadata query"),
                    VizStep(label="Stolen Credentials", sub="IAM Role Creds", type="impact"),
                ],
            )
        )
    return chains


def _detect_public_lambda_admin(
    by_check: dict[str, list[Finding]],
    rels: ResourceRelationships,
) -> list[AttackChain]:
    """AC-05: Public Lambda function URL + admin IAM role."""
    chains: list[AttackChain] = []
    public_lambdas = by_check.get("aws-lambda-001", [])
    if not public_lambdas:
        return chains

    for f in public_lambdas:
        fn_name = f.resource_id
        role_arn = rels.lambda_roles.get(fn_name, "")
        role_name = _role_name_from_arn(role_arn)
        if role_name and _role_is_admin(rels, role_name):
            chains.append(
                AttackChain(
                    chain_id="AC-05",
                    name="Public Lambda with Admin Access",
                    severity=Severity.CRITICAL,
                    findings=[f],
                    attack_narrative=(
                        f"Lambda function '{fn_name}' has a public URL (no auth) "
                        f"and executes with admin IAM role '{role_name}'. "
                        f"Anyone on the internet can invoke this function and "
                        f"leverage admin credentials."
                    ),
                    priority_fix="Add IAM or Cognito auth to the function URL (effort: MEDIUM).",
                    mitre_refs=["T1190", "T1078.004"],
                    resources=[fn_name],
                    viz_steps=[
                        VizStep(label="Internet", sub="No Auth", type="internet", edge_label="invokes function"),
                        VizStep(label=fn_name, sub="Lambda (public URL)", type="compute", edge_label="executes as"),
                        VizStep(label=role_name, sub="IAM Role (admin)", type="identity", edge_label="full access"),
                        VizStep(label="Account Takeover", sub="Admin Privileges", type="impact"),
                    ],
                )
            )
    return chains


def _detect_cicd_admin_takeover(
    by_check: dict[str, list[Finding]],
    rels: ResourceRelationships,
) -> list[AttackChain]:
    """AC-07: OIDC trust without sub + admin policy on role."""
    chains: list[AttackChain] = []
    oidc = by_check.get("aws-iam-007", [])
    if not oidc:
        return chains

    for f in oidc:
        role_name = _role_name_from_arn(f.resource_id)
        if _role_is_admin(rels, role_name):
            chains.append(
                AttackChain(
                    chain_id="AC-07",
                    name="CI/CD to Admin Takeover",
                    severity=Severity.CRITICAL,
                    findings=[f],
                    attack_narrative=(
                        f"Role '{role_name}' trusts an OIDC provider without "
                        f"restricting the 'sub' claim AND has admin permissions. "
                        f"Any repository on the CI/CD platform can assume this role "
                        f"and gain full AWS admin access. Google's UNC6426 used "
                        f"this exact pattern."
                    ),
                    priority_fix="Add 'sub' condition to the trust policy (effort: LOW).",
                    mitre_refs=["T1078.004", "T1550.001"],
                    resources=[f.resource_id],
                    viz_steps=[
                        VizStep(
                            label="Any CI/CD Repo", sub="OIDC Federation", type="internet", edge_label="assumes role"
                        ),
                        VizStep(label=role_name, sub="IAM Role", type="identity", edge_label="has policy"),
                        VizStep(label="AdministratorAccess", sub="IAM Policy", type="identity", edge_label="grants"),
                        VizStep(label="Full AWS Access", sub="Account Compromise", type="impact"),
                    ],
                )
            )
    return chains


# --- Tier 2: Missing Controls ---


def _detect_unmonitored_admin(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-09: No root MFA + no CloudTrail."""
    chains: list[AttackChain] = []
    root_mfa = by_check.get("aws-iam-001", [])
    no_ct = by_check.get("aws-ct-001", [])
    if not root_mfa or not no_ct:
        return chains

    chains.append(
        AttackChain(
            chain_id="AC-09",
            name="Unmonitored Admin Access",
            severity=Severity.CRITICAL,
            findings=[root_mfa[0], no_ct[0]],
            attack_narrative=(
                "Root account has no MFA and CloudTrail is disabled. "
                "An attacker with root credentials operates with full admin "
                "access and zero audit trail."
            ),
            priority_fix="Enable CloudTrail first (immediate visibility), then add root MFA.",
            mitre_refs=["T1078.004", "T1562.008"],
            resources=["root", "cloudtrail"],
            viz_steps=[
                VizStep(label="Root Account", sub="No MFA", type="identity", edge_label="no audit trail"),
                VizStep(label="CloudTrail", sub="Disabled", type="finding", edge_label="undetected"),
                VizStep(label="Silent Takeover", sub="Full Admin, No Logs", type="impact"),
            ],
        )
    )
    return chains


def _detect_blind_admin(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-10: No root MFA + no CloudTrail + no GuardDuty."""
    chains: list[AttackChain] = []
    root_mfa = by_check.get("aws-iam-001", [])
    no_ct = by_check.get("aws-ct-001", [])
    no_gd = by_check.get("aws-gd-001", [])
    if not root_mfa or not no_ct or not no_gd:
        return chains

    chains.append(
        AttackChain(
            chain_id="AC-10",
            name="Completely Blind Admin",
            severity=Severity.CRITICAL,
            findings=[root_mfa[0], no_ct[0], no_gd[0]],
            attack_narrative=(
                "Root account has no MFA, CloudTrail is off, and GuardDuty "
                "is disabled. The account has zero detection capability - "
                "any compromise will go completely unnoticed."
            ),
            priority_fix="Enable CloudTrail (effort: LOW) - detection before prevention.",
            mitre_refs=["T1078.004", "T1562.008", "T1562.001"],
            resources=["root", "cloudtrail", "guardduty"],
            viz_steps=[
                VizStep(label="Root Account", sub="No MFA", type="identity", edge_label="no logging"),
                VizStep(label="CloudTrail", sub="Disabled", type="finding", edge_label="no detection"),
                VizStep(label="GuardDuty", sub="Disabled", type="finding", edge_label="blind"),
                VizStep(label="Zero Visibility", sub="Complete Blindness", type="impact"),
            ],
        )
    )
    return chains


def _detect_zero_visibility(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-11: No CloudTrail + no GuardDuty + no Config (same region)."""
    chains: list[AttackChain] = []
    no_ct = by_check.get("aws-ct-001", [])
    no_gd = by_check.get("aws-gd-001", [])
    no_cfg = by_check.get("aws-cfg-001", [])
    if not no_ct or not no_gd or not no_cfg:
        return chains

    # Match by region
    gd_regions = {f.region for f in no_gd}
    cfg_regions = {f.region for f in no_cfg}

    for ct_f in no_ct:
        r = ct_f.region
        if r in gd_regions and r in cfg_regions:
            gd_f = next(f for f in no_gd if f.region == r)
            cfg_f = next(f for f in no_cfg if f.region == r)
            chains.append(
                AttackChain(
                    chain_id="AC-11",
                    name="Zero Security Visibility",
                    severity=Severity.HIGH,
                    findings=[ct_f, gd_f, cfg_f],
                    attack_narrative=(
                        f"Region {r} has no CloudTrail, no GuardDuty, and no "
                        f"AWS Config. All three detection services are disabled - "
                        f"attackers can operate with zero chance of detection."
                    ),
                    priority_fix=f"Enable CloudTrail in {r} (effort: LOW).",
                    mitre_refs=["T1562.008", "T1562.001"],
                    resources=["cloudtrail", "guardduty", "config"],
                    viz_steps=[
                        VizStep(label="CloudTrail", sub=f"Disabled ({r})", type="finding", edge_label="no logs"),
                        VizStep(label="GuardDuty", sub=f"Disabled ({r})", type="finding", edge_label="no alerts"),
                        VizStep(label="AWS Config", sub=f"Disabled ({r})", type="finding", edge_label="no tracking"),
                        VizStep(label="Zero Visibility", sub="All Detection Off", type="impact"),
                    ],
                )
            )
            break  # One chain per account is enough
    return chains


def _detect_admin_no_mfa(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-12: Admin policy exists + users without MFA."""
    chains: list[AttackChain] = []
    admin = by_check.get("aws-iam-005", [])
    no_mfa = by_check.get("aws-iam-002", [])
    if not admin or not no_mfa:
        return chains

    chains.append(
        AttackChain(
            chain_id="AC-12",
            name="Admin Without MFA",
            severity=Severity.CRITICAL,
            findings=[admin[0], no_mfa[0]],
            attack_narrative=(
                f"Admin-level IAM policy '{admin[0].resource_id}' exists and "
                f"user '{no_mfa[0].resource_id}' has console access without MFA. "
                f"If the unprotected user has admin access, a single password "
                f"compromise gives full account control."
            ),
            priority_fix=f"Enable MFA for '{no_mfa[0].resource_id}' (effort: LOW).",
            mitre_refs=["T1078.004", "T1110"],
            resources=[admin[0].resource_id, no_mfa[0].resource_id],
            viz_steps=[
                VizStep(label=no_mfa[0].resource_id, sub="No MFA", type="identity", edge_label="has access to"),
                VizStep(label=admin[0].resource_id, sub="Admin Policy", type="identity", edge_label="grants"),
                VizStep(label="Account Takeover", sub="Password = Full Access", type="impact"),
            ],
        )
    )
    return chains


def _detect_open_unmonitored_network(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-13: Open SG (all traffic) + no VPC flow logs in same region."""
    chains: list[AttackChain] = []
    open_sg = [f for f in by_check.get("aws-vpc-002", []) if f.severity == Severity.CRITICAL]
    no_flow = by_check.get("aws-vpc-003", [])
    if not open_sg or not no_flow:
        return chains

    flow_regions = {f.region for f in no_flow}
    for f in open_sg:
        if f.region in flow_regions:
            flow_f = next(fl for fl in no_flow if fl.region == f.region)
            chains.append(
                AttackChain(
                    chain_id="AC-13",
                    name="Wide Open and Unmonitored Network",
                    severity=Severity.HIGH,
                    findings=[f, flow_f],
                    attack_narrative=(
                        f"Security group {f.resource_id} allows all inbound "
                        f"traffic from the internet AND VPC flow logs are "
                        f"disabled in {f.region}. Network intrusions will "
                        f"not be logged."
                    ),
                    priority_fix=f"Restrict {f.resource_id} to specific ports (effort: LOW).",
                    mitre_refs=["T1190", "T1562.008"],
                    resources=[f.resource_id, flow_f.resource_id],
                    viz_steps=[
                        VizStep(label="Internet", sub="Entry Point", type="internet", edge_label="all traffic"),
                        VizStep(
                            label=f.resource_id, sub="Security Group (open)", type="network", edge_label="no logging"
                        ),
                        VizStep(
                            label="VPC Flow Logs", sub=f"Disabled ({f.region})", type="finding", edge_label="invisible"
                        ),
                        VizStep(label="Unmonitored Access", sub="No Network Logs", type="impact"),
                    ],
                )
            )
            break  # One per region is enough
    return chains


def _detect_no_network_layers(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-14: Unrestricted NACL + open SG + no flow logs in same region."""
    chains: list[AttackChain] = []
    nacl = by_check.get("aws-vpc-004", [])
    sg = by_check.get("aws-vpc-002", [])
    no_flow = by_check.get("aws-vpc-003", [])
    if not nacl or not sg or not no_flow:
        return chains

    sg_regions = {f.region for f in sg}
    flow_regions = {f.region for f in no_flow}

    for f in nacl:
        if f.region in sg_regions and f.region in flow_regions:
            sg_f = next(s for s in sg if s.region == f.region)
            flow_f = next(fl for fl in no_flow if fl.region == f.region)
            chains.append(
                AttackChain(
                    chain_id="AC-14",
                    name="No Network Security Layers",
                    severity=Severity.HIGH,
                    findings=[f, sg_f, flow_f],
                    attack_narrative=(
                        f"Region {f.region} has unrestricted NACLs, open "
                        f"security groups, and no flow logs. All three network "
                        f"defense layers are effectively bypassed."
                    ),
                    priority_fix=f"Restrict security group {sg_f.resource_id} (effort: LOW).",
                    mitre_refs=["T1190", "T1562.008"],
                    resources=[f.resource_id, sg_f.resource_id],
                    viz_steps=[
                        VizStep(label="Internet", sub="Entry Point", type="internet", edge_label="unrestricted"),
                        VizStep(label=f.resource_id, sub="NACL (open)", type="network", edge_label="no filtering"),
                        VizStep(
                            label=sg_f.resource_id, sub="Security Group (open)", type="network", edge_label="no logging"
                        ),
                        VizStep(
                            label="VPC Flow Logs", sub=f"Disabled ({f.region})", type="finding", edge_label="invisible"
                        ),
                        VizStep(label="Layered Failure", sub="All Defenses Down", type="impact"),
                    ],
                )
            )
            break
    return chains


# --- Tier 3: Data Protection Failures ---


def _detect_exposed_db_no_trail(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-17: Public RDS + no encryption + no CloudTrail."""
    chains: list[AttackChain] = []
    public = by_check.get("aws-rds-001", [])
    unenc = by_check.get("aws-rds-002", [])
    no_ct = by_check.get("aws-ct-001", [])
    if not public or not unenc or not no_ct:
        return chains

    unenc_ids = {f.resource_id for f in unenc}
    for f in public:
        if f.resource_id in unenc_ids:
            enc_f = next(e for e in unenc if e.resource_id == f.resource_id)
            chains.append(
                AttackChain(
                    chain_id="AC-17",
                    name="Exposed Database Without Audit Trail",
                    severity=Severity.CRITICAL,
                    findings=[f, enc_f, no_ct[0]],
                    attack_narrative=(
                        f"RDS '{f.resource_id}' is publicly accessible and "
                        f"unencrypted, with no CloudTrail logging. An attacker "
                        f"can access the database from the internet, exfiltrate "
                        f"plaintext data, and leave no API audit trail."
                    ),
                    priority_fix=f"Disable public access on '{f.resource_id}' (effort: LOW).",
                    mitre_refs=["T1190", "T1530", "T1562.008"],
                    resources=[f.resource_id],
                    viz_steps=[
                        VizStep(label="Internet", sub="Entry Point", type="internet", edge_label="public endpoint"),
                        VizStep(label=f.resource_id, sub="RDS (public)", type="storage", edge_label="reads data"),
                        VizStep(label=enc_f.resource_id, sub="Unencrypted", type="storage", edge_label="no audit"),
                        VizStep(label="CloudTrail", sub="Disabled", type="finding", edge_label="undetected"),
                        VizStep(label="Invisible Breach", sub="Data Exfiltration", type="impact"),
                    ],
                )
            )
    return chains


# --- Tier 4: Container & Secrets ---


def _detect_container_breakout(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-19: ECS privileged mode + exec enabled."""
    chains: list[AttackChain] = []
    priv = by_check.get("aws-ecs-001", [])
    exec_ = by_check.get("aws-ecs-003", [])
    if not priv or not exec_:
        return chains

    exec_regions = {f.region for f in exec_}
    for f in priv:
        if f.region in exec_regions:
            exec_f = next(e for e in exec_ if e.region == f.region)
            chains.append(
                AttackChain(
                    chain_id="AC-19",
                    name="Container Breakout Path",
                    severity=Severity.CRITICAL,
                    findings=[f, exec_f],
                    attack_narrative=(
                        f"ECS tasks run in privileged mode and ECS Exec is "
                        f"enabled in {f.region}. An attacker with exec access "
                        f"can break out of the container to the host."
                    ),
                    priority_fix="Disable privileged mode on task definitions (effort: MEDIUM).",
                    mitre_refs=["T1611", "T1059"],
                    resources=[f.resource_id, exec_f.resource_id],
                    viz_steps=[
                        VizStep(
                            label="ECS Task", sub=f"Privileged ({f.region})", type="compute", edge_label="exec enabled"
                        ),
                        VizStep(label="ECS Exec", sub="Interactive Shell", type="compute", edge_label="breaks out"),
                        VizStep(label="Host Escape", sub="Container Breakout", type="impact"),
                    ],
                )
            )
            break
    return chains


def _detect_unmonitored_containers(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-20: ECS no logging + exec enabled."""
    chains: list[AttackChain] = []
    no_log = by_check.get("aws-ecs-002", [])
    exec_ = by_check.get("aws-ecs-003", [])
    if not no_log or not exec_:
        return chains

    exec_regions = {f.region for f in exec_}
    for f in no_log:
        if f.region in exec_regions:
            exec_f = next(e for e in exec_ if e.region == f.region)
            chains.append(
                AttackChain(
                    chain_id="AC-20",
                    name="Unmonitored Container Access",
                    severity=Severity.HIGH,
                    findings=[f, exec_f],
                    attack_narrative=(
                        f"ECS Exec is enabled but container logging is "
                        f"disabled in {f.region}. Interactive shell sessions "
                        f"leave no trace."
                    ),
                    priority_fix="Enable CloudWatch logging on task definitions (effort: LOW).",
                    mitre_refs=["T1059", "T1562.008"],
                    resources=[f.resource_id, exec_f.resource_id],
                    viz_steps=[
                        VizStep(label="ECS Exec", sub=f"Enabled ({f.region})", type="compute", edge_label="no logs"),
                        VizStep(label="Container Logs", sub="Disabled", type="finding", edge_label="invisible"),
                        VizStep(label="Ghost Access", sub="Untraced Sessions", type="impact"),
                    ],
                )
            )
            break
    return chains


def _detect_plaintext_secrets(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-21: SSM insecure params + Lambda env secrets in same region."""
    chains: list[AttackChain] = []
    ssm = by_check.get("aws-ssm-002", [])
    lam = by_check.get("aws-lambda-003", [])
    if not ssm or not lam:
        return chains

    lam_regions = {f.region for f in lam}
    for f in ssm:
        if f.region in lam_regions:
            lam_f = next(lf for lf in lam if lf.region == f.region)
            chains.append(
                AttackChain(
                    chain_id="AC-21",
                    name="Secrets in Plaintext Across Services",
                    severity=Severity.HIGH,
                    findings=[f, lam_f],
                    attack_narrative=(
                        f"SSM parameters store secrets as plaintext String "
                        f"and Lambda functions have secrets in environment "
                        f"variables in {f.region}. Multiple services expose "
                        f"credentials without encryption."
                    ),
                    priority_fix="Migrate SSM parameters to SecureString (effort: LOW).",
                    mitre_refs=["T1552.001"],
                    resources=[f.resource_id, lam_f.resource_id],
                    viz_steps=[
                        VizStep(
                            label="SSM Parameters", sub=f"Plaintext ({f.region})", type="storage", edge_label="exposed"
                        ),
                        VizStep(
                            label="Lambda Env Vars", sub=f"Secrets ({f.region})", type="compute", edge_label="readable"
                        ),
                        VizStep(label="Credential Leak", sub="Multi-Service Exposure", type="impact"),
                    ],
                )
            )
            break
    return chains


# --- Tier 5: OIDC Specific ---


def _detect_cicd_data_exfil(
    by_check: dict[str, list[Finding]],
    rels: ResourceRelationships,
) -> list[AttackChain]:
    """AC-23: OIDC no sub + role with S3 access."""
    chains: list[AttackChain] = []
    oidc = by_check.get("aws-iam-007", [])
    if not oidc:
        return chains

    for f in oidc:
        role_name = _role_name_from_arn(f.resource_id)
        if _role_has_s3(rels, role_name) and not _role_is_admin(rels, role_name):
            chains.append(
                AttackChain(
                    chain_id="AC-23",
                    name="CI/CD Data Exfiltration",
                    severity=Severity.HIGH,
                    findings=[f],
                    attack_narrative=(
                        f"Role '{role_name}' trusts an OIDC provider without "
                        f"'sub' restriction and has S3 access. Any repository "
                        f"can assume this role and read/write S3 data."
                    ),
                    priority_fix="Add 'sub' condition to the trust policy (effort: LOW).",
                    mitre_refs=["T1078.004", "T1530"],
                    resources=[f.resource_id],
                    viz_steps=[
                        VizStep(
                            label="Any CI/CD Repo", sub="OIDC (no sub)", type="internet", edge_label="assumes role"
                        ),
                        VizStep(label=role_name, sub="IAM Role", type="identity", edge_label="S3 access"),
                        VizStep(label="S3 Buckets", sub="Read/Write", type="storage", edge_label="exfiltrates"),
                        VizStep(label="Data Exfiltration", sub="S3 Data Stolen", type="impact"),
                    ],
                )
            )
    return chains


def _detect_cicd_lateral_movement(
    by_check: dict[str, list[Finding]],
    rels: ResourceRelationships,
) -> list[AttackChain]:
    """AC-24: OIDC no sub + role with EC2/ECS access."""
    chains: list[AttackChain] = []
    oidc = by_check.get("aws-iam-007", [])
    if not oidc:
        return chains

    for f in oidc:
        role_name = _role_name_from_arn(f.resource_id)
        if _role_has_ec2(rels, role_name) and not _role_is_admin(rels, role_name):
            chains.append(
                AttackChain(
                    chain_id="AC-24",
                    name="CI/CD Lateral Movement",
                    severity=Severity.HIGH,
                    findings=[f],
                    attack_narrative=(
                        f"Role '{role_name}' trusts an OIDC provider without "
                        f"'sub' restriction and has EC2/ECS access. Any "
                        f"repository can assume this role and launch or access "
                        f"compute resources for lateral movement."
                    ),
                    priority_fix="Add 'sub' condition to the trust policy (effort: LOW).",
                    mitre_refs=["T1078.004", "T1021"],
                    resources=[f.resource_id],
                    viz_steps=[
                        VizStep(
                            label="Any CI/CD Repo", sub="OIDC (no sub)", type="internet", edge_label="assumes role"
                        ),
                        VizStep(label=role_name, sub="IAM Role", type="identity", edge_label="compute access"),
                        VizStep(label="EC2 / ECS", sub="Launch/Access", type="compute", edge_label="moves laterally"),
                        VizStep(label="Lateral Movement", sub="Compute Compromised", type="impact"),
                    ],
                )
            )
    return chains


# --- Tier 6: CIS-driven chains (new checks) ---


def _detect_root_keys_no_trail(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-25: Root access keys exist + no CloudTrail."""
    chains: list[AttackChain] = []
    root_keys = by_check.get("aws-iam-008", [])
    no_ct = by_check.get("aws-ct-001", [])
    if not root_keys or not no_ct:
        return chains

    chains.append(
        AttackChain(
            chain_id="AC-25",
            name="Root Access Keys Without Audit Trail",
            severity=Severity.CRITICAL,
            findings=[root_keys[0], no_ct[0]],
            attack_narrative=(
                "Root account has active access keys and CloudTrail is disabled. "
                "An attacker with root keys has unrestricted access to all AWS "
                "resources with zero audit trail. Root key usage cannot be "
                "restricted by IAM policies."
            ),
            priority_fix="Delete root access keys immediately (effort: LOW).",
            mitre_refs=["T1078.004", "T1562.008"],
            resources=["root", "cloudtrail"],
            viz_steps=[
                VizStep(label="Root Access Keys", sub="Active", type="identity", edge_label="no audit trail"),
                VizStep(label="CloudTrail", sub="Disabled", type="finding", edge_label="undetected"),
                VizStep(label="Unrestricted Access", sub="Root + No Logs", type="impact"),
            ],
        )
    )
    return chains


def _detect_admin_no_mfa_no_alarm(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-26: Admin policy + users without MFA + no root usage alarm."""
    chains: list[AttackChain] = []
    admin = by_check.get("aws-iam-005", [])
    no_mfa = by_check.get("aws-iam-002", [])
    no_alarm = by_check.get("aws-cw-001", [])
    if not admin or not no_mfa or not no_alarm:
        return chains

    chains.append(
        AttackChain(
            chain_id="AC-26",
            name="Unmonitored Admin Escalation Path",
            severity=Severity.CRITICAL,
            findings=[admin[0], no_mfa[0], no_alarm[0]],
            attack_narrative=(
                f"Admin-level IAM policy exists, user '{no_mfa[0].resource_id}' "
                f"has console access without MFA, and root account usage is not "
                f"monitored. An attacker can compromise the unprotected user, "
                f"escalate to admin, and operate undetected."
            ),
            priority_fix=f"Enable MFA for '{no_mfa[0].resource_id}' (effort: LOW).",
            mitre_refs=["T1078.004", "T1110", "T1562.008"],
            resources=[admin[0].resource_id, no_mfa[0].resource_id],
            viz_steps=[
                VizStep(label=no_mfa[0].resource_id, sub="No MFA", type="identity", edge_label="escalates to"),
                VizStep(label=admin[0].resource_id, sub="Admin Policy", type="identity", edge_label="no alarm"),
                VizStep(label="Root Alarm", sub="Not Configured", type="finding", edge_label="undetected"),
                VizStep(label="Silent Escalation", sub="Admin Without Alerts", type="impact"),
            ],
        )
    )
    return chains


def _detect_default_sg_no_flow_logs(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-27: Default SG has rules + no VPC flow logs in same region."""
    chains: list[AttackChain] = []
    default_sg = by_check.get("aws-vpc-005", [])
    no_flow = by_check.get("aws-vpc-003", [])
    if not default_sg or not no_flow:
        return chains

    flow_regions = {f.region for f in no_flow}
    for f in default_sg:
        if f.region in flow_regions:
            flow_f = next(fl for fl in no_flow if fl.region == f.region)
            chains.append(
                AttackChain(
                    chain_id="AC-27",
                    name="Default Network Access Without Logging",
                    severity=Severity.HIGH,
                    findings=[f, flow_f],
                    attack_narrative=(
                        f"Default security group in {f.region} allows traffic and "
                        f"VPC flow logs are disabled. Resources launched without "
                        f"explicit SG assignment get network access that is not logged."
                    ),
                    priority_fix=f"Remove rules from default SG {f.resource_id} (effort: LOW).",
                    mitre_refs=["T1190", "T1562.008"],
                    resources=[f.resource_id, flow_f.resource_id],
                    viz_steps=[
                        VizStep(
                            label=f.resource_id,
                            sub=f"Default SG ({f.region})",
                            type="network",
                            edge_label="allows traffic",
                        ),
                        VizStep(label="VPC Flow Logs", sub="Disabled", type="finding", edge_label="unmonitored"),
                        VizStep(label="Shadow Access", sub="Default + No Logs", type="impact"),
                    ],
                )
            )
            break
    return chains


def _detect_oidc_no_analyzer(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-28: OIDC trust without sub + no Access Analyzer."""
    chains: list[AttackChain] = []
    oidc = by_check.get("aws-iam-007", [])
    no_aa = by_check.get("aws-iam-012", [])
    if not oidc or not no_aa:
        return chains

    chains.append(
        AttackChain(
            chain_id="AC-28",
            name="External Access Without Analysis",
            severity=Severity.HIGH,
            findings=[oidc[0], no_aa[0]],
            attack_narrative=(
                f"Role '{_role_name_from_arn(oidc[0].resource_id)}' trusts an "
                f"OIDC provider without 'sub' restriction, and IAM Access "
                f"Analyzer is not enabled. External access paths exist but "
                f"the tool that detects them is not running."
            ),
            priority_fix="Enable IAM Access Analyzer and add 'sub' condition (effort: LOW).",
            mitre_refs=["T1078.004", "T1550.001"],
            resources=[oidc[0].resource_id],
            viz_steps=[
                VizStep(
                    label=_role_name_from_arn(oidc[0].resource_id),
                    sub="OIDC (no sub)",
                    type="identity",
                    edge_label="external access",
                ),
                VizStep(label="Access Analyzer", sub="Not Enabled", type="finding", edge_label="not detected"),
                VizStep(label="Blind External Access", sub="No Analysis", type="impact"),
            ],
        )
    )
    return chains


# --- Tier 7: New-check chains (v1.3.0) ---


def _detect_unpatched_exposed_instance(
    by_check: dict[str, list[Finding]],
    rels: ResourceRelationships,
) -> list[AttackChain]:
    """AC-29: Unpatched EC2 instance reachable from the internet."""
    chains: list[AttackChain] = []
    sg_findings = by_check.get("aws-vpc-002", [])
    patch_findings = by_check.get("aws-ssm-003", [])
    if not sg_findings or not patch_findings or not rels.ec2_sgs:
        return chains

    open_sgs = {f.resource_id for f in sg_findings}
    patch_instances = {f.resource_id: f for f in patch_findings}

    for instance_id, patch_f in patch_instances.items():
        instance_sgs = set(rels.ec2_sgs.get(instance_id, []))
        exposed_sgs = instance_sgs & open_sgs
        if not exposed_sgs:
            continue
        sg_f = next(f for f in sg_findings if f.resource_id in exposed_sgs)
        chains.append(
            AttackChain(
                chain_id="AC-29",
                name="Unpatched Instance Exposed to Internet",
                severity=Severity.CRITICAL,
                findings=[sg_f, patch_f],
                attack_narrative=(
                    f"Instance {instance_id} has known unpatched vulnerabilities and is "
                    f"internet-reachable via open security group {sg_f.resource_id}. "
                    f"An attacker can exploit published CVEs for remote code execution."
                ),
                priority_fix=f"Restrict security group {sg_f.resource_id} to specific IPs (effort: LOW).",
                mitre_refs=["T1190", "T1203"],
                resources=[instance_id, sg_f.resource_id],
                viz_steps=[
                    VizStep(label="Internet", sub="Entry Point", type="internet", edge_label="scans ports"),
                    VizStep(label=sg_f.resource_id, sub="Security Group", type="network", edge_label="allows access"),
                    VizStep(label=instance_id, sub="Unpatched EC2", type="compute", edge_label="known CVEs"),
                    VizStep(label="Remote Code Execution", sub="Full Instance Access", type="impact"),
                ],
            )
        )
    return chains


def _detect_unpatched_no_scanning(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-30: Unpatched instances + no vulnerability scanning."""
    chains: list[AttackChain] = []
    patch = by_check.get("aws-ssm-003", [])
    no_inspector = by_check.get("aws-inspector-001", [])
    if not patch or not no_inspector:
        return chains

    if _region_overlap(by_check, "aws-ssm-003", "aws-inspector-001"):
        chains.append(
            AttackChain(
                chain_id="AC-30",
                name="Unpatched Instances Without Vulnerability Scanning",
                severity=Severity.HIGH,
                findings=[patch[0], no_inspector[0]],
                attack_narrative=(
                    "EC2 instances have known unpatched vulnerabilities and Amazon "
                    "Inspector is not enabled. The organization has no visibility into "
                    "which instances are vulnerable or how to prioritize remediation."
                ),
                priority_fix="Enable Amazon Inspector (effort: LOW) for immediate vulnerability visibility.",
                mitre_refs=["T1203", "T1562.001"],
                resources=["ssm-patch-compliance", "inspector"],
                viz_steps=[
                    VizStep(label="EC2 Instances", sub="Unpatched", type="compute", edge_label="missing patches"),
                    VizStep(label="Inspector", sub="Not Enabled", type="finding", edge_label="no scanning"),
                    VizStep(label="Blind Vulnerability Mgmt", sub="No Prioritization", type="impact"),
                ],
            )
        )
    return chains


def _detect_exposed_no_waf_no_logs(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-31: Internet-facing resources without WAF or flow logs."""
    chains: list[AttackChain] = []
    no_waf = by_check.get("aws-waf-001", [])
    open_sg = by_check.get("aws-vpc-002", [])
    no_flow = by_check.get("aws-vpc-003", [])
    if not no_waf or not open_sg or not no_flow:
        return chains

    if _region_overlap(by_check, "aws-waf-001", "aws-vpc-002", "aws-vpc-003"):
        chains.append(
            AttackChain(
                chain_id="AC-31",
                name="Internet-Exposed Without WAF or Flow Logs",
                severity=Severity.HIGH,
                findings=[no_waf[0], open_sg[0], no_flow[0]],
                attack_narrative=(
                    "Internet-facing resources have unrestricted security groups, "
                    "no WAF to filter malicious traffic, and no VPC flow logs for "
                    "detection. Attackers can send arbitrary payloads with zero "
                    "chance of being blocked or logged."
                ),
                priority_fix="Create WAFv2 WebACL with AWS Managed Rules (effort: MEDIUM).",
                mitre_refs=["T1190", "T1562.008", "T1595"],
                resources=["waf", "security-groups", "flow-logs"],
                viz_steps=[
                    VizStep(label="Internet", sub="Entry Point", type="internet", edge_label="malicious traffic"),
                    VizStep(label="No WAF", sub="No Filtering", type="finding", edge_label="unblocked"),
                    VizStep(label="Open SG", sub="All Ports", type="network", edge_label="unrestricted"),
                    VizStep(label="No Flow Logs", sub="No Detection", type="finding", edge_label="invisible"),
                    VizStep(label="Undetected Breach", sub="No Evidence", type="impact"),
                ],
            )
        )
    return chains


def _detect_cloudtrail_blind_spot(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-32: CloudTrail not delivering to CloudWatch = all alarms non-functional."""
    chains: list[AttackChain] = []
    no_cw_integration = by_check.get("aws-ct-008", [])
    no_root_alarm = by_check.get("aws-cw-001", [])
    if not no_cw_integration or not no_root_alarm:
        return chains

    chains.append(
        AttackChain(
            chain_id="AC-32",
            name="CloudTrail Blind Spot - Alarms Non-Functional",
            severity=Severity.HIGH,
            findings=[no_cw_integration[0], no_root_alarm[0]],
            attack_narrative=(
                "CloudTrail is not integrated with CloudWatch Logs. All CIS Section 4 "
                "metric filter alarms (root usage, IAM changes, unauthorized API calls) "
                "are non-functional because log data never reaches CloudWatch. "
                "The account appears monitored but no alerts will fire."
            ),
            priority_fix=(
                "Configure CloudTrail CloudWatch Logs delivery (effort: MEDIUM) to activate all existing alarms."
            ),
            mitre_refs=["T1562.008", "T1078.004"],
            resources=["cloudtrail", "cloudwatch-logs"],
            viz_steps=[
                VizStep(label="CloudTrail", sub="Logging to S3", type="storage", edge_label="no CW delivery"),
                VizStep(label="CloudWatch Logs", sub="Empty", type="finding", edge_label="no data"),
                VizStep(label="15 CIS Alarms", sub="Non-Functional", type="finding", edge_label="never fire"),
                VizStep(label="False Sense of Security", sub="No Real-Time Detection", type="impact"),
            ],
        )
    )
    return chains


def _detect_all_public_vpc_no_segmentation(
    by_check: dict[str, list[Finding]],
) -> list[AttackChain]:
    """AC-33: VPC with all public subnets + open SGs + no flow logs."""
    chains: list[AttackChain] = []
    no_private = by_check.get("aws-vpc-006", [])
    open_sg = by_check.get("aws-vpc-002", [])
    no_flow = by_check.get("aws-vpc-003", [])
    if not no_private or not open_sg or not no_flow:
        return chains

    if _region_overlap(by_check, "aws-vpc-006", "aws-vpc-002", "aws-vpc-003"):
        chains.append(
            AttackChain(
                chain_id="AC-33",
                name="All-Public VPC Without Network Segmentation",
                severity=Severity.HIGH,
                findings=[no_private[0], open_sg[0], no_flow[0]],
                attack_narrative=(
                    "A VPC has exclusively public subnets with no private/public boundary. "
                    "Combined with open security groups and no flow logs, all workloads "
                    "are directly internet-addressable and lateral movement is unlogged."
                ),
                priority_fix="Create private subnets and move backend resources to them (effort: MEDIUM).",
                mitre_refs=["T1190", "T1021", "T1562.008"],
                resources=["vpc", "subnets", "security-groups"],
                viz_steps=[
                    VizStep(label="Internet", sub="Entry Point", type="internet", edge_label="direct access"),
                    VizStep(label="All-Public VPC", sub="No Segmentation", type="network", edge_label="flat network"),
                    VizStep(label="Open SG", sub="All Ports", type="network", edge_label="lateral movement"),
                    VizStep(label="No Flow Logs", sub="No Detection", type="finding", edge_label="invisible"),
                    VizStep(label="Full VPC Compromise", sub="All Resources Exposed", type="impact"),
                ],
            )
        )
    return chains


# ---------------------------------------------------------------------------
# Main detection function
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# IAM Privilege Escalation chain rules (AC-34 through AC-36)
# ---------------------------------------------------------------------------


def _detect_iam_self_escalation(by_check: dict[str, list[Finding]]) -> list[AttackChain]:
    """AC-35: Principal can self-escalate via IAM policy modification."""
    escalation_findings = by_check.get("aws-iam-018", [])
    if not escalation_findings:
        return []

    # Filter for self-mutation category
    self_mutation = [
        f
        for f in escalation_findings
        if "self_mutation" in f.description.lower()
        or "CreatePolicyVersion" in f.title
        or "AttachUserPolicy" in f.title
        or "AttachGroupPolicy" in f.title
        or "AttachRolePolicy" in f.title
        or "PutUserPolicy" in f.title
        or "PutGroupPolicy" in f.title
        or "PutRolePolicy" in f.title
        or "SetDefaultPolicyVersion" in f.title
    ]
    if not self_mutation:
        return []

    chains: list[AttackChain] = []
    # Group by principal
    by_principal: dict[str, list[Finding]] = {}
    for f in self_mutation:
        by_principal.setdefault(f.resource_id, []).append(f)

    for principal_arn, findings in by_principal.items():
        methods = ", ".join(f.title.split("via ")[-1] if "via " in f.title else "policy modification" for f in findings)
        name = findings[0].resource_id.split("/")[-1] if "/" in findings[0].resource_id else findings[0].resource_id
        chains.append(
            AttackChain(
                chain_id="AC-35",
                name=f"Self-Escalation to Admin ({name})",
                severity=Severity.CRITICAL,
                findings=findings,
                attack_narrative=(
                    f"Principal '{name}' can modify IAM policies to grant itself admin access "
                    f"via: {methods}. No additional permissions or services needed - "
                    f"a single API call is sufficient for full account takeover."
                ),
                priority_fix=f"Remove dangerous IAM mutation permissions from '{name}'",
                mitre_refs=["T1098.001"],
                resources=[principal_arn],
            )
        )

    return chains


def _detect_passrole_escalation(by_check: dict[str, list[Finding]]) -> list[AttackChain]:
    """AC-34: Principal can escalate via PassRole + service exploitation."""
    escalation_findings = by_check.get("aws-iam-018", [])
    if not escalation_findings:
        return []

    passrole = [f for f in escalation_findings if "PassRole" in f.title]
    if not passrole:
        return []

    chains: list[AttackChain] = []
    by_principal: dict[str, list[Finding]] = {}
    for f in passrole:
        by_principal.setdefault(f.resource_id, []).append(f)

    for principal_arn, findings in by_principal.items():
        name = findings[0].resource_id.split("/")[-1] if "/" in findings[0].resource_id else findings[0].resource_id
        services = ", ".join(f.title.split("via ")[-1] if "via " in f.title else "service" for f in findings)
        chains.append(
            AttackChain(
                chain_id="AC-34",
                name=f"PassRole Escalation to Admin ({name})",
                severity=Severity.CRITICAL,
                findings=findings,
                attack_narrative=(
                    f"Principal '{name}' has iam:PassRole and can create resources with privileged "
                    f"roles via: {services}. The attacker passes an admin role to a service, "
                    f"then uses that service to execute code with admin privileges."
                ),
                priority_fix=f"Scope iam:PassRole for '{name}' to specific role ARNs",
                mitre_refs=["T1098.001", "T1078.004"],
                resources=[principal_arn],
            )
        )

    return chains


def _detect_oidc_escalation(by_check: dict[str, list[Finding]]) -> list[AttackChain]:
    """AC-36: OIDC role without sub condition + escalation path = external admin."""
    oidc_findings = by_check.get("aws-iam-007", [])
    escalation_findings = by_check.get("aws-iam-018", [])
    if not oidc_findings or not escalation_findings:
        return []

    # Find OIDC roles that also have escalation paths
    oidc_roles = {f.resource_id for f in oidc_findings}
    escalation_for_oidc = [f for f in escalation_findings if f.resource_id in oidc_roles]
    if not escalation_for_oidc:
        return []

    chains: list[AttackChain] = []
    by_role: dict[str, list[Finding]] = {}
    for f in escalation_for_oidc:
        by_role.setdefault(f.resource_id, []).append(f)

    for role_arn, findings in by_role.items():
        role_name = role_arn.split("/")[-1] if "/" in role_arn else role_arn
        oidc_finding = next((f for f in oidc_findings if f.resource_id == role_arn), None)
        all_findings = ([oidc_finding] if oidc_finding else []) + findings
        chains.append(
            AttackChain(
                chain_id="AC-36",
                name=f"External Escalation via OIDC ({role_name})",
                severity=Severity.CRITICAL,
                findings=all_findings,
                attack_narrative=(
                    f"Role '{role_name}' trusts an OIDC provider without restricting the 'sub' "
                    f"claim (any repo can assume it) AND the role has privilege escalation paths. "
                    f"An external attacker compromises any repo → assumes the role → escalates to admin."
                ),
                priority_fix=f"Add 'sub' condition to OIDC trust policy on '{role_name}'",
                mitre_refs=["T1078.004", "T1098.001"],
                resources=[role_arn],
            )
        )

    return chains


# ---------------------------------------------------------------------------
# AI Security chain rules (AC-37 through AC-39)
# ---------------------------------------------------------------------------


def _detect_ai_model_theft(by_check: dict[str, list[Finding]]) -> list[AttackChain]:
    """AC-37: SageMaker notebook with root access + internet = AI model theft risk."""
    root_findings = by_check.get("aws-sagemaker-001", [])
    internet_findings = by_check.get("aws-sagemaker-002", [])
    if not root_findings or not internet_findings:
        return []

    # Match by region
    root_regions = {f.region for f in root_findings}
    internet_regions = {f.region for f in internet_findings}
    overlap = root_regions & internet_regions
    if not overlap:
        return []

    combined = [f for f in root_findings + internet_findings if f.region in overlap]
    return [
        AttackChain(
            chain_id="AC-37",
            name="AI Model Theft via SageMaker",
            severity=Severity.CRITICAL,
            findings=combined,
            attack_narrative=(
                "SageMaker notebooks have root access AND direct internet access. "
                "An attacker who gains notebook access can exfiltrate proprietary models, "
                "training data, and credentials to the internet without restriction."
            ),
            priority_fix="Disable root access and direct internet on SageMaker notebooks",
            mitre_refs=["T1530"],
            resources=[f.resource_id for f in combined[:3]],
        )
    ]


def _detect_llmjacking(by_check: dict[str, list[Finding]]) -> list[AttackChain]:
    """AC-38: Bedrock without logging + no guardrails = LLMjacking risk."""
    no_logging = by_check.get("aws-bedrock-001", [])
    no_guardrails = by_check.get("aws-bedrock-002", [])
    if not no_logging:
        return []

    # LLMjacking requires at least no logging; guardrails absence amplifies it
    logging_regions = {f.region for f in no_logging}
    combined = list(no_logging)
    if no_guardrails:
        combined.extend(f for f in no_guardrails if f.region in logging_regions)

    return [
        AttackChain(
            chain_id="AC-38",
            name="LLMjacking - Unauthorized Model Usage",
            severity=Severity.HIGH,
            findings=combined,
            attack_narrative=(
                "Bedrock model invocation logging is disabled"
                + (" and no guardrails are configured" if no_guardrails else "")
                + ". An attacker with stolen credentials can invoke expensive models "
                "(Claude, Titan) at your expense without detection. "
                "LLMjacking attacks have cost victims $50K+ in compute charges."
            ),
            priority_fix="Enable Bedrock model invocation logging",
            mitre_refs=["T1496"],
            resources=[f.resource_id for f in combined[:3]],
        )
    ]


def _detect_ai_data_poisoning(by_check: dict[str, list[Finding]]) -> list[AttackChain]:
    """AC-39: SageMaker notebook root + internet + no Bedrock guardrails = data poisoning."""
    root_nb = by_check.get("aws-sagemaker-001", [])
    no_guardrails = by_check.get("aws-bedrock-002", [])
    if not root_nb or not no_guardrails:
        return []

    combined = root_nb[:2] + no_guardrails[:2]
    return [
        AttackChain(
            chain_id="AC-39",
            name="AI Data Poisoning via Unguarded Pipeline",
            severity=Severity.HIGH,
            findings=combined,
            attack_narrative=(
                "SageMaker notebooks have root access (can modify training data) and "
                "Bedrock has no guardrails (no output validation). An attacker can poison "
                "training data or model weights and the corrupted output passes through "
                "to production without content filtering."
            ),
            priority_fix="Disable SageMaker root access and configure Bedrock guardrails",
            mitre_refs=["T1565"],
            resources=[f.resource_id for f in combined[:3]],
        )
    ]


# All rule functions in execution order
_SIMPLE_RULES = [
    _detect_unmonitored_admin,  # AC-09
    _detect_blind_admin,  # AC-10
    _detect_zero_visibility,  # AC-11
    _detect_admin_no_mfa,  # AC-12
    _detect_open_unmonitored_network,  # AC-13
    _detect_no_network_layers,  # AC-14
    _detect_exposed_db_no_trail,  # AC-17
    _detect_container_breakout,  # AC-19
    _detect_unmonitored_containers,  # AC-20
    _detect_plaintext_secrets,  # AC-21
    _detect_root_keys_no_trail,  # AC-25
    _detect_admin_no_mfa_no_alarm,  # AC-26
    _detect_default_sg_no_flow_logs,  # AC-27
    _detect_oidc_no_analyzer,  # AC-28
    _detect_unpatched_no_scanning,  # AC-30
    _detect_exposed_no_waf_no_logs,  # AC-31
    _detect_cloudtrail_blind_spot,  # AC-32
    _detect_all_public_vpc_no_segmentation,  # AC-33
    _detect_passrole_escalation,  # AC-34
    _detect_iam_self_escalation,  # AC-35
    _detect_oidc_escalation,  # AC-36
    _detect_ai_model_theft,  # AC-37
    _detect_llmjacking,  # AC-38
    _detect_ai_data_poisoning,  # AC-39
]

_RELATIONSHIP_RULES = [
    _detect_exposed_admin_instance,  # AC-01
    _detect_ssrf_credential_theft,  # AC-02
    _detect_public_lambda_admin,  # AC-05
    _detect_cicd_admin_takeover,  # AC-07
    _detect_cicd_data_exfil,  # AC-23
    _detect_cicd_lateral_movement,  # AC-24
    _detect_unpatched_exposed_instance,  # AC-29
]


def detect_attack_chains(
    findings: list[Finding],
    relationships: ResourceRelationships | None = None,
) -> list[AttackChain]:
    """Detect attack chains by correlating findings and resource relationships.

    Args:
        findings: All findings from the scan.
        relationships: Resource relationship data (EC2->role, Lambda->role, etc.).
                      If None, only simple correlation rules run.

    Returns:
        List of detected attack chains, sorted by severity.
    """
    if not findings:
        return []

    by_check = _findings_by_check(findings)
    chains: list[AttackChain] = []

    # Run simple rules (no relationship data needed)
    for simple_fn in _SIMPLE_RULES:
        chains.extend(simple_fn(by_check))

    # Run relationship rules (need EC2/Lambda/IAM data)
    if relationships:
        for rel_fn in _RELATIONSHIP_RULES:
            chains.extend(rel_fn(by_check, relationships))

    # Deduplicate: if AC-10 fires, suppress AC-09 (AC-10 is a superset)
    chain_ids = {c.chain_id for c in chains}
    suppress_map = {
        "AC-09": "AC-10",  # Blind Admin supersedes Unmonitored Admin
        "AC-12": "AC-26",  # Unmonitored Admin Escalation supersedes Admin No MFA
        "AC-07": "AC-36",  # OIDC + Escalation supersedes plain OIDC
    }
    chains = [c for c in chains if c.chain_id not in suppress_map or suppress_map[c.chain_id] not in chain_ids]

    # Sort by severity
    severity_order = list(Severity)
    chains.sort(key=lambda c: severity_order.index(c.severity))

    return chains
