"""TF-007: CI/CD roles vulnerable to whoAMI confusion attack.

The whoAMI confusion attack (disclosed by Datadog Security Labs in February 2025
and re-presented at fwd:cloudsec 2025 as 'whoAMI confusion attack at scale')
abuses CI/CD pipelines that call ec2:DescribeImages with a `most-recent` filter
but WITHOUT an `--owners` restriction. An attacker publishes a malicious public
AMI whose name matches the victim's filter pattern; AWS sorts it as the
'most recent' match; the CI pipeline launches it; the attacker now has code
execution inside the victim's VPC with the instance profile attached.

This is a PIPELINE pattern, not a posture issue per se: the offending behaviour
lives in the pipeline code (Packer, Terraform, EC2 launch scripts) not in IAM.
But cloud-audit can flag the IAM PRECONDITION: any CI/CD-style role (trusted by
codebuild, github OIDC, gitlab OIDC, jenkins OIDC) that has broad EC2
permissions allowing DescribeImages WITHOUT the typical owner-scoped pattern.

Severity is MEDIUM by default - this is a HEURISTIC that points operators at
roles worth manually reviewing, not a certain finding. We deliberately
under-flag rather than over-alert to keep signal-to-noise ratio honest.

References:
    - https://securitylabs.datadoghq.com/articles/whoami-a-cloud-image-name-confusion-attack/
    - https://github.com/Cybr-Inc/fwdcloudsec-2025-summaries
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


PATTERN_ID = "TF-007-whoami-confusion"
CHECK_ID = "aws-tf-007"
PATTERN_NAME = "CI/CD role at risk of whoAMI confusion attack"
PATTERN_SEVERITY = Severity.MEDIUM
DOC_URL = "https://securitylabs.datadoghq.com/articles/whoami-a-cloud-image-name-confusion-attack/"

_REFERENCES = [
    "https://securitylabs.datadoghq.com/articles/whoami-a-cloud-image-name-confusion-attack/",
    "https://github.com/Cybr-Inc/fwdcloudsec-2025-summaries",
]

# Service principals + identity providers that indicate a CI/CD context.
_CI_SERVICE_PRINCIPALS = frozenset(
    {
        "codebuild.amazonaws.com",
        "codepipeline.amazonaws.com",
        "codedeploy.amazonaws.com",
    }
)

# Substrings that indicate an OIDC-federated CI/CD role (GitHub/GitLab/Jenkins)
_CI_FEDERATED_SUBSTRINGS = (
    "token.actions.githubusercontent.com",
    "vstoken.actions.githubusercontent.com",
    "gitlab.com",
    "/oidc/",
    "buildkite.com",
)

# Managed policies that grant DescribeImages broadly enough to enable the attack
_BROAD_EC2_POLICIES = frozenset(
    {
        "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
        "arn:aws:iam::aws:policy/PowerUserAccess",
        "arn:aws:iam::aws:policy/AdministratorAccess",
    }
)


def _trust_indicates_ci(trust_policy: dict[str, Any]) -> bool:
    """Return True if the AssumeRolePolicyDocument indicates a CI/CD context."""
    statements = trust_policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", {}) or {}
        if isinstance(principal, str):
            continue  # legacy form, ignore

        # Service-based trust (codebuild etc.)
        services = principal.get("Service", [])
        if isinstance(services, str):
            services = [services]
        if any(s in _CI_SERVICE_PRINCIPALS for s in services):
            return True

        # OIDC-federated trust (GitHub / GitLab Actions)
        federated = principal.get("Federated", [])
        if isinstance(federated, str):
            federated = [federated]
        for fed in federated:
            if any(sub in fed for sub in _CI_FEDERATED_SUBSTRINGS):
                return True
    return False


def _trust_label(trust_policy: dict[str, Any]) -> str:
    """Best-effort short label of WHICH CI surface trusts this role."""
    statements = trust_policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        principal = stmt.get("Principal", {}) or {}
        if isinstance(principal, str):
            continue
        services = principal.get("Service", [])
        if isinstance(services, str):
            services = [services]
        if services:
            ci_svc = next((s for s in services if s in _CI_SERVICE_PRINCIPALS), None)
            if ci_svc:
                return str(ci_svc).split(".", 1)[0]
        federated = principal.get("Federated", [])
        if isinstance(federated, str):
            federated = [federated]
        for fed in federated:
            if "github" in fed:
                return "github-oidc"
            if "gitlab" in fed:
                return "gitlab-oidc"
            if "buildkite" in fed:
                return "buildkite-oidc"
    return "ci-cd"


def _build_finding(role_name: str, role_arn: str, trust_label: str, broad_policy_arn: str) -> Finding:
    return Finding(
        check_id=CHECK_ID,
        title=f"CI/CD role '{role_name}' ({trust_label}) has broad EC2 access - whoAMI risk",
        severity=PATTERN_SEVERITY,
        category=Category.THREAT,
        resource_type="AWS::IAM::Role",
        resource_id=role_arn,
        region="global",
        description=(
            f"Role '{role_name}' is trusted by a CI/CD identity ({trust_label}) AND has "
            f"the {broad_policy_arn.rsplit('/', 1)[-1]} managed policy attached. This role "
            "can call ec2:DescribeImages and ec2:RunInstances with no owner restriction. "
            "If your pipeline code looks up an AMI by name pattern + most-recent filter "
            "without specifying --owners (or Owners in boto3), an attacker publishing a "
            "malicious public AMI matching the pattern can hijack the launch - the "
            "Datadog Feb 2025 'whoAMI' research demonstrated this against thousands of "
            "AWS accounts. The fix lives in the PIPELINE code, not IAM, but this role "
            "is the precondition that makes the attack reachable."
        ),
        recommendation=(
            "(1) Audit your pipeline code for ec2:DescribeImages calls. Require "
            "--owners (or Owners=['amazon', 'self', '<known-account-id>']) on EVERY "
            "call. (2) For Terraform: pin AMI IDs in tfvars instead of using "
            "data.aws_ami with most-recent without owner filter. (3) Reduce this "
            "role's IAM scope - replace AmazonEC2FullAccess with a custom policy "
            "scoping ec2:DescribeImages with a Condition on ec2:Owner."
        ),
        remediation=Remediation(
            cli=(
                f"# 1) Inventory current pipelines using DescribeImages without owner filter:\n"
                f"#    grep -rE 'describe-images|aws_ami' your-pipeline-repo\n"
                f"\n# 2) Detach the over-broad managed policy:\n"
                f"aws iam detach-role-policy --role-name {role_name} \\\n"
                f"  --policy-arn {broad_policy_arn}\n"
                f"\n# 3) Attach a scoped custom policy (example below) instead:\n"
                f"#    aws iam create-policy --policy-name {role_name}-ec2-scoped \\\n"
                f"#      --policy-document file://scoped-ec2.json"
            ),
            terraform=(
                'data "aws_iam_policy_document" "ci_ec2" {\n'
                "  statement {\n"
                '    actions = ["ec2:DescribeImages"]\n'
                '    resources = ["*"]\n'
                "    condition {\n"
                '      test     = "StringEquals"\n'
                '      variable = "ec2:Owner"\n'
                '      values   = ["amazon", "self"]  # or specific account IDs\n'
                "    }\n"
                "  }\n"
                "}"
            ),
            doc_url=DOC_URL,
            effort=Effort.MEDIUM,
        ),
        threat_pattern_id=PATTERN_ID,
        references=_REFERENCES,
    )


def detect(provider: AWSProvider) -> CheckResult:
    """Scan IAM roles for the whoAMI precondition: CI trust + broad EC2 access."""
    result = CheckResult(check_id=CHECK_ID, check_name=PATTERN_NAME)

    try:
        iam = provider.client("iam")
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                role_name = role["RoleName"]
                if role_name.startswith("AWSServiceRole"):
                    continue
                trust = role.get("AssumeRolePolicyDocument") or {}
                if not _trust_indicates_ci(trust):
                    continue
                result.resources_scanned += 1
                try:
                    attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
                except Exception as exc:
                    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                    if code in ("AccessDenied", "NoSuchEntity"):
                        continue
                    raise
                broad = next((p["PolicyArn"] for p in attached if p.get("PolicyArn") in _BROAD_EC2_POLICIES), None)
                if not broad:
                    continue
                result.findings.append(
                    _build_finding(
                        role_name=role_name,
                        role_arn=role["Arn"],
                        trust_label=_trust_label(trust),
                        broad_policy_arn=broad,
                    )
                )
    except Exception as e:
        result.error = str(e)

    return result
