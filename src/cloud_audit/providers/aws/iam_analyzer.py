"""IAM Privilege Escalation Analyzer.

Detects IAM privilege escalation paths by:
1. Fetching all IAM data via GetAccountAuthorizationDetails (single paginated call)
2. Resolving effective permissions per principal (users + roles)
3. Checking each principal against known escalation methods

References:
- Cloudsplaining (Salesforce, BSD-3): 21 methods
- Hacking The Cloud: 40+ methods
- pathfinding.cloud (Datadog, Apache-2.0): 65 paths

Coverage: 61 detection methods across 9 categories (57 action-based +
4 lateral). v2.1.0 expanded from 25 methods through three tiers: Tier 1
added PassRole variants, resource policy abuse, deny-removal patterns,
and MFA bypass; Tier 2 added new compute primitives (CodeBuild, AppRunner,
SageMaker, Bedrock, Step Functions), SSM-based compute hijack, and EC2
Instance Connect; Tier 3 added trust-policy graph analysis with lateral
movement detection (Direct/Chain AssumeRole, WildcardTrust, CrossAccountRoot).
"""

from __future__ import annotations

import fnmatch
import json
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from cloud_audit.models import EscalationCategory, EscalationPath, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider

# ---------------------------------------------------------------------------
# Module-level cache (reset between scans via _reset_escalation_cache)
# ---------------------------------------------------------------------------
_escalation_cache: list[EscalationPath] | None = None
_escalation_lock = threading.Lock()


def _reset_escalation_cache() -> None:
    """Reset the escalation cache. Called between scans in tests."""
    global _escalation_cache
    with _escalation_lock:
        _escalation_cache = None


def get_cached_escalation_paths() -> list[EscalationPath]:
    """Return cached escalation paths (populated by check_privilege_escalation)."""
    with _escalation_lock:
        return list(_escalation_cache) if _escalation_cache is not None else []


# ---------------------------------------------------------------------------
# Escalation method definitions (data-driven)
# ---------------------------------------------------------------------------
@dataclass
class _MethodDef:
    actions: list[str]
    category: EscalationCategory
    severity: Severity
    target: str


ESCALATION_METHODS: dict[str, _MethodDef] = {
    # Category 1: IAM Self-Mutation (8 methods)
    "CreatePolicyVersion": _MethodDef(
        actions=["iam:CreatePolicyVersion"],
        category=EscalationCategory.IAM_SELF_MUTATION,
        severity=Severity.CRITICAL,
        target="Admin via new policy version with *:*",
    ),
    "SetDefaultPolicyVersion": _MethodDef(
        actions=["iam:SetDefaultPolicyVersion"],
        category=EscalationCategory.IAM_SELF_MUTATION,
        severity=Severity.CRITICAL,
        target="Admin via activating permissive policy version",
    ),
    "AttachUserPolicy": _MethodDef(
        actions=["iam:AttachUserPolicy"],
        category=EscalationCategory.IAM_SELF_MUTATION,
        severity=Severity.CRITICAL,
        target="Admin via attaching AdministratorAccess to self",
    ),
    "AttachRolePolicy": _MethodDef(
        actions=["iam:AttachRolePolicy", "sts:AssumeRole"],
        category=EscalationCategory.IAM_SELF_MUTATION,
        severity=Severity.CRITICAL,
        target="Admin via attaching policy to assumable role",
    ),
    "AttachGroupPolicy": _MethodDef(
        actions=["iam:AttachGroupPolicy"],
        category=EscalationCategory.IAM_SELF_MUTATION,
        severity=Severity.CRITICAL,
        target="Admin via attaching policy to own group",
    ),
    "PutUserPolicy": _MethodDef(
        actions=["iam:PutUserPolicy"],
        category=EscalationCategory.IAM_SELF_MUTATION,
        severity=Severity.CRITICAL,
        target="Admin via inline policy on self",
    ),
    "PutGroupPolicy": _MethodDef(
        actions=["iam:PutGroupPolicy"],
        category=EscalationCategory.IAM_SELF_MUTATION,
        severity=Severity.CRITICAL,
        target="Admin via inline policy on own group",
    ),
    "PutRolePolicy": _MethodDef(
        actions=["iam:PutRolePolicy", "sts:AssumeRole"],
        category=EscalationCategory.IAM_SELF_MUTATION,
        severity=Severity.CRITICAL,
        target="Admin via inline policy on assumable role",
    ),
    # Category 2: Credential Access (4 methods)
    "CreateAccessKey": _MethodDef(
        actions=["iam:CreateAccessKey"],
        category=EscalationCategory.CREDENTIAL_ACCESS,
        severity=Severity.HIGH,
        target="Credentials for another user",
    ),
    "CreateLoginProfile": _MethodDef(
        actions=["iam:CreateLoginProfile"],
        category=EscalationCategory.CREDENTIAL_ACCESS,
        severity=Severity.HIGH,
        target="Console access for another user",
    ),
    "UpdateLoginProfile": _MethodDef(
        actions=["iam:UpdateLoginProfile"],
        category=EscalationCategory.CREDENTIAL_ACCESS,
        severity=Severity.HIGH,
        target="Reset another user password",
    ),
    "AddUserToGroup": _MethodDef(
        actions=["iam:AddUserToGroup"],
        category=EscalationCategory.CREDENTIAL_ACCESS,
        severity=Severity.HIGH,
        target="Add self to admin group",
    ),
    # Category 3: PassRole + Service Exploitation (6 methods)
    "PassRole+EC2": _MethodDef(
        actions=["iam:PassRole", "ec2:RunInstances"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.CRITICAL,
        target="Admin via EC2 instance with privileged role",
    ),
    "PassRole+Lambda": _MethodDef(
        actions=["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.CRITICAL,
        target="Admin via Lambda with privileged role",
    ),
    "PassRole+CloudFormation": _MethodDef(
        actions=["iam:PassRole", "cloudformation:CreateStack"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.CRITICAL,
        target="Admin via CloudFormation stack with privileged role",
    ),
    "PassRole+Glue": _MethodDef(
        actions=["iam:PassRole", "glue:CreateDevEndpoint"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.HIGH,
        target="Code execution via Glue dev endpoint",
    ),
    "PassRole+DataPipeline": _MethodDef(
        actions=["iam:PassRole", "datapipeline:CreatePipeline"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.HIGH,
        target="Code execution via Data Pipeline",
    ),
    "PassRole+ECS": _MethodDef(
        actions=["iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.CRITICAL,
        target="Admin via ECS task with privileged role",
    ),
    # Category 4: Lambda Code Modification (2 methods)
    "UpdateFunctionCode": _MethodDef(
        actions=["lambda:UpdateFunctionCode"],
        category=EscalationCategory.LAMBDA_CODE_MOD,
        severity=Severity.HIGH,
        target="Hijack existing Lambda execution role",
    ),
    "UpdateFunctionConfiguration": _MethodDef(
        actions=["lambda:UpdateFunctionConfiguration"],
        category=EscalationCategory.LAMBDA_CODE_MOD,
        severity=Severity.HIGH,
        target="Layer injection to hijack Lambda execution",
    ),
    # Category 5: Trust Policy Abuse (1 method)
    "UpdateAssumeRolePolicy": _MethodDef(
        actions=["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
        category=EscalationCategory.TRUST_POLICY_ABUSE,
        severity=Severity.CRITICAL,
        target="Modify trust policy to allow self to assume role",
    ),
    # Category 6: Permission Boundary Bypass (4 methods)
    "DeleteRolePermissionsBoundary": _MethodDef(
        actions=["iam:DeleteRolePermissionsBoundary"],
        category=EscalationCategory.PERMISSION_BOUNDARY,
        severity=Severity.CRITICAL,
        target="Remove permission boundary defense on a role",
    ),
    "DeleteUserPermissionsBoundary": _MethodDef(
        actions=["iam:DeleteUserPermissionsBoundary"],
        category=EscalationCategory.PERMISSION_BOUNDARY,
        severity=Severity.CRITICAL,
        target="Remove permission boundary defense on a user",
    ),
    "PutRolePermissionsBoundary": _MethodDef(
        actions=["iam:PutRolePermissionsBoundary"],
        category=EscalationCategory.PERMISSION_BOUNDARY,
        severity=Severity.HIGH,
        target="Replace permission boundary with permissive one",
    ),
    "PutUserPermissionsBoundary": _MethodDef(
        actions=["iam:PutUserPermissionsBoundary"],
        category=EscalationCategory.PERMISSION_BOUNDARY,
        severity=Severity.HIGH,
        target="Replace permission boundary with permissive one",
    ),
    # ---------------------------------------------------------------------
    # Tier 1 additions (v2.1.0): +20 methods, total 45
    # Coverage of pathfinding.cloud (Datadog, 66 paths): 38% -> ~68%
    # ---------------------------------------------------------------------
    # Category 3 extensions: PassRole + Service variants (10 methods)
    "PassRole+Glue:CreateJob": _MethodDef(
        actions=["iam:PassRole", "glue:CreateJob"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.HIGH,
        target="Code execution via Glue Job with privileged role",
    ),
    "PassRole+Glue:UpdateJob": _MethodDef(
        actions=["iam:PassRole", "glue:UpdateJob"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.HIGH,
        target="Hijack existing Glue Job to run with privileged role",
    ),
    "PassRole+Glue:CreateSession": _MethodDef(
        actions=["iam:PassRole", "glue:CreateSession"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.HIGH,
        target="Interactive Spark session running with privileged role",
    ),
    "PassRole+ECS:UpdateService": _MethodDef(
        actions=["iam:PassRole", "ecs:UpdateService", "ecs:RegisterTaskDefinition"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.CRITICAL,
        target="Replace task definition on running ECS service with privileged role",
    ),
    "PassRole+ECS:RegisterTaskDefinition": _MethodDef(
        actions=["iam:PassRole", "ecs:RegisterTaskDefinition"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.HIGH,
        target="Register task definition with privileged role (auto-deploy required)",
    ),
    "PassRole+CloudFormation:UpdateStack": _MethodDef(
        actions=["iam:PassRole", "cloudformation:UpdateStack"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.CRITICAL,
        target="Admin via CloudFormation stack update with privileged role",
    ),
    "PassRole+EC2:AssociateInstanceProfile": _MethodDef(
        actions=["iam:PassRole", "ec2:AssociateIamInstanceProfile"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.CRITICAL,
        target="Attach privileged instance profile to running EC2 instance",
    ),
    "PassRole+EC2:ReplaceInstanceProfileAssociation": _MethodDef(
        actions=["iam:PassRole", "ec2:ReplaceIamInstanceProfileAssociation"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.CRITICAL,
        target="Replace instance profile on running EC2 with privileged role",
    ),
    "PassRole+Lambda:CreateEventSourceMapping": _MethodDef(
        actions=["iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.HIGH,
        target="Trigger privileged Lambda via event source mapping",
    ),
    "InstanceProfileRoleSwap": _MethodDef(
        actions=["iam:RemoveRoleFromInstanceProfile", "iam:AddRoleToInstanceProfile"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.HIGH,
        target="Swap role on existing instance profile to gain privileged role",
    ),
    # Category 7: Resource Policy Abuse (NEW category, 2 methods)
    "Lambda:AddPermission": _MethodDef(
        actions=["lambda:AddPermission"],
        category=EscalationCategory.RESOURCE_POLICY_ABUSE,
        severity=Severity.HIGH,
        target="Cross-account invocation of privileged Lambda via resource policy",
    ),
    "Lambda:AddLayerVersionPermission": _MethodDef(
        actions=["lambda:AddLayerVersionPermission"],
        category=EscalationCategory.RESOURCE_POLICY_ABUSE,
        severity=Severity.HIGH,
        target="Share malicious Lambda layer used by privileged functions",
    ),
    # Category 1 extensions: IAM Self-Mutation (5 methods)
    "DeleteRolePolicy": _MethodDef(
        actions=["iam:DeleteRolePolicy", "sts:AssumeRole"],
        category=EscalationCategory.IAM_SELF_MUTATION,
        severity=Severity.HIGH,
        target="Remove blocking inline policy on assumable role",
    ),
    "DeleteUserPolicy": _MethodDef(
        actions=["iam:DeleteUserPolicy"],
        category=EscalationCategory.IAM_SELF_MUTATION,
        severity=Severity.HIGH,
        target="Remove blocking inline policy on a user (deny removal)",
    ),
    "DetachRolePolicy": _MethodDef(
        actions=["iam:DetachRolePolicy", "sts:AssumeRole"],
        category=EscalationCategory.IAM_SELF_MUTATION,
        severity=Severity.HIGH,
        target="Detach blocking managed policy from assumable role",
    ),
    "DetachUserPolicy": _MethodDef(
        actions=["iam:DetachUserPolicy"],
        category=EscalationCategory.IAM_SELF_MUTATION,
        severity=Severity.HIGH,
        target="Detach blocking managed policy from a user (deny removal)",
    ),
    "CreateServiceLinkedRole": _MethodDef(
        actions=["iam:CreateServiceLinkedRole"],
        category=EscalationCategory.IAM_SELF_MUTATION,
        severity=Severity.HIGH,
        target="Create service-linked role with service-managed admin policies",
    ),
    # Category 2 extensions: Credential Access (3 methods)
    "UpdateAccessKey": _MethodDef(
        actions=["iam:UpdateAccessKey"],
        category=EscalationCategory.CREDENTIAL_ACCESS,
        severity=Severity.HIGH,
        target="Re-enable disabled access key for another user",
    ),
    "DeactivateMFADevice": _MethodDef(
        actions=["iam:DeactivateMFADevice"],
        category=EscalationCategory.CREDENTIAL_ACCESS,
        severity=Severity.HIGH,
        target="Remove MFA from user, bypass MFA-required policies",
    ),
    "DeleteVirtualMFADevice": _MethodDef(
        actions=["iam:DeleteVirtualMFADevice"],
        category=EscalationCategory.CREDENTIAL_ACCESS,
        severity=Severity.HIGH,
        target="Delete virtual MFA device, bypass MFA-required policies",
    ),
    # ---------------------------------------------------------------------
    # Tier 2 additions (v2.1.0): +12 methods, total 57
    # New compute primitives + SSM + EC2 Instance Connect + Step Functions
    # Coverage of pathfinding.cloud (Datadog, 66 paths): ~68% -> ~86%
    # ---------------------------------------------------------------------
    # Category 3 extensions: PassRole + new compute services (6 methods)
    "PassRole+CodeBuild:CreateProject": _MethodDef(
        actions=["iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.CRITICAL,
        target="Admin via CodeBuild project with privileged role (buildspec exec)",
    ),
    "PassRole+AppRunner:CreateService": _MethodDef(
        actions=["iam:PassRole", "apprunner:CreateService"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.CRITICAL,
        target="Admin via AppRunner container with privileged role",
    ),
    "PassRole+SageMaker:CreateNotebookInstance": _MethodDef(
        actions=["iam:PassRole", "sagemaker:CreateNotebookInstance"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.CRITICAL,
        target="Admin via SageMaker Jupyter notebook with privileged execution role",
    ),
    "PassRole+SageMaker:CreateProcessingJob": _MethodDef(
        actions=["iam:PassRole", "sagemaker:CreateProcessingJob"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.HIGH,
        target="Code execution via SageMaker processing job with privileged role",
    ),
    "PassRole+Bedrock:CreateAgent": _MethodDef(
        actions=["iam:PassRole", "bedrock:CreateAgent"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.HIGH,
        target="Admin via Bedrock agent invoking AWS APIs with privileged role",
    ),
    "PassRole+StepFunctions:CreateStateMachine": _MethodDef(
        actions=["iam:PassRole", "states:CreateStateMachine"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.CRITICAL,
        target="Admin via Step Functions state machine with privileged role",
    ),
    # Category 8: Compute Hijack (NEW category, 5 methods)
    # Exploit existing compute that already has a privileged role attached.
    # No PassRole required - the role is already on the target instance/service.
    "SSM:SendCommand": _MethodDef(
        actions=["ssm:SendCommand"],
        category=EscalationCategory.COMPUTE_HIJACK,
        severity=Severity.HIGH,
        target="Execute arbitrary commands on managed EC2 with its instance role",
    ),
    "SSM:StartSession": _MethodDef(
        actions=["ssm:StartSession"],
        category=EscalationCategory.COMPUTE_HIJACK,
        severity=Severity.HIGH,
        target="Interactive shell on managed EC2 inheriting its instance role",
    ),
    "EC2InstanceConnect:SendSSHPublicKey": _MethodDef(
        actions=["ec2-instance-connect:SendSSHPublicKey"],
        category=EscalationCategory.COMPUTE_HIJACK,
        severity=Severity.HIGH,
        target="Push SSH key to EC2 and login with its instance role",
    ),
    "CodeBuild:UpdateProject": _MethodDef(
        actions=["codebuild:UpdateProject", "codebuild:StartBuild"],
        category=EscalationCategory.COMPUTE_HIJACK,
        severity=Severity.CRITICAL,
        target="Hijack existing CodeBuild project to run arbitrary code with its role",
    ),
    "AppRunner:UpdateService": _MethodDef(
        actions=["apprunner:UpdateService"],
        category=EscalationCategory.COMPUTE_HIJACK,
        severity=Severity.HIGH,
        target="Replace running AppRunner service image, retain privileged role",
    ),
    # Category 2 extension: Credential Access via Parameter Store (1 method)
    "SSM:GetParameter": _MethodDef(
        actions=["ssm:GetParameter"],
        category=EscalationCategory.CREDENTIAL_ACCESS,
        severity=Severity.HIGH,
        target="Read secrets stored in SSM Parameter Store (DB creds, API keys)",
    ),
    # ---------------------------------------------------------------------
    # Tier 2 extensions (post-benchmark): +3 methods, total 60
    # Coverage parity with Bishop Fox IAM Vulnerable extra paths
    # ---------------------------------------------------------------------
    "Glue:UpdateDevEndpoint": _MethodDef(
        actions=["glue:UpdateDevEndpoint"],
        category=EscalationCategory.COMPUTE_HIJACK,
        severity=Severity.HIGH,
        target="Hijack existing Glue dev endpoint to run code with its role",
    ),
    "SageMaker:CreatePresignedNotebookUrl": _MethodDef(
        actions=["sagemaker:CreatePresignedNotebookInstanceUrl"],
        category=EscalationCategory.COMPUTE_HIJACK,
        severity=Severity.HIGH,
        target="Generate presigned URL for existing SageMaker notebook, gain access with its role",
    ),
    "PassRole+SageMaker:CreateTrainingJob": _MethodDef(
        actions=["iam:PassRole", "sagemaker:CreateTrainingJob"],
        category=EscalationCategory.PASSROLE_SERVICE,
        severity=Severity.HIGH,
        target="Code execution via SageMaker training job with privileged role",
    ),
}

# ---------------------------------------------------------------------------
# IAM Data Collection
# ---------------------------------------------------------------------------


def get_authorization_details(provider: AWSProvider) -> dict[str, Any]:
    """Fetch all IAM data via single paginated GetAccountAuthorizationDetails call."""
    iam = provider.client("iam")
    paginator = iam.get_paginator("get_account_authorization_details")

    result: dict[str, list[Any]] = {
        "UserDetailList": [],
        "RoleDetailList": [],
        "GroupDetailList": [],
        "Policies": [],
    }

    for page in paginator.paginate(Filter=["User", "Role", "Group", "LocalManagedPolicy", "AWSManagedPolicy"]):
        for key in result:
            result[key].extend(page.get(key, []))

    return result


# ---------------------------------------------------------------------------
# Policy Resolution
# ---------------------------------------------------------------------------
@dataclass
class ResolvedPrincipal:
    """Effective permissions for a single IAM principal."""

    arn: str
    name: str
    principal_type: str  # "User" or "Role"
    allowed_actions: set[str] = field(default_factory=set)
    denied_actions: set[str] = field(default_factory=set)


def _action_matches(pattern: str, action: str) -> bool:
    """Check if an IAM action pattern matches a specific action (case-insensitive)."""
    return fnmatch.fnmatch(action.lower(), pattern.lower())


def _has_action(principal: ResolvedPrincipal, action: str) -> bool:
    """Check if principal has an action (considering wildcards) and it's not denied."""
    # Check explicit deny first
    for denied in principal.denied_actions:
        if _action_matches(denied, action):
            return False
    # Check allow
    return any(_action_matches(allowed, action) for allowed in principal.allowed_actions)


def _extract_actions_from_policy(policy_doc: dict[str, Any] | str) -> tuple[set[str], set[str]]:
    """Extract allowed and denied actions from a policy document.

    Returns (allowed_actions, denied_actions).
    """
    doc: dict[str, Any] = json.loads(policy_doc) if isinstance(policy_doc, str) else policy_doc

    allowed: set[str] = set()
    denied: set[str] = set()

    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        effect = stmt.get("Effect", "")
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        # Skip NotAction for MVP
        if "NotAction" in stmt:
            continue

        target_set = allowed if effect == "Allow" else denied if effect == "Deny" else None
        if target_set is not None:
            target_set.update(actions)

    return allowed, denied


def _resolve_managed_policy(policy_arn: str, policies_map: dict[str, Any]) -> tuple[set[str], set[str]]:
    """Resolve actions from a managed policy by ARN."""
    policy = policies_map.get(policy_arn)
    if not policy:
        return set(), set()

    for version in policy.get("PolicyVersionList", []):
        if version.get("IsDefaultVersion"):
            doc = version.get("Document", {})
            return _extract_actions_from_policy(doc)

    return set(), set()


def resolve_principals(auth_details: dict[str, Any]) -> list[ResolvedPrincipal]:
    """Resolve effective permissions for each user and role."""
    # Build managed policies lookup
    policies_map: dict[str, Any] = {}
    for policy in auth_details.get("Policies", []):
        policies_map[policy["Arn"]] = policy

    # Build group->actions lookup for user group membership resolution
    group_actions: dict[str, tuple[set[str], set[str]]] = {}
    for group in auth_details.get("GroupDetailList", []):
        g_allowed: set[str] = set()
        g_denied: set[str] = set()
        for inline in group.get("GroupPolicyList", []):
            a, d = _extract_actions_from_policy(inline.get("PolicyDocument", {}))
            g_allowed.update(a)
            g_denied.update(d)
        for attached in group.get("AttachedManagedPolicies", []):
            a, d = _resolve_managed_policy(attached["PolicyArn"], policies_map)
            g_allowed.update(a)
            g_denied.update(d)
        group_actions[group["GroupName"]] = (g_allowed, g_denied)

    principals: list[ResolvedPrincipal] = []

    # Resolve users
    for user in auth_details.get("UserDetailList", []):
        p = ResolvedPrincipal(
            arn=user["Arn"],
            name=user["UserName"],
            principal_type="User",
        )
        # Inline policies
        for inline in user.get("UserPolicyList", []):
            a, d = _extract_actions_from_policy(inline.get("PolicyDocument", {}))
            p.allowed_actions.update(a)
            p.denied_actions.update(d)
        # Managed policies
        for attached in user.get("AttachedManagedPolicies", []):
            a, d = _resolve_managed_policy(attached["PolicyArn"], policies_map)
            p.allowed_actions.update(a)
            p.denied_actions.update(d)
        # Group memberships
        for group_name in user.get("GroupList", []):
            g_a, g_d = group_actions.get(group_name, (set(), set()))
            p.allowed_actions.update(g_a)
            p.denied_actions.update(g_d)

        principals.append(p)

    # Resolve roles (skip service-linked roles and AWS service roles)
    for role in auth_details.get("RoleDetailList", []):
        role_name = role["RoleName"]
        role_path = role.get("Path", "")
        # Skip service-linked roles (managed by AWS, SCP-exempt)
        if "/aws-service-role/" in role_path:
            continue
        # Skip AWS service roles that start with AWS prefix
        if role_name.startswith("AWS") and "/service-role/" in role_path:
            continue

        p = ResolvedPrincipal(
            arn=role["Arn"],
            name=role_name,
            principal_type="Role",
        )
        for inline in role.get("RolePolicyList", []):
            a, d = _extract_actions_from_policy(inline.get("PolicyDocument", {}))
            p.allowed_actions.update(a)
            p.denied_actions.update(d)
        for attached in role.get("AttachedManagedPolicies", []):
            a, d = _resolve_managed_policy(attached["PolicyArn"], policies_map)
            p.allowed_actions.update(a)
            p.denied_actions.update(d)

        principals.append(p)

    return principals


# ---------------------------------------------------------------------------
# Escalation Path Detection
# ---------------------------------------------------------------------------


def _is_already_admin(principal: ResolvedPrincipal) -> bool:
    """Check if principal already has admin (detecting escalation is meaningless)."""
    for action in principal.allowed_actions:
        if (action == "*" or action == "*:*") and not any(_action_matches(d, "*") for d in principal.denied_actions):
            return True
    return False


def detect_escalation_paths(principals: list[ResolvedPrincipal]) -> list[EscalationPath]:
    """Check each principal against all escalation methods.

    Skips principals that already have admin access.
    """
    paths: list[EscalationPath] = []

    for principal in principals:
        if _is_already_admin(principal):
            continue

        for method_name, method_def in ESCALATION_METHODS.items():
            if all(_has_action(principal, action) for action in method_def.actions):
                paths.append(
                    EscalationPath(
                        principal_arn=principal.arn,
                        principal_name=principal.name,
                        principal_type=principal.principal_type,
                        method=method_name,
                        category=method_def.category,
                        required_actions=method_def.actions,
                        target_privilege=method_def.target,
                        severity=method_def.severity,
                    )
                )

    return paths


# ---------------------------------------------------------------------------
# Main entry point (called from check function, populates cache)
# ---------------------------------------------------------------------------


def analyze_escalation(provider: AWSProvider) -> list[EscalationPath]:
    """Run the full escalation analysis pipeline. Caches result for correlation engine.

    Two-stage detection:
    1. Action-based escalation via ESCALATION_METHODS catalog (57 methods)
    2. Lateral movement via AssumeRole trust graph (4 methods)
    """
    global _escalation_cache

    from cloud_audit.providers.aws.iam_trust_graph import (
        build_assume_role_graph,
        find_lateral_escalations,
    )

    auth_details = get_authorization_details(provider)
    principals = resolve_principals(auth_details)
    paths = detect_escalation_paths(principals)

    # Tier 3: lateral escalation via trust policy graph
    graph = build_assume_role_graph(auth_details)
    paths.extend(find_lateral_escalations(graph, principals))

    with _escalation_lock:
        _escalation_cache = paths

    return paths
