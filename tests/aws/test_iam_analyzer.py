"""Tests for IAM Privilege Escalation Analyzer."""

from __future__ import annotations

from cloud_audit.models import EscalationCategory, Severity
from cloud_audit.providers.aws.iam_analyzer import (
    ESCALATION_METHODS,
    ResolvedPrincipal,
    _action_matches,
    _extract_actions_from_policy,
    _has_action,
    _is_already_admin,
    detect_escalation_paths,
    resolve_principals,
)


# ---------------------------------------------------------------------------
# Action matching tests
# ---------------------------------------------------------------------------
class TestActionMatches:
    def test_exact_match(self) -> None:
        assert _action_matches("iam:CreatePolicyVersion", "iam:CreatePolicyVersion")

    def test_case_insensitive(self) -> None:
        assert _action_matches("IAM:CreatePolicyVersion", "iam:createpolicyversion")

    def test_service_wildcard(self) -> None:
        assert _action_matches("iam:*", "iam:CreatePolicyVersion")

    def test_full_wildcard(self) -> None:
        assert _action_matches("*", "iam:CreatePolicyVersion")

    def test_prefix_wildcard(self) -> None:
        assert _action_matches("s3:Get*", "s3:GetObject")
        assert not _action_matches("s3:Get*", "s3:PutObject")

    def test_no_match(self) -> None:
        assert not _action_matches("ec2:*", "iam:CreatePolicyVersion")

    def test_star_colon_star(self) -> None:
        assert _action_matches("*:*", "iam:CreatePolicyVersion")


# ---------------------------------------------------------------------------
# Policy extraction tests
# ---------------------------------------------------------------------------
class TestExtractActions:
    def test_simple_allow(self) -> None:
        doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}],
        }
        allowed, denied = _extract_actions_from_policy(doc)
        assert "iam:CreatePolicyVersion" in allowed
        assert len(denied) == 0

    def test_deny_actions(self) -> None:
        doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": ["iam:*"], "Resource": "*"}],
        }
        allowed, denied = _extract_actions_from_policy(doc)
        assert "iam:*" in denied
        assert len(allowed) == 0

    def test_multiple_statements(self) -> None:
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "*"},
                {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
            ],
        }
        allowed, denied = _extract_actions_from_policy(doc)
        assert "s3:GetObject" in allowed
        assert "s3:PutObject" in allowed
        assert "s3:DeleteObject" in denied

    def test_string_policy_doc(self) -> None:
        import json

        doc = json.dumps({"Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}]})
        allowed, _ = _extract_actions_from_policy(doc)
        assert "ec2:*" in allowed

    def test_not_action_skipped(self) -> None:
        doc = {"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]}
        allowed, _denied = _extract_actions_from_policy(doc)
        assert len(allowed) == 0

    def test_single_statement_not_list(self) -> None:
        doc = {"Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}}
        allowed, _ = _extract_actions_from_policy(doc)
        assert "s3:*" in allowed


# ---------------------------------------------------------------------------
# Has-action with deny tests
# ---------------------------------------------------------------------------
class TestHasAction:
    def test_allowed_action(self) -> None:
        p = ResolvedPrincipal(arn="arn:test", name="test", principal_type="User")
        p.allowed_actions = {"iam:CreatePolicyVersion"}
        assert _has_action(p, "iam:CreatePolicyVersion")

    def test_denied_overrides_allow(self) -> None:
        p = ResolvedPrincipal(arn="arn:test", name="test", principal_type="User")
        p.allowed_actions = {"iam:*"}
        p.denied_actions = {"iam:CreatePolicyVersion"}
        assert not _has_action(p, "iam:CreatePolicyVersion")

    def test_wildcard_allow(self) -> None:
        p = ResolvedPrincipal(arn="arn:test", name="test", principal_type="User")
        p.allowed_actions = {"iam:*"}
        assert _has_action(p, "iam:CreatePolicyVersion")

    def test_wildcard_deny(self) -> None:
        p = ResolvedPrincipal(arn="arn:test", name="test", principal_type="User")
        p.allowed_actions = {"*"}
        p.denied_actions = {"iam:*"}
        assert not _has_action(p, "iam:CreatePolicyVersion")


# ---------------------------------------------------------------------------
# Is-already-admin tests
# ---------------------------------------------------------------------------
class TestIsAlreadyAdmin:
    def test_admin_with_star(self) -> None:
        p = ResolvedPrincipal(arn="arn:test", name="test", principal_type="User")
        p.allowed_actions = {"*"}
        assert _is_already_admin(p)

    def test_admin_with_star_colon_star(self) -> None:
        p = ResolvedPrincipal(arn="arn:test", name="test", principal_type="User")
        p.allowed_actions = {"*:*"}
        assert _is_already_admin(p)

    def test_not_admin(self) -> None:
        p = ResolvedPrincipal(arn="arn:test", name="test", principal_type="User")
        p.allowed_actions = {"s3:*", "ec2:*"}
        assert not _is_already_admin(p)

    def test_admin_denied(self) -> None:
        p = ResolvedPrincipal(arn="arn:test", name="test", principal_type="User")
        p.allowed_actions = {"*"}
        p.denied_actions = {"*"}
        assert not _is_already_admin(p)


# ---------------------------------------------------------------------------
# Escalation detection tests
# ---------------------------------------------------------------------------
class TestDetectEscalation:
    def test_create_policy_version(self) -> None:
        p = ResolvedPrincipal(
            arn="arn:aws:iam::123:user/attacker",
            name="attacker",
            principal_type="User",
        )
        p.allowed_actions = {"iam:CreatePolicyVersion"}
        paths = detect_escalation_paths([p])
        assert any(ep.method == "CreatePolicyVersion" for ep in paths)
        assert paths[0].severity == Severity.CRITICAL
        assert paths[0].category == EscalationCategory.IAM_SELF_MUTATION

    def test_passrole_lambda(self) -> None:
        p = ResolvedPrincipal(
            arn="arn:aws:iam::123:user/ci-bot",
            name="ci-bot",
            principal_type="User",
        )
        p.allowed_actions = {"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"}
        paths = detect_escalation_paths([p])
        assert any(ep.method == "PassRole+Lambda" for ep in paths)

    def test_passrole_ec2(self) -> None:
        p = ResolvedPrincipal(arn="arn:test", name="test", principal_type="User")
        p.allowed_actions = {"iam:PassRole", "ec2:RunInstances"}
        paths = detect_escalation_paths([p])
        assert any(ep.method == "PassRole+EC2" for ep in paths)

    def test_update_function_code(self) -> None:
        p = ResolvedPrincipal(arn="arn:test", name="test", principal_type="User")
        p.allowed_actions = {"lambda:UpdateFunctionCode"}
        paths = detect_escalation_paths([p])
        assert any(ep.method == "UpdateFunctionCode" for ep in paths)

    def test_delete_permission_boundary(self) -> None:
        p = ResolvedPrincipal(arn="arn:test", name="test", principal_type="User")
        p.allowed_actions = {"iam:DeleteRolePermissionsBoundary"}
        paths = detect_escalation_paths([p])
        assert any(ep.method == "DeleteRolePermissionsBoundary" for ep in paths)

    def test_admin_user_skipped(self) -> None:
        """Admins should not be flagged for escalation — they're already admin."""
        p = ResolvedPrincipal(arn="arn:test", name="admin", principal_type="User")
        p.allowed_actions = {"*"}
        paths = detect_escalation_paths([p])
        assert len(paths) == 0

    def test_no_escalation_clean_user(self) -> None:
        p = ResolvedPrincipal(arn="arn:test", name="readonly", principal_type="User")
        p.allowed_actions = {"s3:GetObject", "s3:ListBucket"}
        paths = detect_escalation_paths([p])
        assert len(paths) == 0

    def test_multiple_methods_same_user(self) -> None:
        """A user with multiple dangerous permissions gets multiple paths."""
        p = ResolvedPrincipal(arn="arn:test", name="dangerous", principal_type="User")
        p.allowed_actions = {
            "iam:CreatePolicyVersion",
            "iam:AttachUserPolicy",
            "iam:PassRole",
            "lambda:CreateFunction",
            "lambda:InvokeFunction",
        }
        paths = detect_escalation_paths([p])
        methods = {ep.method for ep in paths}
        assert "CreatePolicyVersion" in methods
        assert "AttachUserPolicy" in methods
        assert "PassRole+Lambda" in methods
        assert len(paths) >= 3

    def test_wildcard_permissions_match_methods(self) -> None:
        """iam:* should match all IAM escalation methods."""
        p = ResolvedPrincipal(arn="arn:test", name="dev", principal_type="User")
        p.allowed_actions = {"iam:*", "sts:AssumeRole"}
        # Should not be admin (iam:* != *), but should match IAM methods
        paths = detect_escalation_paths([p])
        assert len(paths) > 5  # Many IAM-based methods should match

    def test_role_type_preserved(self) -> None:
        p = ResolvedPrincipal(
            arn="arn:aws:iam::123:role/ci-role",
            name="ci-role",
            principal_type="Role",
        )
        p.allowed_actions = {"iam:CreatePolicyVersion"}
        paths = detect_escalation_paths([p])
        assert paths[0].principal_type == "Role"


# ---------------------------------------------------------------------------
# Principal resolution tests
# ---------------------------------------------------------------------------
class TestResolvePrincipals:
    def test_user_with_inline_policy(self) -> None:
        auth = {
            "UserDetailList": [
                {
                    "Arn": "arn:aws:iam::123:user/dev",
                    "UserName": "dev",
                    "GroupList": [],
                    "UserPolicyList": [
                        {
                            "PolicyName": "inline",
                            "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
                        }
                    ],
                    "AttachedManagedPolicies": [],
                }
            ],
            "RoleDetailList": [],
            "GroupDetailList": [],
            "Policies": [],
        }
        principals = resolve_principals(auth)
        assert len(principals) == 1
        assert "s3:*" in principals[0].allowed_actions

    def test_user_inherits_group_permissions(self) -> None:
        auth = {
            "UserDetailList": [
                {
                    "Arn": "arn:aws:iam::123:user/dev",
                    "UserName": "dev",
                    "GroupList": ["developers"],
                    "UserPolicyList": [],
                    "AttachedManagedPolicies": [],
                }
            ],
            "RoleDetailList": [],
            "GroupDetailList": [
                {
                    "GroupName": "developers",
                    "GroupPolicyList": [
                        {
                            "PolicyName": "group-inline",
                            "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}]},
                        }
                    ],
                    "AttachedManagedPolicies": [],
                }
            ],
            "Policies": [],
        }
        principals = resolve_principals(auth)
        assert len(principals) == 1
        assert "ec2:*" in principals[0].allowed_actions

    def test_service_linked_role_skipped(self) -> None:
        auth = {
            "UserDetailList": [],
            "RoleDetailList": [
                {
                    "Arn": "arn:aws:iam::123:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
                    "RoleName": "AWSServiceRoleForConfig",
                    "Path": "/aws-service-role/config.amazonaws.com/",
                    "RolePolicyList": [],
                    "AttachedManagedPolicies": [],
                }
            ],
            "GroupDetailList": [],
            "Policies": [],
        }
        principals = resolve_principals(auth)
        assert len(principals) == 0

    def test_managed_policy_resolved(self) -> None:
        auth = {
            "UserDetailList": [
                {
                    "Arn": "arn:aws:iam::123:user/dev",
                    "UserName": "dev",
                    "GroupList": [],
                    "UserPolicyList": [],
                    "AttachedManagedPolicies": [
                        {"PolicyArn": "arn:aws:iam::123:policy/custom", "PolicyName": "custom"}
                    ],
                }
            ],
            "RoleDetailList": [],
            "GroupDetailList": [],
            "Policies": [
                {
                    "Arn": "arn:aws:iam::123:policy/custom",
                    "PolicyVersionList": [
                        {
                            "VersionId": "v1",
                            "IsDefaultVersion": True,
                            "Document": {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]},
                        }
                    ],
                }
            ],
        }
        principals = resolve_principals(auth)
        assert len(principals) == 1
        assert "iam:PassRole" in principals[0].allowed_actions


# ---------------------------------------------------------------------------
# Tier 1 additions (v2.1.0): 20 new escalation methods
# ---------------------------------------------------------------------------
def _principal(allowed: set[str], denied: set[str] | None = None) -> ResolvedPrincipal:
    """Helper: build a non-admin principal with given allow/deny actions."""
    p = ResolvedPrincipal(arn="arn:aws:iam::123:user/test", name="test", principal_type="User")
    p.allowed_actions = set(allowed)
    p.denied_actions = set(denied or set())
    return p


def _has_method(paths: list, method: str) -> bool:
    return any(ep.method == method for ep in paths)


class TestTier1MethodCount:
    """Regression guard for the size of the escalation method catalog."""

    def test_total_method_count(self) -> None:
        # 25 (v2.0) + 20 (Tier 1) + 12 (Tier 2) + 3 (post-benchmark) = 60
        assert len(ESCALATION_METHODS) == 60

    def test_resource_policy_abuse_category_exists(self) -> None:
        assert EscalationCategory.RESOURCE_POLICY_ABUSE.value == "resource_policy_abuse"

    def test_compute_hijack_category_exists(self) -> None:
        assert EscalationCategory.COMPUTE_HIJACK.value == "compute_hijack"

    def test_each_method_has_required_fields(self) -> None:
        for name, method in ESCALATION_METHODS.items():
            assert method.actions, f"{name}: actions empty"
            assert method.target, f"{name}: target empty"
            assert isinstance(method.severity, Severity), f"{name}: bad severity"
            assert isinstance(method.category, EscalationCategory), f"{name}: bad category"


class TestTier1PassRoleGlue:
    """Glue PassRole variants beyond the legacy CreateDevEndpoint check."""

    def test_create_job(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:PassRole", "glue:CreateJob"})])
        assert _has_method(paths, "PassRole+Glue:CreateJob")

    def test_update_job(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:PassRole", "glue:UpdateJob"})])
        assert _has_method(paths, "PassRole+Glue:UpdateJob")

    def test_create_session(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:PassRole", "glue:CreateSession"})])
        assert _has_method(paths, "PassRole+Glue:CreateSession")

    def test_create_job_missing_passrole(self) -> None:
        paths = detect_escalation_paths([_principal({"glue:CreateJob"})])
        assert not _has_method(paths, "PassRole+Glue:CreateJob")

    def test_create_job_missing_glue_action(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:PassRole"})])
        assert not _has_method(paths, "PassRole+Glue:CreateJob")

    def test_severity_high(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:PassRole", "glue:CreateJob"})])
        match = [ep for ep in paths if ep.method == "PassRole+Glue:CreateJob"]
        assert match and match[0].severity == Severity.HIGH
        assert match[0].category == EscalationCategory.PASSROLE_SERVICE


class TestTier1PassRoleECS:
    def test_update_service_requires_all_actions(self) -> None:
        # UpdateService requires PassRole + UpdateService + RegisterTaskDefinition
        paths = detect_escalation_paths(
            [_principal({"iam:PassRole", "ecs:UpdateService", "ecs:RegisterTaskDefinition"})]
        )
        assert _has_method(paths, "PassRole+ECS:UpdateService")
        match = [ep for ep in paths if ep.method == "PassRole+ECS:UpdateService"]
        assert match[0].severity == Severity.CRITICAL

    def test_update_service_missing_register(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:PassRole", "ecs:UpdateService"})])
        assert not _has_method(paths, "PassRole+ECS:UpdateService")

    def test_register_task_only(self) -> None:
        # RegisterTaskDefinition alone (without UpdateService/RunTask) is a HIGH path
        # because some services auto-deploy new task definition revisions.
        paths = detect_escalation_paths([_principal({"iam:PassRole", "ecs:RegisterTaskDefinition"})])
        assert _has_method(paths, "PassRole+ECS:RegisterTaskDefinition")
        match = [ep for ep in paths if ep.method == "PassRole+ECS:RegisterTaskDefinition"]
        assert match[0].severity == Severity.HIGH

    def test_legacy_passrole_ecs_still_detected(self) -> None:
        """The original PassRole+ECS (with RunTask) must keep firing for compatibility."""
        paths = detect_escalation_paths([_principal({"iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask"})])
        assert _has_method(paths, "PassRole+ECS")  # legacy method still in dict


class TestTier1PassRoleCloudFormation:
    def test_update_stack(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:PassRole", "cloudformation:UpdateStack"})])
        assert _has_method(paths, "PassRole+CloudFormation:UpdateStack")
        match = [ep for ep in paths if ep.method == "PassRole+CloudFormation:UpdateStack"]
        assert match[0].severity == Severity.CRITICAL

    def test_update_stack_missing_passrole(self) -> None:
        paths = detect_escalation_paths([_principal({"cloudformation:UpdateStack"})])
        assert not _has_method(paths, "PassRole+CloudFormation:UpdateStack")


class TestTier1InstanceProfileHijack:
    def test_associate_instance_profile(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:PassRole", "ec2:AssociateIamInstanceProfile"})])
        assert _has_method(paths, "PassRole+EC2:AssociateInstanceProfile")
        match = [ep for ep in paths if ep.method == "PassRole+EC2:AssociateInstanceProfile"]
        assert match[0].severity == Severity.CRITICAL

    def test_replace_instance_profile_association(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:PassRole", "ec2:ReplaceIamInstanceProfileAssociation"})])
        assert _has_method(paths, "PassRole+EC2:ReplaceInstanceProfileAssociation")

    def test_role_swap_via_instance_profile(self) -> None:
        # No PassRole needed — swap role on existing instance profile
        paths = detect_escalation_paths(
            [_principal({"iam:RemoveRoleFromInstanceProfile", "iam:AddRoleToInstanceProfile"})]
        )
        assert _has_method(paths, "InstanceProfileRoleSwap")
        match = [ep for ep in paths if ep.method == "InstanceProfileRoleSwap"]
        assert match[0].severity == Severity.HIGH

    def test_role_swap_missing_remove(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:AddRoleToInstanceProfile"})])
        assert not _has_method(paths, "InstanceProfileRoleSwap")


class TestTier1LambdaEventSource:
    def test_create_event_source_mapping(self) -> None:
        paths = detect_escalation_paths(
            [_principal({"iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"})]
        )
        assert _has_method(paths, "PassRole+Lambda:CreateEventSourceMapping")

    def test_event_source_missing_create_function(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:PassRole", "lambda:CreateEventSourceMapping"})])
        assert not _has_method(paths, "PassRole+Lambda:CreateEventSourceMapping")


class TestTier1ResourcePolicyAbuse:
    """New RESOURCE_POLICY_ABUSE category."""

    def test_lambda_add_permission(self) -> None:
        paths = detect_escalation_paths([_principal({"lambda:AddPermission"})])
        assert _has_method(paths, "Lambda:AddPermission")
        match = [ep for ep in paths if ep.method == "Lambda:AddPermission"]
        assert match[0].category == EscalationCategory.RESOURCE_POLICY_ABUSE
        assert match[0].severity == Severity.HIGH

    def test_lambda_add_layer_version_permission(self) -> None:
        paths = detect_escalation_paths([_principal({"lambda:AddLayerVersionPermission"})])
        assert _has_method(paths, "Lambda:AddLayerVersionPermission")
        match = [ep for ep in paths if ep.method == "Lambda:AddLayerVersionPermission"]
        assert match[0].category == EscalationCategory.RESOURCE_POLICY_ABUSE

    def test_clean_user_no_resource_policy_abuse(self) -> None:
        paths = detect_escalation_paths([_principal({"s3:GetObject"})])
        assert not any(ep.category == EscalationCategory.RESOURCE_POLICY_ABUSE for ep in paths)


class TestTier1IamSelfMutationExtensions:
    def test_delete_role_policy(self) -> None:
        # DeleteRolePolicy alone is not enough — needs sts:AssumeRole to use the
        # role after the deny is removed.
        paths = detect_escalation_paths([_principal({"iam:DeleteRolePolicy", "sts:AssumeRole"})])
        assert _has_method(paths, "DeleteRolePolicy")

    def test_delete_role_policy_without_assume(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:DeleteRolePolicy"})])
        assert not _has_method(paths, "DeleteRolePolicy")

    def test_delete_user_policy(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:DeleteUserPolicy"})])
        assert _has_method(paths, "DeleteUserPolicy")
        match = [ep for ep in paths if ep.method == "DeleteUserPolicy"]
        assert match[0].category == EscalationCategory.IAM_SELF_MUTATION

    def test_detach_role_policy(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:DetachRolePolicy", "sts:AssumeRole"})])
        assert _has_method(paths, "DetachRolePolicy")

    def test_detach_user_policy(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:DetachUserPolicy"})])
        assert _has_method(paths, "DetachUserPolicy")

    def test_create_service_linked_role(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:CreateServiceLinkedRole"})])
        assert _has_method(paths, "CreateServiceLinkedRole")

    def test_deny_blocks_new_iam_methods(self) -> None:
        # Wildcard allow with explicit deny on the specific action must NOT match
        paths = detect_escalation_paths(
            [
                _principal(
                    allowed={"iam:*", "sts:AssumeRole"},
                    denied={"iam:DeleteRolePolicy", "iam:DeleteUserPolicy"},
                )
            ]
        )
        assert not _has_method(paths, "DeleteRolePolicy")
        assert not _has_method(paths, "DeleteUserPolicy")
        # But other iam:* methods still fire
        assert _has_method(paths, "CreatePolicyVersion")


class TestTier1CredentialAccessExtensions:
    def test_update_access_key(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:UpdateAccessKey"})])
        assert _has_method(paths, "UpdateAccessKey")
        match = [ep for ep in paths if ep.method == "UpdateAccessKey"]
        assert match[0].category == EscalationCategory.CREDENTIAL_ACCESS

    def test_deactivate_mfa(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:DeactivateMFADevice"})])
        assert _has_method(paths, "DeactivateMFADevice")

    def test_delete_virtual_mfa(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:DeleteVirtualMFADevice"})])
        assert _has_method(paths, "DeleteVirtualMFADevice")


class TestTier1Integration:
    def test_admin_user_still_skipped(self) -> None:
        """Admin must not be flagged for any new method either."""
        p = _principal({"*"})
        paths = detect_escalation_paths([p])
        assert paths == []

    def test_dangerous_devops_user_gets_many_paths(self) -> None:
        """Realistic DevOps user with broad but not admin permissions — many Tier 1 hits."""
        p = _principal(
            {
                "iam:PassRole",
                "ec2:AssociateIamInstanceProfile",
                "ecs:UpdateService",
                "ecs:RegisterTaskDefinition",
                "cloudformation:UpdateStack",
                "lambda:AddPermission",
                "iam:UpdateAccessKey",
            }
        )
        paths = detect_escalation_paths([p])
        methods = {ep.method for ep in paths}
        assert "PassRole+EC2:AssociateInstanceProfile" in methods
        assert "PassRole+ECS:UpdateService" in methods
        assert "PassRole+CloudFormation:UpdateStack" in methods
        assert "Lambda:AddPermission" in methods
        assert "UpdateAccessKey" in methods

    def test_wildcard_iam_matches_new_methods(self) -> None:
        """iam:* should match all new IAM-based Tier 1 methods (deny-removal + credential)."""
        p = _principal({"iam:*", "sts:AssumeRole"})
        paths = detect_escalation_paths([p])
        methods = {ep.method for ep in paths}
        # Tier 1 IAM_SELF_MUTATION extensions
        assert "DeleteRolePolicy" in methods
        assert "DeleteUserPolicy" in methods
        assert "DetachRolePolicy" in methods
        assert "DetachUserPolicy" in methods
        assert "CreateServiceLinkedRole" in methods
        # Tier 1 CREDENTIAL_ACCESS extensions
        assert "UpdateAccessKey" in methods
        assert "DeactivateMFADevice" in methods
        assert "DeleteVirtualMFADevice" in methods
        # InstanceProfileRoleSwap requires both Add+Remove on profile (also iam:*)
        assert "InstanceProfileRoleSwap" in methods

    def test_resource_policy_abuse_independent_of_iam_wildcard(self) -> None:
        """Lambda resource-policy abuse is NOT iam:*, must require lambda permissions."""
        p = _principal({"iam:*", "sts:AssumeRole"})
        paths = detect_escalation_paths([p])
        methods = {ep.method for ep in paths}
        assert "Lambda:AddPermission" not in methods
        assert "Lambda:AddLayerVersionPermission" not in methods

    def test_principal_type_role_for_tier1(self) -> None:
        p = ResolvedPrincipal(
            arn="arn:aws:iam::123:role/ci-role",
            name="ci-role",
            principal_type="Role",
        )
        p.allowed_actions = {"iam:PassRole", "glue:CreateJob"}
        paths = detect_escalation_paths([p])
        match = [ep for ep in paths if ep.method == "PassRole+Glue:CreateJob"]
        assert match
        assert match[0].principal_type == "Role"

    def test_required_actions_preserved_in_path(self) -> None:
        """EscalationPath must echo the actions used to detect it (consumed by remediation)."""
        p = _principal({"iam:PassRole", "ec2:AssociateIamInstanceProfile"})
        paths = detect_escalation_paths([p])
        match = [ep for ep in paths if ep.method == "PassRole+EC2:AssociateInstanceProfile"]
        assert match
        assert "iam:PassRole" in match[0].required_actions
        assert "ec2:AssociateIamInstanceProfile" in match[0].required_actions


# ---------------------------------------------------------------------------
# Tier 2 additions (v2.1.0): 12 new methods covering new compute primitives
# ---------------------------------------------------------------------------
class TestTier2PassRoleCodeBuild:
    def test_create_project(self) -> None:
        paths = detect_escalation_paths(
            [_principal({"iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"})]
        )
        assert _has_method(paths, "PassRole+CodeBuild:CreateProject")
        match = [ep for ep in paths if ep.method == "PassRole+CodeBuild:CreateProject"]
        assert match[0].severity == Severity.CRITICAL
        assert match[0].category == EscalationCategory.PASSROLE_SERVICE

    def test_create_project_missing_start_build(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:PassRole", "codebuild:CreateProject"})])
        assert not _has_method(paths, "PassRole+CodeBuild:CreateProject")

    def test_create_project_missing_passrole(self) -> None:
        paths = detect_escalation_paths([_principal({"codebuild:CreateProject", "codebuild:StartBuild"})])
        assert not _has_method(paths, "PassRole+CodeBuild:CreateProject")


class TestTier2PassRoleAppRunner:
    def test_create_service(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:PassRole", "apprunner:CreateService"})])
        assert _has_method(paths, "PassRole+AppRunner:CreateService")
        match = [ep for ep in paths if ep.method == "PassRole+AppRunner:CreateService"]
        assert match[0].severity == Severity.CRITICAL

    def test_create_service_missing_passrole(self) -> None:
        paths = detect_escalation_paths([_principal({"apprunner:CreateService"})])
        assert not _has_method(paths, "PassRole+AppRunner:CreateService")


class TestTier2PassRoleSageMaker:
    def test_create_notebook_instance(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:PassRole", "sagemaker:CreateNotebookInstance"})])
        assert _has_method(paths, "PassRole+SageMaker:CreateNotebookInstance")
        match = [ep for ep in paths if ep.method == "PassRole+SageMaker:CreateNotebookInstance"]
        assert match[0].severity == Severity.CRITICAL

    def test_create_processing_job(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:PassRole", "sagemaker:CreateProcessingJob"})])
        assert _has_method(paths, "PassRole+SageMaker:CreateProcessingJob")
        match = [ep for ep in paths if ep.method == "PassRole+SageMaker:CreateProcessingJob"]
        assert match[0].severity == Severity.HIGH

    def test_notebook_missing_passrole(self) -> None:
        paths = detect_escalation_paths([_principal({"sagemaker:CreateNotebookInstance"})])
        assert not _has_method(paths, "PassRole+SageMaker:CreateNotebookInstance")


class TestTier2PassRoleBedrock:
    def test_create_agent(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:PassRole", "bedrock:CreateAgent"})])
        assert _has_method(paths, "PassRole+Bedrock:CreateAgent")
        match = [ep for ep in paths if ep.method == "PassRole+Bedrock:CreateAgent"]
        assert match[0].category == EscalationCategory.PASSROLE_SERVICE

    def test_create_agent_missing_passrole(self) -> None:
        paths = detect_escalation_paths([_principal({"bedrock:CreateAgent"})])
        assert not _has_method(paths, "PassRole+Bedrock:CreateAgent")


class TestTier2PassRoleStepFunctions:
    def test_create_state_machine(self) -> None:
        paths = detect_escalation_paths([_principal({"iam:PassRole", "states:CreateStateMachine"})])
        assert _has_method(paths, "PassRole+StepFunctions:CreateStateMachine")
        match = [ep for ep in paths if ep.method == "PassRole+StepFunctions:CreateStateMachine"]
        assert match[0].severity == Severity.CRITICAL

    def test_create_state_machine_missing_passrole(self) -> None:
        paths = detect_escalation_paths([_principal({"states:CreateStateMachine"})])
        assert not _has_method(paths, "PassRole+StepFunctions:CreateStateMachine")


class TestTier2ComputeHijack:
    """COMPUTE_HIJACK category: exploit existing compute with existing role."""

    def test_ssm_send_command(self) -> None:
        paths = detect_escalation_paths([_principal({"ssm:SendCommand"})])
        assert _has_method(paths, "SSM:SendCommand")
        match = [ep for ep in paths if ep.method == "SSM:SendCommand"]
        assert match[0].category == EscalationCategory.COMPUTE_HIJACK
        assert match[0].severity == Severity.HIGH

    def test_ssm_start_session(self) -> None:
        paths = detect_escalation_paths([_principal({"ssm:StartSession"})])
        assert _has_method(paths, "SSM:StartSession")
        match = [ep for ep in paths if ep.method == "SSM:StartSession"]
        assert match[0].category == EscalationCategory.COMPUTE_HIJACK

    def test_ec2_instance_connect_send_ssh_key(self) -> None:
        paths = detect_escalation_paths([_principal({"ec2-instance-connect:SendSSHPublicKey"})])
        assert _has_method(paths, "EC2InstanceConnect:SendSSHPublicKey")
        match = [ep for ep in paths if ep.method == "EC2InstanceConnect:SendSSHPublicKey"]
        assert match[0].category == EscalationCategory.COMPUTE_HIJACK

    def test_codebuild_update_project(self) -> None:
        paths = detect_escalation_paths([_principal({"codebuild:UpdateProject", "codebuild:StartBuild"})])
        assert _has_method(paths, "CodeBuild:UpdateProject")
        match = [ep for ep in paths if ep.method == "CodeBuild:UpdateProject"]
        assert match[0].severity == Severity.CRITICAL

    def test_codebuild_update_project_missing_start_build(self) -> None:
        paths = detect_escalation_paths([_principal({"codebuild:UpdateProject"})])
        assert not _has_method(paths, "CodeBuild:UpdateProject")

    def test_apprunner_update_service(self) -> None:
        paths = detect_escalation_paths([_principal({"apprunner:UpdateService"})])
        assert _has_method(paths, "AppRunner:UpdateService")
        match = [ep for ep in paths if ep.method == "AppRunner:UpdateService"]
        assert match[0].category == EscalationCategory.COMPUTE_HIJACK

    def test_compute_hijack_methods_have_correct_category(self) -> None:
        """All COMPUTE_HIJACK entries must use the new category enum value."""
        compute_hijack_methods = {
            "SSM:SendCommand",
            "SSM:StartSession",
            "EC2InstanceConnect:SendSSHPublicKey",
            "CodeBuild:UpdateProject",
            "AppRunner:UpdateService",
        }
        for name in compute_hijack_methods:
            assert ESCALATION_METHODS[name].category == EscalationCategory.COMPUTE_HIJACK, (
                f"{name} should be COMPUTE_HIJACK"
            )

    def test_clean_user_no_compute_hijack(self) -> None:
        paths = detect_escalation_paths([_principal({"s3:GetObject", "ec2:Describe*"})])
        assert not any(ep.category == EscalationCategory.COMPUTE_HIJACK for ep in paths)

    def test_deny_blocks_compute_hijack(self) -> None:
        """Wildcard ssm:* with explicit deny on SendCommand must NOT match."""
        p = _principal(allowed={"ssm:*"}, denied={"ssm:SendCommand", "ssm:StartSession"})
        paths = detect_escalation_paths([p])
        assert not _has_method(paths, "SSM:SendCommand")
        assert not _has_method(paths, "SSM:StartSession")
        # GetParameter is also in ssm:* but not denied
        assert _has_method(paths, "SSM:GetParameter")


class TestTier2CredentialAccessSSM:
    def test_get_parameter(self) -> None:
        paths = detect_escalation_paths([_principal({"ssm:GetParameter"})])
        assert _has_method(paths, "SSM:GetParameter")
        match = [ep for ep in paths if ep.method == "SSM:GetParameter"]
        assert match[0].category == EscalationCategory.CREDENTIAL_ACCESS
        assert match[0].severity == Severity.HIGH


class TestTier2Integration:
    def test_admin_user_still_skipped_after_tier2(self) -> None:
        """Admin must not be flagged for any Tier 2 method either."""
        p = _principal({"*"})
        paths = detect_escalation_paths([p])
        assert paths == []

    def test_data_engineer_realistic_account(self) -> None:
        """Data engineer with broad ML + CI permissions hits multiple Tier 2 paths."""
        p = _principal(
            {
                "iam:PassRole",
                "sagemaker:CreateNotebookInstance",
                "sagemaker:CreateProcessingJob",
                "codebuild:CreateProject",
                "codebuild:StartBuild",
                "ssm:GetParameter",
            }
        )
        paths = detect_escalation_paths([p])
        methods = {ep.method for ep in paths}
        assert "PassRole+SageMaker:CreateNotebookInstance" in methods
        assert "PassRole+SageMaker:CreateProcessingJob" in methods
        assert "PassRole+CodeBuild:CreateProject" in methods
        assert "SSM:GetParameter" in methods

    def test_ops_engineer_with_ssm_full_access(self) -> None:
        """Ops engineer with ssm:* hits 3 SSM paths (SendCommand/StartSession/GetParameter)."""
        p = _principal({"ssm:*"})
        paths = detect_escalation_paths([p])
        methods = {ep.method for ep in paths}
        assert "SSM:SendCommand" in methods
        assert "SSM:StartSession" in methods
        assert "SSM:GetParameter" in methods
        # Verify category split: 2 in COMPUTE_HIJACK, 1 in CREDENTIAL_ACCESS
        compute_hijack_paths = [ep for ep in paths if ep.category == EscalationCategory.COMPUTE_HIJACK]
        ssm_compute_methods = {ep.method for ep in compute_hijack_paths if "SSM" in ep.method}
        assert ssm_compute_methods == {"SSM:SendCommand", "SSM:StartSession"}

    def test_ec2_instance_connect_only_path(self) -> None:
        """ec2-instance-connect:SendSSHPublicKey alone is sufficient escalation."""
        p = _principal({"ec2-instance-connect:SendSSHPublicKey"})
        paths = detect_escalation_paths([p])
        methods = {ep.method for ep in paths}
        assert methods == {"EC2InstanceConnect:SendSSHPublicKey"}

    def test_resource_policy_abuse_unchanged_by_tier2(self) -> None:
        """Tier 2 must not regress Tier 1 resource policy abuse detection."""
        p = _principal({"lambda:AddPermission"})
        paths = detect_escalation_paths([p])
        assert _has_method(paths, "Lambda:AddPermission")

    def test_legacy_passrole_lambda_unchanged_by_tier2(self) -> None:
        """Legacy PassRole+Lambda must keep firing for compatibility."""
        p = _principal({"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"})
        paths = detect_escalation_paths([p])
        assert _has_method(paths, "PassRole+Lambda")

    def test_tier2_methods_count(self) -> None:
        """Verify exactly 12 Tier 2 methods present."""
        tier2_method_names = {
            "PassRole+CodeBuild:CreateProject",
            "PassRole+AppRunner:CreateService",
            "PassRole+SageMaker:CreateNotebookInstance",
            "PassRole+SageMaker:CreateProcessingJob",
            "PassRole+Bedrock:CreateAgent",
            "PassRole+StepFunctions:CreateStateMachine",
            "SSM:SendCommand",
            "SSM:StartSession",
            "EC2InstanceConnect:SendSSHPublicKey",
            "CodeBuild:UpdateProject",
            "AppRunner:UpdateService",
            "SSM:GetParameter",
        }
        assert len(tier2_method_names) == 12
        # All 12 must be in the catalog
        for name in tier2_method_names:
            assert name in ESCALATION_METHODS, f"{name} missing from ESCALATION_METHODS"

    def test_role_principal_for_tier2(self) -> None:
        """Roles can also escalate via Tier 2 methods."""
        p = ResolvedPrincipal(
            arn="arn:aws:iam::123:role/data-science-role",
            name="data-science-role",
            principal_type="Role",
        )
        p.allowed_actions = {"iam:PassRole", "sagemaker:CreateNotebookInstance"}
        paths = detect_escalation_paths([p])
        match = [ep for ep in paths if ep.method == "PassRole+SageMaker:CreateNotebookInstance"]
        assert match
        assert match[0].principal_type == "Role"


class TestPostBenchmarkAdditions:
    """Methods added after Bishop Fox IAM Vulnerable benchmark coverage gap."""

    def test_glue_update_dev_endpoint(self) -> None:
        p = _principal({"glue:UpdateDevEndpoint"})
        paths = detect_escalation_paths([p])
        assert _has_method(paths, "Glue:UpdateDevEndpoint")
        match = [ep for ep in paths if ep.method == "Glue:UpdateDevEndpoint"]
        assert match[0].category == EscalationCategory.COMPUTE_HIJACK
        assert match[0].severity == Severity.HIGH

    def test_sagemaker_create_presigned_notebook_url(self) -> None:
        p = _principal({"sagemaker:CreatePresignedNotebookInstanceUrl"})
        paths = detect_escalation_paths([p])
        assert _has_method(paths, "SageMaker:CreatePresignedNotebookUrl")
        match = [ep for ep in paths if ep.method == "SageMaker:CreatePresignedNotebookUrl"]
        assert match[0].category == EscalationCategory.COMPUTE_HIJACK

    def test_passrole_sagemaker_create_training_job(self) -> None:
        p = _principal({"iam:PassRole", "sagemaker:CreateTrainingJob"})
        paths = detect_escalation_paths([p])
        assert _has_method(paths, "PassRole+SageMaker:CreateTrainingJob")
        match = [ep for ep in paths if ep.method == "PassRole+SageMaker:CreateTrainingJob"]
        assert match[0].category == EscalationCategory.PASSROLE_SERVICE

    def test_passrole_sagemaker_training_job_missing_passrole(self) -> None:
        p = _principal({"sagemaker:CreateTrainingJob"})
        paths = detect_escalation_paths([p])
        assert not _has_method(paths, "PassRole+SageMaker:CreateTrainingJob")


# ---------------------------------------------------------------------------
# Tier 3 integration: action-based + lateral pipelines combined
# ---------------------------------------------------------------------------
class TestTier3CatalogIntegration:
    def test_lateral_methods_count(self) -> None:
        from cloud_audit.providers.aws.iam_trust_graph import LATERAL_METHODS

        assert len(LATERAL_METHODS) == 4

    def test_total_detection_methods_64(self) -> None:
        """Total = action-based (60) + lateral (4) = 64."""
        from cloud_audit.providers.aws.iam_trust_graph import LATERAL_METHODS

        assert len(ESCALATION_METHODS) + len(LATERAL_METHODS) == 64

    def test_lateral_methods_have_lateral_category(self) -> None:
        from cloud_audit.providers.aws.iam_trust_graph import LATERAL_METHODS

        for method in LATERAL_METHODS.values():
            assert method.category == EscalationCategory.LATERAL_ASSUME_ROLE

    def test_no_overlap_between_action_and_lateral_method_names(self) -> None:
        from cloud_audit.providers.aws.iam_trust_graph import LATERAL_METHODS

        action_names = set(ESCALATION_METHODS.keys())
        lateral_names = set(LATERAL_METHODS.keys())
        assert action_names.isdisjoint(lateral_names)
