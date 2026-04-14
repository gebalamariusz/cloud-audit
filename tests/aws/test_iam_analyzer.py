"""Tests for IAM Privilege Escalation Analyzer."""

from __future__ import annotations

from cloud_audit.models import EscalationCategory, Severity
from cloud_audit.providers.aws.iam_analyzer import (
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
