"""Tests for IAM Trust Policy Graph Analyzer (Tier 3 of v2.1.0)."""

from __future__ import annotations

import json
from typing import Any

from cloud_audit.models import EscalationCategory, Severity
from cloud_audit.providers.aws.iam_analyzer import ResolvedPrincipal
from cloud_audit.providers.aws.iam_trust_graph import (
    LATERAL_METHODS,
    TrustedPrincipal,
    _doc_grants_admin,
    _extract_account_id_from_arn,
    _has_assume_role,
    _normalize_aws_principal,
    _role_is_admin,
    build_assume_role_graph,
    find_lateral_escalations,
    parse_trust_policy,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
ADMIN_DOC = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


def _trust_doc(principals: dict[str, Any] | str | list, with_condition: bool = False) -> dict[str, Any]:
    """Build a minimal AssumeRolePolicyDocument with the given Principal block."""
    stmt: dict[str, Any] = {
        "Effect": "Allow",
        "Principal": principals,
        "Action": "sts:AssumeRole",
    }
    if with_condition:
        stmt["Condition"] = {
            "StringEquals": {"sts:ExternalId": "unique-secret"},
        }
    return {"Version": "2012-10-17", "Statement": [stmt]}


def _role(arn: str, name: str, trust: dict[str, Any], admin: bool = False) -> dict[str, Any]:
    """Build a RoleDetailList entry."""
    return {
        "Arn": arn,
        "RoleName": name,
        "Path": "/",
        "AssumeRolePolicyDocument": trust,
        "RolePolicyList": [{"PolicyName": "admin", "PolicyDocument": ADMIN_DOC}] if admin else [],
        "AttachedManagedPolicies": [],
    }


def _user(arn: str, name: str, allowed: set[str]) -> ResolvedPrincipal:
    p = ResolvedPrincipal(arn=arn, name=name, principal_type="User")
    p.allowed_actions = set(allowed)
    return p


def _role_principal(arn: str, name: str, allowed: set[str]) -> ResolvedPrincipal:
    p = ResolvedPrincipal(arn=arn, name=name, principal_type="Role")
    p.allowed_actions = set(allowed)
    return p


# ---------------------------------------------------------------------------
# Lateral method catalog
# ---------------------------------------------------------------------------
class TestLateralMethodCatalog:
    def test_four_methods_present(self) -> None:
        assert len(LATERAL_METHODS) == 4

    def test_method_names(self) -> None:
        assert set(LATERAL_METHODS.keys()) == {
            "AssumeRole:Direct",
            "AssumeRole:Chain",
            "AssumeRole:WildcardTrust",
            "AssumeRole:CrossAccountRoot",
        }

    def test_all_have_lateral_category(self) -> None:
        for method in LATERAL_METHODS.values():
            assert method.category == EscalationCategory.LATERAL_ASSUME_ROLE

    def test_severities(self) -> None:
        assert LATERAL_METHODS["AssumeRole:Direct"].base_severity == Severity.CRITICAL
        assert LATERAL_METHODS["AssumeRole:Chain"].base_severity == Severity.CRITICAL
        assert LATERAL_METHODS["AssumeRole:WildcardTrust"].base_severity == Severity.CRITICAL
        assert LATERAL_METHODS["AssumeRole:CrossAccountRoot"].base_severity == Severity.HIGH


# ---------------------------------------------------------------------------
# parse_trust_policy
# ---------------------------------------------------------------------------
class TestParseTrustPolicy:
    def test_single_aws_principal(self) -> None:
        doc = _trust_doc({"AWS": "arn:aws:iam::123:user/alice"})
        principals, has_cond = parse_trust_policy(doc)
        assert len(principals) == 1
        assert principals[0] == TrustedPrincipal(kind="AWS", value="arn:aws:iam::123:user/alice")
        assert has_cond is False

    def test_aws_principal_list(self) -> None:
        doc = _trust_doc({"AWS": ["arn:aws:iam::123:user/alice", "arn:aws:iam::123:role/deploy"]})
        principals, _ = parse_trust_policy(doc)
        assert len(principals) == 2
        assert TrustedPrincipal(kind="AWS", value="arn:aws:iam::123:user/alice") in principals
        assert TrustedPrincipal(kind="AWS", value="arn:aws:iam::123:role/deploy") in principals

    def test_account_root_arn(self) -> None:
        doc = _trust_doc({"AWS": "arn:aws:iam::999:root"})
        principals, _ = parse_trust_policy(doc)
        assert principals[0].kind == "AWS"
        assert principals[0].value == "arn:aws:iam::999:root"

    def test_bare_account_id(self) -> None:
        """AWS allows bare 12-digit account IDs; parse them as AWS principals (normalized later)."""
        doc = _trust_doc({"AWS": "999888777666"})
        principals, _ = parse_trust_policy(doc)
        assert principals[0].kind == "AWS"
        assert principals[0].value == "999888777666"

    def test_service_principal(self) -> None:
        doc = _trust_doc({"Service": "lambda.amazonaws.com"})
        principals, _ = parse_trust_policy(doc)
        assert principals[0] == TrustedPrincipal(kind="Service", value="lambda.amazonaws.com")

    def test_service_principal_list(self) -> None:
        doc = _trust_doc({"Service": ["lambda.amazonaws.com", "ecs-tasks.amazonaws.com"]})
        principals, _ = parse_trust_policy(doc)
        assert len(principals) == 2

    def test_federated_principal(self) -> None:
        doc = _trust_doc({"Federated": "arn:aws:iam::123:oidc-provider/token.actions.githubusercontent.com"})
        principals, _ = parse_trust_policy(doc)
        assert principals[0].kind == "Federated"

    def test_wildcard_principal_string(self) -> None:
        doc = _trust_doc("*")
        principals, _ = parse_trust_policy(doc)
        assert principals[0] == TrustedPrincipal(kind="Wildcard", value="*")

    def test_wildcard_principal_in_dict(self) -> None:
        doc = _trust_doc({"AWS": "*"})
        principals, _ = parse_trust_policy(doc)
        assert principals[0] == TrustedPrincipal(kind="Wildcard", value="*")

    def test_conditions_detected(self) -> None:
        doc = _trust_doc({"AWS": "arn:aws:iam::123:user/alice"}, with_condition=True)
        principals, has_cond = parse_trust_policy(doc)
        assert has_cond is True
        assert principals[0].value == "arn:aws:iam::123:user/alice"

    def test_string_policy_doc(self) -> None:
        doc = json.dumps(_trust_doc({"AWS": "arn:aws:iam::123:user/alice"}))
        principals, _ = parse_trust_policy(doc)
        assert len(principals) == 1

    def test_deny_statement_skipped(self) -> None:
        doc = {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": "arn:aws:iam::123:user/blocked"},
                    "Action": "sts:AssumeRole",
                }
            ]
        }
        principals, _ = parse_trust_policy(doc)
        assert principals == []

    def test_non_assume_role_action_skipped(self) -> None:
        doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123:user/alice"},
                    "Action": "sts:GetCallerIdentity",
                }
            ]
        }
        principals, _ = parse_trust_policy(doc)
        assert principals == []

    def test_assume_role_with_saml_detected(self) -> None:
        doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": "arn:aws:iam::123:saml-provider/Okta"},
                    "Action": "sts:AssumeRoleWithSAML",
                }
            ]
        }
        principals, _ = parse_trust_policy(doc)
        assert len(principals) == 1
        assert principals[0].kind == "Federated"

    def test_single_statement_not_list(self) -> None:
        doc = {"Statement": _trust_doc({"AWS": "arn:aws:iam::123:user/alice"})["Statement"][0]}
        principals, _ = parse_trust_policy(doc)
        assert len(principals) == 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
class TestHelpers:
    def test_extract_account_id(self) -> None:
        assert _extract_account_id_from_arn("arn:aws:iam::123456789012:user/alice") == "123456789012"

    def test_extract_account_id_invalid(self) -> None:
        assert _extract_account_id_from_arn("not-an-arn") == ""

    def test_normalize_bare_account_to_root(self) -> None:
        assert _normalize_aws_principal("123456789012", "111") == "arn:aws:iam::123456789012:root"

    def test_normalize_arn_unchanged(self) -> None:
        arn = "arn:aws:iam::123:user/alice"
        assert _normalize_aws_principal(arn, "111") == arn

    def test_doc_grants_admin_star(self) -> None:
        assert _doc_grants_admin({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})

    def test_doc_grants_admin_star_colon_star(self) -> None:
        assert _doc_grants_admin({"Statement": [{"Effect": "Allow", "Action": "*:*", "Resource": "*"}]})

    def test_doc_does_not_grant_admin_when_resource_scoped(self) -> None:
        assert not _doc_grants_admin(
            {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::my-bucket"}]}
        )

    def test_doc_does_not_grant_admin_when_action_scoped(self) -> None:
        assert not _doc_grants_admin({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]})

    def test_role_is_admin_via_inline(self) -> None:
        role = _role("arn:aws:iam::123:role/admin", "admin", _trust_doc({"AWS": "*"}), admin=True)
        assert _role_is_admin(role, {})

    def test_role_is_admin_via_aws_managed_admin(self) -> None:
        role = {
            "Arn": "arn:aws:iam::123:role/admin",
            "RoleName": "admin",
            "Path": "/",
            "AssumeRolePolicyDocument": _trust_doc({"AWS": "*"}),
            "RolePolicyList": [],
            "AttachedManagedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}],
        }
        assert _role_is_admin(role, {})

    def test_role_is_admin_via_customer_managed(self) -> None:
        role = {
            "Arn": "arn:aws:iam::123:role/r",
            "RoleName": "r",
            "Path": "/",
            "AssumeRolePolicyDocument": _trust_doc({"AWS": "*"}),
            "RolePolicyList": [],
            "AttachedManagedPolicies": [{"PolicyArn": "arn:aws:iam::123:policy/MyAdmin"}],
        }
        policies_map = {
            "arn:aws:iam::123:policy/MyAdmin": {
                "PolicyVersionList": [{"IsDefaultVersion": True, "Document": ADMIN_DOC}]
            }
        }
        assert _role_is_admin(role, policies_map)

    def test_role_not_admin(self) -> None:
        role = _role("arn:aws:iam::123:role/r", "r", _trust_doc({"AWS": "*"}), admin=False)
        role["RolePolicyList"] = [
            {
                "PolicyName": "limited",
                "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}]},
            }
        ]
        assert not _role_is_admin(role, {})

    def test_has_assume_role_basic(self) -> None:
        p = _user("arn:test", "u", {"sts:AssumeRole"})
        assert _has_assume_role(p)

    def test_has_assume_role_via_wildcard(self) -> None:
        p = _user("arn:test", "u", {"sts:*"})
        assert _has_assume_role(p)

    def test_has_assume_role_blocked_by_deny(self) -> None:
        p = _user("arn:test", "u", {"sts:*"})
        p.denied_actions = {"sts:AssumeRole"}
        assert not _has_assume_role(p)


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------
class TestBuildGraph:
    def test_account_id_extracted(self) -> None:
        auth = {
            "RoleDetailList": [_role("arn:aws:iam::123456789012:role/r", "r", _trust_doc({"AWS": "*"}))],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        assert graph.account_id == "123456789012"

    def test_service_linked_role_skipped(self) -> None:
        auth = {
            "RoleDetailList": [
                {
                    "Arn": "arn:aws:iam::123:role/aws-service-role/x/AWSServiceRoleForX",
                    "RoleName": "AWSServiceRoleForX",
                    "Path": "/aws-service-role/x/",
                    "AssumeRolePolicyDocument": _trust_doc({"AWS": "*"}),
                    "RolePolicyList": [],
                    "AttachedManagedPolicies": [],
                }
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        assert graph.edges == []
        assert graph.role_arn_to_name == {}

    def test_admin_status_set(self) -> None:
        admin_arn = "arn:aws:iam::123:role/admin"
        auth = {
            "RoleDetailList": [_role(admin_arn, "admin", _trust_doc({"AWS": "*"}), admin=True)],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        assert graph.role_admin_status[admin_arn] is True

    def test_edges_built_from_trust_policy(self) -> None:
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123:role/deploy",
                    "deploy",
                    _trust_doc({"AWS": "arn:aws:iam::123:user/alice"}),
                )
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        assert len(graph.edges) == 1
        edge = graph.edges[0]
        assert edge.source_arn == "arn:aws:iam::123:user/alice"
        assert edge.target_role_arn == "arn:aws:iam::123:role/deploy"

    def test_bare_account_normalized_to_root(self) -> None:
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123:role/r",
                    "r",
                    _trust_doc({"AWS": "999888777666"}),
                )
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        assert graph.edges[0].source_arn == "arn:aws:iam::999888777666:root"


# ---------------------------------------------------------------------------
# WildcardTrust detection
# ---------------------------------------------------------------------------
class TestWildcardTrust:
    def test_admin_role_wildcard_trust_critical(self) -> None:
        admin_arn = "arn:aws:iam::123:role/admin"
        auth = {
            "RoleDetailList": [_role(admin_arn, "admin", _trust_doc({"AWS": "*"}), admin=True)],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        paths = find_lateral_escalations(graph, [])
        wild = [p for p in paths if p.method == "AssumeRole:WildcardTrust"]
        assert len(wild) == 1
        assert wild[0].severity == Severity.CRITICAL
        assert wild[0].principal_arn == admin_arn

    def test_non_admin_role_wildcard_trust_high(self) -> None:
        auth = {
            "RoleDetailList": [_role("arn:aws:iam::123:role/r", "r", _trust_doc({"AWS": "*"}), admin=False)],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        paths = find_lateral_escalations(graph, [])
        wild = [p for p in paths if p.method == "AssumeRole:WildcardTrust"]
        assert len(wild) == 1
        assert wild[0].severity == Severity.HIGH

    def test_principal_string_wildcard(self) -> None:
        auth = {
            "RoleDetailList": [_role("arn:aws:iam::123:role/r", "r", _trust_doc("*"), admin=True)],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        paths = find_lateral_escalations(graph, [])
        wild = [p for p in paths if p.method == "AssumeRole:WildcardTrust"]
        assert len(wild) == 1

    def test_conditions_noted_in_target_privilege(self) -> None:
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123:role/r",
                    "r",
                    _trust_doc({"AWS": "*"}, with_condition=True),
                    admin=True,
                )
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        paths = find_lateral_escalations(graph, [])
        wild = [p for p in paths if p.method == "AssumeRole:WildcardTrust"]
        assert "conditions" in wild[0].target_privilege.lower()

    def test_normal_trust_not_flagged(self) -> None:
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123:role/deploy",
                    "deploy",
                    _trust_doc({"AWS": "arn:aws:iam::123:user/alice"}),
                )
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        paths = find_lateral_escalations(graph, [])
        assert not any(p.method == "AssumeRole:WildcardTrust" for p in paths)


# ---------------------------------------------------------------------------
# CrossAccountRoot detection
# ---------------------------------------------------------------------------
class TestCrossAccountRoot:
    def test_external_root_admin_critical(self) -> None:
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123:role/admin",
                    "admin",
                    _trust_doc({"AWS": "arn:aws:iam::999:root"}),
                    admin=True,
                )
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        paths = find_lateral_escalations(graph, [])
        cx = [p for p in paths if p.method == "AssumeRole:CrossAccountRoot"]
        assert len(cx) == 1
        assert cx[0].severity == Severity.CRITICAL
        assert "999" in cx[0].target_privilege

    def test_external_root_non_admin_high(self) -> None:
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123:role/r",
                    "r",
                    _trust_doc({"AWS": "arn:aws:iam::999:root"}),
                )
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        paths = find_lateral_escalations(graph, [])
        cx = [p for p in paths if p.method == "AssumeRole:CrossAccountRoot"]
        assert len(cx) == 1
        assert cx[0].severity == Severity.HIGH

    def test_same_account_root_not_flagged_as_cross_account(self) -> None:
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123:role/r",
                    "r",
                    _trust_doc({"AWS": "arn:aws:iam::123:root"}),
                )
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        paths = find_lateral_escalations(graph, [])
        assert not any(p.method == "AssumeRole:CrossAccountRoot" for p in paths)

    def test_external_bare_account_id_normalized(self) -> None:
        """A bare 12-digit account ID should be detected as cross-account root."""
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123456789012:role/r",
                    "r",
                    _trust_doc({"AWS": "999888777666"}),
                    admin=True,
                )
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        paths = find_lateral_escalations(graph, [])
        cx = [p for p in paths if p.method == "AssumeRole:CrossAccountRoot"]
        assert len(cx) == 1

    def test_specific_external_user_arn_not_flagged_as_root(self) -> None:
        """Cross-account trust to a SPECIFIC user ARN is not the same as root - skip here."""
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123:role/r",
                    "r",
                    _trust_doc({"AWS": "arn:aws:iam::999:user/external"}),
                )
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        paths = find_lateral_escalations(graph, [])
        assert not any(p.method == "AssumeRole:CrossAccountRoot" for p in paths)


# ---------------------------------------------------------------------------
# Direct AssumeRole detection
# ---------------------------------------------------------------------------
class TestAssumeRoleDirect:
    def test_user_can_assume_admin_role(self) -> None:
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123:role/admin",
                    "admin",
                    _trust_doc({"AWS": "arn:aws:iam::123:user/alice"}),
                    admin=True,
                )
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        alice = _user("arn:aws:iam::123:user/alice", "alice", {"sts:AssumeRole"})
        paths = find_lateral_escalations(graph, [alice])

        direct = [p for p in paths if p.method == "AssumeRole:Direct"]
        assert len(direct) == 1
        assert direct[0].principal_name == "alice"
        assert direct[0].severity == Severity.CRITICAL
        assert "alice" in direct[0].target_privilege
        assert "admin" in direct[0].target_privilege

    def test_user_without_assume_role_no_lateral(self) -> None:
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123:role/admin",
                    "admin",
                    _trust_doc({"AWS": "arn:aws:iam::123:user/alice"}),
                    admin=True,
                )
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        alice = _user("arn:aws:iam::123:user/alice", "alice", {"s3:Get*"})  # no sts:AssumeRole
        paths = find_lateral_escalations(graph, [alice])
        assert not any(p.method == "AssumeRole:Direct" for p in paths)

    def test_admin_user_not_flagged_for_lateral(self) -> None:
        """Already-admin user should not be reported for lateral escalation."""
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123:role/admin",
                    "admin",
                    _trust_doc({"AWS": "arn:aws:iam::123:user/alice"}),
                    admin=True,
                )
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        alice_admin = _user("arn:aws:iam::123:user/alice", "alice", {"*"})
        paths = find_lateral_escalations(graph, [alice_admin])
        assert not any(p.method == "AssumeRole:Direct" for p in paths)

    def test_assume_role_to_non_admin_not_flagged(self) -> None:
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123:role/dev",
                    "dev",
                    _trust_doc({"AWS": "arn:aws:iam::123:user/alice"}),
                    admin=False,
                )
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        alice = _user("arn:aws:iam::123:user/alice", "alice", {"sts:AssumeRole"})
        paths = find_lateral_escalations(graph, [alice])
        assert not any(p.method == "AssumeRole:Direct" for p in paths)

    def test_role_principal_can_lateral(self) -> None:
        """Roles (not just users) can also escalate via AssumeRole."""
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123:role/admin",
                    "admin",
                    _trust_doc({"AWS": "arn:aws:iam::123:role/ci"}),
                    admin=True,
                ),
                _role(
                    "arn:aws:iam::123:role/ci",
                    "ci",
                    _trust_doc({"Service": "codebuild.amazonaws.com"}),
                ),
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        ci_role = _role_principal("arn:aws:iam::123:role/ci", "ci", {"sts:AssumeRole"})
        paths = find_lateral_escalations(graph, [ci_role])
        direct = [p for p in paths if p.method == "AssumeRole:Direct"]
        assert len(direct) == 1
        assert direct[0].principal_type == "Role"


# ---------------------------------------------------------------------------
# Multi-hop chain detection
# ---------------------------------------------------------------------------
class TestAssumeRoleChain:
    def test_two_hop_chain(self) -> None:
        """alice -> deployer -> admin (where deployer also has sts:AssumeRole)."""
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123:role/deployer",
                    "deployer",
                    _trust_doc({"AWS": "arn:aws:iam::123:user/alice"}),
                    admin=False,
                ),
                _role(
                    "arn:aws:iam::123:role/admin",
                    "admin",
                    _trust_doc({"AWS": "arn:aws:iam::123:role/deployer"}),
                    admin=True,
                ),
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        alice = _user("arn:aws:iam::123:user/alice", "alice", {"sts:AssumeRole"})
        deployer = _role_principal("arn:aws:iam::123:role/deployer", "deployer", {"sts:AssumeRole"})
        paths = find_lateral_escalations(graph, [alice, deployer])

        chain = [p for p in paths if p.method == "AssumeRole:Chain" and p.principal_name == "alice"]
        assert len(chain) == 1
        assert "alice" in chain[0].target_privilege
        assert "deployer" in chain[0].target_privilege
        assert "admin" in chain[0].target_privilege

    def test_three_hop_chain(self) -> None:
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123:role/A",
                    "A",
                    _trust_doc({"AWS": "arn:aws:iam::123:user/alice"}),
                ),
                _role(
                    "arn:aws:iam::123:role/B",
                    "B",
                    _trust_doc({"AWS": "arn:aws:iam::123:role/A"}),
                ),
                _role(
                    "arn:aws:iam::123:role/admin",
                    "admin",
                    _trust_doc({"AWS": "arn:aws:iam::123:role/B"}),
                    admin=True,
                ),
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        alice = _user("arn:aws:iam::123:user/alice", "alice", {"sts:AssumeRole"})
        a_role = _role_principal("arn:aws:iam::123:role/A", "A", {"sts:AssumeRole"})
        b_role = _role_principal("arn:aws:iam::123:role/B", "B", {"sts:AssumeRole"})
        paths = find_lateral_escalations(graph, [alice, a_role, b_role])
        chain = [p for p in paths if p.method == "AssumeRole:Chain" and p.principal_name == "alice"]
        assert len(chain) == 1

    def test_chain_broken_by_missing_assume_role(self) -> None:
        """If intermediate role lacks sts:AssumeRole, chain is broken."""
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123:role/deployer",
                    "deployer",
                    _trust_doc({"AWS": "arn:aws:iam::123:user/alice"}),
                ),
                _role(
                    "arn:aws:iam::123:role/admin",
                    "admin",
                    _trust_doc({"AWS": "arn:aws:iam::123:role/deployer"}),
                    admin=True,
                ),
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        alice = _user("arn:aws:iam::123:user/alice", "alice", {"sts:AssumeRole"})
        # deployer has NO sts:AssumeRole
        deployer = _role_principal("arn:aws:iam::123:role/deployer", "deployer", {"s3:Get*"})
        paths = find_lateral_escalations(graph, [alice, deployer])
        # alice -> deployer is fine (1 hop), but deployer cannot continue to admin
        # However, if deployer ITSELF is reached, that's not admin, so no path returned.
        chain = [p for p in paths if p.principal_name == "alice"]
        assert chain == []

    def test_cycle_handled(self) -> None:
        """A trusts B trusts A, neither admin - should terminate without infinite loop."""
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123:role/A",
                    "A",
                    _trust_doc({"AWS": "arn:aws:iam::123:role/B"}),
                ),
                _role(
                    "arn:aws:iam::123:role/B",
                    "B",
                    _trust_doc({"AWS": "arn:aws:iam::123:role/A"}),
                ),
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        a_role = _role_principal("arn:aws:iam::123:role/A", "A", {"sts:AssumeRole"})
        paths = find_lateral_escalations(graph, [a_role])
        # No admin reachable
        assert not any(p.method in {"AssumeRole:Direct", "AssumeRole:Chain"} for p in paths)


# ---------------------------------------------------------------------------
# Same-account root expansion
# ---------------------------------------------------------------------------
class TestSameAccountRootExpansion:
    def test_role_trusting_same_account_root_reachable_by_any_user(self) -> None:
        """A role with Principal: {AWS: arn:aws:iam::SAME:root} can be assumed by any
        principal in the same account with sts:AssumeRole."""
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123:role/admin",
                    "admin",
                    _trust_doc({"AWS": "arn:aws:iam::123:root"}),
                    admin=True,
                )
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        # Alice has no explicit trust to admin role, but has sts:AssumeRole and is in
        # the same account, which means same-account-root expansion makes admin
        # reachable.
        alice = _user("arn:aws:iam::123:user/alice", "alice", {"sts:AssumeRole"})
        paths = find_lateral_escalations(graph, [alice])
        direct = [p for p in paths if p.method == "AssumeRole:Direct"]
        assert len(direct) == 1
        assert direct[0].principal_name == "alice"

    def test_external_root_does_not_expand_for_local_principals(self) -> None:
        """External account root must NOT expand to local principals."""
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123:role/admin",
                    "admin",
                    _trust_doc({"AWS": "arn:aws:iam::999:root"}),
                    admin=True,
                )
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        alice = _user("arn:aws:iam::123:user/alice", "alice", {"sts:AssumeRole"})
        paths = find_lateral_escalations(graph, [alice])
        direct = [p for p in paths if p.method == "AssumeRole:Direct"]
        assert direct == []
        # But CrossAccountRoot finding should be present
        cx = [p for p in paths if p.method == "AssumeRole:CrossAccountRoot"]
        assert len(cx) == 1


# ---------------------------------------------------------------------------
# Conditions caveat
# ---------------------------------------------------------------------------
class TestConditionsCaveat:
    def test_chain_with_conditions_notes_warning(self) -> None:
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123:role/admin",
                    "admin",
                    _trust_doc({"AWS": "arn:aws:iam::123:user/alice"}, with_condition=True),
                    admin=True,
                )
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        alice = _user("arn:aws:iam::123:user/alice", "alice", {"sts:AssumeRole"})
        paths = find_lateral_escalations(graph, [alice])
        direct = [p for p in paths if p.method == "AssumeRole:Direct"]
        assert len(direct) == 1
        assert "condition" in direct[0].target_privilege.lower()


# ---------------------------------------------------------------------------
# Realistic scenarios (integration)
# ---------------------------------------------------------------------------
class TestRealisticScenarios:
    def test_devops_user_with_jump_role_to_admin(self) -> None:
        """Common pattern: dev assumes 'jump' role, jump role can assume admin."""
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123:role/jump",
                    "jump",
                    _trust_doc({"AWS": "arn:aws:iam::123:user/dev"}),
                ),
                _role(
                    "arn:aws:iam::123:role/admin",
                    "admin",
                    _trust_doc({"AWS": "arn:aws:iam::123:role/jump"}),
                    admin=True,
                ),
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        dev = _user("arn:aws:iam::123:user/dev", "dev", {"sts:AssumeRole"})
        jump_role = _role_principal("arn:aws:iam::123:role/jump", "jump", {"sts:AssumeRole", "s3:*"})
        paths = find_lateral_escalations(graph, [dev, jump_role])

        dev_chain = [p for p in paths if p.principal_name == "dev"]
        assert len(dev_chain) == 1
        assert dev_chain[0].method == "AssumeRole:Chain"

    def test_overly_permissive_demo_account(self) -> None:
        """Demo account with multiple problems: wildcard trust + cross-account + chain."""
        auth = {
            "RoleDetailList": [
                _role(
                    "arn:aws:iam::123456789012:role/PublicAdmin",
                    "PublicAdmin",
                    _trust_doc({"AWS": "*"}),
                    admin=True,
                ),
                _role(
                    "arn:aws:iam::123456789012:role/PartnerAccess",
                    "PartnerAccess",
                    _trust_doc({"AWS": "arn:aws:iam::999888777666:root"}),
                    admin=True,
                ),
                _role(
                    "arn:aws:iam::123456789012:role/SafeRole",
                    "SafeRole",
                    _trust_doc({"Service": "lambda.amazonaws.com"}),
                ),
            ],
            "Policies": [],
        }
        graph = build_assume_role_graph(auth)
        paths = find_lateral_escalations(graph, [])
        method_counts: dict[str, int] = {}
        for p in paths:
            method_counts[p.method] = method_counts.get(p.method, 0) + 1
        assert method_counts.get("AssumeRole:WildcardTrust", 0) == 1
        assert method_counts.get("AssumeRole:CrossAccountRoot", 0) == 1
