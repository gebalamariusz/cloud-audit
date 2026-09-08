"""Raw policy grants for selected principals (iam_analyzer.resolve_principal_grants)."""

from __future__ import annotations

from typing import Any

from cloud_audit.providers.aws.iam_analyzer import resolve_principal_grants

ACCOUNT = "123456789012"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/agent-role"
USER = f"arn:aws:iam::{ACCOUNT}:user/ops"
MANAGED = f"arn:aws:iam::{ACCOUNT}:policy/secrets-read"


def _auth_details() -> dict[str, Any]:
    return {
        "Policies": [
            {
                "Arn": MANAGED,
                "PolicyVersionList": [
                    {
                        "IsDefaultVersion": False,
                        "Document": {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
                    },
                    {
                        "IsDefaultVersion": True,
                        "Document": {
                            "Statement": [
                                {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": "*"},
                                {"Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3:::hr-files/*"},
                            ]
                        },
                    },
                ],
            }
        ],
        "GroupDetailList": [
            {
                "GroupName": "readers",
                "GroupPolicyList": [
                    {
                        "PolicyName": "grp",
                        "PolicyDocument": {"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}},
                    }
                ],
                "AttachedManagedPolicies": [],
            }
        ],
        "UserDetailList": [
            {
                "Arn": USER,
                "UserName": "ops",
                "GroupList": ["readers"],
                "UserPolicyList": [],
                "AttachedManagedPolicies": [{"PolicyName": "secrets-read", "PolicyArn": MANAGED}],
            }
        ],
        "RoleDetailList": [
            {
                "Arn": ROLE,
                "RoleName": "agent-role",
                "Path": "/",
                "RolePolicyList": [
                    {
                        "PolicyName": "kb-read",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["s3:GetObject", "s3:ListBucket"],
                                    "Resource": ["arn:aws:s3:::kb-docs/*", "arn:aws:s3:::kb-docs"],
                                    "Condition": {"StringEquals": {"aws:PrincipalTag/team": "ai"}},
                                },
                                {"Effect": "Allow", "NotAction": ["iam:*", "organizations:*"], "Resource": "*"},
                                {
                                    "Effect": "Deny",
                                    "Action": "s3:DeleteObject",
                                    "NotResource": "arn:aws:s3:::scratch/*",
                                },
                            ],
                        },
                    }
                ],
                "AttachedManagedPolicies": [{"PolicyName": "secrets-read", "PolicyArn": MANAGED}],
            },
            {
                "Arn": f"arn:aws:iam::{ACCOUNT}:role/other",
                "RoleName": "other",
                "Path": "/",
                "RolePolicyList": [],
                "AttachedManagedPolicies": [],
            },
        ],
    }


def test_role_grants_keep_resource_condition_and_source() -> None:
    grants = resolve_principal_grants(_auth_details(), [ROLE])
    assert set(grants) == {ROLE}
    g = grants[ROLE]
    kb = [x for x in g if x.action == "s3:GetObject"]
    assert {x.resource for x in kb} == {"arn:aws:s3:::kb-docs/*", "arn:aws:s3:::kb-docs"}
    assert all(x.has_condition for x in kb)
    assert all(x.source == "inline:kb-read" for x in kb)
    assert all(x.effect == "Allow" for x in kb)


def test_not_action_and_not_resource_are_flagged_not_expanded() -> None:
    g = resolve_principal_grants(_auth_details(), [ROLE])[ROLE]
    na = [x for x in g if x.not_action]
    assert len(na) == 1
    assert na[0].action == "NotAction:iam:*,organizations:*"
    assert na[0].resource == "*"
    nr = [x for x in g if x.not_resource]
    assert len(nr) == 1
    assert nr[0].effect == "Deny"
    assert nr[0].action == "s3:DeleteObject"
    assert nr[0].resource == "NotResource:arn:aws:s3:::scratch/*"


def test_managed_policy_uses_default_version_only() -> None:
    g = resolve_principal_grants(_auth_details(), [ROLE])[ROLE]
    managed = [x for x in g if x.source == f"managed:{MANAGED}"]
    assert {(x.action, x.effect) for x in managed} == {("secretsmanager:GetSecretValue", "Allow"), ("s3:*", "Deny")}
    # the non-default version's s3:* Allow must not leak in
    assert not any(x.action == "s3:*" and x.effect == "Allow" for x in g)


def test_user_grants_include_group_policies() -> None:
    g = resolve_principal_grants(_auth_details(), [USER])[USER]
    grp = [x for x in g if x.source.startswith("group:readers/")]
    assert len(grp) == 1
    assert grp[0].action == "s3:GetObject"
    assert grp[0].source == "group:readers/inline:grp"
    assert any(x.action == "secretsmanager:GetSecretValue" for x in g)


def test_only_requested_principals_are_returned() -> None:
    grants = resolve_principal_grants(_auth_details(), [ROLE, USER])
    assert set(grants) == {ROLE, USER}
    assert f"arn:aws:iam::{ACCOUNT}:role/other" not in grants


def test_unknown_principal_gets_empty_list() -> None:
    missing = f"arn:aws:iam::{ACCOUNT}:role/deleted"
    grants = resolve_principal_grants(_auth_details(), [missing])
    assert grants == {missing: []}


def test_empty_request_is_noop() -> None:
    assert resolve_principal_grants(_auth_details(), []) == {}


def test_case_insensitive_arn_match_keeps_original_casing() -> None:
    grants = resolve_principal_grants(_auth_details(), [ROLE.upper()])
    assert ROLE in grants
    assert grants[ROLE]


def test_string_policy_documents_are_parsed() -> None:
    details = _auth_details()
    details["RoleDetailList"][0]["RolePolicyList"][0]["PolicyDocument"] = (
        '{"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", '
        '"Resource": "arn:aws:iam::123456789012:role/x"}]}'
    )
    g = resolve_principal_grants(details, [ROLE])[ROLE]
    assert any(x.action == "sts:AssumeRole" and x.resource.endswith("role/x") for x in g)
