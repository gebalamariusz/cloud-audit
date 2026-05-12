"""Tests for TF-010: DataZone over-grant detector."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from cloud_audit.models import Category, Severity
from cloud_audit.providers.aws.provider import AWSProvider
from cloud_audit.providers.aws.threat_feed import datazone_overgrant

_DATAZONE_FULL = "arn:aws:iam::aws:policy/AmazonDataZoneFullAccess"
_DATAZONE_USER = "arn:aws:iam::aws:policy/AmazonDataZoneFullUserAccess"
_ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _paginator(pages: list[dict[str, Any]]) -> MagicMock:
    p = MagicMock()
    p.paginate.return_value = iter(pages)
    return p


def _iam(
    *,
    users: list[dict[str, str]] | None = None,
    roles: list[dict[str, str]] | None = None,
    user_attachments: dict[str, list[str]] | None = None,
    role_attachments: dict[str, list[str]] | None = None,
) -> MagicMock:
    users = users or []
    roles = roles or []
    user_attachments = user_attachments or {}
    role_attachments = role_attachments or {}

    iam = MagicMock()

    def get_paginator(op: str) -> MagicMock:
        if op == "list_users":
            return _paginator([{"Users": users}])
        if op == "list_roles":
            return _paginator([{"Roles": roles}])
        raise AssertionError(op)

    iam.get_paginator.side_effect = get_paginator

    def list_attached_user(UserName: str) -> dict[str, Any]:
        return {"AttachedPolicies": [{"PolicyArn": a} for a in user_attachments.get(UserName, [])]}

    def list_attached_role(RoleName: str) -> dict[str, Any]:
        return {"AttachedPolicies": [{"PolicyArn": a} for a in role_attachments.get(RoleName, [])]}

    iam.list_attached_user_policies.side_effect = list_attached_user
    iam.list_attached_role_policies.side_effect = list_attached_role
    return iam


def _provider(iam: MagicMock) -> MagicMock:
    p = MagicMock(spec=AWSProvider)
    p.client.return_value = iam
    return p


def _user(name: str) -> dict[str, str]:
    return {"UserName": name, "Arn": f"arn:aws:iam::123456789012:user/{name}"}


def _role(name: str) -> dict[str, str]:
    return {"RoleName": name, "Arn": f"arn:aws:iam::123456789012:role/{name}"}


# -----------------------------------------------------------------------------


def test_no_principals_no_findings() -> None:
    iam = _iam()
    result = datazone_overgrant.detect(_provider(iam))
    assert result.error is None
    assert result.findings == []


def test_user_with_datazone_full_access_flagged() -> None:
    iam = _iam(
        users=[_user("data-analyst")],
        user_attachments={"data-analyst": [_DATAZONE_FULL]},
    )
    result = datazone_overgrant.detect(_provider(iam))
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.HIGH
    assert f.category == Category.THREAT
    assert f.threat_pattern_id == datazone_overgrant.PATTERN_ID
    assert "data-analyst" in f.title
    assert f.resource_type == "AWS::IAM::User"
    assert "AmazonDataZoneFullUserAccess" in f.remediation.cli  # remediation suggests scoped variant


def test_role_with_datazone_full_access_flagged() -> None:
    iam = _iam(
        roles=[_role("data-eng-role")],
        role_attachments={"data-eng-role": [_DATAZONE_FULL]},
    )
    result = datazone_overgrant.detect(_provider(iam))
    assert len(result.findings) == 1
    assert result.findings[0].resource_type == "AWS::IAM::Role"


def test_admin_with_datazone_full_not_flagged() -> None:
    """Already an admin - DataZone full is noise, not over-permission."""
    iam = _iam(
        users=[_user("admin-user")],
        user_attachments={"admin-user": [_ADMIN, _DATAZONE_FULL]},
    )
    result = datazone_overgrant.detect(_provider(iam))
    assert result.findings == []


def test_user_with_only_scoped_variant_not_flagged() -> None:
    """AmazonDataZoneFullUserAccess (scoped) is the recommended grant - not flagged."""
    iam = _iam(
        users=[_user("analyst")],
        user_attachments={"analyst": [_DATAZONE_USER]},
    )
    result = datazone_overgrant.detect(_provider(iam))
    assert result.findings == []


def test_unrelated_policies_not_flagged() -> None:
    iam = _iam(
        users=[_user("readonly")],
        user_attachments={"readonly": ["arn:aws:iam::aws:policy/ReadOnlyAccess"]},
    )
    result = datazone_overgrant.detect(_provider(iam))
    assert result.findings == []


def test_service_linked_role_skipped() -> None:
    iam = _iam(
        roles=[_role("AWSServiceRoleForDataZone"), _role("customer-role")],
        role_attachments={
            "AWSServiceRoleForDataZone": [_DATAZONE_FULL],
            "customer-role": [_DATAZONE_FULL],
        },
    )
    result = datazone_overgrant.detect(_provider(iam))
    # Only the customer role is flagged
    assert len(result.findings) == 1
    assert "customer-role" in result.findings[0].resource_id


def test_mixed_users_and_roles_aggregated() -> None:
    iam = _iam(
        users=[_user("u1"), _user("u2-admin")],
        roles=[_role("r1")],
        user_attachments={
            "u1": [_DATAZONE_FULL],
            "u2-admin": [_ADMIN, _DATAZONE_FULL],  # admin: skipped
        },
        role_attachments={"r1": [_DATAZONE_FULL]},
    )
    result = datazone_overgrant.detect(_provider(iam))
    assert len(result.findings) == 2  # u1 + r1, NOT u2-admin
    names = {f.resource_id for f in result.findings}
    assert any("u1" in n for n in names)
    assert any("r1" in n for n in names)
    assert not any("u2-admin" in n for n in names)


def test_pattern_metadata_exposed() -> None:
    assert datazone_overgrant.PATTERN_ID == "TF-010-datazone-overgrant"
    assert datazone_overgrant.CHECK_ID == "aws-tf-010"
    assert datazone_overgrant.PATTERN_SEVERITY == Severity.HIGH


def test_top_level_exception_recorded() -> None:
    p = MagicMock(spec=AWSProvider)
    p.client.side_effect = RuntimeError("boom")
    result = datazone_overgrant.detect(p)
    assert "boom" in (result.error or "")
