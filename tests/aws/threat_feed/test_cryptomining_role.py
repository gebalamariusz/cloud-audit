"""Tests for TF-005: cryptomining campaign IAM role detector."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

from cloud_audit.models import Category, Severity
from cloud_audit.providers.aws.provider import AWSProvider
from cloud_audit.providers.aws.threat_feed import cryptomining_role

_NOW = datetime.now(timezone.utc)


def _paginator(pages: list[dict[str, Any]]) -> MagicMock:
    p = MagicMock()
    p.paginate.return_value = iter(pages)
    return p


def _role(name: str, created_hours_ago: float = 1.0) -> dict[str, Any]:
    return {
        "RoleName": name,
        "Arn": f"arn:aws:iam::123456789012:role/{name}",
        "CreateDate": _NOW - timedelta(hours=created_hours_ago),
    }


def _iam(roles: list[dict[str, Any]], attachments: dict[str, list[str]] | None = None) -> MagicMock:
    attachments = attachments or {}
    iam = MagicMock()
    iam.get_paginator.return_value = _paginator([{"Roles": roles}])

    def list_attached(RoleName: str) -> dict[str, Any]:
        return {"AttachedPolicies": [{"PolicyArn": a} for a in attachments.get(RoleName, [])]}

    iam.list_attached_role_policies.side_effect = list_attached
    return iam


def _provider(iam: MagicMock) -> MagicMock:
    p = MagicMock(spec=AWSProvider)
    p.client.return_value = iam
    return p


# -----------------------------------------------------------------------------


def test_no_roles_no_findings() -> None:
    iam = _iam(roles=[])
    result = cryptomining_role.detect(_provider(iam))
    assert result.error is None
    assert result.findings == []


def test_old_role_with_ec2_full_not_flagged() -> None:
    """Role >48h old + EC2FullAccess = legitimate ops role, not flagged."""
    iam = _iam(
        roles=[_role("old-ops", created_hours_ago=240)],  # 10 days old
        attachments={"old-ops": ["arn:aws:iam::aws:policy/AmazonEC2FullAccess"]},
    )
    result = cryptomining_role.detect(_provider(iam))
    assert result.findings == []


def test_fresh_role_without_compute_access_not_flagged() -> None:
    """Brand new role but only ReadOnlyAccess - no campaign signal."""
    iam = _iam(
        roles=[_role("fresh-readonly", created_hours_ago=2)],
        attachments={"fresh-readonly": ["arn:aws:iam::aws:policy/ReadOnlyAccess"]},
    )
    result = cryptomining_role.detect(_provider(iam))
    assert result.findings == []


def test_fresh_role_with_ec2_full_flagged_high() -> None:
    iam = _iam(
        roles=[_role("crypto-miner", created_hours_ago=4)],
        attachments={"crypto-miner": ["arn:aws:iam::aws:policy/AmazonEC2FullAccess"]},
    )
    result = cryptomining_role.detect(_provider(iam))
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.HIGH
    assert f.category == Category.THREAT
    assert f.threat_pattern_id == cryptomining_role.PATTERN_ID
    assert "crypto-miner" in f.title
    assert "4h old" in f.title or "4 hours" in f.description.lower()


def test_fresh_role_with_admin_access_flagged_critical_when_ses_inferred() -> None:
    """AdministratorAccess implies SES too -> CRITICAL (mining + email spam combo)."""
    iam = _iam(
        roles=[_role("admin-fresh", created_hours_ago=6)],
        attachments={"admin-fresh": ["arn:aws:iam::aws:policy/AdministratorAccess"]},
    )
    result = cryptomining_role.detect(_provider(iam))
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.CRITICAL
    assert "email-spam" in f.description.lower()


def test_fresh_role_with_ec2_plus_explicit_ses_critical() -> None:
    """EC2 full + SES full both attached = explicit cryptomining+spam combo."""
    iam = _iam(
        roles=[_role("combo", created_hours_ago=10)],
        attachments={
            "combo": [
                "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
                "arn:aws:iam::aws:policy/AmazonSESFullAccess",
            ]
        },
    )
    result = cryptomining_role.detect(_provider(iam))
    assert result.findings[0].severity == Severity.CRITICAL


def test_role_at_freshness_boundary_included() -> None:
    """Role created exactly within window IS flagged; role just outside is NOT."""
    iam = _iam(
        roles=[
            _role("just-inside", created_hours_ago=47.5),
            _role("just-outside", created_hours_ago=48.5),
        ],
        attachments={
            "just-inside": ["arn:aws:iam::aws:policy/PowerUserAccess"],
            "just-outside": ["arn:aws:iam::aws:policy/PowerUserAccess"],
        },
    )
    result = cryptomining_role.detect(_provider(iam))
    assert len(result.findings) == 1
    assert "just-inside" in result.findings[0].resource_id


def test_service_linked_roles_skipped() -> None:
    iam = _iam(
        roles=[_role("AWSServiceRoleForEC2", created_hours_ago=1)],
        attachments={"AWSServiceRoleForEC2": ["arn:aws:iam::aws:policy/AmazonEC2FullAccess"]},
    )
    result = cryptomining_role.detect(_provider(iam))
    assert result.findings == []


def test_remediation_includes_policy_detach_and_audit() -> None:
    iam = _iam(
        roles=[_role("suspect", created_hours_ago=3)],
        attachments={"suspect": ["arn:aws:iam::aws:policy/AmazonEC2FullAccess"]},
    )
    result = cryptomining_role.detect(_provider(iam))
    rem = result.findings[0].remediation
    assert "detach-role-policy" in rem.cli
    assert "lookup-events" in rem.cli
    assert "CreateRole" in rem.cli


def test_pattern_metadata_exposed() -> None:
    assert cryptomining_role.PATTERN_ID == "TF-005-cryptomining-role"
    assert cryptomining_role.CHECK_ID == "aws-tf-005"
    assert cryptomining_role.PATTERN_SEVERITY == Severity.HIGH


def test_top_level_exception_recorded() -> None:
    p = MagicMock(spec=AWSProvider)
    p.client.side_effect = RuntimeError("boom")
    result = cryptomining_role.detect(p)
    assert "boom" in (result.error or "")
