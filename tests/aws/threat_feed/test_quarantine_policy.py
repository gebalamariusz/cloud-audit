"""Tests for TF-003: AWSCompromisedKeyQuarantine* detector.

We mock the IAM client directly (instead of using moto) because moto does not
pre-load AWS-managed policy ARNs like AWSCompromisedKeyQuarantineV3 - they
are not attachable in the moto policy catalog. Direct mocking lets us simulate
exactly the IAM API responses the pattern parses.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from cloud_audit.models import Category, Severity
from cloud_audit.providers.aws.provider import AWSProvider
from cloud_audit.providers.aws.threat_feed import quarantine_policy


def _make_paginator(pages: list[dict[str, Any]]) -> MagicMock:
    """Build a paginator mock that yields the provided pages on .paginate()."""
    paginator = MagicMock()
    paginator.paginate.return_value = iter(pages)
    return paginator


def _make_iam_client(
    *,
    users: list[dict[str, str]],
    roles: list[dict[str, str]],
    user_attachments: dict[str, list[dict[str, str]]] | None = None,
    role_attachments: dict[str, list[dict[str, str]]] | None = None,
) -> MagicMock:
    """Build a mock IAM client that mimics list_users/list_roles + attached policies.

    user_attachments / role_attachments: maps principal name -> list of {PolicyArn, PolicyName}
    Missing entries default to empty list.
    """
    user_attachments = user_attachments or {}
    role_attachments = role_attachments or {}

    iam = MagicMock()

    def get_paginator(op: str) -> MagicMock:
        if op == "list_users":
            return _make_paginator([{"Users": users}])
        if op == "list_roles":
            return _make_paginator([{"Roles": roles}])
        raise AssertionError(f"unexpected paginator: {op}")

    iam.get_paginator.side_effect = get_paginator

    def list_attached_user_policies(UserName: str) -> dict[str, Any]:
        return {"AttachedPolicies": user_attachments.get(UserName, [])}

    def list_attached_role_policies(RoleName: str) -> dict[str, Any]:
        return {"AttachedPolicies": role_attachments.get(RoleName, [])}

    iam.list_attached_user_policies.side_effect = list_attached_user_policies
    iam.list_attached_role_policies.side_effect = list_attached_role_policies
    return iam


def _run_detect(iam_client: MagicMock):
    """Execute the detector against a stubbed provider that yields the given IAM client."""
    provider = MagicMock(spec=AWSProvider)
    provider.client.return_value = iam_client
    return quarantine_policy.detect(provider)


def _quarantine_attachment(version: str = "V3") -> dict[str, str]:
    suffix = "" if version == "V1" else version
    return {
        "PolicyArn": f"arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantine{suffix}",
        "PolicyName": f"AWSCompromisedKeyQuarantine{suffix}",
    }


# -----------------------------------------------------------------------------
# Detection tests
# -----------------------------------------------------------------------------


def test_clean_account_no_findings() -> None:
    iam = _make_iam_client(
        users=[{"UserName": "alice", "Arn": "arn:aws:iam::123456789012:user/alice"}],
        roles=[{"RoleName": "app-role", "Arn": "arn:aws:iam::123456789012:role/app-role"}],
    )
    result = _run_detect(iam)

    assert result.error is None
    assert result.findings == []
    assert result.resources_scanned == 2


def test_user_with_quarantine_v3_flagged() -> None:
    iam = _make_iam_client(
        users=[{"UserName": "leaked-bot", "Arn": "arn:aws:iam::123456789012:user/leaked-bot"}],
        roles=[],
        user_attachments={"leaked-bot": [_quarantine_attachment("V3")]},
    )
    result = _run_detect(iam)

    assert result.error is None
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.category == Category.THREAT
    assert f.threat_pattern_id == quarantine_policy.PATTERN_ID
    assert "leaked-bot" in f.title
    assert f.resource_type == "AWS::IAM::User"
    assert f.references, "Threat findings must have references for credibility"
    assert all(r.startswith("https://") for r in f.references)
    assert f.remediation is not None
    assert "rotate" in f.recommendation.lower()


def test_role_with_quarantine_v3_flagged() -> None:
    iam = _make_iam_client(
        users=[],
        roles=[{"RoleName": "leaked-deploy-role", "Arn": "arn:aws:iam::123456789012:role/leaked-deploy-role"}],
        role_attachments={"leaked-deploy-role": [_quarantine_attachment("V3")]},
    )
    result = _run_detect(iam)

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.resource_type == "AWS::IAM::Role"
    assert "leaked-deploy-role" in f.resource_id
    assert "leaked-deploy-role" in f.remediation.cli  # CLI mentions principal
    assert "detach-role-policy" in f.remediation.cli


def test_legacy_v1_v2_quarantine_also_flagged() -> None:
    iam = _make_iam_client(
        users=[
            {"UserName": "old-leak-1", "Arn": "arn:aws:iam::123456789012:user/old-leak-1"},
            {"UserName": "old-leak-2", "Arn": "arn:aws:iam::123456789012:user/old-leak-2"},
        ],
        roles=[],
        user_attachments={
            "old-leak-1": [_quarantine_attachment("V1")],
            "old-leak-2": [_quarantine_attachment("V2")],
        },
    )
    result = _run_detect(iam)

    assert len(result.findings) == 2
    titles = {f.title for f in result.findings}
    assert any("old-leak-1" in t for t in titles)
    assert any("old-leak-2" in t for t in titles)


def test_unrelated_managed_policy_not_flagged() -> None:
    iam = _make_iam_client(
        users=[{"UserName": "readonly-user", "Arn": "arn:aws:iam::123456789012:user/readonly-user"}],
        roles=[],
        user_attachments={
            "readonly-user": [{"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess", "PolicyName": "ReadOnlyAccess"}]
        },
    )
    result = _run_detect(iam)

    assert result.findings == []


def test_service_linked_roles_skipped() -> None:
    """AWSServiceRole* roles excluded - they cannot host leaked credentials."""
    iam = _make_iam_client(
        users=[],
        roles=[
            {
                "RoleName": "AWSServiceRoleForOrganizations",
                "Arn": "arn:aws:iam::123456789012:role/aws-service-role/AWSServiceRoleForOrganizations",
            },
            {
                "RoleName": "customer-app-role",
                "Arn": "arn:aws:iam::123456789012:role/customer-app-role",
            },
        ],
    )
    result = _run_detect(iam)

    assert result.resources_scanned == 1  # service-linked role excluded
    assert result.findings == []


def test_multiple_attached_policies_with_one_quarantine() -> None:
    """User has several policies, only the quarantine one matters."""
    iam = _make_iam_client(
        users=[{"UserName": "compromised", "Arn": "arn:aws:iam::123456789012:user/compromised"}],
        roles=[],
        user_attachments={
            "compromised": [
                {"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess", "PolicyName": "ReadOnlyAccess"},
                _quarantine_attachment("V3"),
                {
                    "PolicyArn": "arn:aws:iam::123456789012:policy/CustomDeploy",
                    "PolicyName": "CustomDeploy",
                },
            ]
        },
    )
    result = _run_detect(iam)

    assert len(result.findings) == 1
    assert result.findings[0].threat_pattern_id == quarantine_policy.PATTERN_ID


# -----------------------------------------------------------------------------
# Error handling
# -----------------------------------------------------------------------------


def test_access_denied_per_principal_does_not_abort_scan() -> None:
    """If list_attached_user_policies fails for one user with AccessDenied, scan continues."""
    iam = _make_iam_client(
        users=[
            {"UserName": "ok-user", "Arn": "arn:aws:iam::123456789012:user/ok-user"},
            {"UserName": "denied-user", "Arn": "arn:aws:iam::123456789012:user/denied-user"},
        ],
        roles=[],
        user_attachments={"ok-user": [_quarantine_attachment("V3")]},
    )

    class _AccessDenied(Exception):
        def __init__(self) -> None:
            super().__init__("AccessDenied")
            self.response = {"Error": {"Code": "AccessDenied"}}

    original = iam.list_attached_user_policies.side_effect

    def maybe_deny(UserName: str) -> dict[str, Any]:
        if UserName == "denied-user":
            raise _AccessDenied()
        return original(UserName=UserName)

    iam.list_attached_user_policies.side_effect = maybe_deny

    result = _run_detect(iam)

    # The denied user did not abort; the OK user still produced a finding
    assert result.error is None
    assert len(result.findings) == 1
    assert "ok-user" in result.findings[0].title


def test_top_level_exception_recorded_in_result_error() -> None:
    """If provider.client() itself raises, the result records the error string."""
    provider = MagicMock(spec=AWSProvider)
    provider.client.side_effect = RuntimeError("boom")

    result = quarantine_policy.detect(provider)

    assert "boom" in (result.error or "")
    assert result.findings == []


# -----------------------------------------------------------------------------
# Pattern metadata + provider integration
# -----------------------------------------------------------------------------


def test_pattern_metadata_exposed() -> None:
    assert quarantine_policy.PATTERN_ID == "TF-003-quarantine-policy"
    assert quarantine_policy.CHECK_ID == "aws-tf-003"
    assert quarantine_policy.PATTERN_SEVERITY == Severity.CRITICAL
    assert quarantine_policy.PATTERN_NAME
    assert quarantine_policy.DOC_URL.startswith("https://")


def test_check_registered_in_provider() -> None:
    """The threat feed pattern must show up in AWSProvider.get_checks()."""
    with patch("boto3.Session") as mock_session:
        mock_session.return_value.region_name = "us-east-1"
        provider = AWSProvider(regions=["us-east-1"])
        check_ids = {c.check_id for c in provider.get_checks()}
        assert quarantine_policy.CHECK_ID in check_ids


def test_category_filter_includes_threat() -> None:
    """Filtering by THREAT category returns the threat feed checks and only those."""
    with patch("boto3.Session") as mock_session:
        mock_session.return_value.region_name = "us-east-1"
        provider = AWSProvider(regions=["us-east-1"])
        threat_checks = provider.get_checks(categories=[Category.THREAT])
        assert any(c.check_id == quarantine_policy.CHECK_ID for c in threat_checks)
        assert all(getattr(c, "category", None) == Category.THREAT for c in threat_checks)
