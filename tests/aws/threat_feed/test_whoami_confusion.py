"""Tests for TF-007: whoAMI confusion CI/CD precondition detector."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from cloud_audit.models import Category, Severity
from cloud_audit.providers.aws.provider import AWSProvider
from cloud_audit.providers.aws.threat_feed import whoami_confusion


def _paginator(pages: list[dict[str, Any]]) -> MagicMock:
    p = MagicMock()
    p.paginate.return_value = iter(pages)
    return p


def _trust_codebuild() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }


def _trust_github_oidc() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
            }
        ],
    }


def _trust_human_user() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:user/alice"},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _role(name: str, trust: dict[str, Any]) -> dict[str, Any]:
    return {
        "RoleName": name,
        "Arn": f"arn:aws:iam::123456789012:role/{name}",
        "AssumeRolePolicyDocument": trust,
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
    result = whoami_confusion.detect(_provider(iam))
    assert result.error is None
    assert result.findings == []


def test_codebuild_role_with_ec2_full_access_flagged() -> None:
    iam = _iam(
        roles=[_role("ci-build", _trust_codebuild())],
        attachments={"ci-build": ["arn:aws:iam::aws:policy/AmazonEC2FullAccess"]},
    )
    result = whoami_confusion.detect(_provider(iam))
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.MEDIUM
    assert f.category == Category.THREAT
    assert f.threat_pattern_id == whoami_confusion.PATTERN_ID
    assert "ci-build" in f.title
    assert "codebuild" in f.title
    assert "whoAMI" in f.title
    assert "Owner" in f.remediation.terraform


def test_github_oidc_role_with_power_user_flagged() -> None:
    iam = _iam(
        roles=[_role("gh-deploy", _trust_github_oidc())],
        attachments={"gh-deploy": ["arn:aws:iam::aws:policy/PowerUserAccess"]},
    )
    result = whoami_confusion.detect(_provider(iam))
    assert len(result.findings) == 1
    assert "github-oidc" in result.findings[0].title


def test_codebuild_role_without_ec2_access_not_flagged() -> None:
    """CI role with only ReadOnlyAccess - DescribeImages exists but launch path doesn't."""
    iam = _iam(
        roles=[_role("ci-readonly", _trust_codebuild())],
        attachments={"ci-readonly": ["arn:aws:iam::aws:policy/ReadOnlyAccess"]},
    )
    result = whoami_confusion.detect(_provider(iam))
    assert result.findings == []


def test_human_role_with_ec2_full_not_flagged() -> None:
    """User-trusted role with EC2 full access - human admin, not CI/CD pipeline. Not the target."""
    iam = _iam(
        roles=[_role("human-admin", _trust_human_user())],
        attachments={"human-admin": ["arn:aws:iam::aws:policy/AmazonEC2FullAccess"]},
    )
    result = whoami_confusion.detect(_provider(iam))
    assert result.findings == []
    # human role is also not even counted as a candidate scan resource
    assert result.resources_scanned == 0


def test_service_linked_role_skipped() -> None:
    iam = _iam(
        roles=[_role("AWSServiceRoleForCodeBuild", _trust_codebuild())],
        attachments={"AWSServiceRoleForCodeBuild": ["arn:aws:iam::aws:policy/AmazonEC2FullAccess"]},
    )
    result = whoami_confusion.detect(_provider(iam))
    assert result.findings == []


def test_multiple_ci_roles_aggregated() -> None:
    iam = _iam(
        roles=[
            _role("ci-1", _trust_codebuild()),
            _role("ci-2", _trust_github_oidc()),
            _role("human", _trust_human_user()),
        ],
        attachments={
            "ci-1": ["arn:aws:iam::aws:policy/AmazonEC2FullAccess"],
            "ci-2": ["arn:aws:iam::aws:policy/AdministratorAccess"],
            "human": ["arn:aws:iam::aws:policy/AmazonEC2FullAccess"],  # not flagged - trust is human
        },
    )
    result = whoami_confusion.detect(_provider(iam))
    assert len(result.findings) == 2
    names = {f.resource_id for f in result.findings}
    assert any("ci-1" in n for n in names)
    assert any("ci-2" in n for n in names)
    assert not any("human" in n for n in names)


def test_pattern_metadata_exposed() -> None:
    assert whoami_confusion.PATTERN_ID == "TF-007-whoami-confusion"
    assert whoami_confusion.CHECK_ID == "aws-tf-007"
    assert whoami_confusion.PATTERN_SEVERITY == Severity.MEDIUM


def test_top_level_exception_recorded() -> None:
    p = MagicMock(spec=AWSProvider)
    p.client.side_effect = RuntimeError("boom")
    result = whoami_confusion.detect(p)
    assert "boom" in (result.error or "")
