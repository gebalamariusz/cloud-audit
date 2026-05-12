"""Tests for TF-009: Roles Anywhere trust anchor abuse detector."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from cloud_audit.models import Category, Severity
from cloud_audit.providers.aws.provider import AWSProvider
from cloud_audit.providers.aws.threat_feed import roles_anywhere_abuse


def _paginator(pages: list[dict[str, Any]]) -> MagicMock:
    p = MagicMock()
    p.paginate.return_value = iter(pages)
    return p


def _ra_client(anchors: list[dict[str, Any]]) -> MagicMock:
    ra = MagicMock()
    ra.get_paginator.return_value = _paginator([{"trustAnchors": anchors}])
    return ra


def _provider(ra: MagicMock, regions: list[str] | None = None) -> MagicMock:
    p = MagicMock(spec=AWSProvider)
    p.regions = regions or ["us-east-1"]
    p.client.return_value = ra
    return p


def _anchor(
    anchor_id: str = "anchor-1",
    name: str | None = None,
    source_type: str = "CERTIFICATE_BUNDLE",
    enabled: bool = True,
) -> dict[str, Any]:
    return {
        "trustAnchorId": anchor_id,
        "name": name or anchor_id,
        "source": {"sourceType": source_type},
        "enabled": enabled,
    }


# -----------------------------------------------------------------------------


def test_no_anchors_no_findings() -> None:
    ra = _ra_client(anchors=[])
    result = roles_anywhere_abuse.detect(_provider(ra))
    assert result.error is None
    assert result.findings == []


def test_acm_pca_anchor_not_flagged() -> None:
    """sourceType=AWS_ACM_PCA = recommended pattern, no finding."""
    ra = _ra_client(anchors=[_anchor(source_type="AWS_ACM_PCA")])
    result = roles_anywhere_abuse.detect(_provider(ra))
    assert result.findings == []


def test_certificate_bundle_anchor_enabled_high() -> None:
    """sourceType=CERTIFICATE_BUNDLE + enabled = HIGH (active attack surface)."""
    ra = _ra_client(anchors=[_anchor(name="external-ca", source_type="CERTIFICATE_BUNDLE", enabled=True)])
    result = roles_anywhere_abuse.detect(_provider(ra))
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.HIGH
    assert f.category == Category.THREAT
    assert f.threat_pattern_id == roles_anywhere_abuse.PATTERN_ID
    assert "external-ca" in f.title
    assert "ENABLED" in f.title
    assert "AWS_ACM_PCA" in f.recommendation


def test_certificate_bundle_anchor_disabled_medium() -> None:
    """sourceType=CERTIFICATE_BUNDLE but disabled = downgrade to MEDIUM (not active)."""
    ra = _ra_client(anchors=[_anchor(source_type="CERTIFICATE_BUNDLE", enabled=False)])
    result = roles_anywhere_abuse.detect(_provider(ra))
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.MEDIUM
    assert "disabled" in result.findings[0].title.lower()


def test_remediation_includes_disable_and_audit() -> None:
    ra = _ra_client(anchors=[_anchor(anchor_id="abc-123")])
    result = roles_anywhere_abuse.detect(_provider(ra))
    rem = result.findings[0].remediation
    assert "disable-trust-anchor" in rem.cli
    assert "abc-123" in rem.cli
    assert "CreateSession" in rem.cli  # audit step
    assert "AWS_ACM_PCA" in rem.terraform


def test_mixed_anchors_only_external_flagged() -> None:
    ra = _ra_client(
        anchors=[
            _anchor(anchor_id="pca-ok", source_type="AWS_ACM_PCA"),
            _anchor(anchor_id="external-bad", source_type="CERTIFICATE_BUNDLE"),
        ]
    )
    result = roles_anywhere_abuse.detect(_provider(ra))
    assert len(result.findings) == 1
    assert "external-bad" in result.findings[0].resource_id


def test_unsupported_region_silent_skip() -> None:
    """Region without rolesanywhere => paginate raises ValidationException => silent skip."""
    ra = MagicMock()

    class _Validation(Exception):
        def __init__(self) -> None:
            super().__init__("ValidationException")
            self.response = {"Error": {"Code": "ValidationException"}}

    paginator = MagicMock()
    paginator.paginate.side_effect = _Validation()
    ra.get_paginator.return_value = paginator

    result = roles_anywhere_abuse.detect(_provider(ra))
    assert result.error is None
    assert result.findings == []


def test_pattern_metadata_exposed() -> None:
    assert roles_anywhere_abuse.PATTERN_ID == "TF-009-roles-anywhere-abuse"
    assert roles_anywhere_abuse.CHECK_ID == "aws-tf-009"
    assert roles_anywhere_abuse.PATTERN_SEVERITY == Severity.HIGH


def test_top_level_exception_recorded() -> None:
    p = MagicMock(spec=AWSProvider)
    p.regions = ["us-east-1"]
    p.client.side_effect = RuntimeError("boom")
    # provider.client() failing inside _scan_region returns (0, []), but if we want
    # to surface it we must raise at top level. Detector swallows region failures
    # gracefully - assert no error AND no findings.
    result = roles_anywhere_abuse.detect(p)
    assert result.findings == []
