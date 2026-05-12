"""Tests for TF-004: TruffleHog/leaked-creds-scanner UA detector."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

from cloud_audit.models import Category, Severity
from cloud_audit.providers.aws.provider import AWSProvider
from cloud_audit.providers.aws.threat_feed import trufflehog_ua


def _event(user_agent: str, principal_arn: str = "arn:aws:iam::123456789012:user/leaked") -> dict[str, Any]:
    """Wrap an event in the CloudTrailEvent JSON-string format the API returns."""
    inner = {
        "eventTime": "2026-05-12T10:00:00Z",
        "userAgent": user_agent,
        "userIdentity": {"arn": principal_arn, "principalId": "AIDA-EXAMPLE"},
        "sourceIPAddress": "203.0.113.42",
    }
    return {"CloudTrailEvent": json.dumps(inner)}


def _ct_with_events(events: list[dict[str, Any]]) -> MagicMock:
    ct = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = iter([{"Events": events}])
    ct.get_paginator.return_value = paginator
    return ct


def _provider(ct: MagicMock, regions: list[str] | None = None) -> MagicMock:
    p = MagicMock(spec=AWSProvider)
    p.regions = regions or ["us-east-1"]
    p.client.return_value = ct
    return p


# -----------------------------------------------------------------------------


def test_no_events_no_findings() -> None:
    ct = _ct_with_events(events=[])
    result = trufflehog_ua.detect(_provider(ct))
    assert result.error is None
    assert result.findings == []


def test_normal_ua_not_flagged() -> None:
    """aws-cli or boto3 UA is normal traffic - no finding."""
    ct = _ct_with_events(events=[_event("aws-cli/2.15.0 Python/3.10")])
    result = trufflehog_ua.detect(_provider(ct))
    assert result.findings == []


def test_trufflehog_ua_flagged_critical() -> None:
    ct = _ct_with_events(events=[_event("trufflehog/3.63.2", principal_arn="arn:aws:iam::123456789012:user/exposed")])
    result = trufflehog_ua.detect(_provider(ct))
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.category == Category.THREAT
    assert f.threat_pattern_id == trufflehog_ua.PATTERN_ID
    assert "trufflehog" in f.title.lower()
    assert "exposed" in f.title
    assert "203.0.113.42" in f.description
    assert "TREAT AS CONFIRMED" in f.recommendation


def test_gitleaks_ua_also_flagged() -> None:
    ct = _ct_with_events(events=[_event("gitleaks/8.18.1")])
    result = trufflehog_ua.detect(_provider(ct))
    assert len(result.findings) == 1
    assert "gitleaks" in result.findings[0].title.lower()


def test_case_insensitive_match() -> None:
    """UA matching is case-insensitive (TruffleHog vs trufflehog)."""
    ct = _ct_with_events(events=[_event("TruffleHog/3.0 (compatible)")])
    result = trufflehog_ua.detect(_provider(ct))
    assert len(result.findings) == 1


def test_mixed_events_only_scanner_flagged() -> None:
    ct = _ct_with_events(
        events=[
            _event("aws-cli/2.15.0"),
            _event("trufflehog/3.0", principal_arn="arn:aws:iam::123456789012:user/leak1"),
            _event("Boto3/1.34.0"),
            _event("noseyparker/0.18", principal_arn="arn:aws:iam::123456789012:user/leak2"),
        ]
    )
    result = trufflehog_ua.detect(_provider(ct))
    assert len(result.findings) == 2
    arns = {f.resource_id for f in result.findings}
    assert any("leak1" in a for a in arns)
    assert any("leak2" in a for a in arns)


def test_malformed_cloudtrail_event_skipped() -> None:
    """Event with garbage CloudTrailEvent JSON does not crash the scan."""
    ct = _ct_with_events(events=[{"CloudTrailEvent": "not-valid-json"}, _event("trufflehog/3.0")])
    result = trufflehog_ua.detect(_provider(ct))
    # The valid one is still detected
    assert len(result.findings) == 1


def test_remediation_includes_rotation_steps() -> None:
    ct = _ct_with_events(events=[_event("trufflehog/3.0")])
    result = trufflehog_ua.detect(_provider(ct))
    rem = result.findings[0].remediation
    assert "update-access-key" in rem.cli
    assert "Inactive" in rem.cli
    assert "lookup-events" in rem.cli


def test_unsupported_region_silent() -> None:
    ct = MagicMock()
    paginator = MagicMock()

    class _Validation(Exception):
        def __init__(self) -> None:
            super().__init__("ValidationException")
            self.response = {"Error": {"Code": "ValidationException"}}

    paginator.paginate.side_effect = _Validation()
    ct.get_paginator.return_value = paginator

    result = trufflehog_ua.detect(_provider(ct))
    assert result.error is None
    assert result.findings == []


def test_pattern_metadata_exposed() -> None:
    assert trufflehog_ua.PATTERN_ID == "TF-004-trufflehog-ua-cloudtrail"
    assert trufflehog_ua.CHECK_ID == "aws-tf-004"
    assert trufflehog_ua.PATTERN_SEVERITY == Severity.CRITICAL


def test_cloudgrappler_ua_not_flagged() -> None:
    """v2.2.1: defensive tools (Permiso CloudGrappler) must NOT be flagged.

    Their UA appearing in CloudTrail means a defender is running them
    against the account, not that the account is under attack.
    """
    ct = _ct_with_events(events=[_event("cloudgrappler/1.0")])
    result = trufflehog_ua.detect(_provider(ct))
    assert result.findings == []


def test_detention_dodger_ua_not_flagged() -> None:
    """v2.2.1: defensive tools (Permiso DetentionDodger) must NOT be flagged."""
    ct = _ct_with_events(events=[_event("detention-dodger/1.0")])
    result = trufflehog_ua.detect(_provider(ct))
    assert result.findings == []
