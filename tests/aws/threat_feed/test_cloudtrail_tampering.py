"""Tests for TF-008: CloudTrail tampering precursors detector."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from cloud_audit.models import Category, Severity
from cloud_audit.providers.aws.provider import AWSProvider
from cloud_audit.providers.aws.threat_feed import cloudtrail_tampering


def _ct_client(trails: list[dict[str, Any]], statuses: dict[str, dict[str, Any]]) -> MagicMock:
    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": trails}

    def get_status(Name: str) -> dict[str, Any]:
        # Match by ARN or by short name
        for key, status in statuses.items():
            if Name.endswith(key) or Name == key:
                return status
        return {"IsLogging": True}

    ct.get_trail_status.side_effect = get_status
    return ct


def _provider(ct: MagicMock, regions: list[str] | None = None) -> MagicMock:
    p = MagicMock(spec=AWSProvider)
    p.regions = regions or ["us-east-1"]
    p.client.return_value = ct
    return p


def _trail(name: str, home_region: str = "us-east-1") -> dict[str, Any]:
    return {
        "Name": name,
        "TrailARN": f"arn:aws:cloudtrail:{home_region}:123456789012:trail/{name}",
        "HomeRegion": home_region,
    }


# -----------------------------------------------------------------------------


def test_no_trails_no_findings() -> None:
    ct = _ct_client(trails=[], statuses={})
    result = cloudtrail_tampering.detect(_provider(ct))
    assert result.error is None
    assert result.findings == []


def test_healthy_logging_trail_not_flagged() -> None:
    ct = _ct_client(
        trails=[_trail("ok-trail")],
        statuses={"ok-trail": {"IsLogging": True, "LatestDeliveryError": ""}},
    )
    result = cloudtrail_tampering.detect(_provider(ct))
    assert result.findings == []
    assert result.resources_scanned == 1


def test_logging_stopped_critical() -> None:
    """IsLogging=False on existing trail = CRITICAL (canonical attacker behaviour)."""
    ct = _ct_client(
        trails=[_trail("stopped-trail")],
        statuses={"stopped-trail": {"IsLogging": False}},
    )
    result = cloudtrail_tampering.detect(_provider(ct))
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.category == Category.THREAT
    assert f.threat_pattern_id == cloudtrail_tampering.PATTERN_ID
    assert "stopped-trail" in f.title
    assert "start-logging" in f.remediation.cli
    assert "StopLogging" in f.remediation.cli  # forensics step


def test_delivery_error_high() -> None:
    """IsLogging=True but delivery error = HIGH (S3 destination broken)."""
    ct = _ct_client(
        trails=[_trail("broken-delivery")],
        statuses={
            "broken-delivery": {
                "IsLogging": True,
                "LatestDeliveryError": "AccessDenied: Bucket policy denies cloudtrail.amazonaws.com",
            }
        },
    )
    result = cloudtrail_tampering.detect(_provider(ct))
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.HIGH
    assert "delivery error" in f.title.lower()
    assert "AccessDenied" in f.description


def test_stopped_trail_with_delivery_error_only_one_finding() -> None:
    """Don't double-flag: if logging is stopped, the delivery error is moot."""
    ct = _ct_client(
        trails=[_trail("double-issue")],
        statuses={
            "double-issue": {
                "IsLogging": False,
                "LatestDeliveryError": "BucketNotFound",
            }
        },
    )
    result = cloudtrail_tampering.detect(_provider(ct))
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.CRITICAL


def test_shadow_trail_skipped_in_secondary_region() -> None:
    """Multi-region trails appear in every region with HomeRegion=primary - count only home."""
    primary_trail = _trail("multi-region-trail", home_region="us-east-1")

    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": [primary_trail]}
    ct.get_trail_status.return_value = {"IsLogging": True}

    p = MagicMock(spec=AWSProvider)
    p.regions = ["eu-west-1"]  # we are scanning eu-west-1, not us-east-1
    p.client.return_value = ct

    result = cloudtrail_tampering.detect(p)
    # Trail's home is us-east-1, we are in eu-west-1 -> shadow, skipped
    assert result.resources_scanned == 0
    assert result.findings == []


def test_describe_trails_access_denied_silent() -> None:
    ct = MagicMock()

    class _Denied(Exception):
        def __init__(self) -> None:
            super().__init__("AccessDeniedException")
            self.response = {"Error": {"Code": "AccessDeniedException"}}

    ct.describe_trails.side_effect = _Denied()

    result = cloudtrail_tampering.detect(_provider(ct))
    assert result.error is None
    assert result.findings == []


def test_pattern_metadata_exposed() -> None:
    assert cloudtrail_tampering.PATTERN_ID == "TF-008-cloudtrail-tampering"
    assert cloudtrail_tampering.CHECK_ID == "aws-tf-008"
    assert cloudtrail_tampering.PATTERN_SEVERITY == Severity.HIGH


def test_top_level_exception_recorded() -> None:
    p = MagicMock(spec=AWSProvider)
    p.regions = ["us-east-1"]
    p.client.side_effect = RuntimeError("boom")
    result = cloudtrail_tampering.detect(p)
    assert "boom" in (result.error or "")
