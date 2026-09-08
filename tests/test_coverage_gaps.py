"""Coverage gaps on the report model: reads denied to the scanner are counted, not hidden."""

from __future__ import annotations

import json

from cloud_audit.models import CheckResult, ScanReport
from cloud_audit.reports.markdown import generate_markdown


def _report(*results: CheckResult) -> ScanReport:
    report = ScanReport(provider="aws", account_id="123456789012", regions=["eu-central-1"])
    report.results.extend(results)
    report.compute_summary()
    return report


def test_check_result_defaults_to_no_gaps() -> None:
    r = CheckResult(check_id="aws-agc-005", check_name="gw")
    assert r.coverage_gaps == []


def test_summary_counts_gaps_across_checks() -> None:
    a = CheckResult(check_id="aws-agc-001", check_name="ci", coverage_gaps=["us-east-1: ListCodeInterpreters denied"])
    b = CheckResult(
        check_id="aws-agc-005",
        check_name="gw",
        coverage_gaps=["us-east-1: ListGateways denied", "eu-west-1: ListGateways denied"],
    )
    c = CheckResult(check_id="aws-s3-001", check_name="s3")
    report = _report(a, b, c)
    assert report.summary.coverage_gaps == 3
    # a gap is not an error and not a failure; the check still counts as "passed" (no findings)
    assert report.summary.checks_errored == 0
    assert report.summary.checks_failed == 0
    assert report.summary.checks_passed == 3


def test_gaps_survive_json_round_trip() -> None:
    a = CheckResult(check_id="aws-agc-001", check_name="ci", coverage_gaps=["us-east-1: ListCodeInterpreters denied"])
    report = _report(a)
    loaded = ScanReport.model_validate_json(report.model_dump_json())
    assert loaded.results[0].coverage_gaps == ["us-east-1: ListCodeInterpreters denied"]
    assert loaded.summary.coverage_gaps == 1


def test_old_reports_without_the_field_still_load() -> None:
    """Backward compat: reports written before coverage_gaps existed parse with empty gaps."""
    payload = {
        "provider": "aws",
        "account_id": "123456789012",
        "results": [{"check_id": "aws-agc-001", "check_name": "ci", "findings": [], "resources_scanned": 0}],
    }
    loaded = ScanReport.model_validate_json(json.dumps(payload))
    assert loaded.results[0].coverage_gaps == []
    assert loaded.summary.coverage_gaps == 0


def test_markdown_report_lists_gaps_only_when_present() -> None:
    clean = _report(CheckResult(check_id="aws-s3-001", check_name="s3"))
    assert "Coverage gaps" not in generate_markdown(clean)
    gapped = _report(
        CheckResult(check_id="aws-agc-005", check_name="gw", coverage_gaps=["us-east-1: ListGateways denied"])
    )
    md = generate_markdown(gapped)
    assert "| Coverage gaps (reads denied, not assessed) | 1 |" in md
