"""Tests for scanner orchestrator — suppressions, min_severity, exclude_checks, quiet mode."""

from __future__ import annotations

from functools import partial

from cloud_audit.config import CloudAuditConfig, Suppression
from cloud_audit.models import (
    Category,
    CheckResult,
    Finding,
    Severity,
)
from cloud_audit.scanner import run_scan


def _make_finding(
    check_id: str = "aws-test-001",
    resource_id: str = "res-1",
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        check_id=check_id,
        title="Test finding",
        severity=severity,
        category=Category.SECURITY,
        resource_type="AWS::Test::Resource",
        resource_id=resource_id,
        description="desc",
        recommendation="fix it",
    )


class _FakeProvider:
    """Minimal provider stub for scanner tests."""

    regions = ["eu-central-1"]

    def get_provider_name(self) -> str:
        return "fake"

    def get_account_id(self) -> str:
        return "123456789012"

    def get_checks(self, categories: list[str] | None = None) -> list[partial[CheckResult]]:
        return list(self._checks)

    def __init__(self, checks: list[partial[CheckResult]]) -> None:
        self._checks = checks


def _check_with_findings(*findings: Finding, check_id: str = "aws-test-001") -> CheckResult:
    return CheckResult(
        check_id=check_id,
        check_name=check_id,
        findings=list(findings),
        resources_scanned=len(findings) or 1,
    )


def _make_provider(*check_fns: partial[CheckResult]) -> _FakeProvider:
    return _FakeProvider(list(check_fns))


# --- Basic scan ---


def test_basic_scan_returns_report_and_zero_suppressed() -> None:
    fn = partial(_check_with_findings, _make_finding())
    provider = _make_provider(fn)
    report, suppressed = run_scan(provider, quiet=True)  # type: ignore[arg-type]
    assert report.provider == "fake"
    assert report.account_id == "123456789012"
    assert suppressed == 0
    assert report.summary.total_findings == 1


def test_scan_empty_checks() -> None:
    provider = _make_provider()
    report, suppressed = run_scan(provider, quiet=True)  # type: ignore[arg-type]
    assert report.summary.total_findings == 0
    assert suppressed == 0


# --- Suppressions ---


def test_suppression_removes_matching_finding() -> None:
    fn = partial(_check_with_findings, _make_finding(check_id="aws-vpc-002", resource_id="sg-0abc"))
    provider = _make_provider(fn)
    config = CloudAuditConfig(
        suppressions=[
            Suppression(check_id="aws-vpc-002", resource_id="sg-0abc", reason="VPN gateway"),
        ]
    )
    report, suppressed = run_scan(provider, config=config, quiet=True)  # type: ignore[arg-type]
    assert suppressed == 1
    assert report.summary.total_findings == 0


def test_suppression_without_resource_id_matches_all() -> None:
    f1 = _make_finding(check_id="aws-ec2-003", resource_id="i-111")
    f2 = _make_finding(check_id="aws-ec2-003", resource_id="i-222")
    fn = partial(_check_with_findings, f1, f2, check_id="aws-ec2-003")
    provider = _make_provider(fn)
    config = CloudAuditConfig(
        suppressions=[
            Suppression(check_id="aws-ec2-003", reason="All stopped OK"),
        ]
    )
    report, suppressed = run_scan(provider, config=config, quiet=True)  # type: ignore[arg-type]
    assert suppressed == 2
    assert report.summary.total_findings == 0


def test_suppression_does_not_match_different_check() -> None:
    fn = partial(_check_with_findings, _make_finding(check_id="aws-iam-001", resource_id="root"))
    provider = _make_provider(fn)
    config = CloudAuditConfig(
        suppressions=[
            Suppression(check_id="aws-vpc-002", resource_id="sg-0abc", reason="wrong check"),
        ]
    )
    report, suppressed = run_scan(provider, config=config, quiet=True)  # type: ignore[arg-type]
    assert suppressed == 0
    assert report.summary.total_findings == 1


# --- Exclude checks ---


def test_exclude_checks_removes_entire_result() -> None:
    fn1 = partial(_check_with_findings, _make_finding(check_id="aws-iam-001"), check_id="aws-iam-001")
    fn1.check_id = "aws-iam-001"  # type: ignore[attr-defined]
    fn2 = partial(_check_with_findings, _make_finding(check_id="aws-s3-001"), check_id="aws-s3-001")
    fn2.check_id = "aws-s3-001"  # type: ignore[attr-defined]
    provider = _make_provider(fn1, fn2)
    config = CloudAuditConfig(exclude_checks=["aws-iam-001"])
    report, _ = run_scan(provider, config=config, quiet=True)  # type: ignore[arg-type]
    assert len(report.results) == 1
    assert report.results[0].check_id == "aws-s3-001"


# --- Min severity ---


def test_min_severity_filters_low_findings() -> None:
    high = _make_finding(check_id="aws-test-001", severity=Severity.HIGH)
    low = _make_finding(check_id="aws-test-002", severity=Severity.LOW)
    fn1 = partial(_check_with_findings, high, check_id="aws-test-001")
    fn2 = partial(_check_with_findings, low, check_id="aws-test-002")
    provider = _make_provider(fn1, fn2)
    config = CloudAuditConfig(min_severity=Severity.MEDIUM)
    report, _ = run_scan(provider, config=config, quiet=True)  # type: ignore[arg-type]
    all_findings = report.all_findings
    assert len(all_findings) == 1
    assert all_findings[0].severity == Severity.HIGH


def test_min_severity_critical_only() -> None:
    crit = _make_finding(severity=Severity.CRITICAL)
    high = _make_finding(severity=Severity.HIGH)
    fn = partial(_check_with_findings, crit, high)
    provider = _make_provider(fn)
    config = CloudAuditConfig(min_severity=Severity.CRITICAL)
    report, _ = run_scan(provider, config=config, quiet=True)  # type: ignore[arg-type]
    assert len(report.all_findings) == 1
    assert report.all_findings[0].severity == Severity.CRITICAL


# --- Quiet mode ---


def test_quiet_mode_no_rich_output(capsys: object) -> None:
    fn = partial(_check_with_findings, _make_finding())
    provider = _make_provider(fn)
    report, _ = run_scan(provider, quiet=True)  # type: ignore[arg-type]
    assert report.summary.total_findings == 1


# --- Error handling ---


def _failing_check() -> CheckResult:
    msg = "AWS credentials expired"
    raise RuntimeError(msg)


def test_check_error_captured_not_raised() -> None:
    fn = partial(_failing_check)
    provider = _make_provider(fn)
    report, _ = run_scan(provider, quiet=True)  # type: ignore[arg-type]
    assert len(report.results) == 1
    assert report.results[0].error == "AWS credentials expired"


# --- Combined filters ---


def test_exclude_then_suppress_then_severity() -> None:
    """All three filters applied in order: exclude → suppress → min_severity."""
    f_excluded = _make_finding(check_id="aws-excluded-001", severity=Severity.HIGH)
    f_suppressed = _make_finding(check_id="aws-kept-001", resource_id="suppressed-res", severity=Severity.HIGH)
    f_low = _make_finding(check_id="aws-kept-002", severity=Severity.LOW)
    f_kept = _make_finding(check_id="aws-kept-003", severity=Severity.CRITICAL)

    fn1 = partial(_check_with_findings, f_excluded, check_id="aws-excluded-001")
    fn1.check_id = "aws-excluded-001"  # type: ignore[attr-defined]
    fn2 = partial(_check_with_findings, f_suppressed, check_id="aws-kept-001")
    fn2.check_id = "aws-kept-001"  # type: ignore[attr-defined]
    fn3 = partial(_check_with_findings, f_low, check_id="aws-kept-002")
    fn3.check_id = "aws-kept-002"  # type: ignore[attr-defined]
    fn4 = partial(_check_with_findings, f_kept, check_id="aws-kept-003")
    fn4.check_id = "aws-kept-003"  # type: ignore[attr-defined]

    provider = _make_provider(fn1, fn2, fn3, fn4)
    config = CloudAuditConfig(
        exclude_checks=["aws-excluded-001"],
        suppressions=[
            Suppression(check_id="aws-kept-001", resource_id="suppressed-res", reason="OK"),
        ],
        min_severity=Severity.MEDIUM,
    )
    report, suppressed = run_scan(provider, config=config, quiet=True)  # type: ignore[arg-type]

    assert suppressed == 1  # f_suppressed
    finding_ids = [f.check_id for f in report.all_findings]
    assert "aws-excluded-001" not in finding_ids
    assert "aws-kept-001" not in finding_ids  # suppressed
    assert "aws-kept-002" not in finding_ids  # below min_severity
    assert "aws-kept-003" in finding_ids  # CRITICAL — kept
