"""Tests for scan history persistence and trend analysis."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest  # noqa: TC002

from cloud_audit.history import (
    ScanSnapshot,
    TrendReport,
    _sparkline,
    compute_trend,
    load_history,
    save_scan_to_history,
)
from cloud_audit.models import (
    Category,
    CheckResult,
    CostEstimateData,
    Finding,
    ScanReport,
    ScanSummary,
    Severity,
)


def _make_report(
    account_id: str = "123456789012",
    score: int = 50,
    findings_count: int = 5,
    chains_count: int = 2,
    timestamp: datetime | None = None,
) -> ScanReport:
    """Create a ScanReport with specific summary values."""
    report = ScanReport(
        provider="aws",
        account_id=account_id,
        regions=["eu-central-1"],
        timestamp=timestamp or datetime.now(timezone.utc),
    )
    findings = [
        Finding(
            check_id="aws-test-001",
            title="Test finding",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            resource_type="AWS::Test",
            resource_id=f"test-{i}",
            description="Test",
            recommendation="Test",
        )
        for i in range(findings_count)
    ]
    report.results.append(
        CheckResult(check_id="test", check_name="Test", findings=findings, resources_scanned=findings_count)
    )
    report.summary = ScanSummary(
        total_findings=findings_count,
        attack_chains_detected=chains_count,
        score=score,
        total_risk_exposure=CostEstimateData(
            low_usd=100_000, high_usd=500_000, display="$100K - $500K", rationale="test"
        ),
    )
    return report


class TestSaveAndLoad:
    def test_save_creates_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("cloud_audit.history._HISTORY_DIR", tmp_path / "history")
        report = _make_report()
        path = save_scan_to_history(report)
        assert path is not None
        assert path.exists()
        assert path.suffix == ".json"

    def test_save_without_account_id_returns_none(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("cloud_audit.history._HISTORY_DIR", tmp_path / "history")
        report = _make_report(account_id="")
        assert save_scan_to_history(report) is None

    def test_load_history_returns_snapshots(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("cloud_audit.history._HISTORY_DIR", tmp_path / "history")
        now = datetime.now(timezone.utc)

        for i in range(3):
            report = _make_report(score=50 + i * 10, timestamp=now + timedelta(hours=i))
            save_scan_to_history(report)

        snapshots = load_history("123456789012")
        assert len(snapshots) == 3
        assert snapshots[0].score == 50
        assert snapshots[2].score == 70

    def test_load_empty_account(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("cloud_audit.history._HISTORY_DIR", tmp_path / "history")
        assert load_history("nonexistent") == []


class TestComputeTrend:
    def test_returns_none_with_single_scan(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("cloud_audit.history._HISTORY_DIR", tmp_path / "history")
        save_scan_to_history(_make_report())
        assert compute_trend("123456789012") is None

    def test_computes_deltas(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("cloud_audit.history._HISTORY_DIR", tmp_path / "history")
        now = datetime.now(timezone.utc)

        save_scan_to_history(_make_report(score=30, chains_count=5, timestamp=now))
        save_scan_to_history(_make_report(score=60, chains_count=2, timestamp=now + timedelta(days=1)))
        save_scan_to_history(_make_report(score=90, chains_count=0, timestamp=now + timedelta(days=2)))

        trend = compute_trend("123456789012")
        assert trend is not None
        assert trend.total_scans == 3
        assert trend.score_first == 30
        assert trend.score_last == 90
        assert trend.chains_first == 5
        assert trend.chains_last == 0
        assert len(trend.deltas) == 2
        assert trend.deltas[0].score_delta == 30
        assert trend.deltas[1].score_delta == 30

    def test_limit_caps_scans(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("cloud_audit.history._HISTORY_DIR", tmp_path / "history")
        now = datetime.now(timezone.utc)

        for i in range(10):
            save_scan_to_history(_make_report(score=i * 10, timestamp=now + timedelta(hours=i)))

        trend = compute_trend("123456789012", limit=5)
        assert trend is not None
        assert trend.total_scans == 5


class TestTrendReport:
    def test_properties_empty(self) -> None:
        tr = TrendReport(account_id="test")
        assert tr.total_scans == 0
        assert tr.score_first == 0
        assert tr.score_last == 0

    def test_properties_with_data(self) -> None:
        now = datetime.now(timezone.utc)
        snap_kwargs = {"risk_low": 0, "risk_high": 0, "risk_display": "$0", "escalation_paths": 0}
        tr = TrendReport(
            account_id="test",
            snapshots=[
                ScanSnapshot(timestamp=now, score=30, findings=10, chains=5, **snap_kwargs),
                ScanSnapshot(timestamp=now, score=80, findings=3, chains=1, **snap_kwargs),
            ],
        )
        assert tr.score_first == 30
        assert tr.score_last == 80


class TestSparkline:
    def test_basic(self) -> None:
        result = _sparkline([0, 50, 100])
        assert len(result) == 3
        assert result[0] == " "  # min
        assert result[-1] != " "  # max is not blank

    def test_empty(self) -> None:
        assert _sparkline([]) == ""

    def test_constant(self) -> None:
        result = _sparkline([50, 50, 50])
        assert len(result) == 3

    def test_width_limit(self) -> None:
        result = _sparkline(list(range(20)), width=5)
        assert len(result) == 5
