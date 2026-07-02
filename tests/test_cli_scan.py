"""Tests for CLI scan command - format, quiet, exit codes, env vars, config integration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from cloud_audit.cli import app

if TYPE_CHECKING:
    import pytest

runner = CliRunner()


def _mock_scan(*args, **kwargs):  # type: ignore[no-untyped-def]
    """Mock run_scan that returns a report with one finding."""
    from cloud_audit.models import (
        Category,
        CheckResult,
        Finding,
        ScanReport,
        Severity,
    )

    report = ScanReport(provider="aws", account_id="123456789012", regions=["eu-central-1"])
    report.results.append(
        CheckResult(
            check_id="aws-test-001",
            check_name="Test Check",
            findings=[
                Finding(
                    check_id="aws-test-001",
                    title="Test finding",
                    severity=Severity.HIGH,
                    category=Category.SECURITY,
                    resource_type="AWS::Test::Resource",
                    resource_id="test-resource",
                    description="desc",
                    recommendation="fix",
                )
            ],
            resources_scanned=1,
        )
    )
    report.compute_summary()
    return report, 0


def _mock_scan_clean(*args, **kwargs):  # type: ignore[no-untyped-def]
    """Mock run_scan that returns a clean report."""
    from cloud_audit.models import ScanReport

    report = ScanReport(provider="aws", account_id="123456789012", regions=["eu-central-1"])
    report.compute_summary()
    return report, 0


def _mock_scan_suppressed(*args, **kwargs):  # type: ignore[no-untyped-def]
    """Mock run_scan that returns a clean report with suppressions."""
    from cloud_audit.models import ScanReport

    report = ScanReport(provider="aws", account_id="123456789012", regions=["eu-central-1"])
    report.compute_summary()
    return report, 3


def _patch_scan_and_provider(mock_scan_fn):  # type: ignore[no-untyped-def]
    """Return combined patch context for scanner.run_scan and AWSProvider."""
    mock_provider_cls = MagicMock()
    mock_provider_instance = MagicMock()
    mock_provider_cls.return_value = mock_provider_instance
    return (
        patch("cloud_audit.scanner.run_scan", mock_scan_fn),
        patch("cloud_audit.providers.aws.AWSProvider", mock_provider_cls),
        patch("cloud_audit.providers.aws.provider.AWSProvider", mock_provider_cls),
    )


# --- Exit codes ---


def test_exit_code_1_when_findings() -> None:
    p1, p2, p3 = _patch_scan_and_provider(_mock_scan)
    with p1, p2, p3:
        result = runner.invoke(app, ["scan", "--quiet"])
    assert result.exit_code == 1


def test_exit_code_0_when_clean() -> None:
    p1, p2, p3 = _patch_scan_and_provider(_mock_scan_clean)
    with p1, p2, p3:
        result = runner.invoke(app, ["scan", "--quiet"])
    assert result.exit_code == 0


# --- Quiet mode ---


def test_quiet_mode_no_output() -> None:
    p1, p2, p3 = _patch_scan_and_provider(_mock_scan_clean)
    with p1, p2, p3:
        result = runner.invoke(app, ["scan", "--quiet"])
    assert result.output.strip() == ""


# --- Format JSON to stdout ---


def test_format_json_to_stdout() -> None:
    p1, p2, p3 = _patch_scan_and_provider(_mock_scan)
    with p1, p2, p3:
        result = runner.invoke(app, ["scan", "--format", "json", "--quiet"])
    data = json.loads(result.output)
    assert data["provider"] == "aws"
    assert data["account_id"] == "123456789012"


# --- Format SARIF to stdout ---


def test_format_sarif_to_stdout() -> None:
    p1, p2, p3 = _patch_scan_and_provider(_mock_scan)
    with p1, p2, p3:
        result = runner.invoke(app, ["scan", "--format", "sarif", "--quiet"])
    data = json.loads(result.output)
    assert data["$schema"] is not None
    assert data["version"] == "2.1.0"


# --- Format markdown to stdout ---


def test_format_markdown_to_stdout() -> None:
    p1, p2, p3 = _patch_scan_and_provider(_mock_scan)
    with p1, p2, p3:
        result = runner.invoke(app, ["scan", "--format", "markdown", "--quiet"])
    assert "# cloud-audit scan report" in result.output


# --- Format to file ---


def test_format_json_to_file(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    p1, p2, p3 = _patch_scan_and_provider(_mock_scan)
    with p1, p2, p3:
        runner.invoke(app, ["scan", "--format", "json", "--output", str(out)])
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["provider"] == "aws"


# --- Suffix detection backward compat ---


def test_output_suffix_detection_json(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    p1, p2, p3 = _patch_scan_and_provider(_mock_scan)
    with p1, p2, p3:
        runner.invoke(app, ["scan", "--output", str(out)])
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["provider"] == "aws"


# --- HTML requires --output ---


def test_html_requires_output() -> None:
    p1, p2, p3 = _patch_scan_and_provider(_mock_scan)
    with p1, p2, p3:
        result = runner.invoke(app, ["scan", "--format", "html"])
    assert result.exit_code == 2


# --- Unknown format ---


def test_unknown_format_exits_2() -> None:
    p1, p2, p3 = _patch_scan_and_provider(_mock_scan)
    with p1, p2, p3:
        result = runner.invoke(app, ["scan", "--format", "xml"])
    assert result.exit_code == 2


# --- Unsupported provider ---


def test_unsupported_provider_exits_2() -> None:
    result = runner.invoke(app, ["scan", "--provider", "gcp"])
    assert result.exit_code == 2


# --- Suppressed count in summary ---


def test_suppressed_count_shown() -> None:
    p1, p2, p3 = _patch_scan_and_provider(_mock_scan_suppressed)
    with p1, p2, p3:
        result = runner.invoke(app, ["scan"])
    assert "3" in result.output


# --- Env vars ---


def test_env_regions_used(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLOUD_AUDIT_REGIONS", "us-east-1,us-west-2")
    p1, p2, p3 = _patch_scan_and_provider(_mock_scan_clean)
    with p1, p2, p3:
        result = runner.invoke(app, ["scan", "--quiet"])
    assert result.exit_code == 0


def test_env_role_arn_used(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLOUD_AUDIT_ROLE_ARN", "arn:aws:iam::123:role/audit")
    p1, p2, p3 = _patch_scan_and_provider(_mock_scan_clean)
    with p1, p2, p3:
        result = runner.invoke(app, ["scan", "--quiet"])
    assert result.exit_code == 0


# --- Config file ---


def test_config_file_loaded(tmp_path: Path) -> None:
    cfg = tmp_path / ".cloud-audit.yml"
    cfg.write_text("provider: aws\nmin_severity: high\n", encoding="utf-8")
    p1, p2, p3 = _patch_scan_and_provider(_mock_scan_clean)
    with p1, p2, p3:
        result = runner.invoke(app, ["scan", "--config", str(cfg), "--quiet"])
    assert result.exit_code == 0


# --- list-checks ---


def test_list_checks_runs() -> None:
    result = runner.invoke(app, ["list-checks"])
    assert result.exit_code == 0
    assert "Available checks" in result.output


def test_list_checks_with_category_filter() -> None:
    result = runner.invoke(app, ["list-checks", "--categories", "security"])
    assert result.exit_code == 0


# --- Support line in console summary ---


def test_support_line_in_console_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CLOUD_AUDIT_NO_SUPPORT_LINE", raising=False)
    p1, p2, p3 = _patch_scan_and_provider(_mock_scan)
    with p1, p2, p3:
        result = runner.invoke(app, ["scan"])
    assert "cloud-audit-support" in result.output


def test_support_line_disabled_by_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLOUD_AUDIT_NO_SUPPORT_LINE", "1")
    p1, p2, p3 = _patch_scan_and_provider(_mock_scan)
    with p1, p2, p3:
        result = runner.invoke(app, ["scan"])
    assert "cloud-audit-support" not in result.output


def test_support_line_absent_when_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CLOUD_AUDIT_NO_SUPPORT_LINE", raising=False)
    p1, p2, p3 = _patch_scan_and_provider(_mock_scan_clean)
    with p1, p2, p3:
        result = runner.invoke(app, ["scan"])
    assert "cloud-audit-support" not in result.output


def test_support_line_not_in_json_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CLOUD_AUDIT_NO_SUPPORT_LINE", raising=False)
    p1, p2, p3 = _patch_scan_and_provider(_mock_scan)
    with p1, p2, p3:
        result = runner.invoke(app, ["scan", "--format", "json", "--quiet"])
    assert "cloud-audit-support" not in result.output
