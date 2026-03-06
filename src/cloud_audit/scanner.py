"""Scanner - orchestrates check execution and produces a report."""

from __future__ import annotations

import time
from datetime import date
from typing import TYPE_CHECKING

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from cloud_audit.models import CheckResult, ScanReport, Severity

if TYPE_CHECKING:
    from cloud_audit.config import CloudAuditConfig
    from cloud_audit.providers.base import BaseProvider, CheckFn

console = Console()

_SEVERITY_ORDER = list(Severity)


def _apply_suppressions(report: ScanReport, config: CloudAuditConfig) -> int:
    """Remove suppressed findings from results. Returns count of suppressed findings."""
    today = date.today()
    suppressed = 0

    active_suppressions = [s for s in config.suppressions if not s.is_expired(today)]

    for check_result in report.results:
        original = check_result.findings[:]
        kept = []
        for finding in original:
            matched = any(s.matches(finding.check_id, finding.resource_id) for s in active_suppressions)
            if matched:
                suppressed += 1
            else:
                kept.append(finding)
        check_result.findings = kept

    return suppressed


def _apply_min_severity(report: ScanReport, min_severity: Severity) -> None:
    """Remove findings below the minimum severity threshold."""
    min_idx = _SEVERITY_ORDER.index(min_severity)

    for check_result in report.results:
        check_result.findings = [f for f in check_result.findings if _SEVERITY_ORDER.index(f.severity) <= min_idx]


def _get_check_id(check_fn: object) -> str:
    """Extract check_id from a check function (partial with metadata or plain callable)."""
    # Prefer explicit .check_id attribute (set by make_check)
    check_id = getattr(check_fn, "check_id", None)
    if check_id:
        return str(check_id)
    # Fallback: function name from partial
    if hasattr(check_fn, "func"):
        return str(check_fn.func.__name__)
    return str(getattr(check_fn, "__name__", "unknown"))


def _execute_check(check_fn: CheckFn) -> CheckResult:
    """Execute a single check, catching exceptions into CheckResult.error."""
    try:
        result: CheckResult = check_fn()
        return result
    except Exception as e:
        check_id = _get_check_id(check_fn)
        return CheckResult(
            check_id=check_id,
            check_name=check_id,
            error=str(e),
        )


def run_scan(
    provider: BaseProvider,
    categories: list[str] | None = None,
    config: CloudAuditConfig | None = None,
    quiet: bool = False,
) -> tuple[ScanReport, int]:
    """Execute all checks for the given provider and return a ScanReport.

    Returns (report, suppressed_count).
    """
    report = ScanReport(provider=provider.get_provider_name())

    # Get account info
    try:
        report.account_id = provider.get_account_id()
    except Exception as e:
        if not quiet:
            console.print(f"[yellow]Warning: Could not get account ID: {e}[/yellow]")

    if hasattr(provider, "regions"):
        report.regions = provider.regions

    exclude_checks: set[str] = set(config.exclude_checks) if config else set()

    checks = provider.get_checks(categories=categories)

    # Pre-filter: skip excluded checks before making any API calls
    if exclude_checks:
        checks = [c for c in checks if _get_check_id(c) not in exclude_checks]

    if not checks:
        if not quiet:
            console.print("[yellow]No checks to run.[/yellow]")
        return report, 0

    if not quiet:
        console.print(f"\n[bold]Running {len(checks)} checks on {report.provider.upper()}...[/bold]\n")

    # Reset per-scan caches
    from cloud_audit.providers.aws.checks.s3 import _reset_bucket_cache

    _reset_bucket_cache()

    start = time.monotonic()

    if quiet:
        for check_fn in checks:
            report.results.append(_execute_check(check_fn))
    else:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning", total=len(checks))

            for check_fn in checks:
                report.results.append(_execute_check(check_fn))
                progress.advance(task)

    report.duration_seconds = round(time.monotonic() - start, 2)

    # Post-scan: apply suppressions
    suppressed_count = 0
    if config and config.suppressions:
        suppressed_count = _apply_suppressions(report, config)

    # Post-scan: apply min_severity filter
    effective_severity = config.min_severity if config else None
    if effective_severity:
        _apply_min_severity(report, effective_severity)

    report.compute_summary()

    return report, suppressed_count
