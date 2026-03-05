"""Scanner - orchestrates check execution and produces a report."""

from __future__ import annotations

import time
from datetime import date
from typing import TYPE_CHECKING

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from cloud_audit.models import ScanReport, Severity

if TYPE_CHECKING:
    from cloud_audit.config import CloudAuditConfig
    from cloud_audit.providers.base import BaseProvider

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

    if not checks:
        if not quiet:
            console.print("[yellow]No checks to run.[/yellow]")
        return report, 0

    if not quiet:
        console.print(f"\n[bold]Running {len(checks)} checks on {report.provider.upper()}...[/bold]\n")

    start = time.monotonic()

    if quiet:
        for check_fn in checks:
            try:
                result = check_fn()
                report.results.append(result)
            except Exception as e:
                from cloud_audit.models import CheckResult

                check_id = getattr(check_fn, "__name__", "unknown")
                report.results.append(
                    CheckResult(
                        check_id=check_id,
                        check_name=check_id,
                        error=str(e),
                    )
                )
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
                try:
                    result = check_fn()
                    report.results.append(result)
                except Exception as e:
                    from cloud_audit.models import CheckResult

                    check_id = getattr(check_fn, "__name__", "unknown")
                    report.results.append(
                        CheckResult(
                            check_id=check_id,
                            check_name=check_id,
                            error=str(e),
                        )
                    )

                progress.advance(task)

    report.duration_seconds = round(time.monotonic() - start, 2)

    # Post-scan: remove excluded check results
    if exclude_checks:
        report.results = [r for r in report.results if r.check_id not in exclude_checks]

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
