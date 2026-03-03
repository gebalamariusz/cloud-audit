"""Scanner - orchestrates check execution and produces a report."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from cloud_audit.models import ScanReport

if TYPE_CHECKING:
    from cloud_audit.providers.base import BaseProvider

console = Console()


def run_scan(provider: BaseProvider, categories: list[str] | None = None) -> ScanReport:
    """Execute all checks for the given provider and return a ScanReport."""
    report = ScanReport(provider=provider.get_provider_name())

    # Get account info
    try:
        report.account_id = provider.get_account_id()
    except Exception as e:
        console.print(f"[yellow]Warning: Could not get account ID: {e}[/yellow]")

    if hasattr(provider, "regions"):
        report.regions = provider.regions

    checks = provider.get_checks(categories=categories)

    if not checks:
        console.print("[yellow]No checks to run.[/yellow]")
        return report

    console.print(f"\n[bold]Running {len(checks)} checks on {report.provider.upper()}...[/bold]\n")

    start = time.monotonic()

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
    report.compute_summary()

    return report
