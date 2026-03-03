"""CLI interface for cloud-audit."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cloud_audit import __version__
from cloud_audit.models import Finding, ScanReport, Severity

app = typer.Typer(
    name="cloud-audit",
    help="Scan your cloud infrastructure for security, cost, and reliability issues.",
    no_args_is_help=True,
)
console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "\u2716",
    Severity.HIGH: "\u2716",
    Severity.MEDIUM: "\u26a0",
    Severity.LOW: "\u25cb",
    Severity.INFO: "\u2139",
}


def _print_summary(report: ScanReport) -> None:
    """Print a rich summary of the scan results to the console."""
    s = report.summary
    all_errored = s.checks_errored > 0 and s.checks_passed == 0 and s.checks_failed == 0

    # If all checks errored, show error banner instead of fake score
    if all_errored:
        console.print()
        console.print(
            Panel(
                "[bold red]SCAN FAILED[/bold red]\n\nAll checks returned errors. No resources were scanned.",
                title="[bold red]Error[/bold red]",
                border_style="red",
                width=60,
            )
        )

        # Show error details
        errored_results = [r for r in report.results if r.error]
        if errored_results:
            # Deduplicate error messages
            unique_errors: dict[str, list[str]] = {}
            for r in errored_results:
                err = r.error or "Unknown error"
                err_short = err.split("\n")[0][:120]
                unique_errors.setdefault(err_short, []).append(r.check_id)

            console.print("\n[bold]Errors:[/bold]")
            for err_msg, check_ids in unique_errors.items():
                console.print(f"  [red]{err_msg}[/red]")
                console.print(f"  [dim]Affected checks: {', '.join(check_ids)}[/dim]\n")

        # Common fix suggestions
        console.print("[bold]Common fixes:[/bold]")
        console.print("  1. Check your AWS credentials: [cyan]aws sts get-caller-identity[/cyan]")
        console.print("  2. Refresh expired token: [cyan]aws sso login --profile <name>[/cyan]")
        console.print("  3. Verify region: [cyan]cloud-audit scan --regions eu-central-1[/cyan]")
        console.print("  4. Use a specific profile: [cyan]cloud-audit scan --profile <name>[/cyan]")
        return

    # Score panel
    score = s.score
    if score >= 80:
        score_color = "green"
    elif score >= 50:
        score_color = "yellow"
    else:
        score_color = "red"

    console.print()
    console.print(
        Panel(
            f"[bold {score_color}]{score}[/bold {score_color}] / 100",
            title="[bold]Health Score[/bold]",
            border_style=score_color,
            width=30,
        )
    )

    # Summary table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="dim")
    table.add_column()
    table.add_row("Provider", report.provider.upper())
    table.add_row("Account", report.account_id or "unknown")
    table.add_row("Regions", ", ".join(report.regions) if report.regions else "default")
    table.add_row("Duration", f"{report.duration_seconds}s")
    table.add_row("Resources scanned", str(s.resources_scanned))
    table.add_row("Checks passed", f"[green]{s.checks_passed}[/green]")
    table.add_row("Checks failed", f"[red]{s.checks_failed}[/red]" if s.checks_failed else "0")
    if s.checks_errored:
        table.add_row("Checks errored", f"[yellow]{s.checks_errored}[/yellow]")
    console.print(table)

    # Show errors if any (partial failure)
    if s.checks_errored:
        errored_results = [r for r in report.results if r.error]
        console.print(f"\n[yellow]Warning: {s.checks_errored} check(s) failed with errors:[/yellow]")
        for r in errored_results:
            err_short = (r.error or "Unknown")[:100]
            console.print(f"  [dim]{r.check_name}:[/dim] [yellow]{err_short}[/yellow]")

    # Findings by severity
    if s.by_severity:
        console.print("\n[bold]Findings by severity:[/bold]")
        for sev in Severity:
            count = s.by_severity.get(sev, 0)
            if count:
                color = SEVERITY_COLORS[sev]
                icon = SEVERITY_ICONS[sev]
                console.print(f"  [{color}]{icon} {sev.value.upper()}: {count}[/{color}]")

    # Top findings
    findings = report.all_findings
    if findings:
        severity_order = list(Severity)
        findings_sorted = sorted(findings, key=lambda f: severity_order.index(f.severity))

        shown = min(len(findings_sorted), 10)
        console.print(f"\n[bold]Top findings ({shown} of {len(findings_sorted)}):[/bold]\n")

        findings_table = Table(box=None, padding=(0, 1), show_header=True, header_style="bold")
        findings_table.add_column("Sev", width=8)
        findings_table.add_column("Region", width=14)
        findings_table.add_column("Check")
        findings_table.add_column("Resource")
        findings_table.add_column("Title", max_width=60)

        for f in findings_sorted[:10]:
            sev_color = SEVERITY_COLORS[f.severity]
            findings_table.add_row(
                f"[{sev_color}]{f.severity.value.upper()}[/{sev_color}]",
                f"[dim]{f.region or 'global'}[/dim]",
                f.check_id,
                f.resource_id[:40],
                f.title[:60],
            )

        console.print(findings_table)

        if len(findings_sorted) > 10:
            remaining = len(findings_sorted) - 10
            console.print(f"\n  [dim]... and {remaining} more. See full report for details.[/dim]")
    elif not s.checks_errored:
        console.print("\n[bold green]No issues found. Your infrastructure looks great![/bold green]")


EFFORT_COLORS = {
    "low": "green",
    "medium": "yellow",
    "high": "red",
}


def _print_remediation(findings: list[Finding]) -> None:
    """Print remediation details for findings that have them."""
    actionable = [f for f in findings if f.remediation]
    if not actionable:
        return

    severity_order = list(Severity)
    actionable.sort(key=lambda f: severity_order.index(f.severity))

    console.print(f"\n[bold]Remediation details ({len(actionable)} actionable findings):[/bold]\n")

    for f in actionable:
        rem = f.remediation
        assert rem is not None  # noqa: S101
        sev_color = SEVERITY_COLORS[f.severity]
        effort_color = EFFORT_COLORS[rem.effort.value]

        console.print(f"  [{sev_color}]{f.severity.value.upper()}[/{sev_color}] {f.title}")
        console.print(f"  [dim]Resource:[/dim] {f.resource_id}")
        if f.compliance_refs:
            console.print(f"  [dim]Compliance:[/dim] {', '.join(f.compliance_refs)}")
        console.print(f"  [dim]Effort:[/dim] [{effort_color}]{rem.effort.value.upper()}[/{effort_color}]")
        console.print(f"  [dim]CLI:[/dim] [cyan]{rem.cli}[/cyan]")
        if rem.terraform:
            # Show first line of terraform snippet as preview
            tf_preview = rem.terraform.split("\n")[0]
            console.print(f"  [dim]Terraform:[/dim] {tf_preview} ...")
        console.print(f"  [dim]Docs:[/dim] {rem.doc_url}")
        console.print()


def _export_fixes(findings: list[Finding], output_path: Path) -> None:
    """Export CLI remediation commands as a bash script."""
    actionable = [f for f in findings if f.remediation]
    if not actionable:
        console.print("[yellow]No actionable findings — nothing to export.[/yellow]")
        return

    severity_order = list(Severity)
    actionable.sort(key=lambda f: severity_order.index(f.severity))

    lines = [
        "#!/bin/bash",
        "set -e",
        "",
        "# =============================================================================",
        "# cloud-audit remediation script",
        "# Generated by cloud-audit — https://github.com/gebalamariusz/cloud-audit",
        "# =============================================================================",
        "#",
        "# DRY RUN: All commands are commented out by default.",
        "# Review each command carefully, then uncomment to execute.",
        "#",
        f"# Total actionable findings: {len(actionable)}",
        "# =============================================================================",
        "",
    ]

    for f in actionable:
        rem = f.remediation
        assert rem is not None  # noqa: S101
        lines.append(f"# [{f.severity.value.upper()}] {f.title}")
        lines.append(f"# Resource: {f.resource_id}")
        if f.compliance_refs:
            lines.append(f"# Compliance: {', '.join(f.compliance_refs)}")
        lines.append(f"# {rem.cli}")
        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")
    console.print(f"\n[green]Remediation script saved to {output_path}[/green]")
    console.print(f"[dim]  {len(actionable)} commands (commented out). Review before uncommenting.[/dim]")


@app.command()
def scan(
    provider: Annotated[str, typer.Option("--provider", "-p", help="Cloud provider")] = "aws",
    profile: Annotated[str | None, typer.Option("--profile", help="AWS profile name")] = None,
    regions: Annotated[str | None, typer.Option("--regions", "-r", help="Comma-separated regions, or 'all'")] = None,
    categories: Annotated[
        str | None, typer.Option("--categories", "-c", help="Filter: security,cost,reliability")
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output file path (.html, .json)")] = None,
    remediation: Annotated[
        bool, typer.Option("--remediation", "-R", help="Show remediation details for findings")
    ] = False,
    export_fixes: Annotated[
        Path | None, typer.Option("--export-fixes", help="Export CLI fix commands as bash script")
    ] = None,
) -> None:
    """Scan cloud infrastructure and generate an audit report."""
    from cloud_audit.scanner import run_scan

    region_list = [r.strip() for r in regions.split(",")] if regions else None
    category_list = [c.strip() for c in categories.split(",")] if categories else None

    # Initialize provider
    if provider == "aws":
        from cloud_audit.providers.aws import AWSProvider

        cloud_provider = AWSProvider(profile=profile, regions=region_list)
    else:
        console.print(f"[red]Provider '{provider}' is not supported yet. Available: aws[/red]")
        raise typer.Exit(1)

    # Run scan
    report = run_scan(cloud_provider, categories=category_list)

    # Print summary
    _print_summary(report)

    # Remediation details
    if remediation:
        _print_remediation(report.all_findings)

    # Export fixes script
    if export_fixes:
        _export_fixes(report.all_findings, export_fixes)

    # Write output
    if output:
        suffix = output.suffix.lower()
        if suffix == ".html":
            from cloud_audit.reports.html import render_html

            html = render_html(report)
            output.write_text(html, encoding="utf-8")
            console.print(f"\n[green]HTML report saved to {output}[/green]")
        elif suffix == ".json":
            output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
            console.print(f"\n[green]JSON report saved to {output}[/green]")
        else:
            console.print(f"[red]Unsupported output format: {suffix}. Use .html or .json[/red]")
            raise typer.Exit(1)


@app.command()
def version() -> None:
    """Show version."""
    console.print(f"cloud-audit {__version__}")


if __name__ == "__main__":
    app()
