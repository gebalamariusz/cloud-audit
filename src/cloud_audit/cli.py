"""CLI interface for cloud-audit."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
from rich.console import Console
from rich.markup import escape as rich_escape
from rich.panel import Panel
from rich.table import Table

from cloud_audit import __version__
from cloud_audit.models import Effort, Finding, ScanReport, Severity

if TYPE_CHECKING:
    from cloud_audit.diff import DiffResult

app = typer.Typer(
    name="cloud-audit",
    help="Scan your cloud infrastructure for security, cost, and reliability issues.",
    no_args_is_help=True,
)
console = Console()


def _safe_write_text(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    """Write text to ``path`` without following pre-existing symlinks.

    Defense against a TOCTOU symlink attack in shared CI runners or multi-user
    workstations: a hostile collaborator could place ``report.json`` as a
    symlink to ``~/.aws/credentials`` or ``/etc/shadow`` before the user runs
    cloud-audit, then the bare ``path.write_text(...)`` happily follows it and
    clobbers the target. Refusing to write through a symlink closes that path.

    The check is best-effort (an attacker who can replace the file between
    the ``is_symlink`` test and the open is still possible in theory), but
    that race is much harder to win than the static pre-placement case.
    """
    if path.is_symlink():
        raise typer.BadParameter(
            f"Refusing to write to {path}: target is a symbolic link. Remove or move the symlink and re-run."
        )
    path.write_text(content, encoding=encoding)


SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "x",
    Severity.HIGH: "x",
    Severity.MEDIUM: "!",
    Severity.LOW: "o",
    Severity.INFO: "i",
}


def _print_summary(report: ScanReport, suppressed_count: int = 0) -> None:
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
    if s.attack_chains_detected:
        table.add_row("Attack chains", f"[red]{s.attack_chains_detected}[/red]")
    if s.total_risk_exposure and s.total_risk_exposure.high_usd > 0:
        risk_display = s.total_risk_exposure.display
        table.add_row("Risk exposure", f"[bold red]{risk_display}[/bold red]  [dim](IBM/Verizon data)[/dim]")
    if suppressed_count:
        table.add_row("Findings suppressed", f"[dim]{suppressed_count}[/dim]")
    console.print(table)

    # Show errors if any (partial failure)
    if s.checks_errored:
        errored_results = [r for r in report.results if r.error]
        console.print(f"\n[yellow]Warning: {s.checks_errored} check(s) failed with errors:[/yellow]")
        for r in errored_results:
            err_short = (r.error or "Unknown")[:100]
            console.print(f"  [dim]{r.check_name}:[/dim] [yellow]{err_short}[/yellow]")

    # Attack chains
    if report.attack_chains:
        chains_table = Table(
            show_header=False,
            box=None,
            padding=(0, 2),
            show_edge=False,
        )
        chains_table.add_column(width=10)
        chains_table.add_column()

        for chain in report.attack_chains:
            sev_color = SEVERITY_COLORS.get(chain.severity, "dim")
            chains_table.add_row(
                f"[{sev_color}]{chain.severity.value.upper()}[/{sev_color}]",
                f"[bold]{rich_escape(chain.name)}[/bold]",
            )
            resources_str = ", ".join(chain.resources[:3]) if chain.resources else ""
            if resources_str:
                chains_table.add_row("", f"[dim]{rich_escape(resources_str)}[/dim]")
            chains_table.add_row("", f"[italic]{rich_escape(chain.attack_narrative)}[/italic]")
            chains_table.add_row(
                "",
                f"Fix: {rich_escape(chain.priority_fix)}",
            )
            if chain.cost_estimate and chain.cost_estimate.high_usd > 0:
                chains_table.add_row(
                    "",
                    f"[bold]Risk: {chain.cost_estimate.display}[/bold]",
                )
            chains_table.add_row("", "")

        console.print(
            Panel(
                chains_table,
                title=f"[bold]Attack Chains ({len(report.attack_chains)} detected)[/bold]",
                border_style="red",
                width=80,
            )
        )

    # Remediation Plan (root cause grouping)
    if report.root_causes:
        total_chains_broken = len({cid for rc in report.root_causes for cid in rc.chains_broken})
        plan_table = Table(box=None, padding=(0, 1), show_header=True, header_style="bold")
        plan_table.add_column("#", width=3, justify="right")
        plan_table.add_column("Fix", min_width=30)
        plan_table.add_column("Effort", width=8)
        plan_table.add_column("Chains", width=7, justify="right")
        plan_table.add_column("Findings", width=9, justify="right")

        has_risk = any(rc.total_risk_reduced for rc in report.root_causes)
        if has_risk:
            plan_table.add_column("Risk Reduced", width=18)

        for i, rc in enumerate(report.root_causes, 1):
            effort_colors = {"low": "green", "medium": "yellow", "high": "red"}
            effort_color = effort_colors.get(rc.effort.value, "dim")
            row: list[str] = [
                str(i),
                rich_escape(rc.fix_title),
                f"[{effort_color}]{rc.effort.value.upper()}[/{effort_color}]",
                str(len(rc.chains_broken)),
                str(rc.findings_closed),
            ]
            if has_risk:
                row.append(rc.total_risk_reduced.display if rc.total_risk_reduced else "")
            plan_table.add_row(*row)

        console.print(
            Panel(
                plan_table,
                title=(
                    f"[bold]Remediation Plan "
                    f"(fix {len(report.root_causes)} things, break {total_chains_broken} chains)[/bold]"
                ),
                border_style="cyan",
                width=80,
            )
        )

    # Quick Wins (copy-paste commands that break CRITICAL chains)
    if report.root_causes and report.attack_chains:
        critical_chain_ids = {c.chain_id for c in report.attack_chains if c.severity == Severity.CRITICAL}
        quick_wins = [
            rc
            for rc in report.root_causes
            if rc.effort == Effort.LOW and rc.remediation and any(cid in critical_chain_ids for cid in rc.chains_broken)
        ]
        if quick_wins:
            chain_name_map = {c.chain_id: c.name for c in report.attack_chains}
            qw_lines: list[str] = []
            for i, qw in enumerate(quick_wins[:5], 1):
                rem = qw.remediation
                if not rem:
                    continue
                cli_first_line = rem.cli.split("\n")[0]
                if cli_first_line.startswith("#"):
                    cli_lines = [ln for ln in rem.cli.split("\n") if not ln.startswith("#")]
                    cli_first_line = cli_lines[0] if cli_lines else cli_first_line
                broken_names = ", ".join(
                    f"{cid} ({chain_name_map.get(cid, '')})" for cid in qw.chains_broken if cid in critical_chain_ids
                )
                qw_lines.append(
                    f"[bold]{i}.[/bold] [green]{rich_escape(cli_first_line.strip())}[/green]\n"
                    f"   [dim]Breaks: {rich_escape(broken_names)}[/dim]"
                )
            console.print(
                Panel(
                    "\n\n".join(qw_lines),
                    title="[bold]Quick Wins (break CRITICAL chains now)[/bold]",
                    border_style="green",
                    width=80,
                )
            )

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

        has_costs = any(f.cost_estimate for f in findings_sorted[:10])

        findings_table = Table(box=None, padding=(0, 1), show_header=True, header_style="bold")
        findings_table.add_column("Sev", width=8)
        findings_table.add_column("Region", width=14)
        findings_table.add_column("Check")
        findings_table.add_column("Resource")
        findings_table.add_column("Title", max_width=50)
        if has_costs:
            findings_table.add_column("Risk", width=16)

        for f in findings_sorted[:10]:
            sev_color = SEVERITY_COLORS[f.severity]
            row = [
                f"[{sev_color}]{f.severity.value.upper()}[/{sev_color}]",
                f"[dim]{f.region or 'global'}[/dim]",
                f.check_id,
                f.resource_id[:40],
                f.title[:50],
            ]
            if has_costs:
                if f.cost_estimate:
                    cost_str = f.cost_estimate.display
                    if f.cost_estimate.source_url:
                        # Show short source tag
                        url = f.cost_estimate.source_url
                        if "ibm.com" in url:
                            src = "IBM"
                        elif "verizon.com" in url:
                            src = "Verizon"
                        elif "capitalone" in url:
                            src = "CapitalOne"
                        elif "mitre.org" in url:
                            src = "MITRE"
                        elif "owasp.org" in url:
                            src = "OWASP"
                        elif "nist.gov" in url:
                            src = "NIST"
                        elif "cisecurity" in url:
                            src = "CIS"
                        else:
                            src = ""
                        if src:
                            cost_str = f"{cost_str} [dim]({src})[/dim]"
                else:
                    cost_str = "-"
                row.append(cost_str)
            findings_table.add_row(*row)

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
        if rem is None:
            continue
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


def _sanitize_shell(value: str) -> str:
    """Strip shell metacharacters from values embedded in bash script comments."""
    return re.sub(r"[`$();&|\\'\"\n\r]", "", value)


def _export_fixes(findings: list[Finding], output_path: Path) -> None:
    """Export CLI remediation commands as a bash script."""
    actionable = [f for f in findings if f.remediation]
    if not actionable:
        console.print("[yellow]No actionable findings - nothing to export.[/yellow]")
        return

    severity_order = list(Severity)
    actionable.sort(key=lambda f: severity_order.index(f.severity))

    lines = [
        "#!/bin/bash",
        "set -e",
        "",
        "# =============================================================================",
        "# cloud-audit remediation script",
        "# Generated by cloud-audit - https://github.com/gebalamariusz/cloud-audit",
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
        if rem is None:
            continue
        lines.append(f"# [{f.severity.value.upper()}] {_sanitize_shell(f.title)}")
        lines.append(f"# Resource: {_sanitize_shell(f.resource_id)}")
        if f.compliance_refs:
            lines.append(f"# Compliance: {', '.join(f.compliance_refs)}")
        lines.append(f"# {_sanitize_shell(rem.cli)}")
        lines.append("")

    import contextlib

    _safe_write_text(output_path, "\n".join(lines))
    with contextlib.suppress(OSError):
        output_path.chmod(0o700)
    console.print(f"\n[green]Remediation script saved to {output_path}[/green]")
    console.print(f"[dim]  {len(actionable)} commands (commented out). Review before uncommenting.[/dim]")


def _resolve_env_regions() -> str | None:
    """Read CLOUD_AUDIT_REGIONS env var."""
    return os.environ.get("CLOUD_AUDIT_REGIONS")


def _resolve_env_min_severity() -> Severity | None:
    """Read CLOUD_AUDIT_MIN_SEVERITY env var."""
    val = os.environ.get("CLOUD_AUDIT_MIN_SEVERITY")
    if val:
        try:
            return Severity(val.lower())
        except ValueError:
            console.print(
                f"[red]Invalid CLOUD_AUDIT_MIN_SEVERITY='{val}'. Valid: {', '.join(s.value for s in Severity)}[/red]"
            )
            raise typer.Exit(2) from None
    return None


def _resolve_env_exclude_checks() -> list[str] | None:
    """Read CLOUD_AUDIT_EXCLUDE_CHECKS env var."""
    val = os.environ.get("CLOUD_AUDIT_EXCLUDE_CHECKS")
    if val:
        return [c.strip() for c in val.split(",") if c.strip()]
    return None


def _resolve_env_role_arn() -> str | None:
    """Read CLOUD_AUDIT_ROLE_ARN env var."""
    return os.environ.get("CLOUD_AUDIT_ROLE_ARN")


@app.command()
def scan(
    provider: Annotated[str, typer.Option("--provider", "-p", help="Cloud provider")] = "aws",
    profile: Annotated[str | None, typer.Option("--profile", help="AWS profile name")] = None,
    regions: Annotated[str | None, typer.Option("--regions", "-r", help="Comma-separated regions, or 'all'")] = None,
    categories: Annotated[
        str | None, typer.Option("--categories", "-c", help="Filter: security,cost,reliability")
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output file path")] = None,
    fmt: Annotated[
        str | None, typer.Option("--format", "-f", help="Output format: json, html, sarif, markdown")
    ] = None,
    min_severity: Annotated[
        str | None, typer.Option("--min-severity", help="Minimum severity: critical, high, medium, low, info")
    ] = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Quiet mode - exit code only")] = False,
    role_arn: Annotated[str | None, typer.Option("--role-arn", help="IAM role ARN for cross-account scanning")] = None,
    config: Annotated[Path | None, typer.Option("--config", help="Path to .cloud-audit.yml config file")] = None,
    remediation: Annotated[
        bool, typer.Option("--remediation", "-R", help="Show remediation details for findings")
    ] = False,
    export_fixes: Annotated[
        Path | None, typer.Option("--export-fixes", help="Export CLI fix commands as bash script")
    ] = None,
    compliance: Annotated[
        str | None,
        typer.Option(
            "--compliance",
            help="Compliance framework ID. Use list-frameworks to see all options.",
        ),
    ] = None,
) -> None:
    """Scan cloud infrastructure and generate an audit report."""
    from cloud_audit.config import CloudAuditConfig, load_config
    from cloud_audit.scanner import run_scan

    # Load config file
    try:
        cfg = load_config(config)
    except Exception as e:
        console.print(f"[red]Config error: {e}[/red]")
        raise typer.Exit(2) from None

    # Resolve precedence: CLI flags > env vars > config > defaults

    # Regions: CLI > env > config
    env_regions = _resolve_env_regions()
    if regions:
        region_list = [r.strip() for r in regions.split(",")]
    elif env_regions:
        region_list = [r.strip() for r in env_regions.split(",")]
    elif cfg.regions:
        region_list = cfg.regions
    else:
        region_list = None

    # Role ARN: CLI > env > none
    effective_role_arn = role_arn or _resolve_env_role_arn()

    # Min severity: CLI > env > config
    env_severity = _resolve_env_min_severity()
    effective_severity: Severity | None = None
    if min_severity:
        try:
            effective_severity = Severity(min_severity.lower())
        except ValueError:
            console.print(
                f"[red]Invalid --min-severity='{min_severity}'. Valid: {', '.join(s.value for s in Severity)}[/red]"
            )
            raise typer.Exit(2) from None
    elif env_severity:
        effective_severity = env_severity
    elif cfg.min_severity:
        effective_severity = cfg.min_severity

    # Exclude checks: env extends config
    env_excludes = _resolve_env_exclude_checks()
    all_excludes = list(set(cfg.exclude_checks + env_excludes)) if env_excludes else cfg.exclude_checks

    # Build effective config for scanner
    effective_config = CloudAuditConfig(
        provider=cfg.provider,
        profile=cfg.profile,
        regions=region_list,
        min_severity=effective_severity,
        exclude_checks=all_excludes,
        suppressions=cfg.suppressions,
    )

    # Validate format early (before scan) to avoid wasting time
    if fmt and fmt not in ("json", "html", "sarif", "markdown"):
        console.print(f"[red]Unknown format '{fmt}'. Available: json, html, sarif, markdown[/red]")
        raise typer.Exit(2)
    if compliance and fmt in ("json", "sarif"):
        console.print(f"[red]--compliance does not support --format {fmt}. Use html or markdown.[/red]")
        raise typer.Exit(2)
    if fmt == "html" and not output:
        console.print("[red]HTML format requires --output <file.html>[/red]")
        raise typer.Exit(2)

    category_list = [c.strip().lower() for c in categories.split(",")] if categories else None

    # Initialize provider
    if provider == "aws":
        from cloud_audit.providers.aws import AWSProvider

        effective_profile = profile or cfg.profile
        cloud_provider = AWSProvider(profile=effective_profile, regions=region_list, role_arn=effective_role_arn)
    else:
        console.print(f"[red]Provider '{provider}' is not supported yet. Available: aws[/red]")
        raise typer.Exit(2)

    # Run scan
    report, suppressed_count = run_scan(
        cloud_provider,
        categories=category_list,
        config=effective_config,
        quiet=quiet,
    )

    # Determine exit code: 0=clean, 1=findings, 2=errors
    has_findings = report.summary.total_findings > 0
    s = report.summary
    all_errored = s.checks_errored > 0 and s.checks_passed == 0 and s.checks_failed == 0

    # Compliance assessment (if requested)
    comp_report = None
    if compliance:
        from cloud_audit.compliance.engine import build_compliance_report

        try:
            # Get attack chains for compliance context
            attack_chains = []
            try:
                from cloud_audit.correlate import collect_relationships, detect_attack_chains

                rels = collect_relationships(cloud_provider, report.all_findings)
                attack_chains = detect_attack_chains(report.all_findings, rels)
            except Exception:  # noqa: S110 - attack chains are optional for compliance
                pass

            comp_report = build_compliance_report(compliance, report, attack_chains)
        except FileNotFoundError as e:
            console.print(f"[red]{e}[/red]")
            raise typer.Exit(2) from None

    # Format output
    if fmt:
        _handle_format(fmt, report, output, quiet, comp_report)
    elif output:
        # Backward compat: detect format from suffix
        suffix = output.suffix.lower()
        suffix_to_fmt = {".json": "json", ".html": "html", ".sarif": "sarif", ".md": "markdown"}
        detected_fmt = suffix_to_fmt.get(suffix)
        if detected_fmt:
            _handle_format(detected_fmt, report, output, quiet, comp_report)
        else:
            console.print(f"[red]Cannot detect format from suffix '{suffix}'. Use --format explicitly.[/red]")
            raise typer.Exit(2)
    else:
        # Default: Rich console output
        if not quiet:
            if comp_report:
                _print_compliance_summary(comp_report)
            else:
                _print_summary(report, suppressed_count)

            if remediation:
                _print_remediation(report.all_findings)

            if export_fixes:
                _export_fixes(report.all_findings, export_fixes)

    # Auto-save scan report for simulate/trend commands
    _auto_save_report(report)

    # Exit code
    if all_errored:
        raise typer.Exit(2)
    if has_findings:
        raise typer.Exit(1)


def _handle_format(
    fmt: str, report: ScanReport, output: Path | None, quiet: bool, comp_report: object | None = None
) -> None:
    """Handle --format output. Writes to file or stdout."""
    if fmt == "json":
        content = report.model_dump_json(indent=2)
    elif fmt == "sarif":
        from cloud_audit.reports.sarif import generate_sarif

        content = generate_sarif(report)
    elif fmt == "markdown":
        if comp_report:
            from cloud_audit.reports.compliance_markdown import generate_compliance_markdown

            content = generate_compliance_markdown(comp_report)  # type: ignore[arg-type]
        else:
            from cloud_audit.reports.markdown import generate_markdown

            content = generate_markdown(report)
    elif fmt == "html":
        if not output:
            console.print("[red]HTML format requires --output <file.html>[/red]")
            raise typer.Exit(2)
        if comp_report:
            from cloud_audit.reports.compliance_html import generate_compliance_html

            content = generate_compliance_html(comp_report)  # type: ignore[arg-type]
        else:
            from cloud_audit.reports.html import render_html

            content = render_html(report)
    else:
        console.print(f"[red]Unknown format '{fmt}'. Available: json, html, sarif, markdown[/red]")
        raise typer.Exit(2)

    if output:
        _safe_write_text(output, content)
        if not quiet:
            console.print(f"[green]{fmt.upper()} report saved to {output}[/green]")
    else:
        sys.stdout.write(content)
        sys.stdout.write("\n")


@app.command(name="list-checks")
def list_checks(
    provider: Annotated[str, typer.Option("--provider", "-p", help="Cloud provider")] = "aws",
    categories: Annotated[
        str | None, typer.Option("--categories", "-c", help="Filter: security,cost,reliability")
    ] = None,
) -> None:
    """List all available checks."""
    if provider == "aws":
        from cloud_audit.providers.aws.provider import _CHECK_MODULES
    else:
        console.print(f"[red]Provider '{provider}' is not supported yet. Available: aws[/red]")
        raise typer.Exit(2)

    category_list = [c.strip().lower() for c in categories.split(",")] if categories else None

    table = Table(title=f"Available checks ({provider.upper()})", show_lines=False)
    table.add_column("Check", style="bold")
    table.add_column("Category")
    table.add_column("Service")

    count = 0
    for module in _CHECK_MODULES:
        # Module name = service name (e.g., iam, s3, ec2)
        service = module.__name__.rsplit(".", 1)[-1].rstrip("_")

        # get_checks requires a provider but we only inspect the returned partials, never call them.
        # Using a sentinel avoids passing None which could break if get_checks validates its argument.
        _sentinel = type("_Sentinel", (), {})()
        try:
            checks = module.get_checks(_sentinel)
        except Exception as exc:
            console.print(f"[yellow]Warning: failed to load checks from {module.__name__}: {exc}[/yellow]")
            continue

        for check_fn in checks:
            category = getattr(check_fn, "category", "unknown")

            cat_val = getattr(category, "value", str(category))
            if category_list and cat_val not in category_list:
                continue

            func_name = getattr(check_fn, "func", check_fn).__name__
            # Convert function name to readable: check_root_mfa -> Root MFA
            readable = func_name.replace("check_", "").replace("_", " ").title()

            cat_color = {"security": "red", "cost": "yellow", "reliability": "cyan", "performance": "green"}.get(
                str(getattr(category, "value", category)), "white"
            )

            table.add_row(
                readable,
                f"[{cat_color}]{getattr(category, 'value', category).upper()}[/{cat_color}]",
                service.upper(),
            )
            count += 1

    console.print(table)
    console.print(f"\n[dim]Total: {count} checks[/dim]")


def _print_compliance_summary(comp_report: object) -> None:
    """Print a Rich compliance assessment summary."""
    from cloud_audit.compliance.engine import ComplianceReport  # noqa: TC001

    cr: ComplianceReport = comp_report  # type: ignore[assignment]

    # Header panel
    score = cr.readiness_score
    score_color = "green" if score >= 80 else ("yellow" if score >= 50 else "red")
    header = (
        f"[bold]{cr.framework_name} v{cr.version}[/bold]\n\n"
        f"Readiness: [{score_color}]{score:.0f}%[/{score_color}]  "
        f"({cr.controls_passing}/{cr.controls_assessed} assessed controls passing)\n"
        f"Coverage: {cr.controls_assessed + cr.controls_not_assessed} controls total, "
        f"{cr.controls_assessed} assessed, {cr.controls_not_assessed} not assessed"
    )
    console.print(Panel(header, title="[bold]Compliance Assessment[/bold]", border_style=score_color))

    # Controls table
    table = Table(title="Controls", show_lines=False, padding=(0, 1))
    table.add_column("Status", width=6)
    table.add_column("ID", width=7, style="bold")
    table.add_column("Title", max_width=55)
    table.add_column("Checks", width=12, justify="right")

    status_style = {
        "PASS": "[green]PASS[/green]",
        "FAIL": "[red]FAIL[/red]",
        "PARTIAL": "[yellow]PART[/yellow]",
        "NOT_ASSESSED": "[dim]N/A[/dim]",
    }

    for ctrl in cr.controls:
        status_str = status_style.get(ctrl.status, ctrl.status)
        chain_marker = " [red]![/red]" if ctrl.violated_by_chains else ""
        checks_str = f"{ctrl.checks_passed}/{ctrl.checks_total}" if ctrl.checks_total > 0 else "[dim]-[/dim]"
        table.add_row(
            status_str,
            ctrl.control_id,
            rich_escape(ctrl.title[:55]) + chain_marker,
            checks_str,
        )

    console.print(table)

    # Attack chain violations
    if cr.chain_violations:
        console.print(f"\n[bold red]Attack Chain Violations ({len(cr.chain_violations)}):[/bold red]")
        for chain, controls in cr.chain_violations:
            ctrl_ids = ", ".join(controls)
            sev_color = SEVERITY_COLORS.get(chain.severity, "dim")
            console.print(
                f"  [{sev_color}]{chain.severity.value.upper():8s}[/{sev_color}]  "
                f"{rich_escape(chain.name)} -> violates {ctrl_ids}"
            )

    # Footer
    console.print()
    if cr.controls_failing > 0 or cr.controls_partial > 0:
        console.print("[dim]For per-control remediation, evidence statements, and compliance references:[/dim]")
        console.print(
            f"[bold]  cloud-audit scan --compliance {cr.framework_id} --format html -o compliance-report.html[/bold]"
        )
    console.print()


@app.command(name="list-frameworks")
def list_frameworks_cmd() -> None:
    """List available compliance frameworks."""
    from cloud_audit.compliance import list_frameworks

    fws = list_frameworks()
    if not fws:
        console.print("[yellow]No compliance frameworks found.[/yellow]")
        return

    table = Table(title="Available Compliance Frameworks", show_lines=False)
    table.add_column("ID", style="bold")
    table.add_column("Name")
    table.add_column("Version")
    table.add_column("Controls", justify="right")
    table.add_column("Status")

    for fw in fws:
        status = fw.get("status", "stable")
        status_display = "[green]Stable[/green]" if status == "stable" else "[yellow]Beta[/yellow]"
        table.add_row(fw["id"], fw["name"], fw["version"], fw["controls_total"], status_display)

    console.print(table)
    console.print("\n[dim]Usage: cloud-audit scan --compliance <ID>[/dim]")


@app.command(name="show-framework")
def show_framework_cmd(
    framework_id: Annotated[str, typer.Argument(help="Framework ID. Use list-frameworks to see all options.")],
) -> None:
    """Show controls for a compliance framework (no scan needed)."""
    from cloud_audit.compliance import load_framework

    try:
        fw = load_framework(framework_id)
    except FileNotFoundError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(2) from None

    console.print(f"\n[bold]{fw['framework_name']} v{fw.get('version', '')}[/bold]")
    console.print(f"[dim]{fw.get('source_url', '')}[/dim]\n")

    table = Table(show_lines=False, padding=(0, 1))
    table.add_column("ID", width=7, style="bold")
    table.add_column("Level", width=4)
    table.add_column("Type", width=6)
    table.add_column("Title", max_width=55)
    table.add_column("Checks", width=30)

    controls = fw.get("controls", {})
    for cid, ctrl in sorted(controls.items(), key=lambda x: [int(p) if p.isdigit() else p for p in x[0].split(".")]):
        checks = ctrl.get("checks", [])
        checks_str = ", ".join(checks) if checks else "[dim](manual)[/dim]"
        assessment = "Auto" if checks else "Man."
        table.add_row(cid, ctrl.get("level", ""), assessment, ctrl.get("title", "")[:55], checks_str)

    console.print(table)
    console.print(f"\n[dim]Total: {len(controls)} controls[/dim]")


@app.command()
def demo() -> None:
    """Show a demo scan with sample output (no AWS credentials needed)."""
    import time

    from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn

    console.print()

    # Simulate progress bar
    with Progress(
        TextColumn("[bold]Running 80 checks on AWS..."),
        BarColumn(bar_width=40),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning", total=80)
        for _ in range(80):
            time.sleep(0.04)
            progress.advance(task)

    # Health score
    console.print()
    console.print(
        Panel(
            "[bold yellow]62[/bold yellow] / 100",
            title="[bold]Health Score[/bold]",
            border_style="yellow",
            width=30,
        )
    )

    # Summary table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="dim")
    table.add_column()
    table.add_row("Provider", "AWS")
    table.add_row("Account", "123456789012")
    table.add_row("Regions", "eu-central-1")
    table.add_row("Duration", "12s")
    table.add_row("Resources scanned", "147")
    table.add_row("Checks passed", "[green]11[/green]")
    table.add_row("Checks failed", "[red]6[/red]")
    console.print(table)

    # Attack chains demo
    demo_chains_table = Table(show_header=False, box=None, padding=(0, 2), show_edge=False)
    demo_chains_table.add_column(width=10)
    demo_chains_table.add_column()
    demo_chains_table.add_row(
        "[bold red]CRITICAL[/bold red]",
        "[bold]Internet-Exposed Admin Instance[/bold]",
    )
    demo_chains_table.add_row("", "[dim]i-0abc123def456789[/dim]")
    demo_chains_table.add_row(
        "",
        "[italic]Attacker lands on EC2 via public SG, queries IMDS for admin role credentials[/italic]",
    )
    demo_chains_table.add_row("", "Fix: Close security group ingress (effort: LOW)")
    demo_chains_table.add_row("", "")
    demo_chains_table.add_row(
        "[bold red]CRITICAL[/bold red]",
        "[bold]CI/CD to Admin Takeover[/bold]",
    )
    demo_chains_table.add_row("", "[dim]github-deploy-role[/dim]")
    demo_chains_table.add_row(
        "",
        "[italic]Any GitHub repo assumes deploy role via OIDC without sub condition, gets admin[/italic]",
    )
    demo_chains_table.add_row("", "Fix: Add sub condition to OIDC trust policy (effort: LOW)")
    console.print(
        Panel(
            demo_chains_table,
            title="[bold]Attack Chains (2 detected)[/bold]",
            border_style="red",
            width=80,
        )
    )

    # Findings by severity
    console.print("\n[bold]Findings by severity:[/bold]")
    console.print("  [bold red]x CRITICAL: 2[/bold red]")
    console.print("  [red]x HIGH: 4[/red]")
    console.print("  [yellow]! MEDIUM: 7[/yellow]")
    console.print("  [cyan]o LOW: 3[/cyan]")

    # Top findings
    console.print("\n[bold]Top findings (5 of 16):[/bold]\n")

    ft = Table(box=None, padding=(0, 1), show_header=True, header_style="bold")
    ft.add_column("Sev", width=8)
    ft.add_column("Region", width=14)
    ft.add_column("Check")
    ft.add_column("Resource")
    ft.add_column("Title", max_width=55)
    ft.add_row(
        "[bold red]CRITICAL[/bold red]",
        "[dim]global[/dim]",
        "aws-iam-001",
        "arn:aws:iam::1234...:root",
        "Root account without MFA enabled",
    )
    ft.add_row(
        "[bold red]CRITICAL[/bold red]",
        "[dim]eu-central-1[/dim]",
        "aws-vpc-002",
        "sg-0a1b2c3d4e5f67890",
        "SG open to 0.0.0.0/0 on port 22",
    )
    ft.add_row(
        "[red]HIGH[/red]",
        "[dim]eu-central-1[/dim]",
        "aws-rds-001",
        "production-db",
        "RDS instance is publicly accessible",
    )
    ft.add_row(
        "[red]HIGH[/red]",
        "[dim]global[/dim]",
        "aws-s3-001",
        "company-backups-2024",
        "S3 public access block disabled",
    )
    ft.add_row(
        "[yellow]MEDIUM[/yellow]",
        "[dim]global[/dim]",
        "aws-iam-003",
        "deploy-key-AKIA...",
        "Access key 347 days old (limit: 90)",
    )
    console.print(ft)

    console.print("\n  [dim]... and 11 more. See full report for details.[/dim]")

    # Remediation preview
    console.print("\n[bold]Remediation details (2 of 6 actionable findings):[/bold]\n")

    console.print("  [bold red]CRITICAL[/bold red]  Root account without MFA enabled")
    console.print("  [dim]Resource:[/dim]   arn:aws:iam::123456789012:root")
    console.print("  [dim]Compliance:[/dim] CIS 1.5")
    console.print("  [dim]Effort:[/dim]     [green]LOW[/green]")
    mfa_cli = "aws iam create-virtual-mfa-device --virtual-mfa-device-name root-mfa"
    console.print(f"  [dim]CLI:[/dim]        [cyan]{mfa_cli}[/cyan]")
    console.print('  [dim]Terraform:[/dim]  resource "aws_iam_virtual_mfa_device" "root" { ... }')
    mfa_docs = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html"
    console.print(f"  [dim]Docs:[/dim]       {mfa_docs}")
    console.print()

    console.print("  [bold red]CRITICAL[/bold red]  Security group open to 0.0.0.0/0 on port 22")
    console.print("  [dim]Resource:[/dim]   sg-0a1b2c3d4e5f67890")
    console.print("  [dim]Compliance:[/dim] CIS 5.2")
    console.print("  [dim]Effort:[/dim]     [green]LOW[/green]")
    sg_cli = (
        "aws ec2 revoke-security-group-ingress"
        " --group-id sg-0a1b2c3d4e5f67890"
        " --protocol tcp --port 22 --cidr 0.0.0.0/0"
    )
    console.print(f"  [dim]CLI:[/dim]        [cyan]{sg_cli}[/cyan]")
    console.print('  [dim]Terraform:[/dim]  resource "aws_security_group_rule" "ssh" { ... }')
    sg_docs = "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html"
    console.print(f"  [dim]Docs:[/dim]       {sg_docs}")
    console.print()

    console.print(
        "[dim]This is sample output. Run [bold]cloud-audit scan[/bold] with AWS credentials for a real scan.[/dim]"
    )


@app.command()
def diff(
    old_report: Annotated[Path, typer.Argument(help="Path to the baseline scan JSON file")],
    new_report: Annotated[Path, typer.Argument(help="Path to the current scan JSON file")],
    fmt: Annotated[str | None, typer.Option("--format", "-f", help="Output format: json, markdown")] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output file path")] = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Quiet mode - exit code only")] = False,
) -> None:
    """Compare two scan reports and show what changed.

    Exit code 0 = no new findings. Exit code 1 = new findings detected.
    """
    from cloud_audit.diff import compute_diff, load_report

    # Auto-detect format from output suffix if not specified
    if fmt is None and output:
        suffix_to_fmt = {".json": "json", ".md": "markdown"}
        fmt = suffix_to_fmt.get(output.suffix.lower())

    # Validate format early (before I/O)
    if fmt is not None and fmt not in ("json", "markdown"):
        console.print(f"[red]Unknown format '{fmt}'. Available: json, markdown[/red]")
        raise typer.Exit(2)

    # Validate inputs
    if not old_report.exists():
        console.print(f"[red]File not found: {old_report}[/red]")
        raise typer.Exit(2)
    if not new_report.exists():
        console.print(f"[red]File not found: {new_report}[/red]")
        raise typer.Exit(2)

    try:
        old = load_report(old_report)
        new = load_report(new_report)
    except Exception as e:
        console.print(f"[red]Failed to load report: {e}[/red]")
        raise typer.Exit(2) from None

    result = compute_diff(old, new)

    if fmt == "json":
        content = result.model_dump_json(indent=2)
        if output:
            _safe_write_text(output, content)
            if not quiet:
                console.print(f"[green]JSON diff saved to {output}[/green]")
        else:
            sys.stdout.write(content)
            sys.stdout.write("\n")
    elif fmt == "markdown":
        from cloud_audit.reports.diff_markdown import generate_diff_markdown

        content = generate_diff_markdown(result)
        if output:
            _safe_write_text(output, content)
            if not quiet:
                console.print(f"[green]Markdown diff saved to {output}[/green]")
        else:
            sys.stdout.write(content)
            sys.stdout.write("\n")
    elif not quiet:
        _print_diff(result)

    # Exit code: 1 if new findings (regression)
    if result.has_regression:
        raise typer.Exit(1)


def _print_diff(result: DiffResult) -> None:
    """Print a Rich-formatted diff to the console."""
    # Score
    if result.score_change > 0:
        sign, score_color = "+", "green"
    elif result.score_change < 0:
        sign, score_color = "", "red"
    else:
        sign, score_color = "", "dim"

    console.print()
    console.print(
        Panel(
            f"[{score_color}]{result.old_score} -> {result.new_score} ({sign}{result.score_change})[/{score_color}]",
            title="[bold]Score Change[/bold]",
            border_style=score_color,
            width=35,
        )
    )

    # Scope warnings
    for w in result.scope_warnings:
        console.print(f"[yellow]Warning: {rich_escape(w)}[/yellow]")

    # Summary line
    console.print(f"\n[dim]Findings: {result.old_total} -> {result.new_total}[/dim]")

    # Fixed
    if result.fixed_findings:
        console.print(f"\n[bold green]Fixed ({len(result.fixed_findings)}):[/bold green]")
        for f in result.fixed_findings:
            sev_color = SEVERITY_COLORS.get(f.severity, "dim")
            res = rich_escape(f.resource_id[:35])
            title = rich_escape(f.title[:50])
            console.print(
                f"  [{sev_color}]{f.severity.value.upper():8s}[/{sev_color}]  {f.check_id:14s}  {res:35s}  {title}"
            )

    # New (regressions)
    if result.new_findings:
        console.print(f"\n[bold red]New ({len(result.new_findings)}):[/bold red]")
        for f in result.new_findings:
            sev_color = SEVERITY_COLORS.get(f.severity, "dim")
            res = rich_escape(f.resource_id[:35])
            title = rich_escape(f.title[:50])
            console.print(
                f"  [{sev_color}]{f.severity.value.upper():8s}[/{sev_color}]  {f.check_id:14s}  {res:35s}  {title}"
            )

    # Changed severity
    if result.changed_findings:
        console.print(f"\n[bold yellow]Changed severity ({len(result.changed_findings)}):[/bold yellow]")
        for f in result.changed_findings:
            old_sev = f.old_severity.value.upper() if f.old_severity else "?"
            new_sev = f.severity.value.upper()
            res = rich_escape(f.resource_id[:35])
            console.print(f"  {f.check_id:14s}  {res:35s}  {old_sev} -> {new_sev}")

    # Unchanged
    if result.unchanged_findings:
        console.print(f"\n[dim]Unchanged ({len(result.unchanged_findings)}):[/dim]")
        for f in result.unchanged_findings:
            res = rich_escape(f.resource_id[:35])
            title = rich_escape(f.title[:50])
            console.print(f"  [dim]{f.severity.value.upper():8s}  {f.check_id:14s}  {res:35s}  {title}[/dim]")

    # No changes at all
    if not result.new_findings and not result.fixed_findings and not result.changed_findings:
        console.print("\n[green]No changes detected.[/green]")

    console.print()


_HISTORY_DIR = Path.home() / ".cloud-audit"


def _auto_save_report(report: ScanReport) -> None:
    """Save scan report for simulate/trend commands. Best-effort, never fails the scan."""
    try:
        _HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        last_scan = _HISTORY_DIR / "last-scan.json"
        _safe_write_text(last_scan, report.model_dump_json(indent=2))
    except Exception:  # noqa: S110 — persistence is best-effort
        pass
    # Also save to timestamped history for trend analysis
    try:
        from cloud_audit.history import save_scan_to_history

        save_scan_to_history(report)
    except Exception:  # noqa: S110
        pass


def _load_last_report() -> ScanReport | None:
    """Load the most recent saved scan report."""
    last_scan = _HISTORY_DIR / "last-scan.json"
    if not last_scan.exists():
        return None
    try:
        return ScanReport.model_validate_json(last_scan.read_text(encoding="utf-8"))
    except Exception:
        return None


@app.command()
def trend(
    account_id: Annotated[
        str | None,
        typer.Option("--account", "-a", help="AWS account ID. Auto-detected from history if omitted."),
    ] = None,
    limit: Annotated[int, typer.Option("--limit", "-n", help="Max number of scans to show.")] = 30,
) -> None:
    """Show security posture trend over time.

    Reads scan history saved by previous 'cloud-audit scan' runs.
    """
    from cloud_audit.history import _sparkline, compute_trend, list_accounts

    # Resolve account ID
    if not account_id:
        accounts = list_accounts()
        if not accounts:
            console.print("[red]No scan history found. Run 'cloud-audit scan' first.[/red]")
            raise typer.Exit(2)
        if len(accounts) == 1:
            account_id = accounts[0]
        else:
            console.print("[bold]Multiple accounts found:[/bold]")
            for acc in accounts:
                console.print(f"  {acc}")
            console.print("\n[dim]Use --account <ID> to select one.[/dim]")
            raise typer.Exit(2)

    trend_report = compute_trend(account_id, limit=limit)
    if trend_report is None:
        console.print(f"[yellow]Need at least 2 scans for trends. Account {account_id} has fewer.[/yellow]")
        raise typer.Exit(0)

    snaps = trend_report.snapshots
    console.print(f"\n[bold]Security Posture Trend[/bold]  Account: {account_id}  ({len(snaps)} scans)\n")

    # Sparkline table
    scores = [s.score for s in snaps]
    chains = [s.chains for s in snaps]
    findings = [s.findings for s in snaps]

    trend_table = Table(box=None, padding=(0, 2), show_header=True, header_style="bold")
    trend_table.add_column("Metric", width=14)
    trend_table.add_column("Trend", width=12)
    trend_table.add_column("First", width=8, justify="right")
    trend_table.add_column("Latest", width=8, justify="right")
    trend_table.add_column("Delta", width=10, justify="right")

    score_d = scores[-1] - scores[0]
    score_color = "green" if score_d > 0 else "red" if score_d < 0 else "dim"
    trend_table.add_row(
        "Score",
        _sparkline(scores),
        str(scores[0]),
        f"[bold]{scores[-1]}[/bold]",
        f"[{score_color}]{'+' if score_d > 0 else ''}{score_d}[/{score_color}]",
    )

    chains_d = chains[-1] - chains[0]
    chains_color = "green" if chains_d < 0 else "red" if chains_d > 0 else "dim"
    trend_table.add_row(
        "Attack Chains",
        _sparkline(chains),
        str(chains[0]),
        f"[bold]{chains[-1]}[/bold]",
        f"[{chains_color}]{'+' if chains_d > 0 else ''}{chains_d}[/{chains_color}]",
    )

    findings_d = findings[-1] - findings[0]
    findings_color = "green" if findings_d < 0 else "red" if findings_d > 0 else "dim"
    trend_table.add_row(
        "Findings",
        _sparkline(findings),
        str(findings[0]),
        f"[bold]{findings[-1]}[/bold]",
        f"[{findings_color}]{'+' if findings_d > 0 else ''}{findings_d}[/{findings_color}]",
    )

    # Risk row
    first_risk = snaps[0].risk_display
    last_risk = snaps[-1].risk_display
    risk_first_high = snaps[0].risk_high
    risk_last_high = snaps[-1].risk_high
    if risk_first_high > 0:
        risk_pct = int((1.0 - risk_last_high / risk_first_high) * 100) if risk_first_high else 0
        risk_color = "green" if risk_pct > 0 else "red" if risk_pct < 0 else "dim"
        trend_table.add_row(
            "Risk Exposure",
            _sparkline([s.risk_high for s in snaps]),
            first_risk,
            f"[bold]{last_risk}[/bold]",
            f"[{risk_color}]{'-' if risk_pct > 0 else '+'}{abs(risk_pct)}%[/{risk_color}]",
        )

    console.print(Panel(trend_table, title="[bold]Posture Over Time[/bold]", border_style="cyan", width=80))

    # Key changes
    significant = [d for d in trend_report.deltas if abs(d.score_delta) >= 5 or abs(d.chains_delta) >= 1]
    if significant:
        console.print("\n[bold]Key changes:[/bold]")
        for delta in significant[-5:]:
            date_str = delta.timestamp.strftime("%b %d")
            if delta.score_delta > 0:
                score_icon = "[green]+[/green]"
            elif delta.score_delta < 0:
                score_icon = "[red]-[/red]"
            else:
                score_icon = " "
            console.print(f"  {date_str}  {score_icon} {rich_escape(delta.description)}")

    console.print()


@app.command()
def simulate(
    fix: Annotated[
        str,
        typer.Option("--fix", "-f", help="Check ID(s) to simulate fixing (comma-separated)"),
    ],
    report_file: Annotated[
        Path | None,
        typer.Option("--report", "-r", help="Path to a JSON scan report. Default: last scan from ~/.cloud-audit/"),
    ] = None,
) -> None:
    """Simulate the impact of applying a fix without changing anything in AWS.

    Shows before/after comparison of health score, attack chains, and risk exposure.
    """
    # Load report
    if report_file:
        if not report_file.exists():
            console.print(f"[red]Report file not found: {report_file}[/red]")
            raise typer.Exit(2)
        try:
            report = ScanReport.model_validate_json(report_file.read_text(encoding="utf-8"))
        except Exception as e:
            console.print(f"[red]Failed to parse report: {e}[/red]")
            raise typer.Exit(2) from None
    else:
        loaded = _load_last_report()
        if loaded is None:
            console.print("[red]No saved scan found. Run 'cloud-audit scan' first, or use --report.[/red]")
            raise typer.Exit(2)
        report = loaded

    check_ids = [c.strip() for c in fix.split(",")]

    # Validate check_ids exist in the report
    report_check_ids = {f.check_id for f in report.all_findings}
    unknown = [c for c in check_ids if c not in report_check_ids]
    if unknown:
        console.print(f"[yellow]Warning: check ID(s) not found in scan: {', '.join(unknown)}[/yellow]")
        check_ids = [c for c in check_ids if c in report_check_ids]
        if not check_ids:
            console.print("[red]No valid check IDs to simulate.[/red]")
            raise typer.Exit(2)

    from cloud_audit.simulate import simulate_fix

    result = simulate_fix(report, check_ids)

    # Render before/after
    console.print()
    fix_names = ", ".join(f"[bold]{t}[/bold]" for t in result.fix_titles)
    console.print(f"Simulation: Apply {fix_names}\n")

    # Build comparison table
    comp_table = Table(box=None, padding=(0, 2), show_header=True, header_style="bold")
    comp_table.add_column("Metric", width=20)
    comp_table.add_column("Before", width=22, justify="right")
    comp_table.add_column("After", width=22, justify="right")
    comp_table.add_column("Delta", width=16, justify="right")

    # Score
    score_color = "green" if result.score_delta > 0 else "red" if result.score_delta < 0 else "dim"
    score_sign = "+" if result.score_delta > 0 else ""
    comp_table.add_row(
        "Health Score",
        f"{result.score_before}/100",
        f"[bold]{result.score_after}/100[/bold]",
        f"[{score_color}]{score_sign}{result.score_delta}[/{score_color}]",
    )

    # Chains
    chains_color = "green" if result.chains_delta < 0 else "dim"
    comp_table.add_row(
        "Attack Chains",
        str(result.chains_before),
        f"[bold]{result.chains_after}[/bold]",
        f"[{chains_color}]{result.chains_delta}[/{chains_color}]",
    )

    # Findings
    findings_delta = result.findings_after - result.findings_before
    comp_table.add_row(
        "Findings",
        str(result.findings_before),
        f"[bold]{result.findings_after}[/bold]",
        f"[green]{findings_delta}[/green]" if findings_delta < 0 else str(findings_delta),
    )

    # Risk
    risk_before_str = result.risk_before.display if result.risk_before else "N/A"
    risk_after_str = result.risk_after.display if result.risk_after else "$0"
    if result.risk_reduction_pct > 0:
        risk_delta_str = f"[green]-{result.risk_reduction_pct:.0f}%[/green]"
    else:
        risk_delta_str = "[dim]-[/dim]"
    comp_table.add_row("Risk Exposure", risk_before_str, f"[bold]{risk_after_str}[/bold]", risk_delta_str)

    console.print(Panel(comp_table, title="[bold]Impact Analysis[/bold]", border_style="cyan", width=80))

    # Chains broken
    if result.chains_broken:
        console.print(f"\n[bold]Chains broken ({len(result.chains_broken)}):[/bold]")
        for chain in result.chains_broken:
            sev_color = SEVERITY_COLORS.get(chain.severity, "dim")
            console.print(
                f"  [{sev_color}]{chain.severity.value.upper():8s}[/{sev_color}]  "
                f"{rich_escape(chain.name)}  [green]-> GONE[/green]"
            )

    # Chains remaining
    if result.chains_remaining:
        console.print(f"\n[bold]Chains remaining ({len(result.chains_remaining)}):[/bold]")
        for chain in result.chains_remaining:
            sev_color = SEVERITY_COLORS.get(chain.severity, "dim")
            console.print(f"  [{sev_color}]{chain.severity.value.upper():8s}[/{sev_color}]  {rich_escape(chain.name)}")

    # Next fix recommendation
    if result.next_fix:
        console.print(
            f"\n[bold]Next recommended fix:[/bold] {rich_escape(result.next_fix.fix_title)} "
            f"-> breaks {len(result.next_fix.chains_broken)} more chain(s)"
        )

    if not result.chains_remaining:
        console.print("\n[bold green]All attack chains eliminated![/bold green]")

    console.print()


@app.command(name="threat-feed")
def threat_feed_cmd(
    profile: Annotated[str | None, typer.Option("--profile", help="AWS profile")] = None,
    regions: Annotated[
        str | None,
        typer.Option("--regions", "-r", help="Comma-separated regions, or 'all' for every enabled region"),
    ] = None,
    pattern: Annotated[
        str | None,
        typer.Option("--pattern", help="Run only one pattern (e.g. aws-tf-003); default = all"),
    ] = None,
    list_patterns: Annotated[
        bool,
        typer.Option("--list", help="List registered patterns and exit (no scan)"),
    ] = False,
    threat_feed_version: Annotated[
        str | None,
        typer.Option("--threat-feed-version", help="Pin a rules-pack version (informational, default = current)"),
    ] = None,
) -> None:
    """Detect ACTIVE abuse patterns from 2025-2026 threat reports.

    Distinct from regular `scan`: looks for indicators that an attacker has ALREADY
    acted on the account (quarantine policies AWS attached after credential leak,
    public Lambda URLs created as persistence, DataZone over-grants, etc.) rather
    than mere misconfigurations.

    Examples:
        cloud-audit threat-feed                       # scan all patterns
        cloud-audit threat-feed --pattern aws-tf-003  # one pattern only
        cloud-audit threat-feed --list                # show registered patterns
    """
    from cloud_audit.providers.aws import threat_feed as tf_module

    if list_patterns:
        table = Table(title=f"Registered threat patterns (rules pack {tf_module.THREAT_FEED_VERSION})")
        table.add_column("Pattern ID", style="bold")
        table.add_column("Check ID")
        table.add_column("Severity")
        table.add_column("Name")
        table.add_column("Doc")
        for p in tf_module.list_patterns():
            sev_color = SEVERITY_COLORS.get(Severity(p["severity"]), "white")
            table.add_row(
                p["pattern_id"],
                p["check_id"],
                f"[{sev_color}]{p['severity'].upper()}[/{sev_color}]",
                p["name"],
                p["doc_url"],
            )
        console.print(table)
        console.print(f"\n[dim]{len(tf_module.list_patterns())} patterns registered.[/dim]")
        return

    active_version = threat_feed_version or tf_module.THREAT_FEED_VERSION
    if threat_feed_version and threat_feed_version != tf_module.THREAT_FEED_VERSION:
        console.print(
            f"[yellow]Note: requested rules pack '{threat_feed_version}' differs from installed "
            f"'{tf_module.THREAT_FEED_VERSION}'. Pinning is informational in this build.[/yellow]"
        )

    from cloud_audit.providers.aws.provider import AWSProvider

    region_list = None
    if regions:
        region_list = ["all"] if regions.strip() == "all" else [r.strip() for r in regions.split(",")]

    try:
        provider = AWSProvider(profile=profile, regions=region_list)
    except Exception as exc:
        console.print(f"[red]Failed to initialize AWS provider: {exc}[/red]")
        raise typer.Exit(2) from exc

    threat_checks = [c for c in provider.get_checks() if getattr(c, "category", None) and c.category.value == "threat"]
    if pattern:
        threat_checks = [c for c in threat_checks if c.check_id == pattern]
        if not threat_checks:
            console.print(f"[red]No registered threat pattern with check_id '{pattern}'.[/red]")
            console.print("Run [cyan]cloud-audit threat-feed --list[/cyan] to see available patterns.")
            raise typer.Exit(2)

    console.print(
        Panel(
            f"Scanning [bold]{len(threat_checks)}[/bold] threat patterns (rules pack [cyan]{active_version}[/cyan])",
            title="[bold]Threat Feed[/bold]",
            border_style="magenta",
        )
    )

    all_findings: list[Finding] = []
    errors: list[tuple[str, str]] = []
    for check in threat_checks:
        try:
            result = check()
        except Exception as exc:  # defensive - check should already capture
            errors.append((check.check_id, str(exc)))
            continue
        if result.error:
            errors.append((check.check_id, result.error))
        all_findings.extend(result.findings)

    if errors:
        console.print()
        for check_id, err in errors:
            console.print(f"[yellow]! {check_id}: {err}[/yellow]")

    if not all_findings:
        console.print("\n[green]No active abuse patterns detected.[/green]\n")
        raise typer.Exit(0)

    table = Table(title=f"Detected threat patterns ({len(all_findings)} findings)", show_lines=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Pattern", style="bold")
    table.add_column("Resource")
    table.add_column("Region")
    table.add_column("References")

    for f in sorted(all_findings, key=lambda x: list(SEVERITY_COLORS).index(x.severity)):
        sev_color = SEVERITY_COLORS[f.severity]
        refs = "\n".join(f.references[:2]) if f.references else "-"
        table.add_row(
            f"[{sev_color}]{f.severity.value.upper()}[/{sev_color}]",
            f"{f.threat_pattern_id or f.check_id}\n[dim]{rich_escape(f.title)}[/dim]",
            rich_escape(f.resource_id),
            f.region,
            refs,
        )

    console.print(table)
    console.print(
        "\n[dim]Use [cyan]cloud-audit scan --categories threat -o json[/cyan] for machine-readable output "
        "(includes full remediation + references).[/dim]\n"
    )

    # Exit 1 when CRITICAL/HIGH detected (CI gate)
    blocking = [f for f in all_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    raise typer.Exit(1 if blocking else 0)


@app.command()
def exposure(
    report_file: Annotated[
        Path | None,
        typer.Option("--report", "-r", help="Path to JSON scan report (defaults to last scan in ~/.cloud-audit/)"),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", "-n", help="Show top-N resources (default 20)"),
    ] = 20,
    output_format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output: table (default) or json"),
    ] = "table",
    output_path: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write to file (only for --format json)"),
    ] = None,
) -> None:
    """Rank resources by effective exposure score from the Security Graph.

    Combines network reachability (internet -> resource), privilege level
    (admin?), and high-value classification (data, identity) into a single
    0-100 number per resource. Useful as the "what should I fix first?" view.
    """
    from cloud_audit.graph import SecurityGraph

    if report_file:
        if not report_file.exists():
            console.print(f"[red]Report file not found: {report_file}[/red]")
            raise typer.Exit(2)
        try:
            report = ScanReport.model_validate_json(report_file.read_text(encoding="utf-8"))
        except Exception as e:
            console.print(f"[red]Failed to parse report: {e}[/red]")
            raise typer.Exit(2) from None
    else:
        loaded = _load_last_report()
        if loaded is None:
            console.print("[red]No saved scan found. Run 'cloud-audit scan' first, or use --report PATH.[/red]")
            raise typer.Exit(2)
        report = loaded

    if report.security_graph is None:
        console.print("[yellow]This scan has no Security Graph (run a fresh scan with v3.0.0+ to populate).[/yellow]")
        raise typer.Exit(2)

    graph = SecurityGraph.from_dict(report.security_graph)
    top = graph.top_exposed(limit=limit)

    fmt = output_format.lower().strip()
    if fmt == "json":
        import json as _json

        payload = _json.dumps(
            {
                "schema_version": "1",
                "items": [
                    {
                        "id": n.id,
                        "type": n.type,
                        "label": n.label,
                        "score": score,
                        "attrs": n.attrs,
                    }
                    for n, score in top
                ],
            },
            indent=2,
        )
        if output_path:
            try:
                _safe_write_text(output_path, payload)
            except OSError as e:
                console.print(f"[red]Failed to write {output_path}: {e}[/red]")
                raise typer.Exit(2) from None
            console.print(f"[green]Wrote exposure ranking to {output_path}[/green]")
        else:
            console.print(payload)
        return

    if fmt != "table":
        console.print(f"[red]Unknown format: {output_format}. Use table or json.[/red]")
        raise typer.Exit(2)

    console.print()
    console.print(
        Panel(
            f"Security Graph: [bold]{graph.node_count()}[/bold] nodes, "
            f"[bold]{graph.edge_count()}[/bold] edges. Top [bold]{len(top)}[/bold] by exposure.",
            title="[bold]Exposure ranking[/bold]",
            border_style="cyan",
            width=80,
        )
    )

    table = Table(show_header=True, box=None, padding=(0, 2), header_style="bold")
    table.add_column("Score", justify="right", width=6)
    table.add_column("Type", width=14)
    table.add_column("Label", width=40)
    table.add_column("Why", style="dim")

    for node, score in top:
        score_color = "red" if score >= 70 else "yellow" if score >= 40 else "dim"
        reasons: list[str] = []
        if graph.paths_from_internet(node.id, max_hops=6) is not None:
            reasons.append("internet-reachable")
        if node.attrs.get("is_admin") is True:
            reasons.append("admin")
        if node.attrs.get("has_escalation") is True:
            reasons.append("escalation")
        if node.type in ("s3_bucket", "secret", "kms_key", "rds_instance"):
            reasons.append("high-value data")
        table.add_row(
            f"[{score_color}]{score}[/{score_color}]",
            node.type,
            rich_escape(node.label[:38] + ("..." if len(node.label) > 38 else "")),
            ", ".join(reasons) or "linked to others",
        )

    console.print(table)
    console.print()


@app.command(name="blast-radius")
def blast_radius_cmd(
    resource: Annotated[
        str,
        typer.Option(
            "--resource",
            "-r",
            help="Seed resource: EC2 id (i-XXX), IAM role/user ARN, Lambda ARN, S3 bucket ARN, or secret ARN",
        ),
    ],
    report_file: Annotated[
        Path | None,
        typer.Option(
            "--report",
            help="Path to JSON scan report (defaults to last scan in ~/.cloud-audit/)",
        ),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: tree (default), json, mermaid, markdown",
        ),
    ] = "tree",
    output_path: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Write output to file instead of stdout",
        ),
    ] = None,
    max_depth: Annotated[
        int,
        typer.Option("--max-depth", help="Maximum BFS depth (default: 5)"),
    ] = 5,
    max_nodes: Annotated[
        int,
        typer.Option("--max-nodes", help="Maximum total nodes in result (default: 50)"),
    ] = 50,
) -> None:
    """Compute blast radius for a single AWS resource.

    Starts from the given resource and walks outward through scan data
    (IAM, AssumeRole graph, attack chains) to show what an attacker
    could reach if THIS resource were compromised. Pure in-memory
    analysis against the saved scan - no AWS API calls.
    """
    from cloud_audit.blast_radius import (
        compute_blast_radius,
        to_json_str,
        to_mermaid,
        to_tree,
    )

    # Load report
    if report_file:
        if not report_file.exists():
            console.print(f"[red]Report file not found: {report_file}[/red]")
            raise typer.Exit(2)
        try:
            report = ScanReport.model_validate_json(report_file.read_text(encoding="utf-8"))
        except Exception as e:
            console.print(f"[red]Failed to parse report: {e}[/red]")
            raise typer.Exit(2) from None
    else:
        loaded = _load_last_report()
        if loaded is None:
            console.print("[red]No saved scan found. Run 'cloud-audit scan' first, or use --report PATH.[/red]")
            raise typer.Exit(2)
        report = loaded

    max_depth_cap = 25
    max_nodes_cap = 10_000
    if max_depth < 1 or max_nodes < 1:
        console.print("[red]--max-depth and --max-nodes must be >= 1.[/red]")
        raise typer.Exit(2)
    if max_depth > max_depth_cap:
        console.print(f"[yellow]--max-depth capped at {max_depth_cap} (requested {max_depth}).[/yellow]")
        max_depth = max_depth_cap
    if max_nodes > max_nodes_cap:
        console.print(f"[yellow]--max-nodes capped at {max_nodes_cap} (requested {max_nodes}).[/yellow]")
        max_nodes = max_nodes_cap

    fmt = output_format.lower().strip()
    if fmt not in {"tree", "json", "mermaid", "markdown"}:
        console.print(f"[red]Unknown format: {output_format}. Use tree, json, mermaid, or markdown.[/red]")
        raise typer.Exit(2)

    # Tree output is ANSI-decorated text and cannot be meaningfully written to
    # a file. Refuse instead of silently writing a different format under the
    # user's nose (CWE-684).
    if fmt == "tree" and output_path is not None:
        console.print(
            "[red]--output is not supported with --format tree (ANSI-decorated). "
            "Use --format json, mermaid, or markdown together with --output.[/red]"
        )
        raise typer.Exit(2)

    result = compute_blast_radius(report, resource, max_depth=max_depth, max_nodes=max_nodes)

    def _write_or_exit(path: Path, payload: str, label: str) -> None:
        """Write ``payload`` to ``path`` or fail with a typed CLI error.

        Wrapping the write surfaces OSError (read-only filesystem, permission
        denied, no such directory) as a clean exit-2 instead of leaking a
        Python traceback to stderr.
        """
        try:
            _safe_write_text(path, payload)
        except OSError as exc:
            console.print(f"[red]Failed to write {label} to {path}: {exc}[/red]")
            raise typer.Exit(2) from None
        console.print(f"[green]Wrote {label} to {path}[/green]")

    if fmt == "json":
        payload = to_json_str(result)
        if output_path:
            _write_or_exit(output_path, payload, "blast radius JSON")
        else:
            console.print(payload)
        return

    if fmt == "mermaid":
        diagram = to_mermaid(result)
        if output_path:
            _write_or_exit(output_path, diagram, "Mermaid diagram")
        else:
            console.print(diagram)
        return

    if fmt == "markdown":
        md = _blast_radius_to_markdown(result)
        if output_path:
            _write_or_exit(output_path, md, "Markdown report")
        else:
            console.print(md)
        return

    # Default: tree. rich_escape() everything sourced from the resource arg or
    # the scan payload to prevent rich-markup injection in the terminal output.
    console.print()
    console.print(
        Panel(
            f"[bold]{rich_escape(result.summary.headline)}[/bold]\n"
            f"Resource: [cyan]{rich_escape(resource)}[/cyan]\n"
            f"Reachable: [yellow]{result.summary.nodes_reachable}[/yellow] "
            f"| Paths to impact: [red]{result.summary.paths_found}[/red] "
            f"| Risk score: [bold]{result.summary.risk_score}/100[/bold]",
            title="[bold]Blast Radius[/bold]",
            border_style="red" if (result.summary.paths_found or 0) > 0 else "yellow",
            width=92,
        )
    )
    console.print()
    console.print(to_tree(result))

    if result.fixes:
        console.print()
        console.print("[bold]Available fixes (from scan findings):[/bold]")
        for fix in result.fixes:
            marker = "[bold red]breaks chain[/bold red]" if fix.breaks_chain else "mitigates"
            console.print(
                f"  - [cyan]{rich_escape(fix.id)}[/cyan] {rich_escape(fix.title)} ({marker}, effort={fix.effort})"
            )


def _md_escape(text: object) -> str:
    """Escape markdown control characters in user-controlled strings.

    The markdown formatter renders scan-derived labels, sub-titles, edge
    descriptions and fix titles into a document that's typically posted to a
    GitHub PR or shared with customers. Without escaping, a resource label
    containing `[click](javascript:...)` or stray `*` / backticks injects
    links/emphasis into the rendered output.
    """
    s = "" if text is None else str(text)
    return (
        s.replace("\\", "\\\\")
        .replace("`", "\\`")
        .replace("*", "\\*")
        .replace("_", "\\_")
        .replace("[", "\\[")
        .replace("]", "\\]")
        .replace("(", "\\(")
        .replace(")", "\\)")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _blast_radius_to_markdown(result: object) -> str:
    """Render a BlastRadiusResult as a compact Markdown summary."""
    from cloud_audit.blast_radius import BlastRadiusResult

    if not isinstance(result, BlastRadiusResult):
        return ""

    lines = [
        f"# Blast Radius - {_md_escape(result.source.resource_id or 'resource')}",
        "",
        f"**Headline:** {_md_escape(result.summary.headline)}",
        f"**Risk score:** {result.summary.risk_score}/100",
        f"**Reachable nodes:** {result.summary.nodes_reachable}",
        f"**Paths to impact:** {result.summary.paths_found}",
        "",
        "## Graph",
        "",
    ]
    for node in result.nodes:
        lines.append(
            f"- `{_md_escape(node.id)}` **{_md_escape(node.label)}** ({_md_escape(node.type)}) - {_md_escape(node.sub)}"
        )
    lines.append("")
    lines.append("## Edges")
    lines.append("")
    for edge in result.edges:
        src = _md_escape(edge.source)
        tgt = _md_escape(edge.target)
        lbl = _md_escape(edge.label)
        typ = _md_escape(edge.type)
        lines.append(f"- `{src}` --[{lbl}]--> `{tgt}` (type={typ}, step={edge.step})")
    lines.append("")
    if result.fixes:
        lines.append("## Available fixes")
        lines.append("")
        for fix in result.fixes:
            lines.append(f"- **{_md_escape(fix.id)}** {_md_escape(fix.title)} (effort={_md_escape(fix.effort)})")
        lines.append("")
    return "\n".join(lines)


@app.command()
def version() -> None:
    """Show version."""
    console.print(f"cloud-audit {__version__}")


if __name__ == "__main__":
    app()
