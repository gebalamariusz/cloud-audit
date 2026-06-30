"""Scanner - orchestrates check execution and produces a report."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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
        # Ensure check_id consistency from make_check metadata
        canonical_id = getattr(check_fn, "check_id", None)
        if canonical_id:
            result.check_id = canonical_id
            for f in result.findings:
                f.check_id = canonical_id
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
    verify: bool = False,
) -> tuple[ScanReport, int]:
    """Execute all checks for the given provider and return a ScanReport.

    Returns (report, suppressed_count).

    When ``verify`` is True (Proof Mode), each detected IAM escalation path is
    cross-checked against the AWS IAM policy simulator (read-only) and annotated
    with a ``verified`` flag plus evidence.
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
    provider.reset_caches()

    start = time.monotonic()
    max_workers = min(8, len(checks))

    if quiet:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_execute_check, fn): fn for fn in checks}
            for future in as_completed(futures):
                report.results.append(future.result())
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

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(_execute_check, fn): fn for fn in checks}
                for future in as_completed(futures):
                    report.results.append(future.result())
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

    # Attack chain detection
    try:
        from cloud_audit.correlate import collect_relationships, detect_attack_chains

        try:
            relationships = collect_relationships(provider, report.all_findings)  # type: ignore[arg-type]
        except Exception:
            relationships = None
        report.attack_chains = detect_attack_chains(report.all_findings, relationships)
        report.summary.attack_chains_detected = len(report.attack_chains)
    except Exception as e:
        if not quiet:
            console.print(f"[yellow]Warning: Attack chain detection failed: {e}[/yellow]")

    # Persist IAM escalation paths from the analyzer cache into the report so
    # downstream consumers (blast-radius, MCP server, anything reading the JSON
    # offline) see them. The cache is populated by the privilege-escalation
    # check during the main scan; without this step it never makes it onto the
    # serialized ScanReport.
    try:
        from cloud_audit.providers.aws.iam_analyzer import get_cached_escalation_paths

        report.escalation_paths = get_cached_escalation_paths()
        report.summary.escalation_paths_detected = len(report.escalation_paths)
    except Exception as e:
        if not quiet:
            console.print(f"[yellow]Warning: Escalation-path persistence failed: {e}[/yellow]")

    # Proof Mode (opt-in): cross-check escalation paths against the read-only IAM
    # policy simulator. Annotates each path with verified + evidence.
    if verify and report.escalation_paths:
        try:
            from cloud_audit.proof import verify_report_escalations
            from cloud_audit.providers.aws.provider import AWSProvider

            if isinstance(provider, AWSProvider):
                verified_count = verify_report_escalations(provider, report.escalation_paths)
                if not quiet:
                    console.print(
                        f"[bold]Proof Mode: {verified_count}/{len(report.escalation_paths)} "
                        f"escalation path(s) policy-allowed by IAM simulator "
                        f"(read-only check, not full exploit confirmation)[/bold]"
                    )
        except Exception as e:
            if not quiet:
                console.print(f"[yellow]Warning: Proof Mode verification failed: {e}[/yellow]")

    # Build the unified Security Graph (v3.0.0+) from the artifacts already
    # produced during this scan. Pure transformation - no extra API calls.
    try:
        from cloud_audit.graph import build_from_scan_artifacts
        from cloud_audit.providers.aws.iam_analyzer import (
            get_authorization_details,
            resolve_principals,
        )
        from cloud_audit.providers.aws.iam_trust_graph import build_assume_role_graph

        trust_graph = None
        try:
            # Reuse the auth details if the IAM check already fetched them; if
            # not, this is a one-line paginated call (idempotent, free).
            # AWS-only path: the IAM analyzer is AWS-specific and the graph
            # only populates rich IAM edges when running against the AWS
            # provider. Skip silently on other providers.
            from cloud_audit.providers.aws.provider import AWSProvider

            if isinstance(provider, AWSProvider):
                auth_details = get_authorization_details(provider)
                trust_graph = build_assume_role_graph(auth_details)
                # resolve_principals fidelity is used for ARN-side links; if it
                # fails, the graph still works on lighter data.
                _ = resolve_principals(auth_details)
        except Exception:
            trust_graph = None

        # collect_relationships() was already called above for chain detection;
        # safe to call again here - it short-circuits on empty findings
        from cloud_audit.correlate import collect_relationships

        try:
            relationships = collect_relationships(provider, report.all_findings)  # type: ignore[arg-type]
        except Exception:
            relationships = None

        sec_graph = build_from_scan_artifacts(
            escalation_paths=report.escalation_paths,
            iam_trust_graph=trust_graph,
            resource_relationships=relationships,
            findings=report.all_findings,
        )
        report.security_graph = sec_graph.to_dict()
    except Exception as e:
        if not quiet:
            console.print(f"[yellow]Warning: Security graph build failed: {e}[/yellow]")

    if not quiet and report.attack_chains:
        console.print(f"[bold]{len(report.attack_chains)} attack chains detected[/bold]")

    # Breach cost estimation (post-scan, zero API calls)
    try:
        from cloud_audit.cost_model import (
            CostEstimate,
            estimate_chain_cost,
            estimate_finding_cost,
            estimate_total_exposure,
        )
        from cloud_audit.models import CostEstimateData

        def _to_data(est: CostEstimate) -> CostEstimateData:
            return CostEstimateData(
                low_usd=est.low,
                high_usd=est.high,
                display=est.display,
                rationale=est.rationale,
                source_url=est.source_url,
            )

        # Annotate individual findings
        for check_result in report.results:
            for finding in check_result.findings:
                est = estimate_finding_cost(finding)
                if est:
                    finding.cost_estimate = _to_data(est)

        # Annotate attack chains
        for chain in report.attack_chains:
            chain.cost_estimate = _to_data(estimate_chain_cost(chain))

        # Compute total exposure
        total = estimate_total_exposure(report)
        report.summary.total_risk_exposure = _to_data(total)
    except Exception as e:
        if not quiet:
            console.print(f"[yellow]Warning: Cost estimation failed: {e}[/yellow]")

    # Root cause grouping (AFTER cost estimation so risk aggregation works)
    if report.attack_chains:
        try:
            from cloud_audit.root_cause import compute_root_causes

            report.root_causes = compute_root_causes(report.all_findings, report.attack_chains)
        except Exception as e:
            if not quiet:
                console.print(f"[yellow]Warning: Root cause grouping failed: {e}[/yellow]")

    return report, suppressed_count
