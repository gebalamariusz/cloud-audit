"""Compliance-specific HTML report generator.

Generates auditor-ready HTML report with per-control evidence,
remediation, and attack chain context.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cloud_audit.compliance.engine import ComplianceReport


def generate_compliance_html(report: ComplianceReport) -> str:
    """Generate a self-contained HTML compliance report."""
    cr = report
    scan = cr.scan_report
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    score = cr.readiness_score
    score_color = "#22c55e" if score >= 80 else ("#eab308" if score >= 50 else "#ef4444")

    # Group controls by section
    sections: dict[str, list[Any]] = {}
    for ctrl in cr.controls:
        sec = ctrl.section or "Other"
        sections.setdefault(sec, []).append(ctrl)

    # Count by status
    pass_count = sum(1 for c in cr.controls if c.status == "PASS")
    fail_count = sum(1 for c in cr.controls if c.status == "FAIL")
    partial_count = sum(1 for c in cr.controls if c.status == "PARTIAL")
    na_count = sum(1 for c in cr.controls if c.status == "NOT_ASSESSED")

    # Build controls HTML
    controls_html = ""
    for section_name, ctrls in sections.items():
        section_pass = sum(1 for c in ctrls if c.status == "PASS")
        section_total = len(ctrls)

        controls_html += f"""
        <div class="section">
            <h2>{_esc(section_name)} <span class="section-score">{section_pass}/{section_total} passing</span></h2>
            <table class="controls-table">
                <thead>
                    <tr>
                        <th class="col-status">Status</th>
                        <th class="col-id">ID</th>
                        <th class="col-title">Title</th>
                        <th class="col-level">Level</th>
                        <th class="col-checks">Checks</th>
                    </tr>
                </thead>
                <tbody>
        """

        for ctrl in ctrls:
            status_class = ctrl.status.lower().replace("not_assessed", "na")
            status_label = {"PASS": "PASS", "FAIL": "FAIL", "PARTIAL": "PARTIAL", "NOT_ASSESSED": "N/A"}[ctrl.status]
            chain_badge = (
                ' <span class="chain-badge" title="Attack chain violation">!</span>' if ctrl.violated_by_chains else ""
            )
            checks_display = f"{ctrl.checks_passed}/{ctrl.checks_total}" if ctrl.checks_total > 0 else "-"

            controls_html += f"""
                    <tr class="control-row {status_class}" id="ctrl-{_esc(ctrl.control_id)}">
                        <td class="col-status"><span class="status-badge {status_class}">{status_label}</span>{chain_badge}</td>
                        <td class="col-id"><strong>{_esc(ctrl.control_id)}</strong></td>
                        <td class="col-title">{_esc(ctrl.title)}</td>
                        <td class="col-level">{_esc(ctrl.level)}</td>
                        <td class="col-checks">{checks_display}</td>
                    </tr>
            """

            # Detail row for FAIL/PARTIAL controls
            if ctrl.status in ("FAIL", "PARTIAL") and ctrl.findings:
                controls_html += f"""
                    <tr class="detail-row">
                        <td colspan="5">
                            <div class="control-detail">
                                <div class="evidence">{_esc(ctrl.evidence_statement)}</div>
                """

                if ctrl.violated_by_chains:
                    chain_ids = ", ".join(ctrl.violated_by_chains)
                    controls_html += f'<div class="chain-violation">Attack chain violation: {_esc(chain_ids)}</div>'

                if ctrl.manual_steps:
                    controls_html += f'<div class="manual-steps"><strong>Manual verification:</strong> {_esc(ctrl.manual_steps)}</div>'

                # Per-finding remediation
                for finding in ctrl.findings:
                    sev_class = finding.severity.value.lower()
                    controls_html += f"""
                                <div class="finding">
                                    <div class="finding-header">
                                        <span class="severity-badge {sev_class}">{finding.severity.value.upper()}</span>
                                        <span class="finding-id">{_esc(finding.check_id)}</span>
                                        <span class="finding-title">{_esc(finding.title)}</span>
                                    </div>
                                    <div class="finding-resource">Resource: {_esc(finding.resource_id)}</div>
                    """

                    if finding.remediation:
                        rem = finding.remediation
                        if rem.cli:
                            controls_html += f"""
                                    <div class="remediation">
                                        <div class="rem-label">CLI fix:</div>
                                        <pre class="rem-code">{_esc(rem.cli)}</pre>
                                    </div>
                            """
                        if rem.terraform:
                            controls_html += f"""
                                    <div class="remediation">
                                        <div class="rem-label">Terraform:</div>
                                        <pre class="rem-code">{_esc(rem.terraform)}</pre>
                                    </div>
                            """
                        safe_doc = _safe_url(rem.doc_url)
                        if safe_doc:
                            controls_html += f'<div class="doc-link"><a href="{safe_doc}" target="_blank" rel="noopener noreferrer">AWS Documentation</a></div>'

                    controls_html += "</div>"  # finding

                controls_html += """
                            </div>
                        </td>
                    </tr>
                """

            # Manual controls info
            elif ctrl.status == "NOT_ASSESSED" and ctrl.manual_steps:
                controls_html += f"""
                    <tr class="detail-row">
                        <td colspan="5">
                            <div class="control-detail manual">
                                <div class="manual-steps">{_esc(ctrl.manual_steps)}</div>
                            </div>
                        </td>
                    </tr>
                """

        controls_html += """
                </tbody>
            </table>
        </div>
        """

    # Attack chains section
    chains_html = ""
    if cr.chain_violations:
        chains_html = '<div class="section"><h2>Attack Chain Violations</h2>'
        for chain, violated_controls in cr.chain_violations:
            sev_class = chain.severity.value.lower()
            ctrl_links = ", ".join(f'<a href="#ctrl-{_esc(c)}">{_esc(c)}</a>' for c in violated_controls)
            chains_html += f"""
            <div class="chain-item">
                <span class="severity-badge {sev_class}">{chain.severity.value.upper()}</span>
                <strong>{_esc(chain.name)}</strong>
                <div class="chain-narrative">{_esc(chain.attack_narrative)}</div>
                <div class="chain-fix">Priority fix: {_esc(chain.priority_fix)}</div>
                <div class="chain-controls">Violates controls: {ctrl_links}</div>
            </div>
            """
        chains_html += "</div>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(cr.framework_name)} - Compliance Report</title>
<style>
:root {{
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #e2e8f0; --text-dim: #94a3b8; --text-bright: #f8fafc;
    --pass: #22c55e; --fail: #ef4444; --partial: #eab308; --na: #64748b;
    --critical: #ef4444; --high: #f97316; --medium: #eab308; --low: #06b6d4;
}}
@media (prefers-color-scheme: light) {{
    :root {{
        --bg: #f8fafc; --surface: #ffffff; --border: #e2e8f0;
        --text: #1e293b; --text-dim: #64748b; --text-bright: #0f172a;
    }}
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; max-width: 1200px; margin: 0 auto; }}
h1 {{ color: var(--text-bright); margin-bottom: 0.5rem; }}
h2 {{ color: var(--text-bright); margin: 1.5rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
.header {{ background: var(--surface); border-radius: 12px; padding: 2rem; margin-bottom: 2rem; border: 1px solid var(--border); }}
.meta {{ display: flex; gap: 2rem; flex-wrap: wrap; margin: 1rem 0; color: var(--text-dim); font-size: 0.9rem; }}
.meta span {{ display: flex; align-items: center; gap: 0.3rem; }}
.score-ring {{ display: inline-flex; align-items: center; justify-content: center; width: 80px; height: 80px; border-radius: 50%; border: 4px solid {score_color}; font-size: 1.5rem; font-weight: bold; color: {score_color}; float: right; margin-top: -1rem; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 1rem; margin: 1.5rem 0; }}
.summary-card {{ background: var(--bg); border-radius: 8px; padding: 1rem; text-align: center; border: 1px solid var(--border); }}
.summary-card .number {{ font-size: 1.8rem; font-weight: bold; }}
.summary-card .label {{ font-size: 0.8rem; color: var(--text-dim); }}
.disclaimer {{ background: var(--surface); border-left: 3px solid var(--na); padding: 0.8rem 1rem; margin: 1rem 0; font-size: 0.85rem; color: var(--text-dim); border-radius: 0 4px 4px 0; }}
.section {{ margin-bottom: 2rem; }}
.section-score {{ font-size: 0.9rem; color: var(--text-dim); font-weight: normal; }}
.controls-table {{ width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; }}
.controls-table th {{ background: var(--bg); padding: 0.6rem 1rem; text-align: left; font-size: 0.85rem; color: var(--text-dim); border-bottom: 1px solid var(--border); }}
.controls-table td {{ padding: 0.6rem 1rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
.col-status {{ width: 80px; }} .col-id {{ width: 70px; }} .col-level {{ width: 50px; }} .col-checks {{ width: 70px; text-align: center; }}
.status-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }}
.status-badge.pass {{ background: rgba(34,197,94,0.15); color: var(--pass); }}
.status-badge.fail {{ background: rgba(239,68,68,0.15); color: var(--fail); }}
.status-badge.partial {{ background: rgba(234,179,8,0.15); color: var(--partial); }}
.status-badge.na {{ background: rgba(100,116,139,0.15); color: var(--na); }}
.chain-badge {{ background: var(--fail); color: white; border-radius: 50%; width: 18px; height: 18px; display: inline-flex; align-items: center; justify-content: center; font-size: 0.7rem; font-weight: bold; margin-left: 4px; }}
.control-row:hover {{ background: rgba(255,255,255,0.03); }}
.detail-row td {{ background: var(--bg); padding: 0; }}
.control-detail {{ padding: 1rem 1.5rem; }}
.control-detail.manual {{ padding: 0.5rem 1.5rem; }}
.evidence {{ color: var(--text-dim); font-size: 0.9rem; margin-bottom: 0.8rem; font-style: italic; }}
.chain-violation {{ background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); border-radius: 4px; padding: 0.5rem 0.8rem; margin-bottom: 0.8rem; color: var(--fail); font-size: 0.85rem; }}
.manual-steps {{ color: var(--text-dim); font-size: 0.85rem; margin-bottom: 0.5rem; }}
.finding {{ background: var(--surface); border-radius: 6px; padding: 0.8rem 1rem; margin-bottom: 0.5rem; border: 1px solid var(--border); }}
.finding-header {{ display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.3rem; }}
.finding-id {{ color: var(--text-dim); font-size: 0.85rem; }}
.finding-title {{ font-weight: 500; }}
.finding-resource {{ font-size: 0.85rem; color: var(--text-dim); margin-bottom: 0.5rem; }}
.severity-badge {{ display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 0.7rem; font-weight: bold; }}
.severity-badge.critical {{ background: rgba(239,68,68,0.15); color: var(--critical); }}
.severity-badge.high {{ background: rgba(249,115,22,0.15); color: var(--high); }}
.severity-badge.medium {{ background: rgba(234,179,8,0.15); color: var(--medium); }}
.severity-badge.low {{ background: rgba(6,182,212,0.15); color: var(--low); }}
.remediation {{ margin: 0.5rem 0; }}
.rem-label {{ font-size: 0.8rem; color: var(--text-dim); margin-bottom: 0.2rem; }}
.rem-code {{ background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 0.5rem 0.8rem; font-size: 0.8rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
.doc-link {{ margin-top: 0.3rem; }} .doc-link a {{ color: #60a5fa; font-size: 0.85rem; }}
.chain-item {{ background: var(--surface); border-radius: 8px; padding: 1rem; margin-bottom: 1rem; border: 1px solid var(--border); }}
.chain-narrative {{ color: var(--text-dim); font-size: 0.9rem; margin: 0.5rem 0; }}
.chain-fix {{ font-size: 0.9rem; margin: 0.3rem 0; }}
.chain-controls {{ font-size: 0.85rem; color: var(--text-dim); }} .chain-controls a {{ color: #60a5fa; }}
.footer {{ margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--text-dim); font-size: 0.8rem; text-align: center; }}
@media print {{ :root {{ --bg: #f8fafc; --surface: #ffffff; --border: #e2e8f0; --text: #1e293b; --text-dim: #64748b; --text-bright: #0f172a; }} body {{ background: white; color: black; }} .controls-table {{ page-break-inside: avoid; }} .finding {{ page-break-inside: avoid; }} }}
</style>
</head>
<body>

<div class="header">
    <div class="score-ring" role="meter" aria-valuenow="{score:.0f}" aria-valuemin="0" aria-valuemax="100">{score:.0f}%</div>
    <h1>{_esc(cr.framework_name)}{"&nbsp;<span style='font-size:0.5em;background:rgba(234,179,8,0.15);color:var(--partial);padding:2px 10px;border-radius:4px;vertical-align:middle;'>BETA</span>" if cr.status == "beta" else ""}</h1>
    <div style="color: var(--text-dim);">Version {_esc(cr.version)} - Compliance Assessment Report</div>
    <div class="meta">
        <span>Account: {_esc(scan.account_id)}</span>
        <span>Regions: {_esc(", ".join(scan.regions))}</span>
        <span>Scanned: {now}</span>
        <span>Duration: {scan.duration_seconds:.1f}s</span>
        <span>Tool: cloud-audit v{_get_version()}</span>
    </div>
    <div class="summary-grid">
        <div class="summary-card"><div class="number" style="color: var(--pass)">{pass_count}</div><div class="label">Passing</div></div>
        <div class="summary-card"><div class="number" style="color: var(--fail)">{fail_count}</div><div class="label">Failing</div></div>
        <div class="summary-card"><div class="number" style="color: var(--partial)">{partial_count}</div><div class="label">Partial</div></div>
        <div class="summary-card"><div class="number" style="color: var(--na)">{na_count}</div><div class="label">Manual Review</div></div>
        <div class="summary-card"><div class="number">{len(cr.controls)}</div><div class="label">Total Controls</div></div>
    </div>
</div>

<div class="disclaimer">{_esc(cr.disclaimer)}</div>

{chains_html}

{controls_html}

<div class="footer">
    Generated by <a href="https://github.com/gebalamariusz/cloud-audit" style="color: #60a5fa;">cloud-audit</a> - {now}<br>
    Source: <a href="{_esc(cr.source_url)}" style="color: #60a5fa;">{_esc(cr.source_url)}</a>
</div>

</body>
</html>"""


def _esc(text: str) -> str:
    """Escape HTML entities."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _safe_url(value: object) -> str:
    """Block non-http(s) URL schemes (defense-in-depth vs `javascript:`/`data:`)."""
    from urllib.parse import urlparse

    if value is None:
        return ""
    s = str(value).strip()
    if not s:
        return ""
    try:
        scheme = urlparse(s).scheme.lower()
    except Exception:
        return ""
    if scheme in {"http", "https", ""}:
        return _esc(s)
    return ""


def _get_version() -> str:
    """Get cloud-audit version."""
    try:
        from cloud_audit import __version__

        return __version__
    except Exception:
        return "unknown"
