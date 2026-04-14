"""Scan history persistence and trend analysis.

Stores scan snapshots in ~/.cloud-audit/history/{account_id}/ and computes
trends across multiple scans (score, chains, risk over time).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime  # noqa: TC003 — used at runtime by dataclass fields
from pathlib import Path

from cloud_audit.models import ScanReport

_HISTORY_DIR = Path.home() / ".cloud-audit" / "history"


@dataclass
class ScanSnapshot:
    """Lightweight summary of a single scan for trend display."""

    timestamp: datetime
    score: int
    findings: int
    chains: int
    risk_low: int
    risk_high: int
    risk_display: str
    escalation_paths: int


@dataclass
class TrendDelta:
    """Change between two consecutive scans."""

    timestamp: datetime
    score_delta: int
    chains_delta: int
    findings_delta: int
    description: str  # Human-readable change summary


@dataclass
class TrendReport:
    """Aggregated trend data across multiple scans."""

    account_id: str
    snapshots: list[ScanSnapshot] = field(default_factory=list)
    deltas: list[TrendDelta] = field(default_factory=list)

    @property
    def total_scans(self) -> int:
        return len(self.snapshots)

    @property
    def score_first(self) -> int:
        return self.snapshots[0].score if self.snapshots else 0

    @property
    def score_last(self) -> int:
        return self.snapshots[-1].score if self.snapshots else 0

    @property
    def chains_first(self) -> int:
        return self.snapshots[0].chains if self.snapshots else 0

    @property
    def chains_last(self) -> int:
        return self.snapshots[-1].chains if self.snapshots else 0


def save_scan_to_history(report: ScanReport) -> Path | None:
    """Save a scan report snapshot to history. Returns the saved path or None on failure."""
    if not report.account_id:
        return None
    try:
        account_dir = _HISTORY_DIR / report.account_id
        account_dir.mkdir(parents=True, exist_ok=True)
        ts = report.timestamp.strftime("%Y%m%dT%H%M%S")
        path = account_dir / f"{ts}.json"
        path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        return path
    except Exception:
        return None


def load_history(account_id: str, limit: int = 30) -> list[ScanSnapshot]:
    """Load scan snapshots for an account, sorted oldest first. Returns last `limit` scans."""
    account_dir = _HISTORY_DIR / account_id
    if not account_dir.exists():
        return []

    snapshots: list[ScanSnapshot] = []
    json_files = sorted(account_dir.glob("*.json"))

    # Take only the last `limit` files
    for path in json_files[-limit:]:
        snap = _parse_snapshot(path)
        if snap:
            snapshots.append(snap)

    return snapshots


def _parse_snapshot(path: Path) -> ScanSnapshot | None:
    """Parse a scan JSON into a lightweight snapshot."""
    try:
        report = ScanReport.model_validate_json(path.read_text(encoding="utf-8"))
        risk = report.summary.total_risk_exposure
        return ScanSnapshot(
            timestamp=report.timestamp,
            score=report.summary.score,
            findings=report.summary.total_findings,
            chains=report.summary.attack_chains_detected,
            risk_low=risk.low_usd if risk else 0,
            risk_high=risk.high_usd if risk else 0,
            risk_display=risk.display if risk else "$0",
            escalation_paths=report.summary.escalation_paths_detected,
        )
    except Exception:
        return None


def compute_trend(account_id: str, limit: int = 30) -> TrendReport | None:
    """Compute trend report from scan history."""
    snapshots = load_history(account_id, limit=limit)
    if len(snapshots) < 2:
        return None

    deltas: list[TrendDelta] = []
    for i in range(1, len(snapshots)):
        prev = snapshots[i - 1]
        curr = snapshots[i]
        score_d = curr.score - prev.score
        chains_d = curr.chains - prev.chains
        findings_d = curr.findings - prev.findings

        parts: list[str] = []
        if score_d != 0:
            parts.append(f"Score {'+' if score_d > 0 else ''}{score_d}")
        if chains_d != 0:
            parts.append(f"Chains {'+' if chains_d > 0 else ''}{chains_d}")
        if findings_d != 0:
            parts.append(f"Findings {'+' if findings_d > 0 else ''}{findings_d}")

        deltas.append(
            TrendDelta(
                timestamp=curr.timestamp,
                score_delta=score_d,
                chains_delta=chains_d,
                findings_delta=findings_d,
                description=", ".join(parts) if parts else "No change",
            )
        )

    return TrendReport(account_id=account_id, snapshots=snapshots, deltas=deltas)


def list_accounts() -> list[str]:
    """List account IDs that have scan history."""
    if not _HISTORY_DIR.exists():
        return []
    return sorted(d.name for d in _HISTORY_DIR.iterdir() if d.is_dir() and any(d.glob("*.json")))


def _sparkline(values: list[int], width: int = 10) -> str:
    """Render a simple ASCII sparkline from a list of integers."""
    if not values:
        return ""
    mn, mx = min(values), max(values)
    blocks = " .:-=+*#%@"
    rng = mx - mn if mx != mn else 1
    return "".join(blocks[min(int((v - mn) / rng * 8), 8)] for v in values[-width:])
