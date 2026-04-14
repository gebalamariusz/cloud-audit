"""Compliance framework mapping and reporting."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_FRAMEWORKS_DIR = Path(__file__).parent / "frameworks"


def list_frameworks() -> list[dict[str, str]]:
    """Return a list of available compliance frameworks."""
    frameworks = []
    for f in sorted(_FRAMEWORKS_DIR.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            status = data.get("status", "stable")
            name = data["framework_name"]
            if status == "beta":
                name = f"{name} (Beta)"
            frameworks.append(
                {
                    "id": data["framework_id"],
                    "name": name,
                    "version": data.get("version", ""),
                    "controls_total": str(len(data.get("controls", {}))),
                    "status": status,
                }
            )
        except Exception:  # noqa: S112
            continue
    return frameworks


def load_framework(framework_id: str) -> dict[str, Any]:
    """Load a compliance framework mapping by ID.

    Raises FileNotFoundError if framework not found.
    """
    # Try exact filename first
    for f in _FRAMEWORKS_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if data.get("framework_id") == framework_id:
                return dict(data)
        except Exception:  # noqa: S112
            continue
    msg = f"Compliance framework '{framework_id}' not found. Available: {[fw['id'] for fw in list_frameworks()]}"
    raise FileNotFoundError(msg)
