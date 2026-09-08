"""Configuration file parser for .cloud-audit.yml."""

from __future__ import annotations

import fnmatch
from datetime import date
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

from cloud_audit.models import Severity

_VALID_KEYS = {
    "provider",
    "profile",
    "regions",
    "min_severity",
    "exclude_checks",
    "suppressions",
}


class Suppression(BaseModel):
    """A single suppression entry -- explicitly accepted finding."""

    check_id: str
    resource_id: str | None = None
    reason: str
    accepted_by: str = ""
    expires: date | None = None

    def is_expired(self, today: date | None = None) -> bool:
        if self.expires is None:
            return False
        return (today or date.today()) > self.expires

    def matches(self, check_id: str, resource_id: str) -> bool:
        if not fnmatch.fnmatchcase(check_id, self.check_id):
            return False
        if self.resource_id is None:
            return True
        return fnmatch.fnmatchcase(resource_id, self.resource_id)


class CloudAuditConfig(BaseModel):
    """Parsed .cloud-audit.yml configuration."""

    provider: str = "aws"
    profile: str | None = None
    regions: list[str] | None = None
    min_severity: Severity | None = None
    exclude_checks: list[str] = Field(default_factory=list)
    suppressions: list[Suppression] = Field(default_factory=list)

    @field_validator("min_severity", mode="before")
    @classmethod
    def _parse_severity(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.lower()
        return v


def _validate_keys(data: dict[str, Any]) -> list[str]:
    """Return list of unknown keys in the config."""
    return [k for k in data if k not in _VALID_KEYS]


def load_config(path: Path | None = None) -> CloudAuditConfig:
    """Load config from YAML file.

    If path is None, looks for .cloud-audit.yml in the current directory.
    Returns default config if no file is found.
    """
    if path is None:
        path = Path.cwd() / ".cloud-audit.yml"

    if not path.exists():
        return CloudAuditConfig()

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        msg = f"Invalid YAML in {path}: {e}"
        raise ValueError(msg) from e

    if not isinstance(raw, dict):
        return CloudAuditConfig()

    unknown = _validate_keys(raw)
    if unknown:
        msg = f"Unknown keys in {path}: {', '.join(unknown)}"
        raise ValueError(msg)

    return CloudAuditConfig(**raw)
