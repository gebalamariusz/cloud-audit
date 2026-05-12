"""Threat Feed - active abuse pattern detectors.

Each pattern in this package detects an attack technique observed in real-world
2025-2026 incidents (cryptomining campaigns, SES phishing, leaked credentials,
AgentCore vulnerabilities). Patterns are versioned via THREAT_FEED_VERSION so
operators can pin a known rules pack.

Patterns vs regular checks:
    - Regular checks (providers/aws/checks/) detect MISCONFIGURATION
    - Threat patterns (this package) detect ACTIVE ABUSE INDICATORS or
      conditions an attacker exploited in a documented incident.

Each pattern produces standard Finding objects with:
    - category=Category.THREAT
    - threat_pattern_id="TF-XXX-name"
    - references=[<URL to research report or CVE>]

Adding a new pattern:
    1. Create src/cloud_audit/providers/aws/threat_feed/<name>.py
    2. Implement: def detect(provider) -> CheckResult
    3. Register in _PATTERN_MODULES below
    4. Add tests in tests/aws/threat_feed/test_<name>.py
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category
from cloud_audit.providers.aws.threat_feed import (
    cloudtrail_tampering,
    datazone_overgrant,
    lambda_function_url,
    mmdsv1_in_use,
    quarantine_policy,
    roles_anywhere_abuse,
    ses_phishing,
    whoami_confusion,
)
from cloud_audit.providers.base import make_check

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn

THREAT_FEED_VERSION = "2026-Q2"
"""Versioned rules pack identifier - bump when patterns added/removed/changed.

Operators pin via `cloud-audit threat-feed --threat-feed-version 2026-Q2`
to get reproducible scans across releases.
"""

_PATTERN_MODULES = [
    ses_phishing,
    lambda_function_url,
    quarantine_policy,
    mmdsv1_in_use,
    whoami_confusion,
    cloudtrail_tampering,
    roles_anywhere_abuse,
    datazone_overgrant,
]
"""Registry of all threat feed pattern modules.

Order matters for output stability - keep it deterministic.
New patterns: append to the end so existing TF-IDs remain stable.
"""


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all threat feed pattern check functions bound to the provider.

    Each pattern module exposes:
        - detect(provider) -> CheckResult
        - PATTERN_ID: str  (e.g. "TF-003-quarantine-policy")
        - CHECK_ID: str    (e.g. "aws-tf-003")
    """
    checks: list[CheckFn] = []
    for module in _PATTERN_MODULES:
        check = make_check(
            module.detect,
            provider,
            check_id=module.CHECK_ID,
            category=Category.THREAT,
        )
        checks.append(check)
    return checks


def list_patterns() -> list[dict[str, str]]:
    """Return metadata for all registered patterns - used by CLI list/help."""
    return [
        {
            "pattern_id": m.PATTERN_ID,
            "check_id": m.CHECK_ID,
            "name": m.PATTERN_NAME,
            "severity": m.PATTERN_SEVERITY.value,
            "doc_url": m.DOC_URL,
        }
        for m in _PATTERN_MODULES
    ]
