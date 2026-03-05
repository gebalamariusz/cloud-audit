"""SARIF v2.1.0 report generator for GitHub Code Scanning integration."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cloud_audit.models import ScanReport

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

_SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _fingerprint(check_id: str, resource_id: str) -> str:
    """Generate a stable fingerprint for deduplication."""
    raw = f"{check_id}:{resource_id}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _build_rules(report: ScanReport) -> list[dict[str, Any]]:
    """Build SARIF rules from unique check IDs in the report."""
    seen: dict[str, dict[str, Any]] = {}
    for finding in report.all_findings:
        if finding.check_id in seen:
            continue
        rule: dict[str, Any] = {
            "id": finding.check_id,
            "shortDescription": {"text": finding.title},
            "defaultConfiguration": {
                "level": _SEVERITY_MAP.get(finding.severity.value, "warning"),
            },
        }
        if finding.remediation and finding.remediation.doc_url:
            rule["helpUri"] = finding.remediation.doc_url
        if finding.compliance_refs:
            rule["properties"] = {"tags": finding.compliance_refs}
        seen[finding.check_id] = rule
    return list(seen.values())


def _build_results(report: ScanReport) -> list[dict[str, Any]]:
    """Build SARIF results from findings."""
    results: list[dict[str, Any]] = []
    for finding in report.all_findings:
        result: dict[str, Any] = {
            "ruleId": finding.check_id,
            "level": _SEVERITY_MAP.get(finding.severity.value, "warning"),
            "message": {
                "text": f"{finding.description} Recommendation: {finding.recommendation}",
            },
            "partialFingerprints": {
                "primaryLocationLineHash": _fingerprint(finding.check_id, finding.resource_id),
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.resource_id,
                            "uriBaseId": finding.region,
                        },
                    },
                }
            ],
            "properties": {
                "resource_type": finding.resource_type,
                "resource_id": finding.resource_id,
                "region": finding.region,
                "category": finding.category.value,
                "severity": finding.severity.value,
            },
        }
        if finding.remediation:
            result["properties"]["remediation_cli"] = finding.remediation.cli
            if finding.remediation.terraform:
                result["properties"]["remediation_terraform"] = finding.remediation.terraform
            result["properties"]["remediation_doc"] = finding.remediation.doc_url
        results.append(result)
    return results


def generate_sarif(report: ScanReport) -> str:
    """Generate a SARIF v2.1.0 JSON string from a ScanReport."""
    from cloud_audit import __version__

    sarif: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cloud-audit",
                        "version": __version__,
                        "informationUri": "https://github.com/gebalamariusz/cloud-audit",
                        "rules": _build_rules(report),
                    },
                },
                "results": _build_results(report),
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "provider": report.provider,
                            "account_id": report.account_id,
                            "regions": report.regions,
                            "duration_seconds": report.duration_seconds,
                            "score": report.summary.score,
                        },
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2)
