"""Tests for TF-001: SES phishing setup precursor detector.

v2.2.1: severity escalation rewritten. HIGH now requires BOTH out-of-sandbox
AND a burst of >=2 recent verifications in the same account scan (matches
Wiz's documented "multiple domains" pattern). The earlier "email identity
without matching domain" signal was removed - it pointed at the wrong
attacker behaviour (Wiz documented attackers adding domains, not single
typosquats).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

from cloud_audit.models import Category, Severity
from cloud_audit.providers.aws.provider import AWSProvider
from cloud_audit.providers.aws.threat_feed import ses_phishing


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ses_client(
    *,
    out_of_sandbox: bool,
    identities: list[dict[str, Any]],
    details: dict[str, dict[str, Any]],
) -> MagicMock:
    """Mock SESv2 client.

    identities: list of {IdentityName, IdentityType, VerifiedForSendingStatus}
    details: maps IdentityName -> {CreatedTimestamp: datetime}
    """
    ses = MagicMock()
    ses.get_account.return_value = {"ProductionAccessEnabled": out_of_sandbox}
    ses.list_email_identities.return_value = {"EmailIdentities": identities}

    def get_identity(EmailIdentity: str) -> dict[str, Any]:
        return details.get(EmailIdentity, {})

    ses.get_email_identity.side_effect = get_identity
    return ses


def _provider(ses: MagicMock, regions: list[str] | None = None) -> MagicMock:
    p = MagicMock(spec=AWSProvider)
    p.regions = regions or ["us-east-1"]
    p.client.return_value = ses
    return p


def _identity(name: str, identity_type: str = "EMAIL_ADDRESS", verified: bool = True) -> dict[str, Any]:
    return {"IdentityName": name, "IdentityType": identity_type, "VerifiedForSendingStatus": verified}


# -----------------------------------------------------------------------------
# Detection tests
# -----------------------------------------------------------------------------


def test_no_identities_no_findings() -> None:
    ses = _ses_client(out_of_sandbox=False, identities=[], details={})
    result = ses_phishing.detect(_provider(ses))
    assert result.error is None
    assert result.findings == []


def test_old_identity_not_flagged() -> None:
    """Identity verified 60 days ago = outside the recent window, no flag."""
    name = "newsletter@company.example"
    ses = _ses_client(
        out_of_sandbox=True,
        identities=[_identity(name)],
        details={name: {"CreatedTimestamp": _now() - timedelta(days=60)}},
    )
    result = ses_phishing.detect(_provider(ses))
    assert result.findings == []


def test_single_recent_identity_out_of_sandbox_medium() -> None:
    """One recent identity, even with production sending, is MEDIUM - not a burst yet."""
    name = "team@trusted.example"
    ses = _ses_client(
        out_of_sandbox=True,
        identities=[_identity(name)],
        details={name: {"CreatedTimestamp": _now() - timedelta(days=2)}},
    )
    result = ses_phishing.detect(_provider(ses))
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.MEDIUM
    assert f.category == Category.THREAT
    assert f.threat_pattern_id == ses_phishing.PATTERN_ID


def test_single_recent_identity_in_sandbox_medium() -> None:
    """Single recent + sandbox = MEDIUM (limited blast radius)."""
    name = "test@dev.example"
    ses = _ses_client(
        out_of_sandbox=False,
        identities=[_identity(name)],
        details={name: {"CreatedTimestamp": _now() - timedelta(days=2)}},
    )
    result = ses_phishing.detect(_provider(ses))
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.MEDIUM
    assert "sandbox" in f.description.lower()


def test_burst_out_of_sandbox_escalates_to_high() -> None:
    """TWO+ recent verifications + production sending = HIGH (Wiz burst pattern)."""
    ses = _ses_client(
        out_of_sandbox=True,
        identities=[
            _identity("domain1.example", identity_type="DOMAIN"),
            _identity("domain2.example", identity_type="DOMAIN"),
        ],
        details={
            "domain1.example": {"CreatedTimestamp": _now() - timedelta(days=1)},
            "domain2.example": {"CreatedTimestamp": _now() - timedelta(days=3)},
        },
    )
    result = ses_phishing.detect(_provider(ses))
    assert len(result.findings) == 2
    # BOTH findings escalate - the burst count is account-scoped, not per-finding
    for f in result.findings:
        assert f.severity == Severity.HIGH
        assert "burst pattern" in f.description.lower()
        assert "wiz" in f.description.lower()


def test_burst_in_sandbox_stays_medium() -> None:
    """Burst but account still in sandbox = MEDIUM (no external blast radius)."""
    ses = _ses_client(
        out_of_sandbox=False,
        identities=[
            _identity("d1.example", identity_type="DOMAIN"),
            _identity("d2.example", identity_type="DOMAIN"),
        ],
        details={
            "d1.example": {"CreatedTimestamp": _now() - timedelta(days=1)},
            "d2.example": {"CreatedTimestamp": _now() - timedelta(days=2)},
        },
    )
    result = ses_phishing.detect(_provider(ses))
    assert len(result.findings) == 2
    for f in result.findings:
        assert f.severity == Severity.MEDIUM


def test_email_no_matching_domain_does_not_escalate() -> None:
    """v2.2.1 regression check: the removed 'typosquat' heuristic must not return.

    Wiz documented attackers verifying DOMAINS in bursts, not single emails
    without a matching domain. A single email identity, even out-of-sandbox,
    must stay MEDIUM unless the burst threshold is met.
    """
    ses = _ses_client(
        out_of_sandbox=True,
        identities=[_identity("support@typosquat.example")],
        details={"support@typosquat.example": {"CreatedTimestamp": _now() - timedelta(days=1)}},
    )
    result = ses_phishing.detect(_provider(ses))
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.MEDIUM


def test_pending_identity_not_flagged() -> None:
    """Identity with VerifiedForSendingStatus=False is not yet usable - skip."""
    name = "pending@dev.example"
    ses = _ses_client(
        out_of_sandbox=True,
        identities=[_identity(name, verified=False)],
        details={name: {"CreatedTimestamp": _now() - timedelta(days=1)}},
    )
    result = ses_phishing.detect(_provider(ses))
    assert result.findings == []


def test_burst_only_counts_recent_identities() -> None:
    """Old (>14d) identities do not contribute to the burst count.

    Account has 1 recent identity and 1 old identity. Old one is filtered
    out before the burst check, so burst_count = 1, severity stays MEDIUM
    even out-of-sandbox.
    """
    ses = _ses_client(
        out_of_sandbox=True,
        identities=[
            _identity("recent.example", identity_type="DOMAIN"),
            _identity("old.example", identity_type="DOMAIN"),
        ],
        details={
            "recent.example": {"CreatedTimestamp": _now() - timedelta(days=2)},
            "old.example": {"CreatedTimestamp": _now() - timedelta(days=200)},
        },
    )
    result = ses_phishing.detect(_provider(ses))
    assert len(result.findings) == 1
    assert "recent.example" in result.findings[0].resource_id
    assert result.findings[0].severity == Severity.MEDIUM


def test_remediation_includes_delete_and_audit() -> None:
    name = "phish-staging@bad.example"
    ses = _ses_client(
        out_of_sandbox=True,
        identities=[_identity(name)],
        details={name: {"CreatedTimestamp": _now() - timedelta(days=1)}},
    )
    result = ses_phishing.detect(_provider(ses))
    rem = result.findings[0].remediation
    assert "delete-email-identity" in rem.cli
    assert "cloudtrail lookup-events" in rem.cli
    assert name in rem.cli


def test_unsupported_region_silent() -> None:
    """Region without sesv2 - return 0 findings, no error."""
    ses = MagicMock()

    class _Validation(Exception):
        def __init__(self) -> None:
            super().__init__("ValidationException")
            self.response = {"Error": {"Code": "ValidationException"}}

    ses.get_account.side_effect = _Validation()

    result = ses_phishing.detect(_provider(ses))
    assert result.error is None
    assert result.findings == []


def test_pattern_metadata_exposed() -> None:
    assert ses_phishing.PATTERN_ID == "TF-001-ses-phishing-setup"
    assert ses_phishing.CHECK_ID == "aws-tf-001"
    assert ses_phishing.PATTERN_SEVERITY == Severity.MEDIUM


def test_provider_client_failure_swallowed_per_region() -> None:
    """sesv2 client init failure in a region is swallowed (region opt-in is the common cause)."""
    p = MagicMock(spec=AWSProvider)
    p.regions = ["us-east-1"]
    p.client.side_effect = RuntimeError("boom")
    result = ses_phishing.detect(p)
    assert result.error is None
    assert result.findings == []
