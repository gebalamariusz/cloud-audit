"""Tests for TF-001: SES phishing setup precursor detector."""

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

    def get_identity(EmailIdentity: str) -> dict[str, Any]:  # noqa: N803
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


def test_no_identities_no_findings() -> None:
    ses = _ses_client(out_of_sandbox=False, identities=[], details={})
    result = ses_phishing.detect(_provider(ses))
    assert result.error is None
    assert result.findings == []


def test_old_identity_not_flagged() -> None:
    """Identity verified 60 days ago = not in attack-window, no flag."""
    name = "newsletter@company.example"
    ses = _ses_client(
        out_of_sandbox=True,
        identities=[_identity(name)],
        details={name: {"CreatedTimestamp": _now() - timedelta(days=60)}},
    )
    result = ses_phishing.detect(_provider(ses))
    assert result.findings == []


def test_recent_identity_in_sandbox_medium() -> None:
    """Recent identity but account in sandbox = MEDIUM (limited blast radius)."""
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
    assert f.category == Category.THREAT
    assert f.threat_pattern_id == ses_phishing.PATTERN_ID
    assert "test@dev.example" in f.title
    assert "sandbox" in f.description.lower()


def test_recent_identity_out_of_sandbox_with_matching_domain_medium() -> None:
    """Recent email identity + production sending + matching DOMAIN identity in account = MEDIUM."""
    email = "alerts@trusted.example"
    domain = "trusted.example"
    ses = _ses_client(
        out_of_sandbox=True,
        identities=[
            _identity(email, identity_type="EMAIL_ADDRESS"),
            _identity(domain, identity_type="DOMAIN"),
        ],
        details={
            email: {"CreatedTimestamp": _now() - timedelta(days=2)},
            domain: {"CreatedTimestamp": _now() - timedelta(days=200)},  # old, won't be flagged
        },
    )
    result = ses_phishing.detect(_provider(ses))
    # Only the recent email is flagged. Domain match -> MEDIUM (not HIGH).
    flagged = [f for f in result.findings if f.severity != Severity.INFO]
    assert len(flagged) == 1
    assert flagged[0].severity == Severity.MEDIUM


def test_recent_email_no_matching_domain_out_of_sandbox_high() -> None:
    """Recent email + out-of-sandbox + NO matching domain = HIGH (typosquat pattern)."""
    name = "support@typosquat.example"
    ses = _ses_client(
        out_of_sandbox=True,
        identities=[_identity(name)],
        details={name: {"CreatedTimestamp": _now() - timedelta(days=1)}},
    )
    result = ses_phishing.detect(_provider(ses))
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.HIGH
    assert "typosquat" in f.description.lower()


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
    """sesv2 client init failure in a region is swallowed (region opt-in is the common cause).

    This differs from patterns where AWS perms errors should surface - SES is region-scoped
    and many regions don't have sesv2 at all. We trade error visibility for noise reduction.
    """
    p = MagicMock(spec=AWSProvider)
    p.regions = ["us-east-1"]
    p.client.side_effect = RuntimeError("boom")
    result = ses_phishing.detect(p)
    assert result.error is None
    assert result.findings == []
