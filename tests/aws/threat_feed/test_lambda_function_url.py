"""Tests for TF-002: Lambda Function URL persistence detector."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from cloud_audit.models import Category, Severity
from cloud_audit.providers.aws.provider import AWSProvider
from cloud_audit.providers.aws.threat_feed import lambda_function_url


def _paginator(pages: list[dict[str, Any]]) -> MagicMock:
    p = MagicMock()
    p.paginate.return_value = iter(pages)
    return p


def _lambda_client(
    *,
    functions: list[dict[str, Any]],
    url_configs: dict[str, dict[str, Any]] | None = None,
) -> MagicMock:
    """Mock lambda client. url_configs maps function name -> get_function_url_config response.
    Missing entries -> ResourceNotFoundException (no URL configured)."""
    url_configs = url_configs or {}
    lam = MagicMock()
    lam.get_paginator.return_value = _paginator([{"Functions": functions}])

    class _NotFound(Exception):
        def __init__(self) -> None:
            super().__init__("ResourceNotFoundException")
            self.response = {"Error": {"Code": "ResourceNotFoundException"}}

    def get_url_cfg(FunctionName: str) -> dict[str, Any]:
        if FunctionName in url_configs:
            return url_configs[FunctionName]
        raise _NotFound()

    lam.get_function_url_config.side_effect = get_url_cfg
    return lam


def _iam_client(role_attachments: dict[str, list[dict[str, str]]] | None = None) -> MagicMock:
    role_attachments = role_attachments or {}
    iam = MagicMock()

    def list_attached(RoleName: str) -> dict[str, Any]:
        return {"AttachedPolicies": role_attachments.get(RoleName, [])}

    iam.list_attached_role_policies.side_effect = list_attached
    return iam


def _provider(lam: MagicMock, iam: MagicMock, regions: list[str] = None) -> MagicMock:
    regions = regions or ["us-east-1"]
    p = MagicMock(spec=AWSProvider)
    p.regions = regions

    def client(service: str, region_name: str | None = None) -> MagicMock:
        if service == "iam":
            return iam
        if service == "lambda":
            return lam
        raise AssertionError(f"unexpected service: {service}")

    p.client.side_effect = client
    return p


def _fn(name: str, role: str = "arn:aws:iam::123456789012:role/lambda-basic") -> dict[str, Any]:
    return {
        "FunctionName": name,
        "FunctionArn": f"arn:aws:lambda:us-east-1:123456789012:function:{name}",
        "Role": role,
    }


def _public_url_cfg(function_name: str, cors_origins: list[str] | None = None) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "AuthType": "NONE",
        "FunctionUrl": "https://abc123.lambda-url.us-east-1.on.aws/",
        "FunctionArn": f"arn:aws:lambda:us-east-1:123456789012:function:{function_name}",
    }
    if cors_origins is not None:
        cfg["Cors"] = {"AllowOrigins": cors_origins}
    return cfg


# -----------------------------------------------------------------------------


def test_no_lambda_functions_no_findings() -> None:
    lam = _lambda_client(functions=[])
    iam = _iam_client()
    result = lambda_function_url.detect(_provider(lam, iam))
    assert result.error is None
    assert result.findings == []
    assert result.resources_scanned == 0


def test_lambda_without_function_url_no_finding() -> None:
    lam = _lambda_client(functions=[_fn("api-handler")])
    iam = _iam_client()
    result = lambda_function_url.detect(_provider(lam, iam))
    assert result.findings == []
    assert result.resources_scanned == 1


def test_lambda_with_aws_iam_url_not_flagged() -> None:
    """AuthType=AWS_IAM is the safe choice - not a finding."""
    lam = _lambda_client(
        functions=[_fn("authed-api")],
        url_configs={
            "authed-api": {
                "AuthType": "AWS_IAM",
                "FunctionUrl": "https://xyz.lambda-url.us-east-1.on.aws/",
            }
        },
    )
    iam = _iam_client()
    result = lambda_function_url.detect(_provider(lam, iam))
    assert result.findings == []


def test_public_url_with_basic_role_flagged_high() -> None:
    """AuthType=NONE + non-admin role = HIGH severity."""
    lam = _lambda_client(
        functions=[_fn("public-webhook")],
        url_configs={"public-webhook": _public_url_cfg("public-webhook")},
    )
    iam = _iam_client()
    result = lambda_function_url.detect(_provider(lam, iam))
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.HIGH
    assert f.category == Category.THREAT
    assert f.threat_pattern_id == lambda_function_url.PATTERN_ID
    assert "public-webhook" in f.title
    assert f.references


def test_public_url_with_admin_role_escalates_to_critical() -> None:
    """AuthType=NONE + admin role = CRITICAL (matches November 2025 campaign profile)."""
    lam = _lambda_client(
        functions=[_fn("backdoor", role="arn:aws:iam::123456789012:role/admin-lambda")],
        url_configs={"backdoor": _public_url_cfg("backdoor")},
    )
    iam = _iam_client(
        role_attachments={
            "admin-lambda": [
                {
                    "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    "PolicyName": "AdministratorAccess",
                }
            ]
        }
    )
    result = lambda_function_url.detect(_provider(lam, iam))
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.CRITICAL
    assert "admin-lambda" in f.description
    assert "cryptomining" in f.description.lower()


def test_secrets_manager_role_also_escalates() -> None:
    """Roles with Secrets/KMS/IAM full access escalate to CRITICAL."""
    lam = _lambda_client(
        functions=[_fn("secrets-fn", role="arn:aws:iam::123456789012:role/secrets-role")],
        url_configs={"secrets-fn": _public_url_cfg("secrets-fn")},
    )
    iam = _iam_client(
        role_attachments={
            "secrets-role": [
                {
                    "PolicyArn": "arn:aws:iam::aws:policy/SecretsManagerReadWrite",
                    "PolicyName": "SecretsManagerReadWrite",
                }
            ]
        }
    )
    result = lambda_function_url.detect(_provider(lam, iam))
    assert result.findings[0].severity == Severity.CRITICAL


def test_wildcard_cors_noted_in_description() -> None:
    """CORS allowing * is called out in the description for browser-context risk."""
    lam = _lambda_client(
        functions=[_fn("cors-wide")],
        url_configs={"cors-wide": _public_url_cfg("cors-wide", cors_origins=["*"])},
    )
    iam = _iam_client()
    result = lambda_function_url.detect(_provider(lam, iam))
    assert "ANY origin" in result.findings[0].description


def test_multi_region_scan() -> None:
    """Functions in two regions - only one has a public URL."""
    lam = MagicMock()
    iam = _iam_client()

    def get_paginator(_op: str) -> MagicMock:
        return _paginator([{"Functions": [_fn("region-fn")]}])

    lam.get_paginator.side_effect = get_paginator

    class _NotFound(Exception):
        def __init__(self) -> None:
            super().__init__("ResourceNotFoundException")
            self.response = {"Error": {"Code": "ResourceNotFoundException"}}

    call_count = {"n": 0}

    def get_url_cfg(FunctionName: str) -> dict[str, Any]:
        call_count["n"] += 1
        # First region returns config, second region returns NotFound
        if call_count["n"] == 1:
            return _public_url_cfg("region-fn")
        raise _NotFound()

    lam.get_function_url_config.side_effect = get_url_cfg

    result = lambda_function_url.detect(_provider(lam, iam, regions=["us-east-1", "eu-west-1"]))
    assert result.resources_scanned == 2  # 1 fn x 2 regions
    assert len(result.findings) == 1


def test_remediation_includes_cloudtrail_lookup_and_delete_url() -> None:
    lam = _lambda_client(
        functions=[_fn("suspicious")],
        url_configs={"suspicious": _public_url_cfg("suspicious")},
    )
    iam = _iam_client()
    result = lambda_function_url.detect(_provider(lam, iam))
    rem = result.findings[0].remediation
    assert "cloudtrail lookup-events" in rem.cli
    assert "delete-function-url-config" in rem.cli
    assert "AWS_IAM" in rem.terraform


def test_pattern_metadata_exposed() -> None:
    assert lambda_function_url.PATTERN_ID == "TF-002-lambda-function-url-persistence"
    assert lambda_function_url.CHECK_ID == "aws-tf-002"
    assert lambda_function_url.PATTERN_SEVERITY == Severity.HIGH
    assert lambda_function_url.DOC_URL.startswith("https://")


def test_role_lookup_access_denied_does_not_escalate() -> None:
    """If we can't read the role, default to base severity (don't crash)."""
    lam = _lambda_client(
        functions=[_fn("opaque-fn", role="arn:aws:iam::123456789012:role/opaque")],
        url_configs={"opaque-fn": _public_url_cfg("opaque-fn")},
    )

    iam = MagicMock()

    class _Denied(Exception):
        def __init__(self) -> None:
            super().__init__("AccessDenied")
            self.response = {"Error": {"Code": "AccessDenied"}}

    iam.list_attached_role_policies.side_effect = _Denied()

    result = lambda_function_url.detect(_provider(lam, iam))
    # Still flagged at HIGH (base severity), no crash
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.HIGH


def test_top_level_exception_recorded() -> None:
    p = MagicMock(spec=AWSProvider)
    p.client.side_effect = RuntimeError("boom")
    result = lambda_function_url.detect(p)
    assert "boom" in (result.error or "")
