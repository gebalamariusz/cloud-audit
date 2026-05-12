"""Tests for TF-006: MMDSv1 still in use detector."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from cloud_audit.models import Category, Severity
from cloud_audit.providers.aws.provider import AWSProvider
from cloud_audit.providers.aws.threat_feed import mmdsv1_in_use


def _paginator(pages: list[dict[str, Any]]) -> MagicMock:
    p = MagicMock()
    p.paginate.return_value = iter(pages)
    return p


def _ec2_with_instances(instances: list[dict[str, Any]]) -> MagicMock:
    """Mock EC2 client returning the given instances on describe_instances pagination."""
    ec2 = MagicMock()
    page = {"Reservations": [{"Instances": instances}]}
    ec2.get_paginator.return_value = _paginator([page])
    return ec2


def _agentcore_empty() -> MagicMock:
    """Mock bedrock-agent that returns no agents."""
    ac = MagicMock()
    ac.get_paginator.return_value = _paginator([{"agentSummaries": []}])
    return ac


def _provider(ec2: MagicMock, agentcore: MagicMock | None = None, regions: list[str] | None = None) -> MagicMock:
    p = MagicMock(spec=AWSProvider)
    p.regions = regions or ["us-east-1"]
    ac = agentcore if agentcore is not None else _agentcore_empty()

    def client(service: str, region_name: str | None = None) -> MagicMock:
        if service == "ec2":
            return ec2
        if service == "bedrock-agent":
            return ac
        raise AssertionError(service)

    p.client.side_effect = client
    return p


def _instance(instance_id: str, http_tokens: str = "optional", hop_limit: int = 1) -> dict[str, Any]:
    return {
        "InstanceId": instance_id,
        "MetadataOptions": {
            "HttpTokens": http_tokens,
            "HttpPutResponseHopLimit": hop_limit,
            "HttpEndpoint": "enabled",
        },
    }


# -----------------------------------------------------------------------------


def test_no_instances_no_findings() -> None:
    ec2 = _ec2_with_instances([])
    result = mmdsv1_in_use.detect(_provider(ec2))
    assert result.error is None
    assert result.findings == []


def test_imdsv2_required_not_flagged() -> None:
    """HttpTokens=required = IMDSv2 enforced = safe."""
    ec2 = _ec2_with_instances([_instance("i-safe", http_tokens="required")])
    result = mmdsv1_in_use.detect(_provider(ec2))
    assert result.findings == []
    assert result.resources_scanned == 1


def test_imdsv1_optional_flagged() -> None:
    """HttpTokens=optional = v1 callable = HIGH finding."""
    ec2 = _ec2_with_instances([_instance("i-vulnerable", http_tokens="optional")])
    result = mmdsv1_in_use.detect(_provider(ec2))
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.HIGH
    assert f.category == Category.THREAT
    assert f.threat_pattern_id == mmdsv1_in_use.PATTERN_ID
    assert "i-vulnerable" in f.title
    assert "modify-instance-metadata-options" in f.remediation.cli
    assert "http-tokens required" in f.remediation.cli


def test_high_hop_limit_calls_out_container_risk() -> None:
    """hop_limit > 1 = container/pod can reach IMDS - flagged in description."""
    ec2 = _ec2_with_instances([_instance("i-multi-hop", http_tokens="optional", hop_limit=5)])
    result = mmdsv1_in_use.detect(_provider(ec2))
    assert "Capital-One-style" in result.findings[0].description


def test_metadata_options_missing_treated_as_v1() -> None:
    """Instance without MetadataOptions field = legacy = v1 by default."""
    inst = {"InstanceId": "i-legacy"}  # no MetadataOptions at all
    ec2 = _ec2_with_instances([inst])
    result = mmdsv1_in_use.detect(_provider(ec2))
    assert len(result.findings) == 1
    assert "i-legacy" in result.findings[0].resource_id


def test_mixed_safe_and_vulnerable() -> None:
    ec2 = _ec2_with_instances(
        [
            _instance("i-safe", http_tokens="required"),
            _instance("i-vuln", http_tokens="optional"),
            _instance("i-also-vuln"),  # no MetadataOptions = vulnerable
        ]
    )
    result = mmdsv1_in_use.detect(_provider(ec2))
    assert len(result.findings) == 2
    ids = {f.resource_id for f in result.findings}
    assert ids == {"i-vuln", "i-also-vuln"}


def test_ec2_access_denied_in_region_does_not_abort() -> None:
    """If EC2 describe_instances raises AccessDenied, scan continues."""
    ec2 = MagicMock()

    class _Denied(Exception):
        def __init__(self) -> None:
            super().__init__("AccessDeniedException")
            self.response = {"Error": {"Code": "AccessDeniedException"}}

    ec2.get_paginator.side_effect = _Denied()

    result = mmdsv1_in_use.detect(_provider(ec2))
    assert result.error is None  # gracefully skipped
    assert result.findings == []


def test_bedrock_agentcore_v1_flagged_critical() -> None:
    """AgentCore agent on v1 metadata = CRITICAL (active CVE)."""
    ec2 = _ec2_with_instances([])
    ac = MagicMock()
    ac.get_paginator.return_value = _paginator([{"agentSummaries": [{"agentId": "AGENT123", "agentName": "rag-bot"}]}])
    ac.get_agent.return_value = {"agent": {"metadataVersion": "v1"}}

    result = mmdsv1_in_use.detect(_provider(ec2, agentcore=ac))

    agentcore_findings = [f for f in result.findings if f.resource_type == "AWS::Bedrock::Agent"]
    assert len(agentcore_findings) == 1
    f = agentcore_findings[0]
    assert f.severity == Severity.CRITICAL
    assert "rag-bot" in f.title
    assert "AGENT123" in f.resource_id
    assert any("thehackernews" in r for r in f.references)


def test_bedrock_agentcore_v2_not_flagged() -> None:
    ec2 = _ec2_with_instances([])
    ac = MagicMock()
    ac.get_paginator.return_value = _paginator(
        [{"agentSummaries": [{"agentId": "AGENT-OK", "agentName": "modern-agent"}]}]
    )
    ac.get_agent.return_value = {"agent": {"metadataVersion": "v2"}}

    result = mmdsv1_in_use.detect(_provider(ec2, agentcore=ac))
    assert result.findings == []


def test_bedrock_agentcore_unsupported_region_silent() -> None:
    """If list_agents raises ValidationException (region without service), skip silently."""
    ec2 = _ec2_with_instances([])
    ac = MagicMock()

    class _Validation(Exception):
        def __init__(self) -> None:
            super().__init__("ValidationException")
            self.response = {"Error": {"Code": "ValidationException"}}

    paginator = MagicMock()
    paginator.paginate.side_effect = _Validation()
    ac.get_paginator.return_value = paginator

    result = mmdsv1_in_use.detect(_provider(ec2, agentcore=ac))
    assert result.error is None
    assert result.findings == []


def test_pattern_metadata_exposed() -> None:
    assert mmdsv1_in_use.PATTERN_ID == "TF-006-mmdsv1-in-use"
    assert mmdsv1_in_use.CHECK_ID == "aws-tf-006"
    assert mmdsv1_in_use.PATTERN_SEVERITY == Severity.HIGH


def test_top_level_exception_recorded() -> None:
    p = MagicMock(spec=AWSProvider)
    p.regions = ["us-east-1"]
    p.client.side_effect = RuntimeError("boom")
    result = mmdsv1_in_use.detect(p)
    assert "boom" in (result.error or "")
