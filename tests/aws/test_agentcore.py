"""Tests for Amazon Bedrock AgentCore checks (agentcore.py).

moto does not implement bedrock-agentcore-control, so a fake client feeds
controlled list/get responses. The field names, operations and enum values
exercised here match the live boto3 service model (verified at design time).
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError, EndpointConnectionError

from cloud_audit.providers.aws.checks import agentcore


class _FakePaginator:
    def __init__(self, page: dict[str, Any]) -> None:
        self._page = page

    def paginate(self) -> list[dict[str, Any]]:
        return [self._page]


class _FakeClient:
    """Minimal stand-in for a bedrock-agentcore-control client."""

    def __init__(
        self,
        *,
        lists: dict[str, dict[str, Any]] | None = None,
        gets: dict[str, dict[str, Any]] | None = None,
        errors: dict[str, Exception] | None = None,
    ) -> None:
        self._lists = lists or {}
        self._gets = gets or {}
        self._errors = errors or {}

    def get_paginator(self, method: str) -> _FakePaginator:
        if method in self._errors:
            raise self._errors[method]
        return _FakePaginator(self._lists.get(method, {}))

    def __getattr__(self, name: str) -> Any:
        def _call(**_kwargs: Any) -> dict[str, Any]:
            if name in self._errors:
                raise self._errors[name]
            return self._gets.get(name, {})

        return _call


class _FakeProvider:
    def __init__(self, client: _FakeClient, regions: tuple[str, ...] = ("us-east-1",)) -> None:
        self._client = client
        self.regions = list(regions)

    def client(self, service: str, region_name: str | None = None) -> _FakeClient:
        return self._client


def _provider(**kwargs: Any) -> Any:
    return _FakeProvider(_FakeClient(**kwargs))


def _denied(op: str) -> ClientError:
    return ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, op)


# ---------------------------------------------------------------------------
# aws-agc-001 Code Interpreter PUBLIC network mode
# ---------------------------------------------------------------------------


def test_code_interpreter_public_flagged() -> None:
    prov = _provider(
        lists={"list_code_interpreters": {"codeInterpreterSummaries": [{"codeInterpreterId": "ci-1"}]}},
        gets={"get_code_interpreter": {"name": "ci", "networkConfiguration": {"networkMode": "PUBLIC"}}},
    )
    result = agentcore.check_code_interpreter_public_network(prov)
    assert result.error is None
    assert len(result.findings) == 1
    assert result.findings[0].check_id == "aws-agc-001"
    assert result.findings[0].severity.value == "high"


def test_code_interpreter_sandbox_clean() -> None:
    prov = _provider(
        lists={"list_code_interpreters": {"codeInterpreterSummaries": [{"codeInterpreterId": "ci-1"}]}},
        gets={"get_code_interpreter": {"networkConfiguration": {"networkMode": "SANDBOX"}}},
    )
    result = agentcore.check_code_interpreter_public_network(prov)
    assert result.findings == []
    assert result.resources_scanned == 1


def test_code_interpreter_vpc_clean() -> None:
    prov = _provider(
        lists={"list_code_interpreters": {"codeInterpreterSummaries": [{"codeInterpreterId": "ci-1"}]}},
        gets={"get_code_interpreter": {"networkConfiguration": {"networkMode": "VPC"}}},
    )
    assert agentcore.check_code_interpreter_public_network(prov).findings == []


# ---------------------------------------------------------------------------
# aws-agc-002 Runtime PUBLIC network mode
# ---------------------------------------------------------------------------


def test_runtime_public_flagged() -> None:
    prov = _provider(
        lists={"list_agent_runtimes": {"agentRuntimes": [{"agentRuntimeId": "rt-1"}]}},
        gets={"get_agent_runtime": {"agentRuntimeName": "rt", "networkConfiguration": {"networkMode": "PUBLIC"}}},
    )
    result = agentcore.check_runtime_public_network(prov)
    assert len(result.findings) == 1
    assert result.findings[0].check_id == "aws-agc-002"


def test_runtime_vpc_clean() -> None:
    prov = _provider(
        lists={"list_agent_runtimes": {"agentRuntimes": [{"agentRuntimeId": "rt-1"}]}},
        gets={"get_agent_runtime": {"networkConfiguration": {"networkMode": "VPC"}}},
    )
    assert agentcore.check_runtime_public_network(prov).findings == []


# ---------------------------------------------------------------------------
# aws-agc-003 Runtime MMDSv2 not enforced
# ---------------------------------------------------------------------------


def test_runtime_mmdsv2_missing_flagged() -> None:
    prov = _provider(
        lists={"list_agent_runtimes": {"agentRuntimes": [{"agentRuntimeId": "rt-1"}]}},
        gets={"get_agent_runtime": {"agentRuntimeName": "rt"}},  # no metadataConfiguration
    )
    result = agentcore.check_runtime_imdsv2(prov)
    assert len(result.findings) == 1
    assert result.findings[0].check_id == "aws-agc-003"


def test_runtime_mmdsv2_false_flagged() -> None:
    prov = _provider(
        lists={"list_agent_runtimes": {"agentRuntimes": [{"agentRuntimeId": "rt-1"}]}},
        gets={"get_agent_runtime": {"metadataConfiguration": {"requireMMDSV2": False}}},
    )
    assert len(agentcore.check_runtime_imdsv2(prov).findings) == 1


def test_runtime_mmdsv2_true_clean() -> None:
    prov = _provider(
        lists={"list_agent_runtimes": {"agentRuntimes": [{"agentRuntimeId": "rt-1"}]}},
        gets={"get_agent_runtime": {"metadataConfiguration": {"requireMMDSV2": True}}},
    )
    assert agentcore.check_runtime_imdsv2(prov).findings == []


# ---------------------------------------------------------------------------
# aws-agc-004 Memory without customer-managed KMS
# ---------------------------------------------------------------------------


def test_memory_no_cmk_flagged() -> None:
    prov = _provider(
        lists={"list_memories": {"memories": [{"id": "mem-1"}]}},
        gets={"get_memory": {"memory": {"name": "m", "arn": "arn:mem"}}},  # no encryptionKeyArn
    )
    result = agentcore.check_memory_encryption(prov)
    assert len(result.findings) == 1
    assert result.findings[0].check_id == "aws-agc-004"
    assert result.findings[0].severity.value == "medium"


def test_memory_with_cmk_clean() -> None:
    prov = _provider(
        lists={"list_memories": {"memories": [{"id": "mem-1"}]}},
        gets={"get_memory": {"memory": {"encryptionKeyArn": "arn:aws:kms:...:key/abc"}}},
    )
    assert agentcore.check_memory_encryption(prov).findings == []


# ---------------------------------------------------------------------------
# aws-agc-005 Gateway without inbound authorizer
# ---------------------------------------------------------------------------


def test_gateway_authorizer_none_flagged() -> None:
    prov = _provider(
        lists={"list_gateways": {"items": [{"gatewayId": "gw-1"}]}},
        gets={"get_gateway": {"name": "gw", "authorizerType": "NONE"}},
    )
    result = agentcore.check_gateway_authorizer(prov)
    assert len(result.findings) == 1
    assert result.findings[0].check_id == "aws-agc-005"


def test_gateway_authorizer_jwt_clean() -> None:
    prov = _provider(
        lists={"list_gateways": {"items": [{"gatewayId": "gw-1"}]}},
        gets={"get_gateway": {"authorizerType": "CUSTOM_JWT"}},
    )
    assert agentcore.check_gateway_authorizer(prov).findings == []


# ---------------------------------------------------------------------------
# aws-agc-006 Gateway policy engine not enforcing
# ---------------------------------------------------------------------------


def test_gateway_policy_logonly_flagged() -> None:
    prov = _provider(
        lists={"list_gateways": {"items": [{"gatewayId": "gw-1"}]}},
        gets={"get_gateway": {"name": "gw", "policyEngineConfiguration": {"mode": "LOG_ONLY"}}},
    )
    result = agentcore.check_gateway_policy_engine(prov)
    assert len(result.findings) == 1
    assert result.findings[0].check_id == "aws-agc-006"


def test_gateway_policy_missing_flagged() -> None:
    prov = _provider(
        lists={"list_gateways": {"items": [{"gatewayId": "gw-1"}]}},
        gets={"get_gateway": {"name": "gw"}},  # no policyEngineConfiguration
    )
    assert len(agentcore.check_gateway_policy_engine(prov).findings) == 1


def test_gateway_policy_enforce_clean() -> None:
    prov = _provider(
        lists={"list_gateways": {"items": [{"gatewayId": "gw-1"}]}},
        gets={"get_gateway": {"policyEngineConfiguration": {"mode": "ENFORCE"}}},
    )
    assert agentcore.check_gateway_policy_engine(prov).findings == []


def test_gateway_policy_empty_config_flagged() -> None:
    """policyEngineConfiguration present but with no mode -> not enforcing."""
    prov = _provider(
        lists={"list_gateways": {"items": [{"gatewayId": "gw-1"}]}},
        gets={"get_gateway": {"name": "gw", "policyEngineConfiguration": {}}},
    )
    assert len(agentcore.check_gateway_policy_engine(prov).findings) == 1


def test_paginate_collects_multiple_pages() -> None:
    """_paginate must aggregate items across all pages, not just the first."""

    class _MultiPaginator:
        def paginate(self) -> list[dict[str, Any]]:
            return [{"items": [{"gatewayId": "a"}]}, {"items": [{"gatewayId": "b"}]}]

    class _MultiClient:
        def get_paginator(self, method: str) -> _MultiPaginator:
            return _MultiPaginator()

    items = agentcore._paginate(_MultiClient(), "list_gateways", "items")
    assert [i["gatewayId"] for i in items] == ["a", "b"]


# ---------------------------------------------------------------------------
# Error handling / availability
# ---------------------------------------------------------------------------


def test_region_unavailable_skipped_no_error() -> None:
    """EndpointConnectionError (service absent in region) -> skip, no error."""
    prov = _FakeProvider(_FakeClient(errors={"list_agent_runtimes": EndpointConnectionError(endpoint_url="x")}))
    result = agentcore.check_runtime_public_network(prov)
    assert result.error is None
    assert result.findings == []


def test_access_denied_skipped() -> None:
    prov = _FakeProvider(_FakeClient(errors={"list_gateways": _denied("ListGateways")}))
    result = agentcore.check_gateway_authorizer(prov)
    assert result.error is None
    assert result.findings == []


def test_not_implemented_skipped() -> None:
    """moto-style '404 / Not yet implemented' (service unsupported here) -> skip, no error."""
    err = ClientError({"Error": {"Code": "404", "Message": "Not yet implemented"}}, "ListCodeInterpreters")
    prov = _FakeProvider(_FakeClient(errors={"list_code_interpreters": err}))
    result = agentcore.check_code_interpreter_public_network(prov)
    assert result.error is None
    assert result.findings == []


def test_get_detail_denied_skips_resource() -> None:
    """List succeeds but a per-resource get is denied -> that resource is skipped."""
    prov = _FakeProvider(
        _FakeClient(
            lists={"list_memories": {"memories": [{"id": "mem-1"}]}},
            errors={"get_memory": _denied("GetMemory")},
        )
    )
    result = agentcore.check_memory_encryption(prov)
    assert result.error is None
    assert result.findings == []


def test_empty_list_clean() -> None:
    prov = _provider(lists={"list_code_interpreters": {"codeInterpreterSummaries": []}})
    result = agentcore.check_code_interpreter_public_network(prov)
    assert result.findings == []
    assert result.resources_scanned == 0


def test_multi_region_aggregates() -> None:
    prov = _FakeProvider(
        _FakeClient(
            lists={"list_gateways": {"items": [{"gatewayId": "gw-1"}]}},
            gets={"get_gateway": {"authorizerType": "NONE"}},
        ),
        regions=("us-east-1", "us-west-2"),
    )
    result = agentcore.check_gateway_authorizer(prov)
    assert len(result.findings) == 2  # one per region


def test_get_checks_returns_six() -> None:
    prov = _provider()
    assert len(agentcore.get_checks(prov)) == 6
