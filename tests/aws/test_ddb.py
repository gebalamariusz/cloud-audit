"""Tests for DynamoDB checks (aws-ddb-001/002/003) added in v2.3.1."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.ddb import (
    check_autoscaling_enabled,
    check_encryption_at_rest,
    check_pitr_enabled,
)

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


def _make_table(
    ddb_client,
    name: str,
    billing: str = "PROVISIONED",
    sse_kms: str | None = None,
) -> None:
    """Helper to create a DynamoDB table with optional SSE/billing variants."""
    kwargs: dict = {
        "TableName": name,
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "BillingMode": billing,
    }
    if billing == "PROVISIONED":
        kwargs["ProvisionedThroughput"] = {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
    if sse_kms == "aws_managed":
        kwargs["SSESpecification"] = {"Enabled": True, "SSEType": "KMS"}
    elif sse_kms == "cmk":
        kwargs["SSESpecification"] = {
            "Enabled": True,
            "SSEType": "KMS",
            "KMSMasterKeyId": "alias/my-custom-key",
        }
    ddb_client.create_table(**kwargs)
    ddb_client.get_waiter("table_exists").wait(TableName=name)


# -----------------------------------------------------------------------------
# aws-ddb-001 - Encryption at rest
# -----------------------------------------------------------------------------


def test_ddb_001_empty_account_no_findings(mock_aws_provider: AWSProvider) -> None:
    """No DynamoDB tables - safe state, no findings, no error."""
    result = check_encryption_at_rest(mock_aws_provider)
    assert result.check_id == "aws-ddb-001"
    assert result.resources_scanned == 0
    assert len(result.findings) == 0
    assert result.error is None


def test_ddb_001_aws_owned_default_produces_low_finding(mock_aws_provider: AWSProvider) -> None:
    """Default key (no SSESpecification) -> SSEDescription absent -> LOW finding."""
    ddb = mock_aws_provider.session.client("dynamodb", region_name="eu-central-1")
    _make_table(ddb, "default-enc-table")

    result = check_encryption_at_rest(mock_aws_provider)
    assert result.resources_scanned == 1
    assert len(result.findings) == 1
    assert result.findings[0].severity.value == "low"
    assert "AWS-owned" in result.findings[0].title


def test_ddb_001_aws_managed_kms_no_finding(mock_aws_provider: AWSProvider) -> None:
    """SSEType=KMS with AWS-managed key -> no finding."""
    ddb = mock_aws_provider.session.client("dynamodb", region_name="eu-central-1")
    _make_table(ddb, "managed-kms-table", sse_kms="aws_managed")

    result = check_encryption_at_rest(mock_aws_provider)
    assert result.resources_scanned == 1
    assert len(result.findings) == 0


def test_ddb_001_cmk_no_finding(mock_aws_provider: AWSProvider) -> None:
    """SSEType=KMS with customer-managed CMK -> no finding."""
    kms = mock_aws_provider.session.client("kms", region_name="eu-central-1")
    key = kms.create_key()
    kms.create_alias(AliasName="alias/my-custom-key", TargetKeyId=key["KeyMetadata"]["KeyId"])

    ddb = mock_aws_provider.session.client("dynamodb", region_name="eu-central-1")
    _make_table(ddb, "cmk-table", sse_kms="cmk")

    result = check_encryption_at_rest(mock_aws_provider)
    assert len(result.findings) == 0


# -----------------------------------------------------------------------------
# aws-ddb-002 - Point-in-time recovery
# -----------------------------------------------------------------------------


def test_ddb_002_empty_account_no_findings(mock_aws_provider: AWSProvider) -> None:
    result = check_pitr_enabled(mock_aws_provider)
    assert result.check_id == "aws-ddb-002"
    assert result.resources_scanned == 0
    assert len(result.findings) == 0
    assert result.error is None


def test_ddb_002_pitr_disabled_produces_medium(mock_aws_provider: AWSProvider) -> None:
    """Newly-created tables have PITR disabled by default - MEDIUM finding."""
    ddb = mock_aws_provider.session.client("dynamodb", region_name="eu-central-1")
    _make_table(ddb, "no-pitr-table")

    result = check_pitr_enabled(mock_aws_provider)
    assert result.resources_scanned == 1
    assert len(result.findings) == 1
    assert result.findings[0].severity.value == "medium"
    assert "point-in-time recovery" in result.findings[0].title


def test_ddb_002_pitr_enabled_no_finding(mock_aws_provider: AWSProvider) -> None:
    ddb = mock_aws_provider.session.client("dynamodb", region_name="eu-central-1")
    _make_table(ddb, "pitr-table")
    ddb.update_continuous_backups(
        TableName="pitr-table",
        PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
    )

    result = check_pitr_enabled(mock_aws_provider)
    assert len(result.findings) == 0


# -----------------------------------------------------------------------------
# aws-ddb-003 - Autoscaling on PROVISIONED billing
# -----------------------------------------------------------------------------


def test_ddb_003_empty_account_no_findings(mock_aws_provider: AWSProvider) -> None:
    result = check_autoscaling_enabled(mock_aws_provider)
    assert result.check_id == "aws-ddb-003"
    assert result.resources_scanned == 0
    assert len(result.findings) == 0


def test_ddb_003_pay_per_request_skipped(mock_aws_provider: AWSProvider) -> None:
    """PAY_PER_REQUEST has no autoscaling concept - skipped, no finding."""
    ddb = mock_aws_provider.session.client("dynamodb", region_name="eu-central-1")
    _make_table(ddb, "on-demand-table", billing="PAY_PER_REQUEST")

    result = check_autoscaling_enabled(mock_aws_provider)
    assert result.resources_scanned == 1
    assert len(result.findings) == 0


def test_ddb_003_provisioned_no_autoscaling_produces_medium(
    mock_aws_provider: AWSProvider,
) -> None:
    """PROVISIONED without any autoscaling -> MEDIUM finding."""
    ddb = mock_aws_provider.session.client("dynamodb", region_name="eu-central-1")
    _make_table(ddb, "prov-no-as-table")

    result = check_autoscaling_enabled(mock_aws_provider)
    assert result.resources_scanned == 1
    assert len(result.findings) == 1
    assert result.findings[0].severity.value == "medium"
    assert "PROVISIONED" in result.findings[0].title


def test_ddb_003_provisioned_with_full_autoscaling_no_finding(
    mock_aws_provider: AWSProvider,
) -> None:
    """PROVISIONED with read+write autoscaling registered -> no finding."""
    ddb = mock_aws_provider.session.client("dynamodb", region_name="eu-central-1")
    aas = mock_aws_provider.session.client("application-autoscaling", region_name="eu-central-1")
    _make_table(ddb, "prov-full-as-table")

    for dim in ("dynamodb:table:ReadCapacityUnits", "dynamodb:table:WriteCapacityUnits"):
        aas.register_scalable_target(
            ServiceNamespace="dynamodb",
            ResourceId="table/prov-full-as-table",
            ScalableDimension=dim,
            MinCapacity=5,
            MaxCapacity=1000,
        )

    # Reset cache so the freshly-registered targets are picked up
    from cloud_audit.providers.aws.checks.ddb import _reset_ddb_cache

    _reset_ddb_cache()

    result = check_autoscaling_enabled(mock_aws_provider)
    assert len(result.findings) == 0


def test_ddb_003_read_only_autoscaling_flags_write(mock_aws_provider: AWSProvider) -> None:
    """PROVISIONED with autoscaling on read only -> flags missing write capacity autoscaling."""
    ddb = mock_aws_provider.session.client("dynamodb", region_name="eu-central-1")
    aas = mock_aws_provider.session.client("application-autoscaling", region_name="eu-central-1")
    _make_table(ddb, "prov-readonly-as")

    aas.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId="table/prov-readonly-as",
        ScalableDimension="dynamodb:table:ReadCapacityUnits",
        MinCapacity=5,
        MaxCapacity=1000,
    )

    from cloud_audit.providers.aws.checks.ddb import _reset_ddb_cache

    _reset_ddb_cache()

    result = check_autoscaling_enabled(mock_aws_provider)
    assert len(result.findings) == 1
    assert "write capacity" in result.findings[0].title.lower()
