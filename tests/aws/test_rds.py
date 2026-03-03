"""Tests for RDS security and reliability checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.rds import (
    check_rds_encryption,
    check_rds_multi_az,
    check_rds_public_access,
)

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


def _create_db_instance(
    rds_client: object,
    db_id: str,
    *,
    publicly_accessible: bool = False,
    storage_encrypted: bool = True,
    multi_az: bool = False,
    instance_class: str = "db.m5.large",
) -> None:
    """Helper to create a test RDS instance."""
    rds_client.create_db_instance(  # type: ignore[union-attr]
        DBInstanceIdentifier=db_id,
        DBInstanceClass=instance_class,
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="SecurePassword123!",  # noqa: S106
        AllocatedStorage=20,
        PubliclyAccessible=publicly_accessible,
        StorageEncrypted=storage_encrypted,
        MultiAZ=multi_az,
    )


def test_rds_public_access_pass(mock_aws_provider: AWSProvider) -> None:
    """Private RDS instance - no finding."""
    rds = mock_aws_provider.session.client("rds", region_name="eu-central-1")
    _create_db_instance(rds, "private-db", publicly_accessible=False)
    result = check_rds_public_access(mock_aws_provider)
    assert result.resources_scanned >= 1
    assert len(result.findings) == 0


def test_rds_public_access_fail(mock_aws_provider: AWSProvider) -> None:
    """Public RDS instance - CRITICAL finding."""
    rds = mock_aws_provider.session.client("rds", region_name="eu-central-1")
    _create_db_instance(rds, "public-db", publicly_accessible=True)
    result = check_rds_public_access(mock_aws_provider)
    pub_findings = [f for f in result.findings if f.resource_id == "public-db"]
    assert len(pub_findings) == 1
    assert pub_findings[0].severity.value == "critical"
    assert pub_findings[0].remediation is not None
    assert "--no-publicly-accessible" in pub_findings[0].remediation.cli


def test_rds_encryption_pass(mock_aws_provider: AWSProvider) -> None:
    """Encrypted RDS instance - no finding."""
    rds = mock_aws_provider.session.client("rds", region_name="eu-central-1")
    _create_db_instance(rds, "encrypted-db", storage_encrypted=True)
    result = check_rds_encryption(mock_aws_provider)
    enc_findings = [f for f in result.findings if f.resource_id == "encrypted-db"]
    assert len(enc_findings) == 0


def test_rds_encryption_fail(mock_aws_provider: AWSProvider) -> None:
    """Unencrypted RDS instance - HIGH finding."""
    rds = mock_aws_provider.session.client("rds", region_name="eu-central-1")
    _create_db_instance(rds, "unencrypted-db", storage_encrypted=False)
    result = check_rds_encryption(mock_aws_provider)
    enc_findings = [f for f in result.findings if f.resource_id == "unencrypted-db"]
    assert len(enc_findings) == 1
    assert enc_findings[0].severity.value == "high"
    assert enc_findings[0].remediation is not None
    assert "create-db-snapshot" in enc_findings[0].remediation.cli


def test_rds_multi_az_pass(mock_aws_provider: AWSProvider) -> None:
    """Multi-AZ RDS instance - no finding."""
    rds = mock_aws_provider.session.client("rds", region_name="eu-central-1")
    _create_db_instance(rds, "ha-db", multi_az=True, instance_class="db.m5.large")
    result = check_rds_multi_az(mock_aws_provider)
    az_findings = [f for f in result.findings if f.resource_id == "ha-db"]
    assert len(az_findings) == 0


def test_rds_multi_az_skip_micro(mock_aws_provider: AWSProvider) -> None:
    """Micro instance without Multi-AZ - skipped (dev/test)."""
    rds = mock_aws_provider.session.client("rds", region_name="eu-central-1")
    _create_db_instance(rds, "dev-db", multi_az=False, instance_class="db.t3.micro")
    result = check_rds_multi_az(mock_aws_provider)
    micro_findings = [f for f in result.findings if f.resource_id == "dev-db"]
    assert len(micro_findings) == 0


def test_rds_multi_az_fail(mock_aws_provider: AWSProvider) -> None:
    """Large instance without Multi-AZ - MEDIUM finding."""
    rds = mock_aws_provider.session.client("rds", region_name="eu-central-1")
    _create_db_instance(rds, "single-az-db", multi_az=False, instance_class="db.m5.large")
    result = check_rds_multi_az(mock_aws_provider)
    az_findings = [f for f in result.findings if f.resource_id == "single-az-db"]
    assert len(az_findings) == 1
    assert az_findings[0].severity.value == "medium"
    assert az_findings[0].remediation is not None
    assert "--multi-az" in az_findings[0].remediation.cli
