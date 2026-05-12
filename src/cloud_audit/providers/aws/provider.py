"""AWS provider implementation."""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any

import boto3
from botocore.config import Config

from cloud_audit.providers.aws import threat_feed
from cloud_audit.providers.aws.checks import (
    account,
    backup,
    bedrock,
    cloudtrail,
    cloudwatch,
    config_,
    ec2,
    ecs,
    efs,
    eip,
    guardduty,
    iam,
    inspector,
    kms,
    lambda_,
    rds,
    s3,
    sagemaker,
    secrets,
    securityhub,
    ssm,
    vpc,
    waf,
)
from cloud_audit.providers.base import BaseProvider

if TYPE_CHECKING:
    from cloud_audit.providers.base import CheckFn

_BOTO_CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 5})

# Registry of all AWS checks, grouped by service
_CHECK_MODULES = [
    account,
    iam,
    s3,
    ec2,
    vpc,
    eip,
    rds,
    efs,
    cloudtrail,
    guardduty,
    config_,
    kms,
    cloudwatch,
    lambda_,
    ecs,
    ssm,
    secrets,
    securityhub,
    backup,
    inspector,
    waf,
    bedrock,
    sagemaker,
    threat_feed,
]


class AWSProvider(BaseProvider):
    """AWS cloud provider - uses boto3 to scan resources."""

    def __init__(
        self,
        profile: str | None = None,
        regions: list[str] | None = None,
        role_arn: str | None = None,
    ) -> None:
        base_session = boto3.Session(profile_name=profile)

        if role_arn:
            sts = base_session.client("sts")
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="cloud-audit-scan")["Credentials"]
            self._session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=base_session.region_name,
            )
        else:
            self._session = base_session

        self._sts = self._session.client("sts", config=_BOTO_CONFIG)
        self._clients: dict[tuple[str, str | None], Any] = {}
        self._clients_lock = threading.Lock()
        self._account_id: str | None = None

        if regions and regions == ["all"]:
            ec2 = self._session.client("ec2", region_name=self._session.region_name or "eu-central-1")
            self._regions = [
                r["RegionName"]
                for r in ec2.describe_regions(
                    Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
                )["Regions"]
            ]
        else:
            self._regions = regions or [self._session.region_name or "eu-central-1"]

    @property
    def session(self) -> boto3.Session:
        return self._session

    @property
    def regions(self) -> list[str]:
        return self._regions

    def client(self, service: str, region_name: str | None = None) -> Any:
        """Get a boto3 client with adaptive retry, cached per (service, region)."""
        key = (service, region_name)
        with self._clients_lock:
            if key not in self._clients:
                self._clients[key] = self._session.client(
                    service_name=service,
                    region_name=region_name,
                    config=_BOTO_CONFIG,  # type: ignore[call-overload]
                )
            return self._clients[key]

    def get_account_id(self) -> str:
        if self._account_id is None:
            identity = self._sts.get_caller_identity()
            self._account_id = str(identity["Account"])
        return self._account_id

    def get_provider_name(self) -> str:
        return "aws"

    def reset_caches(self) -> None:
        """Reset per-scan caches for all AWS check modules."""
        from cloud_audit.providers.aws.checks.cloudtrail import _reset_trail_cache
        from cloud_audit.providers.aws.checks.s3 import _reset_bucket_cache
        from cloud_audit.providers.aws.iam_analyzer import _reset_escalation_cache

        _reset_bucket_cache()
        _reset_trail_cache()
        _reset_escalation_cache()

    def get_checks(self, categories: list[str] | None = None) -> list[CheckFn]:
        checks: list[CheckFn] = []
        for module in _CHECK_MODULES:
            for check_fn in module.get_checks(self):
                if categories:
                    # Each check function has a .category attribute
                    check_category = getattr(check_fn, "category", None)
                    if check_category and check_category not in categories:
                        continue
                checks.append(check_fn)
        return checks
