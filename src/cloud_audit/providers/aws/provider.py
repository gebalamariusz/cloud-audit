"""AWS provider implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING

import boto3

from cloud_audit.providers.aws.checks import (
    cloudtrail,
    cloudwatch,
    config_,
    ec2,
    eip,
    guardduty,
    iam,
    kms,
    rds,
    s3,
    vpc,
)
from cloud_audit.providers.base import BaseProvider

if TYPE_CHECKING:
    from cloud_audit.providers.base import CheckFn

# Registry of all AWS checks, grouped by service
_CHECK_MODULES = [iam, s3, ec2, vpc, eip, rds, cloudtrail, guardduty, config_, kms, cloudwatch]


class AWSProvider(BaseProvider):
    """AWS cloud provider - uses boto3 to scan resources."""

    def __init__(self, profile: str | None = None, regions: list[str] | None = None) -> None:
        self._session = boto3.Session(profile_name=profile)
        self._sts = self._session.client("sts")

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

    def get_account_id(self) -> str:
        identity = self._sts.get_caller_identity()
        return str(identity["Account"])

    def get_provider_name(self) -> str:
        return "aws"

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
