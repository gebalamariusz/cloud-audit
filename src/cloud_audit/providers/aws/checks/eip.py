"""Elastic IP cost checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_unattached_eips(provider: AWSProvider) -> CheckResult:
    """Check for Elastic IPs that are not associated with any resource."""
    result = CheckResult(check_id="aws-eip-001", check_name="Unattached Elastic IPs")

    try:
        for region in provider.regions:
            ec2 = provider.session.client("ec2", region_name=region)
            addresses = ec2.describe_addresses()["Addresses"]

            for addr in addresses:
                result.resources_scanned += 1
                if not addr.get("AssociationId"):
                    eip = addr.get("PublicIp", addr.get("AllocationId", "unknown"))
                    alloc_id = addr.get("AllocationId", eip)
                    result.findings.append(
                        Finding(
                            check_id="aws-eip-001",
                            title=f"Elastic IP {eip} is not attached to any resource",
                            severity=Severity.LOW,
                            category=Category.COST,
                            resource_type="AWS::EC2::EIP",
                            resource_id=alloc_id,
                            region=region,
                            description=f"Elastic IP {eip} is allocated but not associated. Unattached EIPs cost ~$3.65/month.",
                            recommendation="Release the Elastic IP if no longer needed, or associate it with an instance/NAT gateway.",
                            remediation=Remediation(
                                cli=f"aws ec2 release-address --allocation-id {alloc_id} --region {region}",
                                terraform=(
                                    "# Remove the aws_eip resource from your Terraform config\n"
                                    "# or associate it with an instance/NAT gateway:\n"
                                    'resource "aws_eip_association" "this" {\n'
                                    f'  allocation_id = "{alloc_id}"\n'
                                    "  instance_id   = aws_instance.example.id\n"
                                    "}"
                                ),
                                doc_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html",
                                effort=Effort.LOW,
                            ),
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all EIP checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_unattached_eips, provider, check_id="aws-eip-001", category=Category.COST),
    ]
