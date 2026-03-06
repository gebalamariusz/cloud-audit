"""EC2 security and cost checks."""

from __future__ import annotations

import shlex
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_public_amis(provider: AWSProvider) -> CheckResult:
    """Check for AMIs that are publicly shared."""
    result = CheckResult(check_id="aws-ec2-001", check_name="Public AMIs")

    try:
        for region in provider.regions:
            ec2 = provider.session.client("ec2", region_name=region)
            images = ec2.describe_images(Owners=["self"])["Images"]
            for image in images:
                result.resources_scanned += 1
                image_id = image["ImageId"]
                if image.get("Public", False):
                    result.findings.append(
                        Finding(
                            check_id="aws-ec2-001",
                            title=f"AMI '{image_id}' is publicly shared",
                            severity=Severity.HIGH,
                            category=Category.SECURITY,
                            resource_type="AWS::EC2::Image",
                            resource_id=image_id,
                            region=region,
                            description=f"AMI {image_id} ({image.get('Name', 'unnamed')}) is publicly accessible to all AWS accounts.",
                            recommendation="Make the AMI private unless public sharing is intentional.",
                            remediation=Remediation(
                                cli=(
                                    f"aws ec2 modify-image-attribute --image-id {image_id} "
                                    f'--launch-permission \'{{"Remove":[{{"Group":"all"}}]}}\' --region {region}'
                                ),
                                terraform=(
                                    "# Ensure your AMI resource does not have public launch permissions.\n"
                                    "# Use aws_ami_launch_permission to restrict access:\n"
                                    f'resource "aws_ami_launch_permission" "restrict" {{\n'
                                    f'  image_id   = "{image_id}"\n'
                                    f'  account_id = "TRUSTED_ACCOUNT_ID"\n'
                                    f"}}"
                                ),
                                doc_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharing-amis.html",
                                effort=Effort.LOW,
                            ),
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def check_unencrypted_volumes(provider: AWSProvider) -> CheckResult:
    """Check for EBS volumes without encryption."""
    result = CheckResult(check_id="aws-ec2-002", check_name="Unencrypted EBS volumes")

    try:
        for region in provider.regions:
            ec2 = provider.session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for volume in page["Volumes"]:
                    result.resources_scanned += 1
                    if not volume.get("Encrypted", False):
                        vol_id = volume["VolumeId"]
                        size = volume["Size"]
                        result.findings.append(
                            Finding(
                                check_id="aws-ec2-002",
                                title=f"EBS volume '{vol_id}' is not encrypted",
                                severity=Severity.MEDIUM,
                                category=Category.SECURITY,
                                resource_type="AWS::EC2::Volume",
                                resource_id=vol_id,
                                region=region,
                                description=f"Volume {vol_id} ({size} GiB) is not encrypted at rest.",
                                recommendation="Enable EBS default encryption in account settings and migrate existing volumes.",
                                remediation=Remediation(
                                    cli=(
                                        f"# Enable EBS default encryption for the region:\n"
                                        f"aws ec2 enable-ebs-encryption-by-default --region {region}\n"
                                        f"# Migrate existing volume {vol_id}:\n"
                                        f"# 1. Create snapshot: aws ec2 create-snapshot --volume-id {vol_id}\n"
                                        f"# 2. Copy with encryption: aws ec2 copy-snapshot --encrypted --source-snapshot-id snap-xxx\n"
                                        f"# 3. Create volume from encrypted snapshot\n"
                                        f"# 4. Swap volume on the instance"
                                    ),
                                    terraform=(
                                        "# Enable EBS default encryption:\n"
                                        'resource "aws_ebs_encryption_by_default" "this" {\n'
                                        "  enabled = true\n"
                                        "}\n"
                                        "\n"
                                        "# Ensure new volumes are encrypted:\n"
                                        'resource "aws_ebs_volume" "example" {\n'
                                        "  # ...\n"
                                        "  encrypted = true\n"
                                        "}"
                                    ),
                                    doc_url="https://docs.aws.amazon.com/ebs/latest/userguide/encryption-by-default.html",
                                    effort=Effort.HIGH,
                                ),
                                compliance_refs=["CIS 2.2.1"],
                            )
                        )
    except Exception as e:
        result.error = str(e)

    return result


def check_stopped_instances(provider: AWSProvider) -> CheckResult:
    """Check for EC2 instances that have been stopped for more than 7 days."""
    result = CheckResult(check_id="aws-ec2-003", check_name="Stopped EC2 instances (cost)")

    try:
        for region in provider.regions:
            ec2 = provider.session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]):
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        result.resources_scanned += 1
                        instance_id = instance["InstanceId"]
                        instance_type = instance["InstanceType"]
                        name_tag = next(
                            (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"),
                            "unnamed",
                        )

                        result.findings.append(
                            Finding(
                                check_id="aws-ec2-003",
                                title=f"EC2 instance '{name_tag}' ({instance_id}) is stopped",
                                severity=Severity.LOW,
                                category=Category.COST,
                                resource_type="AWS::EC2::Instance",
                                resource_id=instance_id,
                                region=region,
                                description=f"Instance {instance_id} ({instance_type}) is stopped. EBS volumes are still incurring charges.",
                                recommendation="Terminate the instance if no longer needed, or create an AMI and terminate to save on EBS costs.",
                                remediation=Remediation(
                                    cli=(
                                        f"# WARNING: This will permanently delete the instance!\n"
                                        f"# Create an AMI first if you need the data:\n"
                                        f"aws ec2 create-image --instance-id {instance_id} --name {shlex.quote(f'{name_tag}-backup')} --region {region}\n"
                                        f"# Then terminate:\n"
                                        f"aws ec2 terminate-instances --instance-ids {instance_id} --region {region}"
                                    ),
                                    terraform=(
                                        "# Remove the aws_instance resource from your Terraform config\n"
                                        "# and run terraform apply, or set count = 0."
                                    ),
                                    doc_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/terminating-instances.html",
                                    effort=Effort.LOW,
                                ),
                            )
                        )
    except Exception as e:
        result.error = str(e)

    return result


def check_imdsv1(provider: AWSProvider) -> CheckResult:
    """Check for EC2 instances using IMDSv1 (instance metadata service v1)."""
    result = CheckResult(check_id="aws-ec2-004", check_name="EC2 IMDSv1 enabled")

    try:
        for region in provider.regions:
            ec2 = provider.session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        result.resources_scanned += 1
                        instance_id = instance["InstanceId"]
                        name_tag = next(
                            (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"),
                            "unnamed",
                        )
                        metadata_options = instance.get("MetadataOptions", {})
                        http_tokens = metadata_options.get("HttpTokens", "optional")

                        if http_tokens != "required":
                            result.findings.append(
                                Finding(
                                    check_id="aws-ec2-004",
                                    title=f"EC2 instance '{name_tag}' ({instance_id}) allows IMDSv1",
                                    severity=Severity.HIGH,
                                    category=Category.SECURITY,
                                    resource_type="AWS::EC2::Instance",
                                    resource_id=instance_id,
                                    region=region,
                                    description=f"Instance {instance_id} has HttpTokens='{http_tokens}'. IMDSv1 is vulnerable to SSRF attacks that can steal IAM credentials.",
                                    recommendation="Enforce IMDSv2 by setting HttpTokens to 'required'.",
                                    remediation=Remediation(
                                        cli=(
                                            f"aws ec2 modify-instance-metadata-options "
                                            f"--instance-id {instance_id} "
                                            f"--http-tokens required "
                                            f"--http-endpoint enabled "
                                            f"--region {region}"
                                        ),
                                        terraform=(
                                            'resource "aws_instance" "example" {\n'
                                            "  # ...\n"
                                            "  metadata_options {\n"
                                            '    http_tokens   = "required"  # Enforce IMDSv2\n'
                                            '    http_endpoint = "enabled"\n'
                                            "  }\n"
                                            "}"
                                        ),
                                        doc_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
                                        effort=Effort.LOW,
                                    ),
                                )
                            )
    except Exception as e:
        result.error = str(e)

    return result


def check_termination_protection(provider: AWSProvider) -> CheckResult:
    """Check for EC2 instances without termination protection enabled."""
    result = CheckResult(check_id="aws-ec2-005", check_name="EC2 termination protection")

    try:
        for region in provider.regions:
            ec2 = provider.session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        result.resources_scanned += 1
                        instance_id = instance["InstanceId"]
                        name_tag = next(
                            (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"),
                            "unnamed",
                        )

                        try:
                            attr = ec2.describe_instance_attribute(
                                InstanceId=instance_id, Attribute="disableApiTermination"
                            )
                            protected = attr.get("DisableApiTermination", {}).get("Value", False)
                        except Exception:
                            continue

                        if not protected:
                            result.findings.append(
                                Finding(
                                    check_id="aws-ec2-005",
                                    title=f"EC2 instance '{name_tag}' ({instance_id}) has no termination protection",
                                    severity=Severity.LOW,
                                    category=Category.RELIABILITY,
                                    resource_type="AWS::EC2::Instance",
                                    resource_id=instance_id,
                                    region=region,
                                    description=f"Instance {instance_id} does not have API termination protection enabled. It can be accidentally terminated.",
                                    recommendation="Enable termination protection for important instances to prevent accidental deletion.",
                                    remediation=Remediation(
                                        cli=(
                                            f"aws ec2 modify-instance-attribute --instance-id {instance_id} "
                                            f"--disable-api-termination --region {region}"
                                        ),
                                        terraform=(
                                            'resource "aws_instance" "example" {\n'
                                            "  # ...\n"
                                            "  disable_api_termination = true\n"
                                            "}"
                                        ),
                                        doc_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_ChangingDisableAPITermination.html",
                                        effort=Effort.LOW,
                                    ),
                                )
                            )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all EC2 checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_public_amis, provider, check_id="aws-ec2-001", category=Category.SECURITY),
        make_check(check_unencrypted_volumes, provider, check_id="aws-ec2-002", category=Category.SECURITY),
        make_check(check_stopped_instances, provider, check_id="aws-ec2-003", category=Category.COST),
        make_check(check_imdsv1, provider, check_id="aws-ec2-004", category=Category.SECURITY),
        make_check(check_termination_protection, provider, check_id="aws-ec2-005", category=Category.RELIABILITY),
    ]
