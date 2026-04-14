"""Amazon SageMaker AI security checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_notebook_root_access(provider: AWSProvider) -> CheckResult:
    """Check for SageMaker notebooks with root access enabled."""
    result = CheckResult(check_id="aws-sagemaker-001", check_name="SageMaker notebook root access")

    try:
        for region in provider.regions:
            sm = provider.session.client("sagemaker", region_name=region)

            try:
                paginator = sm.get_paginator("list_notebook_instances")
            except Exception:
                # SageMaker may not be available in all regions
                continue

            for page in paginator.paginate():
                for nb in page.get("NotebookInstances", []):
                    nb_name = nb["NotebookInstanceName"]
                    result.resources_scanned += 1

                    try:
                        detail = sm.describe_notebook_instance(NotebookInstanceName=nb_name)
                    except Exception:
                        continue

                    root_access = detail.get("RootAccess", "Enabled")
                    if root_access == "Enabled":
                        result.findings.append(
                            Finding(
                                check_id="aws-sagemaker-001",
                                title=f"SageMaker notebook '{nb_name}' has root access enabled",
                                severity=Severity.CRITICAL,
                                category=Category.SECURITY,
                                resource_type="AWS::SageMaker::NotebookInstance",
                                resource_id=nb.get("NotebookInstanceArn", nb_name),
                                region=region,
                                description=(
                                    f"Notebook instance '{nb_name}' has RootAccess=Enabled. "
                                    "Root access allows full control over the notebook host, "
                                    "enabling container escape, credential theft from the "
                                    "instance metadata service, and lateral movement."
                                ),
                                recommendation="Disable root access unless specifically required for development.",
                                remediation=Remediation(
                                    cli=(
                                        f"aws sagemaker stop-notebook-instance "
                                        f"--notebook-instance-name {nb_name} --region {region}\n"
                                        f"aws sagemaker update-notebook-instance "
                                        f"--notebook-instance-name {nb_name} "
                                        f"--root-access Disabled --region {region}\n"
                                        f"aws sagemaker start-notebook-instance "
                                        f"--notebook-instance-name {nb_name} --region {region}"
                                    ),
                                    terraform=(
                                        f'resource "aws_sagemaker_notebook_instance" "{nb_name}" {{\n'
                                        f'  name        = "{nb_name}"\n'
                                        f'  root_access = "Disabled"\n'
                                        f"  # ...\n"
                                        f"}}"
                                    ),
                                    doc_url="https://docs.aws.amazon.com/sagemaker/latest/dg/nbi-root-access.html",
                                    effort=Effort.LOW,
                                ),
                            )
                        )
    except Exception as e:
        result.error = str(e)

    return result


def check_notebook_direct_internet(provider: AWSProvider) -> CheckResult:
    """Check for SageMaker notebooks with direct internet access."""
    result = CheckResult(check_id="aws-sagemaker-002", check_name="SageMaker notebook internet access")

    try:
        for region in provider.regions:
            sm = provider.session.client("sagemaker", region_name=region)

            try:
                paginator = sm.get_paginator("list_notebook_instances")
            except Exception:
                continue

            for page in paginator.paginate():
                for nb in page.get("NotebookInstances", []):
                    nb_name = nb["NotebookInstanceName"]
                    result.resources_scanned += 1

                    try:
                        detail = sm.describe_notebook_instance(NotebookInstanceName=nb_name)
                    except Exception:
                        continue

                    direct_internet = detail.get("DirectInternetAccess", "Enabled")
                    if direct_internet == "Enabled":
                        result.findings.append(
                            Finding(
                                check_id="aws-sagemaker-002",
                                title=f"SageMaker notebook '{nb_name}' has direct internet access",
                                severity=Severity.HIGH,
                                category=Category.SECURITY,
                                resource_type="AWS::SageMaker::NotebookInstance",
                                resource_id=nb.get("NotebookInstanceArn", nb_name),
                                region=region,
                                description=(
                                    f"Notebook instance '{nb_name}' has DirectInternetAccess=Enabled. "
                                    "This exposes the notebook to internet-based attacks and allows "
                                    "data exfiltration. Notebooks should run in a VPC with internet "
                                    "access through a NAT gateway if needed."
                                ),
                                recommendation="Disable direct internet access and place the notebook in a VPC.",
                                remediation=Remediation(
                                    cli=(
                                        f"# Direct internet access cannot be changed after creation.\n"
                                        f"# Recreate the notebook in a VPC:\n"
                                        f"aws sagemaker create-notebook-instance \\\n"
                                        f"  --notebook-instance-name {nb_name}-vpc \\\n"
                                        f"  --instance-type ml.t3.medium \\\n"
                                        f"  --role-arn ROLE_ARN \\\n"
                                        f"  --subnet-id SUBNET_ID \\\n"
                                        f"  --security-group-ids SG_ID \\\n"
                                        f"  --direct-internet-access Disabled \\\n"
                                        f"  --region {region}"
                                    ),
                                    terraform=(
                                        f'resource "aws_sagemaker_notebook_instance" "{nb_name}" {{\n'
                                        f'  name                    = "{nb_name}"\n'
                                        f'  direct_internet_access  = "Disabled"\n'
                                        f"  subnet_id               = aws_subnet.private.id\n"
                                        f"  security_groups         = [aws_security_group.sagemaker.id]\n"
                                        f"  # ...\n"
                                        f"}}"
                                    ),
                                    doc_url="https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-notebook-and-internet-access.html",
                                    effort=Effort.HIGH,
                                ),
                            )
                        )
    except Exception as e:
        result.error = str(e)

    return result


def check_endpoint_encryption(provider: AWSProvider) -> CheckResult:
    """Check for SageMaker endpoints without KMS encryption."""
    result = CheckResult(check_id="aws-sagemaker-003", check_name="SageMaker endpoint encryption")

    try:
        for region in provider.regions:
            sm = provider.session.client("sagemaker", region_name=region)

            try:
                paginator = sm.get_paginator("list_endpoints")
            except Exception:
                continue

            for page in paginator.paginate():
                for ep in page.get("Endpoints", []):
                    ep_name = ep["EndpointName"]
                    result.resources_scanned += 1

                    try:
                        detail = sm.describe_endpoint(EndpointName=ep_name)
                    except Exception:
                        continue

                    kms_key = detail.get("KmsKeyId", "")
                    if not kms_key:
                        result.findings.append(
                            Finding(
                                check_id="aws-sagemaker-003",
                                title=f"SageMaker endpoint '{ep_name}' not encrypted with KMS",
                                severity=Severity.MEDIUM,
                                category=Category.SECURITY,
                                resource_type="AWS::SageMaker::Endpoint",
                                resource_id=ep.get("EndpointArn", ep_name),
                                region=region,
                                description=(
                                    f"SageMaker endpoint '{ep_name}' does not use KMS encryption "
                                    "for data at rest. Model artifacts and inference data may "
                                    "contain sensitive information."
                                ),
                                recommendation="Recreate the endpoint with a KMS key for encryption.",
                                remediation=Remediation(
                                    cli=(
                                        f"# Endpoint encryption must be set at creation time.\n"
                                        f"# Create an endpoint config with KMS encryption:\n"
                                        f"aws sagemaker create-endpoint-config \\\n"
                                        f"  --endpoint-config-name {ep_name}-encrypted \\\n"
                                        f"  --kms-key-id KMS_KEY_ID \\\n"
                                        f"  --production-variants '[]' \\\n"
                                        f"  --region {region}"
                                    ),
                                    terraform=(
                                        f'resource "aws_sagemaker_endpoint_configuration" "{ep_name}" {{\n'
                                        f"  kms_key_arn = aws_kms_key.sagemaker.arn\n"
                                        f"  # ...\n"
                                        f"}}"
                                    ),
                                    doc_url="https://docs.aws.amazon.com/sagemaker/latest/dg/endpoint-encrypt.html",
                                    effort=Effort.HIGH,
                                ),
                            )
                        )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all SageMaker checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_notebook_root_access, provider, check_id="aws-sagemaker-001", category=Category.SECURITY),
        make_check(check_notebook_direct_internet, provider, check_id="aws-sagemaker-002", category=Category.SECURITY),
        make_check(check_endpoint_encryption, provider, check_id="aws-sagemaker-003", category=Category.SECURITY),
    ]
