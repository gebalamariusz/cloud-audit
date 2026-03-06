"""Lambda security checks."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn

# Last verified: 2026-03-06. Update periodically from:
# https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
_DEPRECATED_RUNTIMES = {
    "python3.6",
    "python3.7",
    "python3.8",
    "python3.9",
    "nodejs12.x",
    "nodejs14.x",
    "nodejs16.x",
    "nodejs18.x",
    "dotnetcore3.1",
    "dotnet6",
    "ruby2.7",
    "java8",
    "go1.x",
}

_SECRET_PATTERNS = re.compile(
    r"(SECRET|PASSWORD|API_KEY|APIKEY|TOKEN|PRIVATE_KEY|DB_PASS|DATABASE_URL|AWS_SECRET)",
    re.IGNORECASE,
)


def check_public_function_url(provider: AWSProvider) -> CheckResult:
    """Check for Lambda functions with public (unauthenticated) function URLs."""
    result = CheckResult(check_id="aws-lambda-001", check_name="Lambda public function URL")

    try:
        for region in provider.regions:
            lam = provider.session.client("lambda", region_name=region)
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page["Functions"]:
                    result.resources_scanned += 1
                    fn_name = fn["FunctionName"]
                    fn_arn = fn["FunctionArn"]

                    try:
                        url_config = lam.get_function_url_config(FunctionName=fn_name)
                        auth_type = url_config.get("AuthType", "")
                        if auth_type == "NONE":
                            result.findings.append(
                                Finding(
                                    check_id="aws-lambda-001",
                                    title=f"Lambda '{fn_name}' has a public function URL (no auth)",
                                    severity=Severity.HIGH,
                                    category=Category.SECURITY,
                                    resource_type="AWS::Lambda::Function",
                                    resource_id=fn_arn,
                                    region=region,
                                    description=f"Function '{fn_name}' has a function URL with AuthType=NONE. Anyone on the internet can invoke it.",
                                    recommendation="Set AuthType to AWS_IAM or remove the function URL if not needed.",
                                    remediation=Remediation(
                                        cli=(
                                            f"# Remove the public function URL:\n"
                                            f"aws lambda delete-function-url-config --function-name {fn_name} --region {region}\n"
                                            f"# Or switch to IAM auth:\n"
                                            f"aws lambda update-function-url-config --function-name {fn_name} "
                                            f"--auth-type AWS_IAM --region {region}"
                                        ),
                                        terraform=(
                                            f'resource "aws_lambda_function_url" "{fn_name}" {{\n'
                                            f'  function_name      = "{fn_name}"\n'
                                            f'  authorization_type = "AWS_IAM"  # Not NONE\n'
                                            f"}}"
                                        ),
                                        doc_url="https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html",
                                        effort=Effort.LOW,
                                    ),
                                )
                            )
                    except Exception:
                        continue  # No function URL configured - OK
    except Exception as e:
        result.error = str(e)

    return result


def check_deprecated_runtime(provider: AWSProvider) -> CheckResult:
    """Check for Lambda functions using deprecated/EOL runtimes."""
    result = CheckResult(check_id="aws-lambda-002", check_name="Lambda deprecated runtime")

    try:
        for region in provider.regions:
            lam = provider.session.client("lambda", region_name=region)
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page["Functions"]:
                    result.resources_scanned += 1
                    fn_name = fn["FunctionName"]
                    fn_arn = fn["FunctionArn"]
                    runtime = fn.get("Runtime", "")

                    if runtime in _DEPRECATED_RUNTIMES:
                        result.findings.append(
                            Finding(
                                check_id="aws-lambda-002",
                                title=f"Lambda '{fn_name}' uses deprecated runtime '{runtime}'",
                                severity=Severity.MEDIUM,
                                category=Category.SECURITY,
                                resource_type="AWS::Lambda::Function",
                                resource_id=fn_arn,
                                region=region,
                                description=f"Function '{fn_name}' uses runtime '{runtime}' which is end-of-life and no longer receives security patches.",
                                recommendation="Upgrade the function to a supported runtime version.",
                                remediation=Remediation(
                                    cli=(
                                        f"aws lambda update-function-configuration "
                                        f"--function-name {fn_name} "
                                        f"--runtime python3.12 "  # example target
                                        f"--region {region}"
                                    ),
                                    terraform=(
                                        f'resource "aws_lambda_function" "{fn_name}" {{\n'
                                        f"  # ...\n"
                                        f'  runtime = "python3.12"  # Upgrade from {runtime}\n'
                                        f"}}"
                                    ),
                                    doc_url="https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html",
                                    effort=Effort.MEDIUM,
                                ),
                            )
                        )
    except Exception as e:
        result.error = str(e)

    return result


def check_env_secrets(provider: AWSProvider) -> CheckResult:
    """Check for Lambda functions with potential secrets in environment variables."""
    result = CheckResult(check_id="aws-lambda-003", check_name="Lambda env var secrets")

    try:
        for region in provider.regions:
            lam = provider.session.client("lambda", region_name=region)
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page["Functions"]:
                    result.resources_scanned += 1
                    fn_name = fn["FunctionName"]
                    fn_arn = fn["FunctionArn"]
                    env_vars = fn.get("Environment", {}).get("Variables", {})

                    suspect_keys = [k for k in env_vars if _SECRET_PATTERNS.search(k)]
                    if suspect_keys:
                        result.findings.append(
                            Finding(
                                check_id="aws-lambda-003",
                                title=f"Lambda '{fn_name}' has potential secrets in env vars: {', '.join(suspect_keys)}",
                                severity=Severity.HIGH,
                                category=Category.SECURITY,
                                resource_type="AWS::Lambda::Function",
                                resource_id=fn_arn,
                                region=region,
                                description=f"Function '{fn_name}' has environment variables matching secret patterns: {', '.join(suspect_keys)}. Secrets in env vars are visible in the Lambda console and API.",
                                recommendation="Move secrets to AWS Secrets Manager or SSM Parameter Store (SecureString) and reference them at runtime.",
                                remediation=Remediation(
                                    cli=(
                                        f"# Store secret in Secrets Manager:\n"
                                        f"aws secretsmanager create-secret --name {fn_name}/secrets "
                                        f"--secret-string '{{...}}' --region {region}\n"
                                        f"# Then remove from Lambda env vars and fetch at runtime"
                                    ),
                                    terraform=(
                                        f'resource "aws_secretsmanager_secret" "{fn_name}_secrets" {{\n'
                                        f'  name = "{fn_name}/secrets"\n'
                                        f"}}\n\n"
                                        f"# Reference in Lambda via data source or SDK at runtime"
                                    ),
                                    doc_url="https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html",
                                    effort=Effort.MEDIUM,
                                ),
                            )
                        )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all Lambda checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_public_function_url, provider, check_id="aws-lambda-001", category=Category.SECURITY),
        make_check(check_deprecated_runtime, provider, check_id="aws-lambda-002", category=Category.SECURITY),
        make_check(check_env_secrets, provider, check_id="aws-lambda-003", category=Category.SECURITY),
    ]
