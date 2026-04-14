"""Amazon Bedrock AI security checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_model_invocation_logging(provider: AWSProvider) -> CheckResult:
    """Check if Bedrock model invocation logging is enabled."""
    result = CheckResult(check_id="aws-bedrock-001", check_name="Bedrock model invocation logging")

    try:
        for region in provider.regions:
            br = provider.session.client("bedrock", region_name=region)
            result.resources_scanned += 1

            try:
                config = br.get_model_invocation_logging_configuration().get("loggingConfig", {})
                s3_enabled = config.get("s3Config", {}).get("bucketName", "")
                cw_enabled = config.get("cloudWatchConfig", {}).get("logGroupName", "")

                if not s3_enabled and not cw_enabled:
                    result.findings.append(
                        Finding(
                            check_id="aws-bedrock-001",
                            title=f"Bedrock model invocation logging disabled in {region}",
                            severity=Severity.HIGH,
                            category=Category.SECURITY,
                            resource_type="AWS::Bedrock::ModelInvocationLogging",
                            resource_id=f"bedrock-logging-{region}",
                            region=region,
                            description=(
                                f"Amazon Bedrock model invocation logging is not configured in {region}. "
                                "Without logging, you cannot audit who invoked which model, detect prompt "
                                "injection attempts, or investigate LLMjacking incidents."
                            ),
                            recommendation="Enable model invocation logging to S3 or CloudWatch Logs.",
                            remediation=Remediation(
                                cli=(
                                    f"aws bedrock put-model-invocation-logging-configuration \\\n"
                                    f'  --logging-config \'{{"cloudWatchConfig":{{"logGroupName":"/aws/bedrock/invocations",'
                                    f'"roleArn":"arn:aws:iam::ACCOUNT:role/bedrock-logging-role"}},'
                                    f'"textDataDeliveryEnabled":true}}\' \\\n'
                                    f"  --region {region}"
                                ),
                                terraform=(
                                    'resource "aws_bedrock_model_invocation_logging_configuration" "this" {\n'
                                    "  logging_config {\n"
                                    "    embedding_data_delivery_enabled = true\n"
                                    "    text_data_delivery_enabled      = true\n"
                                    "    cloudwatch_config {\n"
                                    "      log_group_name = aws_cloudwatch_log_group.bedrock.name\n"
                                    "      role_arn        = aws_iam_role.bedrock_logging.arn\n"
                                    "    }\n"
                                    "  }\n"
                                    "}"
                                ),
                                doc_url="https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
                                effort=Effort.LOW,
                            ),
                        )
                    )
            except Exception as exc:
                error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if error_code in ("AccessDeniedException", "UnrecognizedClientException"):
                    continue
                raise
    except Exception as e:
        result.error = str(e)

    return result


def check_guardrails(provider: AWSProvider) -> CheckResult:
    """Check if Bedrock guardrails are configured."""
    result = CheckResult(check_id="aws-bedrock-002", check_name="Bedrock guardrails")

    try:
        for region in provider.regions:
            br = provider.session.client("bedrock", region_name=region)
            result.resources_scanned += 1

            try:
                guardrails = br.list_guardrails().get("guardrails", [])
                if not guardrails:
                    result.findings.append(
                        Finding(
                            check_id="aws-bedrock-002",
                            title=f"No Bedrock guardrails configured in {region}",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            resource_type="AWS::Bedrock::Guardrail",
                            resource_id=f"bedrock-guardrails-{region}",
                            region=region,
                            description=(
                                f"No Amazon Bedrock guardrails are configured in {region}. "
                                "Without guardrails, models can generate harmful, biased, or "
                                "sensitive content. Guardrails enforce content filters, denied topics, "
                                "word filters, and PII detection."
                            ),
                            recommendation="Create Bedrock guardrails with content filters and topic restrictions.",
                            remediation=Remediation(
                                cli=(
                                    f"aws bedrock create-guardrail \\\n"
                                    f"  --name security-guardrail \\\n"
                                    f"  --blocked-input-messaging 'Input blocked by guardrail' \\\n"
                                    f"  --blocked-outputs-messaging 'Output blocked by guardrail' \\\n"
                                    f"  --content-policy-config "
                                    f'\'{{"filtersConfig":[{{"type":"SEXUAL","inputStrength":"HIGH",'
                                    f'"outputStrength":"HIGH"}}]}}\' \\\n'
                                    f"  --region {region}"
                                ),
                                terraform=(
                                    'resource "aws_bedrock_guardrail" "main" {\n'
                                    '  name                      = "security-guardrail"\n'
                                    '  blocked_input_messaging    = "Input blocked by guardrail"\n'
                                    '  blocked_outputs_messaging  = "Output blocked by guardrail"\n'
                                    "  content_policy_config {\n"
                                    "    filters_config {\n"
                                    '      type            = "SEXUAL"\n'
                                    '      input_strength  = "HIGH"\n'
                                    '      output_strength = "HIGH"\n'
                                    "    }\n"
                                    "  }\n"
                                    "}"
                                ),
                                doc_url="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html",
                                effort=Effort.MEDIUM,
                            ),
                        )
                    )
            except Exception as exc:
                error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if error_code in ("AccessDeniedException", "UnrecognizedClientException"):
                    continue
                # list_guardrails may not be implemented in all regions
                if "NotImplemented" in str(type(exc).__name__):
                    continue
                raise
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all Bedrock checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_model_invocation_logging, provider, check_id="aws-bedrock-001", category=Category.SECURITY),
        make_check(check_guardrails, provider, check_id="aws-bedrock-002", category=Category.SECURITY),
    ]
