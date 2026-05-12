"""TF-002: Lambda Function URL with auth-type NONE used as persistence.

The November-December 2025 cryptomining campaign documented across The Hacker News,
The Register, and Dark Reading used compromised AWS credentials to create Lambda
functions with public Function URLs (AuthType=NONE) attached to internet-reachable
endpoints. The functions ran cryptominers and acted as command-and-control
persistence points - even after the original IAM credentials were rotated, the
public Lambda URL kept working.

Detection signal: any Lambda function with a Function URL config of AuthType=NONE
deserves scrutiny. It is a LEGITIMATE pattern (webhooks, public APIs) so we
flag at HIGH and let the operator triage. Severity escalates to CRITICAL when
the function's execution role grants administrative IAM permissions OR access
to KMS/Secrets Manager - those are the function profiles attackers actually
deployed in 2025-2026.

References:
    - https://thehackernews.com/2025/12/compromised-iam-credentials-power-large.html
    - https://www.theregister.com/2025/12/18/crypto_crooks_use_stolen_aws/
    - https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


PATTERN_ID = "TF-002-lambda-function-url-persistence"
CHECK_ID = "aws-tf-002"
PATTERN_NAME = "Public Lambda Function URL (AuthType=NONE)"
PATTERN_SEVERITY = Severity.HIGH
DOC_URL = "https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html"

_REFERENCES = [
    "https://thehackernews.com/2025/12/compromised-iam-credentials-power-large.html",
    "https://www.theregister.com/2025/12/18/crypto_crooks_use_stolen_aws/",
    "https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html",
]

# Managed policies that, attached to a publicly-invokable Lambda, escalate
# the finding to CRITICAL. These are the role profiles seen in real campaigns.
_HIGH_RISK_MANAGED_POLICIES = frozenset(
    {
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/IAMFullAccess",
        "arn:aws:iam::aws:policy/AWSKeyManagementServicePowerUser",
        "arn:aws:iam::aws:policy/SecretsManagerReadWrite",
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
        "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
    }
)


def _role_name_from_arn(role_arn: str) -> str:
    """Extract role name from arn:aws:iam::ACCOUNT:role/path/Name."""
    return role_arn.rsplit("/", 1)[-1] if role_arn else ""


def _role_has_high_risk_policy(iam: Any, role_arn: str) -> bool:
    """Check whether the Lambda execution role grants admin-class permissions.

    Returns True if any attached managed policy is in _HIGH_RISK_MANAGED_POLICIES.
    Inline policy admin detection is intentionally out of scope for the pattern -
    the iam_analyzer.py module already covers full effective-permissions analysis;
    this is a lightweight heuristic to pick the severity bucket.
    """
    role_name = _role_name_from_arn(role_arn)
    if not role_name:
        return False
    try:
        attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if code in ("AccessDenied", "NoSuchEntity"):
            return False
        raise
    return any(p.get("PolicyArn") in _HIGH_RISK_MANAGED_POLICIES for p in attached)


def _build_finding(
    function_name: str,
    function_arn: str,
    function_url: str,
    region: str,
    cors_allow_origins: list[str],
    role_arn: str,
    severity: Severity,
    high_risk_role: bool,
) -> Finding:
    cors_note = ""
    if cors_allow_origins == ["*"] or "*" in cors_allow_origins:
        cors_note = (
            " The CORS policy allows ANY origin (Access-Control-Allow-Origin: *), making the "
            "URL trivially callable from any browser context."
        )

    role_note = ""
    if high_risk_role:
        role_note = (
            f" The execution role ({_role_name_from_arn(role_arn)}) grants administrative-class "
            "permissions (IAM/KMS/Secrets/Admin) - matching the role profile used in the November "
            "2025 cryptomining campaign. Treat as suspected persistence/backdoor until verified "
            "as intentional."
        )

    return Finding(
        check_id=CHECK_ID,
        title=f"Lambda '{function_name}' exposes a public Function URL (AuthType=NONE)",
        severity=severity,
        category=Category.THREAT,
        resource_type="AWS::Lambda::Function",
        resource_id=function_arn,
        region=region,
        description=(
            f"Lambda function '{function_name}' in {region} has a Function URL configured with "
            f"AuthType=NONE: {function_url}. Anyone on the internet can invoke this function "
            "with no authentication. This is a LEGITIMATE pattern for public webhooks/APIs but "
            "is also the canonical persistence mechanism used by the late-2025 compromised-IAM "
            "cryptomining campaign documented by The Hacker News and The Register." + cors_note + role_note
        ),
        recommendation=(
            "Verify the function is INTENTIONALLY public. If yes, document it in your "
            "infrastructure inventory and add resource-policy IP allowlisting / WAF in front. "
            "If unexpected: (1) immediately delete the function URL config, (2) audit "
            "CloudTrail for the CreateFunctionUrlConfig event to identify the principal that "
            "created it, (3) review the function code for unauthorized payloads, "
            "(4) rotate any credentials the principal had access to."
        ),
        remediation=Remediation(
            cli=(
                f"# 1) Identify who/when the URL was created:\n"
                f"aws cloudtrail lookup-events \\\n"
                f"  --lookup-attributes AttributeKey=ResourceName,AttributeValue={function_name} \\\n"
                f"  --region {region}\n"
                f"\n# 2) If unexpected, immediately remove the public URL:\n"
                f"aws lambda delete-function-url-config \\\n"
                f"  --function-name {function_name} \\\n"
                f"  --region {region}\n"
                f"\n# 3) Inspect the function code for tampering:\n"
                f"aws lambda get-function --function-name {function_name} \\\n"
                f"  --region {region} --query 'Code.Location' --output text"
            ),
            terraform=(
                f"# Remove the aws_lambda_function_url resource if not needed:\n"
                f'# resource "aws_lambda_function_url" "{function_name.replace("-", "_")}" {{\n'
                f"#   function_name      = aws_lambda_function.{function_name.replace('-', '_')}.function_name\n"
                f'#   authorization_type = "NONE"  # <- DELETE this resource\n'
                f"# }}\n"
                f"\n# If you must keep it public, switch to AWS_IAM auth + add resource policy:\n"
                f'resource "aws_lambda_function_url" "{function_name.replace("-", "_")}" {{\n'
                f"  function_name      = aws_lambda_function.{function_name.replace('-', '_')}.function_name\n"
                f'  authorization_type = "AWS_IAM"\n'
                f"}}"
            ),
            doc_url=DOC_URL,
            effort=Effort.LOW if not high_risk_role else Effort.MEDIUM,
        ),
        threat_pattern_id=PATTERN_ID,
        references=_REFERENCES,
    )


def _scan_region(provider: AWSProvider, region: str, iam: Any) -> tuple[int, list[Finding]]:
    """Scan a single region for Lambda functions with public Function URLs.

    Returns (resources_scanned, findings).
    """
    lam = provider.client("lambda", region_name=region)
    findings: list[Finding] = []
    scanned = 0

    paginator = lam.get_paginator("list_functions")
    for page in paginator.paginate():
        for fn in page.get("Functions", []):
            scanned += 1
            function_name = fn.get("FunctionName", "")
            function_arn = fn.get("FunctionArn", "")
            role_arn = fn.get("Role", "")

            try:
                url_cfg = lam.get_function_url_config(FunctionName=function_name)
            except Exception as exc:
                code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if code in ("ResourceNotFoundException", "AccessDeniedException"):
                    continue  # No URL configured (the common case) or no perm to read
                raise

            if url_cfg.get("AuthType") != "NONE":
                continue

            cors = url_cfg.get("Cors") or {}
            cors_origins = cors.get("AllowOrigins") or []

            high_risk = _role_has_high_risk_policy(iam, role_arn)
            severity = Severity.CRITICAL if high_risk else PATTERN_SEVERITY

            findings.append(
                _build_finding(
                    function_name=function_name,
                    function_arn=function_arn,
                    function_url=url_cfg.get("FunctionUrl", ""),
                    region=region,
                    cors_allow_origins=cors_origins,
                    role_arn=role_arn,
                    severity=severity,
                    high_risk_role=high_risk,
                )
            )

    return scanned, findings


def detect(provider: AWSProvider) -> CheckResult:
    """Scan all regions for publicly-invokable Lambda functions."""
    result = CheckResult(check_id=CHECK_ID, check_name=PATTERN_NAME)

    try:
        iam = provider.client("iam")  # global, used for role-policy lookups across regions

        for region in provider.regions:
            try:
                scanned, findings = _scan_region(provider, region, iam)
                result.resources_scanned += scanned
                result.findings.extend(findings)
            except Exception as exc:
                code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if code in ("AccessDeniedException", "UnrecognizedClientException"):
                    continue  # Region opt-in or no Lambda perms
                raise
    except Exception as e:
        result.error = str(e)

    return result
