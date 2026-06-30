"""AWS data perimeter checks - resource-policy boundary hygiene.

A *data perimeter* is the set of guardrails that keep your data reachable only
by trusted identities, from trusted networks, to trusted resources. These
checks evaluate **resource-based policies** for the two boundary failures that
are detectable purely from a single account's configuration (read-only, no AWS
Organizations access required):

- **Confused deputy** (``aws-dp-*`` ``confused_deputy``): an ``Allow`` statement
  grants an AWS *service* principal access without an ``aws:SourceAccount``,
  ``aws:SourceArn``, or ``aws:SourceOrgID`` condition. A service acting on
  behalf of *another* account could be coerced into touching your resource.
  See https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
- **Cross-organization exposure** (``cross_org``): an ``Allow`` statement grants
  a wildcard (``"*"``) or external-account AWS principal access without an
  organization-boundary condition (``aws:PrincipalOrgID``, ``aws:ResourceOrgID``,
  ``aws:SourceOrgID``, ...). Data can leave your account/organization boundary.

Why this exists: the dominant open-source scanner (Prowler) explicitly does not
model SCP/RCP or data-perimeter condition keys (tracked in prowler-cloud/prowler
issue #7114, open since 2025-03), which produces both blind spots and false
positives. cloud-audit reads the condition keys directly, so it reports the
*absence* of a perimeter guardrail without guessing about org-level policy.

Scope note: SCP/RCP enforcement lives at the AWS Organizations level and needs
management-account access, so it is intentionally out of scope here. These
checks operate on per-resource policies that any account-local principal can
read. The taxonomy follows the AWS data perimeter whitepaper and the Datadog
"deep dive into AWS data perimeter misconfigurations" (2026-06-01).

Detection notes and known limitations:

- Condition VALUES are evaluated, not just key presence. An account-scoping key
  (``aws:SourceAccount`` / ``aws:PrincipalAccount`` / ``aws:SourceOwner``) or
  ``aws:SourceArn`` only neutralizes a finding when its value resolves to THIS
  account. A grant "scoped" to a foreign account is still flagged.
- Organization-scoping keys (``aws:PrincipalOrgID``, ``aws:ResourceOrgID``, ...)
  are treated as a guardrail when present, because the org id cannot be verified
  locally without AWS Organizations access. A policy naming a foreign org id is
  therefore not flagged - a documented trade-off favoring zero false positives on
  the common, correct case.
- Scoping is heuristic, not a full IAM policy evaluation: operator semantics
  (e.g. ``...IfExists``) and per-request key presence are not simulated, and
  source- vs principal-scoped conditions are not distinguished. This deliberately
  avoids the maintenance trap that killed PMapper and keeps the false-positive
  rate low.
- Out of scope (not analyzed): ``NotPrincipal`` statements, ``CanonicalUser``
  principals (legacy S3 grants not parseable to an account), and federated *URL*
  principals (external IdPs such as accounts.google.com). Federated provider
  ARNs in a foreign account ARE analyzed as external grants.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


# Organization-scoping condition keys. Their VALUE (the org id) cannot be
# verified locally without AWS Organizations access, so PRESENCE is treated as a
# guardrail - a documented trade-off (see module docstring). The common, locally
# verifiable case (account-scoping keys below) is always value-checked.
ORG_CONDITION_KEYS = {
    "aws:principalorgid",
    "aws:principalorgpaths",
    "aws:resourceorgid",
    "aws:sourceorgid",
    "aws:sourceorgpaths",
}

# Account-scoping condition keys whose VALUE must equal our own account id to
# count as a guardrail. A grant "scoped" by one of these to a FOREIGN account is
# not a guardrail at all and is still flagged. Default SNS/SQS policies rely on
# aws:SourceOwner set to the topic/queue owner, so a correct default scopes to
# our own account and produces no finding.
_ACCOUNT_VALUE_KEYS = {
    "aws:sourceaccount",
    "aws:principalaccount",
    "aws:sourceowner",  # legacy SNS/SQS equivalent of aws:SourceAccount
}


def _condition_key_names(condition: Any) -> set[str]:
    """Return the set of all condition key names used anywhere in a Condition block.

    A Condition is ``{operator: {key: value, ...}, ...}``; the same key can appear
    under any operator (StringEquals, ArnLike, StringEqualsIfExists, Null, ...).
    Key names are returned lowercased because AWS treats them case-insensitively.
    """
    names: set[str] = set()
    if not isinstance(condition, dict):
        return names
    for op_values in condition.values():
        if isinstance(op_values, dict):
            for key in op_values:
                if isinstance(key, str):
                    names.add(key.lower())
    return names


def _service_principals(principal: Any) -> list[str]:
    """Extract AWS service principals (e.g. 'cloudtrail.amazonaws.com')."""
    if isinstance(principal, dict):
        svc = principal.get("Service")
        if isinstance(svc, str):
            return [svc]
        if isinstance(svc, list):
            return [s for s in svc if isinstance(s, str)]
    return []


def _aws_principals(principal: Any) -> list[str]:
    """Extract AWS account/ARN principals. A bare ``"*"`` principal counts here."""
    if principal == "*":
        return ["*"]
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        if isinstance(aws, str):
            return [aws]
        if isinstance(aws, list):
            return [a for a in aws if isinstance(a, str)]
    return []


def _federated_principals(principal: Any) -> list[str]:
    """Extract federated principals (SAML/OIDC provider ARNs or external IdP URLs).

    A federated provider ARN that parses to a foreign account is treated as an
    external grant. Federated *URLs* (e.g. accounts.google.com, cognito) are not
    account-parseable and are intentionally out of scope (see module docstring).
    """
    if isinstance(principal, dict):
        fed = principal.get("Federated")
        if isinstance(fed, str):
            return [fed]
        if isinstance(fed, list):
            return [f for f in fed if isinstance(f, str)]
    return []


def _account_from_arn(value: str) -> str | None:
    """Return the 12-digit account id from an ARN or bare account principal.

    ``arn:aws:iam::123456789012:root`` -> ``123456789012``.
    ``123456789012`` -> ``123456789012``.
    Returns None for ``"*"`` or anything we cannot confidently parse.
    """
    if value == "*":
        return None
    if value.isdigit() and len(value) == 12:
        return value
    parts = value.split(":")
    if len(parts) >= 5 and parts[4].isdigit() and len(parts[4]) == 12:
        return parts[4]
    return None


def _is_external_aws_principal(value: str, account_id: str) -> bool:
    """True if an AWS principal grants access outside our own account.

    Conservative: a principal we cannot parse into an account id (and is not the
    bare wildcard) is treated as NOT external, to avoid false positives on
    unusual-but-scoped ARNs.
    """
    if value == "*":
        return True
    acct = _account_from_arn(value)
    if acct is None:
        return False
    return acct != account_id


def _condition_value_list(value: Any) -> list[str]:
    """Normalize a condition value (str or list of str) to a list of strings."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def _condition_scopes_to_own(condition: Any, account_id: str) -> bool:
    """True if a Condition block binds the grant to our own account or organization.

    Evaluates condition VALUES, not just key presence. This is the fix for the
    core data-perimeter promise: a grant "scoped" by aws:SourceAccount /
    aws:SourceOwner / aws:PrincipalAccount / aws:SourceArn pointing at someone
    ELSE'S account is not a guardrail and must still be flagged.

    - Account-scoping keys: scope to own only if a listed value equals account_id.
    - aws:SourceArn: scopes to own only if a listed ARN parses to account_id.
    - Organization-scoping keys: treated as a guardrail whenever PRESENT, because
      the org id cannot be verified locally without AWS Organizations access. A
      (rare) policy naming a foreign org id is therefore treated as scoped - a
      documented trade-off. Account-level keys cover the common case exactly.
    """
    if not isinstance(condition, dict):
        return False
    for op_values in condition.values():
        if not isinstance(op_values, dict):
            continue
        for key, value in op_values.items():
            if not isinstance(key, str):
                continue
            kl = key.lower()
            if kl in ORG_CONDITION_KEYS:
                return True  # org binding present (value not verifiable locally)
            if kl in _ACCOUNT_VALUE_KEYS and account_id in _condition_value_list(value):
                return True
            if kl == "aws:sourcearn" and any(_account_from_arn(v) == account_id for v in _condition_value_list(value)):
                return True
    return False


class PerimeterGap:
    """A single data-perimeter gap found in one policy statement."""

    __slots__ = ("kind", "principals", "severity", "sid", "wildcard")

    def __init__(self, kind: str, severity: Severity, principals: list[str], wildcard: bool, sid: str) -> None:
        self.kind = kind  # "confused_deputy" | "cross_org"
        self.severity = severity
        self.principals = principals
        self.wildcard = wildcard
        self.sid = sid


def _find_perimeter_gaps(policy: Any, account_id: str) -> list[PerimeterGap]:
    """Analyze a resource policy document and return its data-perimeter gaps.

    Pure function over a parsed policy dict - no AWS calls - so it is exhaustively
    unit-testable. Only ``Allow`` statements are considered; ``Deny`` statements
    tighten a perimeter and are never flagged.
    """
    gaps: list[PerimeterGap] = []
    if not isinstance(policy, dict):
        return gaps

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):  # single-statement policies may be a dict
        statements = [statements]
    if not isinstance(statements, list):
        return gaps

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        if principal is None:
            continue
        condition = stmt.get("Condition", {})
        sid = stmt.get("Sid", "") if isinstance(stmt.get("Sid", ""), str) else ""
        scoped = _condition_scopes_to_own(condition, account_id)

        # Confused deputy: service principal not scoped to our own account/org.
        services = _service_principals(principal)
        if services and not scoped:
            gaps.append(
                PerimeterGap(
                    kind="confused_deputy",
                    severity=Severity.MEDIUM,
                    principals=services,
                    wildcard=False,
                    sid=sid,
                )
            )

        # Cross-org exposure: wildcard, external AWS, or external federated
        # principal not bound to our account/organization. A federated provider
        # ARN in a foreign account counts as external; federated URLs and
        # CanonicalUser principals are out of scope (see module docstring).
        aws_ps = _aws_principals(principal)
        federated_external = [f for f in _federated_principals(principal) if _is_external_aws_principal(f, account_id)]
        external = [p for p in aws_ps if _is_external_aws_principal(p, account_id)] + federated_external
        if external and not scoped:
            wildcard = any(p == "*" for p in external)
            # Wildcard ("any AWS account") is materially worse than a grant to one
            # named external account, which is often an intentional partner share.
            severity = Severity.HIGH if wildcard else Severity.LOW
            gaps.append(
                PerimeterGap(
                    kind="cross_org",
                    severity=severity,
                    principals=external,
                    wildcard=wildcard,
                    sid=sid,
                )
            )

    return gaps


# --------------------------------------------------------------------------- #
# Remediation helpers
# --------------------------------------------------------------------------- #


def _confused_deputy_remediation(service: str, doc_url: str) -> Remediation:
    return Remediation(
        cli=(
            "# Add a source-scoping condition to the service statement so the\n"
            "# service can only act on behalf of THIS account/resource:\n"
            '#   "Condition": { "StringEquals": { "aws:SourceAccount": "ACCOUNT_ID" } }\n'
            "# or the tighter, per-resource form:\n"
            '#   "Condition": { "ArnLike": { "aws:SourceArn": "arn:aws:SERVICE:REGION:ACCOUNT_ID:*" } }\n'
            "# Re-apply the edited policy with the service's put-*-policy API."
        ),
        terraform=(
            "# In the resource policy statement granting access to\n"
            f'# "{service}", add:\n'
            "condition {\n"
            '  test     = "StringEquals"\n'
            '  variable = "aws:SourceAccount"\n'
            "  values   = [data.aws_caller_identity.current.account_id]\n"
            "}"
        ),
        doc_url=doc_url,
        effort=Effort.MEDIUM,
    )


def _cross_org_remediation(doc_url: str) -> Remediation:
    return Remediation(
        cli=(
            "# Constrain the statement to your AWS Organization so data cannot be\n"
            "# accessed from outside the org boundary:\n"
            '#   "Condition": { "StringEquals": { "aws:PrincipalOrgID": "o-xxxxxxxxxx" } }\n'
            "# If the grant to an external account is intentional, scope it to that\n"
            "# exact principal ARN instead of a wildcard, and document the exception\n"
            "# in .cloud-audit.yml suppressions."
        ),
        terraform=(
            "# Add an organization-boundary condition to the statement:\n"
            "condition {\n"
            '  test     = "StringEquals"\n'
            '  variable = "aws:PrincipalOrgID"\n'
            '  values   = ["o-xxxxxxxxxx"]\n'
            "}"
        ),
        doc_url=doc_url,
        effort=Effort.MEDIUM,
    )


def _gap_to_finding(
    gap: PerimeterGap,
    *,
    check_id: str,
    resource_type: str,
    resource_id: str,
    region: str,
    service_label: str,
    doc_url: str,
) -> Finding:
    """Build a Finding from a PerimeterGap for a specific resource."""
    sid_note = f" (statement Sid '{gap.sid}')" if gap.sid else ""
    if gap.kind == "confused_deputy":
        svc = ", ".join(gap.principals)
        return Finding(
            check_id=check_id,
            title=f"{service_label} '{resource_id}' grants service principal without confused-deputy protection",
            severity=gap.severity,
            category=Category.SECURITY,
            resource_type=resource_type,
            resource_id=resource_id,
            region=region,
            description=(
                f"The resource policy on {service_label.lower()} '{resource_id}' allows the AWS service "
                f"principal(s) {svc}{sid_note} without an aws:SourceAccount, aws:SourceArn, or "
                "aws:SourceOrgID condition. A service acting on behalf of a different account could be "
                "tricked into operating on this resource (the confused deputy problem)."
            ),
            recommendation=(
                "Add an aws:SourceAccount or aws:SourceArn condition restricting the service to this account/resource."
            ),
            remediation=_confused_deputy_remediation(svc, doc_url),
            compliance_refs=["SOC2 CC6.1", "ISO27001 A.5.14", "NIS2-RM-05b"],
            references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html"],
        )
    # cross_org
    if gap.wildcard:
        principal_desc = "a wildcard principal ('*', i.e. any AWS account)"
    else:
        principal_desc = f"external AWS principal(s) {', '.join(gap.principals)}"
    return Finding(
        check_id=check_id,
        title=(f"{service_label} '{resource_id}' grants cross-account access without an organization boundary"),
        severity=gap.severity,
        category=Category.SECURITY,
        resource_type=resource_type,
        resource_id=resource_id,
        region=region,
        description=(
            f"The resource policy on {service_label.lower()} '{resource_id}' allows {principal_desc}{sid_note} "
            "without an organization-boundary condition (aws:PrincipalOrgID, aws:ResourceOrgID, "
            "aws:SourceOrgID). Data in this resource can be reached from outside your AWS Organization. "
            "This is the data-perimeter gap that resource control policies (RCPs) and aws:*OrgID "
            "conditions are designed to close."
        ),
        recommendation=(
            "Add an aws:PrincipalOrgID (or aws:ResourceOrgID) condition, or scope the grant to an exact "
            "external principal ARN if the cross-account share is intentional."
        ),
        remediation=_cross_org_remediation(doc_url),
        compliance_refs=["SOC2 CC6.1", "SOC2 CC6.6", "ISO27001 A.5.14", "NIS2-RM-05b"],
        references=[
            "https://docs.aws.amazon.com/whitepapers/latest/building-a-data-perimeter-on-aws/perimeter-overview.html"
        ],
    )


# --------------------------------------------------------------------------- #
# Per-service checks
# --------------------------------------------------------------------------- #

_S3_DOC = "https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html"
_PERIMETER_DOC = (
    "https://docs.aws.amazon.com/whitepapers/latest/building-a-data-perimeter-on-aws/perimeter-overview.html"
)


def check_s3_bucket_policy_perimeter(provider: AWSProvider) -> CheckResult:
    """``aws-dp-001`` - S3 bucket policy data-perimeter gaps.

    Complements aws-s3-001 (public access block): PAB governs anonymous public
    access, while this check governs the *organization boundary* and confused
    deputy posture of the bucket policy itself.
    """
    result = CheckResult(check_id="aws-dp-001", check_name="S3 bucket policy data perimeter")
    try:
        account_id = provider.get_account_id()
        s3 = provider.session.client("s3")
        try:
            buckets = s3.list_buckets()["Buckets"]
        except Exception as exc:
            result.error = str(exc)
            return result

        for bucket in buckets:
            name = bucket["Name"]
            result.resources_scanned += 1
            try:
                policy_str = s3.get_bucket_policy(Bucket=name)["Policy"]
                policy = json.loads(policy_str)
            except Exception as exc:
                error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if error_code in ("NoSuchBucketPolicy", "AccessDenied", "AccessDeniedException"):
                    continue
                continue  # malformed or unexpected - skip rather than false positive

            for gap in _find_perimeter_gaps(policy, account_id):
                result.findings.append(
                    _gap_to_finding(
                        gap,
                        check_id="aws-dp-001",
                        resource_type="AWS::S3::Bucket",
                        resource_id=name,
                        region="global",
                        service_label="S3 bucket",
                        doc_url=_PERIMETER_DOC,
                    )
                )
    except Exception as e:
        result.error = str(e)
    return result


def check_sns_topic_policy_perimeter(provider: AWSProvider) -> CheckResult:
    """``aws-dp-002`` - SNS topic policy data-perimeter gaps."""
    result = CheckResult(check_id="aws-dp-002", check_name="SNS topic policy data perimeter")
    try:
        account_id = provider.get_account_id()
        for region in provider.regions:
            sns = provider.session.client("sns", region_name=region)
            try:
                paginator = sns.get_paginator("list_topics")
                topic_arns = [t["TopicArn"] for page in paginator.paginate() for t in page.get("Topics", [])]
            except Exception as exc:
                error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if error_code in ("AuthorizationError", "AccessDenied", "AccessDeniedException"):
                    continue
                raise

            for arn in topic_arns:
                result.resources_scanned += 1
                try:
                    attrs = sns.get_topic_attributes(TopicArn=arn)["Attributes"]
                except Exception:
                    continue
                policy_str = attrs.get("Policy")
                if not policy_str:
                    continue
                try:
                    policy = json.loads(policy_str)
                except (ValueError, TypeError):
                    continue

                for gap in _find_perimeter_gaps(policy, account_id):
                    result.findings.append(
                        _gap_to_finding(
                            gap,
                            check_id="aws-dp-002",
                            resource_type="AWS::SNS::Topic",
                            resource_id=arn,
                            region=region,
                            service_label="SNS topic",
                            doc_url=_PERIMETER_DOC,
                        )
                    )
    except Exception as e:
        result.error = str(e)
    return result


def check_sqs_queue_policy_perimeter(provider: AWSProvider) -> CheckResult:
    """``aws-dp-003`` - SQS queue policy data-perimeter gaps."""
    result = CheckResult(check_id="aws-dp-003", check_name="SQS queue policy data perimeter")
    try:
        account_id = provider.get_account_id()
        for region in provider.regions:
            sqs = provider.session.client("sqs", region_name=region)
            try:
                paginator = sqs.get_paginator("list_queues")
                queue_urls = [u for page in paginator.paginate() for u in page.get("QueueUrls", [])]
            except Exception as exc:
                error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if error_code in ("AccessDenied", "AccessDeniedException"):
                    continue
                raise

            for url in queue_urls:
                result.resources_scanned += 1
                try:
                    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"])["Attributes"]
                except Exception:
                    continue
                policy_str = attrs.get("Policy")
                if not policy_str:
                    continue
                try:
                    policy = json.loads(policy_str)
                except (ValueError, TypeError):
                    continue

                for gap in _find_perimeter_gaps(policy, account_id):
                    result.findings.append(
                        _gap_to_finding(
                            gap,
                            check_id="aws-dp-003",
                            resource_type="AWS::SQS::Queue",
                            resource_id=url,
                            region=region,
                            service_label="SQS queue",
                            doc_url=_PERIMETER_DOC,
                        )
                    )
    except Exception as e:
        result.error = str(e)
    return result


def check_secrets_resource_policy_perimeter(provider: AWSProvider) -> CheckResult:
    """``aws-dp-004`` - Secrets Manager resource policy data-perimeter gaps.

    Secrets are high-value: a cross-account or wildcard grant on a secret's
    resource policy is a direct data-exfiltration path, so cross-org findings
    here are escalated one level above the generic case.
    """
    result = CheckResult(check_id="aws-dp-004", check_name="Secrets Manager resource policy data perimeter")
    try:
        account_id = provider.get_account_id()
        for region in provider.regions:
            sm = provider.session.client("secretsmanager", region_name=region)
            try:
                paginator = sm.get_paginator("list_secrets")
                secret_ids = [s["ARN"] for page in paginator.paginate() for s in page.get("SecretList", [])]
            except Exception as exc:
                error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if error_code in ("AccessDeniedException", "AccessDenied"):
                    continue
                raise

            for secret_id in secret_ids:
                result.resources_scanned += 1
                try:
                    resp = sm.get_resource_policy(SecretId=secret_id)
                except Exception:
                    continue
                policy_str = resp.get("ResourcePolicy")
                if not policy_str:
                    continue
                try:
                    policy = json.loads(policy_str)
                except (ValueError, TypeError):
                    continue

                for gap in _find_perimeter_gaps(policy, account_id):
                    # Escalate cross-org gaps on secrets - direct exfil path.
                    if gap.kind == "cross_org":
                        gap.severity = Severity.CRITICAL if gap.wildcard else Severity.MEDIUM
                    result.findings.append(
                        _gap_to_finding(
                            gap,
                            check_id="aws-dp-004",
                            resource_type="AWS::SecretsManager::Secret",
                            resource_id=secret_id,
                            region=region,
                            service_label="Secret",
                            doc_url=_PERIMETER_DOC,
                        )
                    )
    except Exception as e:
        result.error = str(e)
    return result


def check_lambda_resource_policy_perimeter(provider: AWSProvider) -> CheckResult:
    """``aws-dp-005`` - Lambda function resource policy data-perimeter gaps.

    Lambda resource policies (built via AddPermission) commonly grant invoke
    rights to AWS services (S3, SNS, EventBridge). Without aws:SourceAccount /
    aws:SourceArn, a service in another account can be steered into invoking
    your function - the classic Lambda confused deputy.
    """
    result = CheckResult(check_id="aws-dp-005", check_name="Lambda resource policy data perimeter")
    try:
        account_id = provider.get_account_id()
        for region in provider.regions:
            lam = provider.session.client("lambda", region_name=region)
            try:
                paginator = lam.get_paginator("list_functions")
                fn_names = [f["FunctionName"] for page in paginator.paginate() for f in page.get("Functions", [])]
            except Exception as exc:
                error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if error_code in ("AccessDeniedException", "AccessDenied"):
                    continue
                raise

            for fn_name in fn_names:
                result.resources_scanned += 1
                try:
                    resp = lam.get_policy(FunctionName=fn_name)
                except Exception as exc:
                    error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                    # ResourceNotFoundException = no resource policy at all = nothing to flag
                    if error_code in ("ResourceNotFoundException", "AccessDeniedException", "AccessDenied"):
                        continue
                    continue
                policy_str = resp.get("Policy")
                if not policy_str:
                    continue
                try:
                    policy = json.loads(policy_str)
                except (ValueError, TypeError):
                    continue

                for gap in _find_perimeter_gaps(policy, account_id):
                    result.findings.append(
                        _gap_to_finding(
                            gap,
                            check_id="aws-dp-005",
                            resource_type="AWS::Lambda::Function",
                            resource_id=fn_name,
                            region=region,
                            service_label="Lambda function",
                            doc_url=_S3_DOC,
                        )
                    )
    except Exception as e:
        result.error = str(e)
    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all data perimeter checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_s3_bucket_policy_perimeter, provider, check_id="aws-dp-001", category=Category.SECURITY),
        make_check(check_sns_topic_policy_perimeter, provider, check_id="aws-dp-002", category=Category.SECURITY),
        make_check(check_sqs_queue_policy_perimeter, provider, check_id="aws-dp-003", category=Category.SECURITY),
        make_check(
            check_secrets_resource_policy_perimeter,
            provider,
            check_id="aws-dp-004",
            category=Category.SECURITY,
        ),
        make_check(
            check_lambda_resource_policy_perimeter,
            provider,
            check_id="aws-dp-005",
            category=Category.SECURITY,
        ),
    ]
