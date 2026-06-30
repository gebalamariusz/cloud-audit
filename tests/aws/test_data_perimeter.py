"""Tests for data perimeter checks (aws-dp-001..005).

Two layers:
- Unit tests over the pure ``_find_perimeter_gaps`` engine and its helpers
  (no AWS calls) - these exhaustively pin the detection semantics.
- Integration tests with moto for each per-service check.
"""

from __future__ import annotations

import io
import json
import zipfile
from typing import TYPE_CHECKING

from cloud_audit.providers.aws.checks.data_perimeter import (
    _account_from_arn,
    _aws_principals,
    _condition_key_names,
    _find_perimeter_gaps,
    _is_external_aws_principal,
    _service_principals,
    check_lambda_resource_policy_perimeter,
    check_s3_bucket_policy_perimeter,
    check_secrets_resource_policy_perimeter,
    check_sns_topic_policy_perimeter,
    check_sqs_queue_policy_perimeter,
)

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider

OWN = "123456789012"  # moto default account id
EXTERNAL = "999888777666"


# ---------------------------------------------------------------------------
# Unit: _condition_key_names
# ---------------------------------------------------------------------------


def test_condition_key_names_basic() -> None:
    cond = {"StringEquals": {"aws:SourceAccount": "123"}, "ArnLike": {"aws:SourceArn": "arn:*"}}
    assert _condition_key_names(cond) == {"aws:sourceaccount", "aws:sourcearn"}


def test_condition_key_names_case_insensitive() -> None:
    cond = {"StringEquals": {"AWS:SourceAccount": "123", "aws:principalOrgID": "o-1"}}
    assert _condition_key_names(cond) == {"aws:sourceaccount", "aws:principalorgid"}


def test_condition_key_names_empty_and_malformed() -> None:
    assert _condition_key_names({}) == set()
    assert _condition_key_names(None) == set()
    assert _condition_key_names("nonsense") == set()
    assert _condition_key_names({"StringEquals": "not-a-dict"}) == set()


# ---------------------------------------------------------------------------
# Unit: _account_from_arn / _is_external_aws_principal / principal extractors
# ---------------------------------------------------------------------------


def test_account_from_arn() -> None:
    assert _account_from_arn("arn:aws:iam::123456789012:root") == "123456789012"
    assert _account_from_arn("arn:aws:iam::123456789012:role/x") == "123456789012"
    assert _account_from_arn("123456789012") == "123456789012"
    assert _account_from_arn("*") is None
    assert _account_from_arn("not-an-arn") is None
    assert _account_from_arn("arn:aws:iam::notanaccount:root") is None


def test_is_external_aws_principal() -> None:
    assert _is_external_aws_principal("*", OWN) is True
    assert _is_external_aws_principal(f"arn:aws:iam::{EXTERNAL}:root", OWN) is True
    assert _is_external_aws_principal(EXTERNAL, OWN) is True
    assert _is_external_aws_principal(f"arn:aws:iam::{OWN}:root", OWN) is False
    assert _is_external_aws_principal(OWN, OWN) is False
    # Unparseable principal is conservatively treated as NOT external
    assert _is_external_aws_principal("some-weird-thing", OWN) is False


def test_service_and_aws_principal_extractors() -> None:
    assert _service_principals({"Service": "cloudtrail.amazonaws.com"}) == ["cloudtrail.amazonaws.com"]
    assert _service_principals({"Service": ["a.com", "b.com"]}) == ["a.com", "b.com"]
    assert _service_principals("*") == []
    assert _service_principals({"AWS": "*"}) == []
    assert _aws_principals("*") == ["*"]
    assert _aws_principals({"AWS": "arn:aws:iam::1:root"}) == ["arn:aws:iam::1:root"]
    assert _aws_principals({"AWS": ["a", "b"]}) == ["a", "b"]
    assert _aws_principals({"Service": "x"}) == []


# ---------------------------------------------------------------------------
# Unit: _find_perimeter_gaps - the detection core
# ---------------------------------------------------------------------------


def _allow(principal: object, condition: object | None = None, sid: str = "") -> dict:
    stmt: dict = {"Effect": "Allow", "Principal": principal, "Action": "s3:GetObject", "Resource": "*"}
    if condition is not None:
        stmt["Condition"] = condition
    if sid:
        stmt["Sid"] = sid
    return {"Version": "2012-10-17", "Statement": [stmt]}


def test_gaps_empty_policy() -> None:
    assert _find_perimeter_gaps({}, OWN) == []
    assert _find_perimeter_gaps({"Statement": []}, OWN) == []
    assert _find_perimeter_gaps("nonsense", OWN) == []


def test_gaps_single_statement_dict() -> None:
    """A policy whose Statement is a single dict (not a list) is handled."""
    policy = {"Statement": {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "*", "Resource": "*"}}
    gaps = _find_perimeter_gaps(policy, OWN)
    assert len(gaps) == 1
    assert gaps[0].kind == "cross_org"


def test_gaps_confused_deputy_detected() -> None:
    gaps = _find_perimeter_gaps(_allow({"Service": "cloudtrail.amazonaws.com"}), OWN)
    assert len(gaps) == 1
    assert gaps[0].kind == "confused_deputy"
    assert gaps[0].severity.value == "medium"
    assert gaps[0].principals == ["cloudtrail.amazonaws.com"]


def test_gaps_confused_deputy_source_account_ok() -> None:
    policy = _allow(
        {"Service": "cloudtrail.amazonaws.com"},
        {"StringEquals": {"aws:SourceAccount": OWN}},
    )
    assert _find_perimeter_gaps(policy, OWN) == []


def test_gaps_confused_deputy_source_arn_ok() -> None:
    policy = _allow(
        {"Service": "cloudtrail.amazonaws.com"},
        {"ArnLike": {"aws:SourceArn": f"arn:aws:cloudtrail:eu-central-1:{OWN}:trail/*"}},
    )
    assert _find_perimeter_gaps(policy, OWN) == []


def test_gaps_confused_deputy_source_owner_ok() -> None:
    """Legacy aws:SourceOwner (SNS/SQS default) neutralizes confused deputy."""
    policy = _allow({"Service": "sns.amazonaws.com"}, {"StringEquals": {"aws:SourceOwner": OWN}})
    assert _find_perimeter_gaps(policy, OWN) == []


def test_gaps_confused_deputy_case_insensitive_condition() -> None:
    policy = _allow({"Service": "cloudtrail.amazonaws.com"}, {"StringEquals": {"AWS:SOURCEACCOUNT": OWN}})
    assert _find_perimeter_gaps(policy, OWN) == []


def test_gaps_confused_deputy_multiple_services() -> None:
    gaps = _find_perimeter_gaps(_allow({"Service": ["a.amazonaws.com", "b.amazonaws.com"]}), OWN)
    assert len(gaps) == 1
    assert gaps[0].principals == ["a.amazonaws.com", "b.amazonaws.com"]


def test_gaps_cross_org_wildcard_high() -> None:
    gaps = _find_perimeter_gaps(_allow({"AWS": "*"}), OWN)
    assert len(gaps) == 1
    assert gaps[0].kind == "cross_org"
    assert gaps[0].wildcard is True
    assert gaps[0].severity.value == "high"


def test_gaps_cross_org_wildcard_with_org_condition_ok() -> None:
    policy = _allow({"AWS": "*"}, {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}})
    assert _find_perimeter_gaps(policy, OWN) == []


def test_gaps_cross_org_wildcard_with_source_owner_ok() -> None:
    """Wildcard principal scoped by aws:SourceOwner is account-bound, not world-open."""
    policy = _allow({"AWS": "*"}, {"StringEquals": {"aws:SourceOwner": OWN}})
    assert _find_perimeter_gaps(policy, OWN) == []


def test_gaps_cross_org_external_account_low() -> None:
    gaps = _find_perimeter_gaps(_allow({"AWS": f"arn:aws:iam::{EXTERNAL}:root"}), OWN)
    assert len(gaps) == 1
    assert gaps[0].kind == "cross_org"
    assert gaps[0].wildcard is False
    assert gaps[0].severity.value == "low"


def test_gaps_cross_org_external_with_org_condition_ok() -> None:
    policy = _allow(
        {"AWS": f"arn:aws:iam::{EXTERNAL}:root"},
        {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
    )
    assert _find_perimeter_gaps(policy, OWN) == []


def test_gaps_same_account_principal_ok() -> None:
    assert _find_perimeter_gaps(_allow({"AWS": f"arn:aws:iam::{OWN}:root"}), OWN) == []
    assert _find_perimeter_gaps(_allow({"AWS": OWN}), OWN) == []


def test_gaps_bare_external_account_id() -> None:
    gaps = _find_perimeter_gaps(_allow({"AWS": EXTERNAL}), OWN)
    assert len(gaps) == 1
    assert gaps[0].kind == "cross_org"


def test_gaps_deny_statement_ignored() -> None:
    policy = {
        "Statement": [
            {"Effect": "Deny", "Principal": {"AWS": "*"}, "Action": "*", "Resource": "*"},
        ]
    }
    assert _find_perimeter_gaps(policy, OWN) == []


def test_gaps_statement_without_principal_ignored() -> None:
    policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    assert _find_perimeter_gaps(policy, OWN) == []


def test_gaps_service_and_aws_wildcard_both() -> None:
    """One statement with both a service and a wildcard AWS principal yields two gaps."""
    policy = _allow({"Service": "cloudtrail.amazonaws.com", "AWS": "*"})
    gaps = _find_perimeter_gaps(policy, OWN)
    kinds = sorted(g.kind for g in gaps)
    assert kinds == ["confused_deputy", "cross_org"]


def test_gaps_malformed_statement_no_crash() -> None:
    assert _find_perimeter_gaps({"Statement": ["a string", 42, None]}, OWN) == []


def test_gaps_sid_preserved() -> None:
    gaps = _find_perimeter_gaps(_allow({"AWS": "*"}, sid="OpenToWorld"), OWN)
    assert gaps[0].sid == "OpenToWorld"


def test_gaps_multi_statement_policy() -> None:
    """A policy with several problematic statements yields one gap per statement."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:*",
                "Resource": "*",
            },
            {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:GetObject", "Resource": "*"},
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{OWN}:root"}, "Action": "s3:*", "Resource": "*"},
        ],
    }
    gaps = _find_perimeter_gaps(policy, OWN)
    kinds = sorted(g.kind for g in gaps)
    assert kinds == ["confused_deputy", "cross_org"]  # same-account statement produces nothing


def test_gaps_not_principal_ignored() -> None:
    """NotPrincipal is a known limitation - statements using it are not analyzed."""
    policy = {"Statement": [{"Effect": "Allow", "NotPrincipal": {"AWS": "*"}, "Action": "*", "Resource": "*"}]}
    assert _find_perimeter_gaps(policy, OWN) == []


def test_gaps_ifexists_condition_counts() -> None:
    """A condition key under an *IfExists operator still counts as present."""
    policy = _allow({"AWS": "*"}, {"StringEqualsIfExists": {"aws:PrincipalOrgID": "o-abc"}})
    assert _find_perimeter_gaps(policy, OWN) == []


def test_gaps_service_wildcard_is_confused_deputy() -> None:
    policy = _allow({"Service": "*"})
    gaps = _find_perimeter_gaps(policy, OWN)
    assert len(gaps) == 1
    assert gaps[0].kind == "confused_deputy"


# ---------------------------------------------------------------------------
# Unit: condition VALUE evaluation (BLOCKER #1 fix - scoping to a foreign
# account/org is not a guardrail)
# ---------------------------------------------------------------------------


def test_gaps_wildcard_source_owner_foreign_flagged() -> None:
    """A scoping key pointing at a FOREIGN account is not a guardrail - still flagged."""
    policy = _allow({"AWS": "*"}, {"StringEquals": {"aws:SourceOwner": EXTERNAL}})
    gaps = _find_perimeter_gaps(policy, OWN)
    assert len(gaps) == 1
    assert gaps[0].kind == "cross_org"
    assert gaps[0].severity.value == "high"


def test_gaps_wildcard_source_account_foreign_flagged() -> None:
    policy = _allow({"AWS": "*"}, {"StringEquals": {"aws:SourceAccount": EXTERNAL}})
    assert len(_find_perimeter_gaps(policy, OWN)) == 1


def test_gaps_wildcard_principal_account_own_ok() -> None:
    policy = _allow({"AWS": "*"}, {"StringEquals": {"aws:PrincipalAccount": OWN}})
    assert _find_perimeter_gaps(policy, OWN) == []


def test_gaps_source_arn_foreign_account_flagged() -> None:
    policy = _allow({"AWS": "*"}, {"ArnLike": {"aws:SourceArn": f"arn:aws:sns:eu-central-1:{EXTERNAL}:topic"}})
    assert len(_find_perimeter_gaps(policy, OWN)) == 1


def test_gaps_source_arn_own_account_ok() -> None:
    policy = _allow({"AWS": "*"}, {"ArnLike": {"aws:SourceArn": f"arn:aws:sns:eu-central-1:{OWN}:topic"}})
    assert _find_perimeter_gaps(policy, OWN) == []


def test_gaps_confused_deputy_source_account_foreign_flagged() -> None:
    """Service principal scoped to a FOREIGN account is still a confused-deputy gap."""
    policy = _allow({"Service": "cloudtrail.amazonaws.com"}, {"StringEquals": {"aws:SourceAccount": EXTERNAL}})
    gaps = _find_perimeter_gaps(policy, OWN)
    assert len(gaps) == 1
    assert gaps[0].kind == "confused_deputy"


def test_gaps_external_with_org_id_is_documented_trust() -> None:
    """Org keys are treated as a guardrail when present (org id not verifiable locally)."""
    policy = _allow(
        {"AWS": f"arn:aws:iam::{EXTERNAL}:root"},
        {"StringEquals": {"aws:PrincipalOrgID": "o-foreign"}},
    )
    assert _find_perimeter_gaps(policy, OWN) == []


def test_gaps_condition_value_as_list() -> None:
    """A condition value may be a list; own account anywhere in it scopes the grant."""
    scoped = _allow({"AWS": "*"}, {"StringEquals": {"aws:SourceAccount": [EXTERNAL, OWN]}})
    assert _find_perimeter_gaps(scoped, OWN) == []
    foreign_only = _allow({"AWS": "*"}, {"StringEquals": {"aws:SourceAccount": [EXTERNAL]}})
    assert len(_find_perimeter_gaps(foreign_only, OWN)) == 1


def test_gaps_condition_value_non_str_no_crash() -> None:
    """A non-string condition value (malformed) is safely ignored, not crashed on."""
    policy = _allow({"AWS": "*"}, {"StringEquals": {"aws:SourceAccount": 123456789012}})
    gaps = _find_perimeter_gaps(policy, OWN)
    assert len(gaps) == 1  # int value cannot match the string account_id -> still flagged


# ---------------------------------------------------------------------------
# Unit: Federated / CanonicalUser principals (BLOCKER #2)
# ---------------------------------------------------------------------------


def test_gaps_federated_foreign_arn_flagged() -> None:
    policy = _allow({"Federated": f"arn:aws:iam::{EXTERNAL}:saml-provider/ExtIdP"})
    gaps = _find_perimeter_gaps(policy, OWN)
    assert len(gaps) == 1
    assert gaps[0].kind == "cross_org"


def test_gaps_federated_own_arn_ok() -> None:
    policy = _allow({"Federated": f"arn:aws:iam::{OWN}:saml-provider/CorpSSO"})
    assert _find_perimeter_gaps(policy, OWN) == []


def test_gaps_federated_url_out_of_scope() -> None:
    """Federated URL IdPs (e.g. Google) are not account-parseable - out of scope."""
    assert _find_perimeter_gaps(_allow({"Federated": "accounts.google.com"}), OWN) == []


def test_gaps_canonical_user_out_of_scope() -> None:
    cid = "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"
    assert _find_perimeter_gaps(_allow({"CanonicalUser": cid}), OWN) == []


# ---------------------------------------------------------------------------
# Integration: aws-dp-001 S3 bucket policy
# ---------------------------------------------------------------------------


def _put_bucket(provider: AWSProvider, name: str, policy: dict | None = None) -> None:
    s3 = provider.session.client("s3")
    s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": "eu-central-1"})
    if policy is not None:
        s3.put_bucket_policy(Bucket=name, Policy=json.dumps(policy))


def test_dp_001_empty_account(mock_aws_provider: AWSProvider) -> None:
    result = check_s3_bucket_policy_perimeter(mock_aws_provider)
    assert result.check_id == "aws-dp-001"
    assert result.resources_scanned == 0
    assert result.findings == []
    assert result.error is None


def test_dp_001_no_policy_no_finding(mock_aws_provider: AWSProvider) -> None:
    _put_bucket(mock_aws_provider, "plain-bucket")
    result = check_s3_bucket_policy_perimeter(mock_aws_provider)
    assert result.resources_scanned == 1
    assert result.findings == []


def test_dp_001_confused_deputy_finding(mock_aws_provider: AWSProvider) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCloudTrail",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::cd-bucket/*",
            }
        ],
    }
    _put_bucket(mock_aws_provider, "cd-bucket", policy)
    result = check_s3_bucket_policy_perimeter(mock_aws_provider)
    assert len(result.findings) == 1
    assert result.findings[0].severity.value == "medium"
    assert "confused-deputy" in result.findings[0].title


def test_dp_001_cross_org_wildcard_finding(mock_aws_provider: AWSProvider) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::open-bucket/*",
            }
        ],
    }
    _put_bucket(mock_aws_provider, "open-bucket", policy)
    result = check_s3_bucket_policy_perimeter(mock_aws_provider)
    assert len(result.findings) == 1
    assert result.findings[0].severity.value == "high"
    assert "organization boundary" in result.findings[0].title


def test_dp_001_org_restricted_no_finding(mock_aws_provider: AWSProvider) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::org-bucket/*",
                "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
            }
        ],
    }
    _put_bucket(mock_aws_provider, "org-bucket", policy)
    result = check_s3_bucket_policy_perimeter(mock_aws_provider)
    assert result.findings == []


def test_dp_001_same_account_no_finding(mock_aws_provider: AWSProvider) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{OWN}:root"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::self-bucket/*",
            }
        ],
    }
    _put_bucket(mock_aws_provider, "self-bucket", policy)
    result = check_s3_bucket_policy_perimeter(mock_aws_provider)
    assert result.findings == []


# ---------------------------------------------------------------------------
# Integration: aws-dp-002 SNS / aws-dp-003 SQS
# ---------------------------------------------------------------------------


def test_dp_002_empty_account(mock_aws_provider: AWSProvider) -> None:
    result = check_sns_topic_policy_perimeter(mock_aws_provider)
    assert result.check_id == "aws-dp-002"
    assert result.findings == []
    assert result.error is None


def test_dp_002_cross_org_wildcard_finding(mock_aws_provider: AWSProvider) -> None:
    sns = mock_aws_provider.session.client("sns", region_name="eu-central-1")
    arn = sns.create_topic(Name="open-topic")["TopicArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sns:Subscribe",
                "Resource": arn,
            }
        ],
    }
    sns.set_topic_attributes(TopicArn=arn, AttributeName="Policy", AttributeValue=json.dumps(policy))
    result = check_sns_topic_policy_perimeter(mock_aws_provider)
    findings = [f for f in result.findings if f.resource_id == arn]
    assert any(f.severity.value == "high" for f in findings)


def test_dp_003_empty_account(mock_aws_provider: AWSProvider) -> None:
    result = check_sqs_queue_policy_perimeter(mock_aws_provider)
    assert result.check_id == "aws-dp-003"
    assert result.findings == []
    assert result.error is None


def test_dp_003_cross_org_external_finding(mock_aws_provider: AWSProvider) -> None:
    sqs = mock_aws_provider.session.client("sqs", region_name="eu-central-1")
    url = sqs.create_queue(QueueName="shared-queue")["QueueUrl"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{EXTERNAL}:root"},
                "Action": "sqs:SendMessage",
                "Resource": "*",
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    result = check_sqs_queue_policy_perimeter(mock_aws_provider)
    findings = [f for f in result.findings if f.resource_id == url]
    assert len(findings) == 1
    assert findings[0].severity.value == "low"


# ---------------------------------------------------------------------------
# Integration: aws-dp-004 Secrets Manager (cross-org escalated)
# ---------------------------------------------------------------------------


def test_dp_004_empty_account(mock_aws_provider: AWSProvider) -> None:
    result = check_secrets_resource_policy_perimeter(mock_aws_provider)
    assert result.check_id == "aws-dp-004"
    assert result.findings == []
    assert result.error is None


def test_dp_004_cross_org_wildcard_critical(mock_aws_provider: AWSProvider) -> None:
    sm = mock_aws_provider.session.client("secretsmanager", region_name="eu-central-1")
    sm.create_secret(Name="prod-db", SecretString="hunter2")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }
        ],
    }
    sm.put_resource_policy(SecretId="prod-db", ResourcePolicy=json.dumps(policy))
    result = check_secrets_resource_policy_perimeter(mock_aws_provider)
    assert len(result.findings) == 1
    assert result.findings[0].severity.value == "critical"


def test_dp_004_confused_deputy_stays_medium(mock_aws_provider: AWSProvider) -> None:
    """Secrets escalation is isolated to cross-org; a confused-deputy gap stays MEDIUM."""
    sm = mock_aws_provider.session.client("secretsmanager", region_name="eu-central-1")
    sm.create_secret(Name="svc-secret", SecretString="x")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }
        ],
    }
    sm.put_resource_policy(SecretId="svc-secret", ResourcePolicy=json.dumps(policy))
    result = check_secrets_resource_policy_perimeter(mock_aws_provider)
    assert len(result.findings) == 1
    assert result.findings[0].severity.value == "medium"


# ---------------------------------------------------------------------------
# Integration: aws-dp-005 Lambda resource policy
# ---------------------------------------------------------------------------


def _zip_code() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", "def handler(event, context):\n    return {}\n")
    return buf.getvalue()


def _make_function(provider: AWSProvider, name: str) -> None:
    iam = provider.session.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=f"{name}-role",
        AssumeRolePolicyDocument=json.dumps(trust),
    )["Role"]["Arn"]
    lam = provider.session.client("lambda", region_name="eu-central-1")
    lam.create_function(
        FunctionName=name,
        Runtime="python3.12",
        Role=role,
        Handler="lambda_function.handler",
        Code={"ZipFile": _zip_code()},
    )


def test_dp_005_empty_account(mock_aws_provider: AWSProvider) -> None:
    result = check_lambda_resource_policy_perimeter(mock_aws_provider)
    assert result.check_id == "aws-dp-005"
    assert result.findings == []
    assert result.error is None


def test_dp_005_no_policy_no_finding(mock_aws_provider: AWSProvider) -> None:
    _make_function(mock_aws_provider, "plain-fn")
    result = check_lambda_resource_policy_perimeter(mock_aws_provider)
    assert result.resources_scanned == 1
    assert result.findings == []


def test_dp_005_confused_deputy_finding(mock_aws_provider: AWSProvider) -> None:
    _make_function(mock_aws_provider, "cd-fn")
    lam = mock_aws_provider.session.client("lambda", region_name="eu-central-1")
    # Grant S3 invoke WITHOUT SourceAccount -> confused deputy
    lam.add_permission(
        FunctionName="cd-fn",
        StatementId="AllowS3",
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
    )
    result = check_lambda_resource_policy_perimeter(mock_aws_provider)
    assert len(result.findings) == 1
    assert result.findings[0].severity.value == "medium"
    assert "confused-deputy" in result.findings[0].title


def test_dp_005_source_account_no_finding(mock_aws_provider: AWSProvider) -> None:
    _make_function(mock_aws_provider, "safe-fn")
    lam = mock_aws_provider.session.client("lambda", region_name="eu-central-1")
    lam.add_permission(
        FunctionName="safe-fn",
        StatementId="AllowS3Scoped",
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
        SourceAccount=OWN,
    )
    result = check_lambda_resource_policy_perimeter(mock_aws_provider)
    assert result.findings == []
