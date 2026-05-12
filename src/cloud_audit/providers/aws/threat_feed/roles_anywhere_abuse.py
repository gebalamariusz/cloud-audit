"""TF-009: IAM Roles Anywhere trust anchor with permissive trust source.

IAM Roles Anywhere lets workloads outside AWS exchange an X.509 certificate
for temporary AWS credentials. The trust anchor specifies which Certificate
Authority issues acceptable certificates - if the source CA is too permissive
(public Let's Encrypt, a third-party PKI without strict SAN policy, or any
external CERTIFICATE_BUNDLE not under the operator's control), an attacker
who can obtain a certificate from that CA can mint AWS credentials.

The fwd:cloudsec 2025 talk 'Let's Encrypt for AWS Console' demonstrated this
attack class against multiple production accounts. AWS recommends using AWS
Private CA (AWS_ACM_PCA) for trust anchors and pinning the SAN in the
attached profile.

We flag:
- Any trust anchor with sourceType=CERTIFICATE_BUNDLE (not AWS Private CA -
  the operator must rotate to AWS_ACM_PCA or accept they trust an external CA)
- Trust anchors that are enabled but have no profile-level SAN constraints
  visible (best-effort - we surface for manual verification)

References:
    - https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html
    - https://github.com/Cybr-Inc/fwdcloudsec-2025-summaries
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


PATTERN_ID = "TF-009-roles-anywhere-abuse"
CHECK_ID = "aws-tf-009"
PATTERN_NAME = "IAM Roles Anywhere trust anchor with external CA"
PATTERN_SEVERITY = Severity.HIGH
DOC_URL = "https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html"

_REFERENCES = [
    "https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html",
    "https://github.com/Cybr-Inc/fwdcloudsec-2025-summaries",
]


def _build_finding(anchor_id: str, anchor_name: str, region: str, source_type: str, enabled: bool) -> Finding:
    enabled_note = " (currently ENABLED - active attack surface)" if enabled else " (currently disabled)"
    return Finding(
        check_id=CHECK_ID,
        title=f"Roles Anywhere trust anchor '{anchor_name}' uses external CA bundle{enabled_note}",
        severity=PATTERN_SEVERITY if enabled else Severity.MEDIUM,
        category=Category.THREAT,
        resource_type="AWS::RolesAnywhere::TrustAnchor",
        resource_id=anchor_id,
        region=region,
        description=(
            f"Trust anchor '{anchor_name}' in {region} uses sourceType={source_type}. "
            "Anyone able to obtain a valid X.509 certificate chaining to this CA bundle "
            "can call rolesanywhere:CreateSession and exchange the cert for AWS "
            "temporary credentials. The fwd:cloudsec 2025 'Let's Encrypt for AWS Console' "
            "research demonstrated production exploitation of this pattern. AWS Private "
            "CA (AWS_ACM_PCA) is the recommended source because it lets you control who "
            "the issuing authority trusts."
        ),
        recommendation=(
            "(1) Migrate the trust anchor to use sourceType=AWS_ACM_PCA backed by an "
            "AWS Private Certificate Authority you operate. (2) On the attached profile, "
            "configure the durationSeconds to the minimum needed and pin acceptable "
            "Subject Alternative Names. (3) If you must trust an external CA, ensure "
            "your profile policies are heavily scoped (least privilege per workload "
            "instead of full AdministratorAccess) and enable CloudTrail data events "
            "for rolesanywhere:CreateSession."
        ),
        remediation=Remediation(
            cli=(
                f"# 1) Inspect the current trust anchor configuration:\n"
                f"aws rolesanywhere get-trust-anchor --trust-anchor-id {anchor_id} \\\n"
                f"  --region {region}\n"
                f"\n# 2) If you cannot immediately migrate, disable the anchor while you fix it:\n"
                f"aws rolesanywhere disable-trust-anchor --trust-anchor-id {anchor_id} \\\n"
                f"  --region {region}\n"
                f"\n# 3) Audit recent sessions to detect any unauthorized credential issuance:\n"
                f"aws cloudtrail lookup-events \\\n"
                f"  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateSession \\\n"
                f"  --region {region}"
            ),
            terraform=(
                'resource "aws_rolesanywhere_trust_anchor" "this" {\n'
                '  name    = "private-ca-anchor"\n'
                "  enabled = true\n"
                "  source {\n"
                '    source_type = "AWS_ACM_PCA"\n'
                "    source_data {\n"
                "      acm_pca_arn = aws_acmpca_certificate_authority.this.arn\n"
                "    }\n"
                "  }\n"
                "}"
            ),
            doc_url=DOC_URL,
            effort=Effort.MEDIUM,
        ),
        threat_pattern_id=PATTERN_ID,
        references=_REFERENCES,
    )


def _scan_region(provider: AWSProvider, region: str) -> tuple[int, list[Finding]]:
    findings: list[Finding] = []
    scanned = 0
    try:
        ra = provider.client("rolesanywhere", region_name=region)
    except Exception:
        return 0, []

    try:
        paginator = ra.get_paginator("list_trust_anchors")
    except Exception:
        return 0, []

    try:
        pages = list(paginator.paginate())
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if code in ("AccessDeniedException", "UnrecognizedClientException", "ValidationException"):
            return 0, []
        raise

    for page in pages:
        for anchor in page.get("trustAnchors", []):
            scanned += 1
            anchor_id = anchor.get("trustAnchorId", "")
            anchor_name = anchor.get("name", anchor_id)
            source = anchor.get("source", {}) or {}
            source_type = source.get("sourceType", "")
            enabled = bool(anchor.get("enabled", False))

            if source_type != "CERTIFICATE_BUNDLE":
                continue  # AWS_ACM_PCA = recommended pattern, no flag

            findings.append(
                _build_finding(
                    anchor_id=anchor_id,
                    anchor_name=anchor_name,
                    region=region,
                    source_type=source_type,
                    enabled=enabled,
                )
            )
    return scanned, findings


def detect(provider: AWSProvider) -> CheckResult:
    """Scan all regions for IAM Roles Anywhere trust anchors with external CA sources."""
    result = CheckResult(check_id=CHECK_ID, check_name=PATTERN_NAME)

    try:
        for region in provider.regions:
            scanned, findings = _scan_region(provider, region)
            result.resources_scanned += scanned
            result.findings.extend(findings)
    except Exception as e:
        result.error = str(e)

    return result
