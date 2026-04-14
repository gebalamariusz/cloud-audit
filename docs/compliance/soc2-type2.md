# SOC 2 Type II - Trust Services Criteria

cloud-audit maps 88 of 94 checks to 43 SOC 2 Trust Services Criteria (AICPA 2017, revised 2022). 24 criteria are automated, 19 require manual review (organizational, procedural, and governance controls).

!!! note "Readiness assessment, not certification"
    SOC 2 compliance requires a formal audit by an AICPA-licensed CPA firm. This tool automates assessment of technical infrastructure controls and generates evidence to support your audit preparation.

## Coverage Summary

Automated includes both fully automated and partially automated criteria - partial criteria have some aspects verified by cloud-audit checks and some requiring manual review.

| Category | Criteria | Automated* | Manual |
|----------|----------|-----------|--------|
| CC1 - Control Environment | 5 | 1 | 4 |
| CC2 - Communication and Information | 3 | 1 | 2 |
| CC3 - Risk Assessment | 4 | 3 | 1 |
| CC4 - Monitoring Activities | 2 | 2 | 0 |
| CC5 - Control Activities | 3 | 2 | 1 |
| CC6 - Logical and Physical Access | 8 | 6 | 2 |
| CC7 - System Operations | 5 | 3 | 2 |
| CC8 - Change Management | 1 | 1 | 0 |
| CC9 - Risk Mitigation | 2 | 1 | 1 |
| A1 - Availability | 3 | 1 | 2 |
| C1 - Confidentiality | 2 | 2 | 0 |
| PI1 - Processing Integrity | 5 | 1 | 4 |
| **Total** | **43** | **24 (56%)** | **19 (44%)** |

Privacy criteria (P1) are not included - they cover legal/procedural requirements (consent, data subject rights, breach notification) that are outside the scope of infrastructure scanning.

## Usage

```bash
# Terminal output with readiness score
cloud-audit scan --compliance soc2_type2

# HTML report for auditors
cloud-audit scan --compliance soc2_type2 --format html --output soc2-report.html

# Markdown for documentation
cloud-audit scan --compliance soc2_type2 --format markdown --output soc2-report.md

# List all frameworks
cloud-audit list-frameworks

# Preview controls without scanning
cloud-audit show-framework soc2_type2
```

## CC1 - Control Environment

| ID | Title | Type | cloud-audit Checks |
|----|-------|------|-------------------|
| CC1.1 | Commitment to integrity and ethical values | Manual | - |
| CC1.2 | Board oversight of internal control | Manual | - |
| CC1.3 | Structures, authorities, and responsibilities | Partial | `aws-iam-005`, `aws-iam-010` |
| CC1.4 | Commitment to competent individuals | Manual | - |
| CC1.5 | Accountability for internal control | Manual | - |

## CC2 - Communication and Information

| ID | Title | Type | cloud-audit Checks |
|----|-------|------|-------------------|
| CC2.1 | Quality information for internal control | Partial | `aws-ct-001`, `aws-ct-002`, `aws-cfg-001`, `aws-cfg-002`, `aws-account-001` |
| CC2.2 | Internal communication | Manual | - |
| CC2.3 | External communication | Manual | - |

## CC3 - Risk Assessment

| ID | Title | Type | cloud-audit Checks |
|----|-------|------|-------------------|
| CC3.1 | Specifies objectives | Manual | - |
| CC3.2 | Identifies and analyzes risks | Partial | `aws-gd-001`, `aws-gd-002`, `aws-sh-001`, `aws-iam-012`, `aws-iam-011` |
| CC3.3 | Considers fraud potential | Partial | `aws-iam-005`, `aws-iam-008`, `aws-iam-007` |
| CC3.4 | Identifies significant changes | Partial | `aws-cfg-001`, `aws-cfg-002`, `aws-cw-005`, `aws-cw-009` |

## CC4 - Monitoring Activities

| ID | Title | Type | cloud-audit Checks |
|----|-------|------|-------------------|
| CC4.1 | Ongoing evaluations | Partial | `aws-cfg-001`, `aws-cfg-002`, `aws-sh-001` |
| CC4.2 | Communicates deficiencies | Partial | `aws-gd-001`, `aws-gd-002`, `aws-cw-001` |

## CC5 - Control Activities

| ID | Title | Type | cloud-audit Checks |
|----|-------|------|-------------------|
| CC5.1 | Selects control activities | Manual | - |
| CC5.2 | Technology controls | Auto | `aws-iam-001`, `aws-iam-002`, `aws-iam-006`, `aws-kms-001`, `aws-kms-002`, `aws-s3-001`, `aws-s3-002`, `aws-ec2-002`, `aws-ec2-006`, `aws-rds-002`, `aws-efs-001`, `aws-vpc-002`, `aws-vpc-005` |
| CC5.3 | Deploys through policies | Partial | `aws-iam-005`, `aws-iam-010` |

## CC6 - Logical and Physical Access Controls

| ID | Title | Type | cloud-audit Checks |
|----|-------|------|-------------------|
| CC6.1 | Logical access security | Auto | `aws-iam-001`, `aws-iam-002`, `aws-iam-006`, `aws-iam-015`, `aws-kms-001`, `aws-kms-002`, `aws-s3-001`, `aws-s3-002`, `aws-ec2-002`, `aws-ec2-006`, `aws-rds-002`, `aws-efs-001` |
| CC6.2 | User registration and deregistration | Auto | `aws-iam-003`, `aws-iam-004`, `aws-iam-009`, `aws-iam-013` |
| CC6.3 | Least privilege and segregation of duties | Auto | `aws-iam-005`, `aws-iam-007`, `aws-iam-008`, `aws-iam-010`, `aws-iam-014`, `aws-iam-016`, `aws-ecs-003` |
| CC6.4 | Physical access | Manual | AWS shared responsibility model |
| CC6.5 | Asset disposal | Manual | AWS shared responsibility model |
| CC6.6 | Boundary protection | Auto | `aws-vpc-002`, `aws-vpc-004`, `aws-vpc-005`, `aws-vpc-001`, `aws-vpc-003`, `aws-rds-001`, `aws-ec2-001`, `aws-ec2-004`, `aws-lambda-001`, `aws-ct-003`, `aws-s3-001` |
| CC6.7 | Data protection in transit and at rest | Auto | `aws-s3-006`, `aws-s3-007`, `aws-s3-002`, `aws-rds-002`, `aws-ec2-002`, `aws-ec2-006`, `aws-efs-001`, `aws-kms-001`, `aws-ct-005`, `aws-ssm-002`, `aws-lambda-003`, `aws-sm-001` |
| CC6.8 | Unauthorized/malicious software | Partial | `aws-gd-001`, `aws-gd-002`, `aws-lambda-002`, `aws-ecs-001` |

## CC7 - System Operations

| ID | Title | Type | cloud-audit Checks |
|----|-------|------|-------------------|
| CC7.1 | Vulnerability detection | Auto | `aws-sh-001`, `aws-cfg-001`, `aws-cfg-002`, `aws-iam-012`, `aws-ssm-001` |
| CC7.2 | Anomaly monitoring | Auto | `aws-gd-001`, `aws-gd-002`, `aws-vpc-003`, `aws-cw-001` - `aws-cw-015`, `aws-ecs-002` |
| CC7.3 | Security event evaluation | Partial | `aws-ct-001`, `aws-ct-002`, `aws-ct-004`, `aws-ct-005`, `aws-ct-006`, `aws-ct-007`, `aws-gd-002`, `aws-s3-005` |
| CC7.4 | Incident response | Manual | - |
| CC7.5 | Recovery from incidents | Manual | - |

## CC8 - Change Management

| ID | Title | Type | cloud-audit Checks |
|----|-------|------|-------------------|
| CC8.1 | Change authorization and detection | Partial | `aws-cfg-001`, `aws-cfg-002`, `aws-cw-005`, `aws-cw-009` - `aws-cw-014` |

## CC9 - Risk Mitigation

| ID | Title | Type | cloud-audit Checks |
|----|-------|------|-------------------|
| CC9.1 | Business disruption risks | Partial | `aws-rds-003`, `aws-s3-003`, `aws-rds-004`, `aws-ec2-005` |
| CC9.2 | Vendor and partner risks | Manual | - |

## A1 - Availability

| ID | Title | Type | cloud-audit Checks |
|----|-------|------|-------------------|
| A1.1 | Capacity management | Manual | - |
| A1.2 | Backup and recovery | Auto | `aws-rds-003`, `aws-s3-003`, `aws-s3-004`, `aws-ec2-005` |
| A1.3 | Recovery testing | Manual | - |

## C1 - Confidentiality

| ID | Title | Type | cloud-audit Checks |
|----|-------|------|-------------------|
| C1.1 | Identifies confidential information | Auto | `aws-s3-001`, `aws-s3-002`, `aws-rds-002`, `aws-ec2-002`, `aws-ec2-006`, `aws-efs-001`, `aws-kms-001`, `aws-kms-002`, `aws-sm-001` |
| C1.2 | Disposes confidential information | Partial | `aws-s3-004`, `aws-sm-002` |

## PI1 - Processing Integrity

| ID | Title | Type | cloud-audit Checks |
|----|-------|------|-------------------|
| PI1.1 | Quality information for processing | Manual | - |
| PI1.2 | Input controls | Manual | - |
| PI1.3 | Processing controls | Manual | - |
| PI1.4 | Output delivery | Manual | - |
| PI1.5 | Data storage integrity | Partial | `aws-s3-003`, `aws-rds-002`, `aws-ec2-002`, `aws-kms-001` |

## Why 19 Controls Are Manual

SOC 2 covers more than technology. Nearly half the criteria address organizational governance, human resources, incident response procedures, vendor management, and board oversight. These cannot be verified by scanning AWS infrastructure - they require document review and interviews by an auditor.

Examples:

- **CC1.4** (competent individuals) - training records, background checks, onboarding
- **CC7.4** (incident response) - runbooks, tabletop exercises, escalation procedures
- **CC9.2** (vendor risks) - third-party assessments, DPAs, AWS SOC 2 report from Artifact

cloud-audit marks these as NOT_ASSESSED with actionable manual steps for each.

## Attack Chain Integration

All 31 attack chain rules are mapped to SOC 2 controls. When a chain is detected, the compliance report shows which controls it violates:

| Chain | SOC 2 Controls Violated |
|-------|------------------------|
| AC-01 Internet-Exposed Admin Instance | CC6.3, CC6.6 |
| AC-02 SSRF to Credential Theft | CC6.6, CC6.7 |
| AC-12 Admin Without MFA | CC6.1, CC6.3 |
| AC-17 Exposed Database Without Audit Trail | CC6.6, CC6.7, CC7.3 |
| AC-26 Unmonitored Admin Escalation | CC6.1, CC6.3, CC7.2 |

This connects individual findings to their compliance impact - showing auditors not just what failed, but how failures combine into exploitable paths.

## Source

[AICPA Trust Services Criteria (2017, revised 2022)](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022)
