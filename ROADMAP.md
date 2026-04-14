# Roadmap

> Current version: **v2.0.0** (April 2026)

## Completed

### v0.1.0 -- Initial Release
- 17 curated AWS security checks (IAM, S3, EC2, VPC, RDS, EIP)
- Rich CLI with progress bar and colored output
- JSON and HTML report output
- Health score (0-100) based on finding severity
- Docker support

### v0.2.0 -- Remediation & CIS Mapping
- Every finding includes copy-paste remediation (AWS CLI + Terraform HCL + docs link)
- CIS AWS Foundations Benchmark references on applicable checks
- `--export-fixes` generates a commented shell script for safe bulk remediation
- Effort estimation per finding (LOW / MEDIUM / HIGH)
- moto-based test suite with 80%+ coverage

### v0.3.0 -- Visibility & Detection
- CloudTrail, GuardDuty, AWS Config, KMS, CloudWatch checks
- Total: 27 checks

### v0.4.0 -- Compute & Secrets
- Lambda, ECS, SSM, Secrets Manager checks
- Total: 42 checks

### v0.5.0 -- Integration
- SARIF output, config file, suppressions, env vars, OIDC, markdown output
- Total: 45 checks

### v0.6.0 -- CI/CD Security
- SHA-pinned GitHub Actions, CI gate for release, non-root Docker, GHCR
- Total: 45 checks

### v0.7.0 -- Quality
- SARIF spec compliance, S3 encryption pivot, accessibility, ruff rules
- Total: 45 checks

### v0.8.0 -- Scan Diff
- `cloud-audit diff` command for tracking drift
- CI/CD examples (daily-scan-with-diff, post-deploy-scan)

### v1.0.0 -- Production Ready (March 2026)
- Breach cost estimation (IBM, Verizon data), MCP Server
- 278 tests

### v1.1.0 -- CIS Compliance Engine
- CIS AWS v3.0: 62 controls, 55 automated
- MkDocs documentation site, 303 tests

### v1.2.0 -- SOC 2 Type II Compliance
- 43 Trust Services Criteria, 335 tests

### v1.3.0 -- Multi-Framework Compliance
- BSI C5:2020, ISO 27001:2022, HIPAA Security Rule, NIS2 Directive
- 6 compliance frameworks total, 412 tests

### v2.0.0 -- Decision Intelligence (April 2026)
- **IAM Privilege Escalation Detection** -- 25 methods across 6 categories (self-mutation, credential access, PassRole+service, Lambda code mod, trust policy abuse, permission boundary bypass). First maintained open-source replacement for PMapper.
- **What-If Remediation Simulator** -- `cloud-audit simulate --fix aws-vpc-002` shows impact on score, chains, risk before changing anything in AWS
- **Root Cause Grouping** -- "fix 4 things, break 22 chains" prioritization. Groups findings by root cause and ranks by chain-breaking impact.
- **Security Posture Trend** -- `cloud-audit trend` tracks health score, chains, and risk over time. History auto-saved after each scan.
- **AI-SPM (Bedrock + SageMaker)** -- 5 checks, 3 attack chains (model theft, LLMjacking, data poisoning). First open-source AI-SPM scanner.
- **Quick Wins** -- CLI section showing LOW-effort fixes that break CRITICAL chains
- 6 new attack chain rules (AC-34 through AC-39)
- Compliance Beta labels (CIS + SOC2 stable, 4 others beta)
- Remediation placeholders replaced with real values
- Terraform snippets completed with missing dependencies
- Cached get_account_id() (1 STS call instead of 10+)
- 94 checks, 23 services, 31 chains, 496 tests

## What's Next

### v3.0.0 -- Security Graph & Exposure Analysis (target: June 2026)

**1. Security Graph + Effective Exposure Score**
In-memory graph (networkx) modeling all resource relationships: VPC routing, subnets, security groups, EC2 instances, IAM roles, policies, S3 buckets, RDS instances. BFS/DFS from internet nodes to high-value targets. Per-resource "effective exposure score" combining network reachability + identity privilege + data sensitivity. Output: "3 paths from internet to production database."

**2. Blast Radius Analysis**
`cloud-audit blast-radius --resource i-0abc123` shows the full impact zone if a specific resource is compromised: IAM role access, network reach, lateral movement paths, data at risk, breach cost estimate. The inverse of attack path analysis.

**3. NHI (Non-Human Identity) Audit + Data Perimeter Scanner**
Full inventory of all non-human identities: IAM users with access keys, IAM roles, OIDC providers, Lambda/ECS/CodeBuild execution roles. Aging, rotation, privilege scoring, trust chain mapping. Data perimeter: RCPs, VPC endpoint policies, aws:SourceOrgID conditions, snapshot sharing.

## Considering

- Multi-account scanning (AWS Organizations)
- SCP + permission boundary evaluation in IAM escalation
- Terraform drift detection (live state vs IaC)
- Cross-account attack path detection
- Terraform remediation.tf generation (complete, apply-ready)
- Python plugin API for custom checks
- Evidence package generation for auditors (ZIP with API dumps per control)
