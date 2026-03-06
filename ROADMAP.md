# Roadmap

> Current version: **v0.6.0** (March 2026)

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
- CloudTrail checks (enabled, log validation, bucket exposure)
- GuardDuty checks (enabled, unresolved findings)
- AWS Config checks (enabled, recorder active)
- KMS checks (key rotation, permissive policies)
- CloudWatch alarm checks (root account usage)
- Total: 27 checks

### v0.4.0 -- Compute & Secrets
- Lambda checks (public URLs, deprecated runtimes, secrets in env vars)
- ECS checks (privileged mode, logging, ECS exec)
- SSM checks (unmanaged instances, insecure parameters)
- Secrets Manager checks (rotation, unused secrets)
- Additional IAM, S3, EC2 checks
- Total: 42 checks

### v0.5.0 / v0.5.1 -- CI/CD Integration
- SARIF v2.1.0 output for GitHub Code Scanning (`--format sarif`)
- Markdown output for PR comments (`--format markdown`)
- Configuration file (`.cloud-audit.yml`) with suppressions
- Environment variables for CI/CD pipelines
- Exit codes: 0 (clean), 1 (findings), 2 (errors)
- `list-checks` command (no AWS credentials required)
- Cross-account scanning via `--role-arn` (STS AssumeRole)
- OIDC authentication support for GitHub Actions
- 3 additional checks (NACL, termination protection, RDS auto-upgrade)
- Total: 45 checks, 170+ tests

### v0.6.0 -- Security Hardening
- Jinja2 minimum bumped to >=3.1.6 (CVE-2025-27516)
- Shell injection protection in `--export-fixes` output and remediation commands
- Dockerfile hardened (non-root user, pinned base image digest)
- SHA-pinned GitHub Actions in CI/CD workflows
- `make_check()` helper for consistent check registration
- ECS/GuardDuty pagination fixes, SG deduplication, NACL TCP/UDP detection
- S3 bucket cache with proper reset between scans
- SARIF, HTML, and Markdown report fixes
- 173 tests passing

## In Progress

### v1.0.0 -- Production Ready
- **Enhanced HTML reports** -- executive summary, priority grouping, CIS compliance overview
- **Diff/Compare** -- `cloud-audit diff <old.json> <new.json>` to track progress over time
- **README overhaul** -- terminal demo GIF, performance benchmarks, comparison table
- **Community** -- issue templates, contributing guide, GitHub Discussions
- **Docker image** on GHCR (`ghcr.io/gebalamariusz/cloud-audit`)
- Target: 50+ curated checks

## Future

### Post v1.0 -- Planned
- Expand to ~60 checks based on community feedback (EKS, SNS, additional KMS/VPC)
- `cloud-audit triage` command -- generate suppression YAML from scan results
- Wildcard support in suppressions (`resource_id: "sg-*"`)
- `--show-suppressed` flag for audit transparency
- Performance benchmarks on accounts of various sizes

### Considering
- Azure provider (~25 checks)
- Custom check plugins (user-defined checks via Python or YAML)
- Slack/Teams notifications
- Terraform Cloud integration

## Design Principles

1. **High-signal only** -- if an attacker can't exploit it, the check doesn't exist
2. **Every finding = a ready fix** -- AWS CLI + Terraform HCL + documentation link
3. **Reports for engineers and managers** -- beautiful, useful, actionable
4. **Zero config to start** -- `pip install cloud-audit && cloud-audit scan` gives value immediately
5. **Fast** -- seconds, not hours
6. **CIS mapping included** -- key CIS AWS Foundations Benchmark controls mapped to checks
