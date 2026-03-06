# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-03-06

### Security

- Bump Jinja2 minimum to >=3.1.6 (fixes CVE-2025-27516 sandbox breakout)
- Sanitize shell metacharacters in `--export-fixes` bash script output
- Use `shlex.quote()` for user-controlled EC2 Name tags in remediation CLI commands
- Set restrictive file permissions (700) on generated remediation scripts
- SHA-pin all GitHub Actions in CI and release workflows
- Dockerfile: non-root user, pinned base image digest, `--no-input` flag

### Added

- `make_check()` helper for consistent check registration with metadata
- `.cloud-audit.example.yml` config template
- Pre-filtering of excluded checks before API calls (no wasted requests)
- S3 bucket cache with proper reset between scans
- NACL check now detects open TCP/UDP rules (not just protocol `-1`)

### Changed

- ECS `list_clusters` and GuardDuty `list_detectors` now paginate correctly
- ECS `describe_services` batched to 10 per call (API limit)
- Security group findings deduplicated per rule (one finding lists all exposed ports)
- CloudWatch root usage alarm check tries CloudTrail-named log groups first
- Default VPC check reports "at least N" ENIs when count hits API limit
- `list-checks --categories` filtering fixed for Python 3.10 compatibility
- Moved `datetime`/`json` imports to module level in IAM and GuardDuty checks
- SARIF output: fixed `uriBaseId`, added `fullDescription` and `originalUriBaseIds`
- HTML report: light mode support, print CSS, ARIA labels, copyCode fix
- Markdown report: pipe escaping in table cells
- ASCII severity icons (fixes UnicodeEncodeError on Windows cp1250)
- CloudTrail: `includeShadowTrails=True` with ARN deduplication
- S3: error code check instead of string matching for encryption detection
- S3: `_tf_name()` handles bucket names starting with digits
- S3: extracted `_lifecycle_remediation()` helper (DRY)

### Fixed

- S3 AccessDenied no longer produces false positive findings
- Deprecated runtimes list updated (python3.9, nodejs18.x, dotnet6)
- `PackageNotFoundError` fallback in `__init__.py`
- `list-checks` warns on module load failure instead of silently continuing

### Documentation

- Backfilled CHANGELOG for v0.3.0 through v0.5.2
- Updated SECURITY.md supported versions to 0.5.x
- Documented suppression `expires` semantics (inclusive last day)
- Fixed CLAUDE.md "immutable by default" claim
- Added docstring to `compute_summary()`
- Clarified `.gitignore` `*.md` pattern

## [0.5.2] - 2026-03-06

### Changed

- README overhaul with updated examples and OIDC recommendation for CI/CD
- Demo command updated to reflect current check count

### Fixed

- Various check accuracy improvements

## [0.5.1] - 2026-03-05

### Fixed

- Remove invalid SARIF `fixes` field; move remediation to `properties`
- Ruff format fixes for v0.5.0 files

## [0.5.0] - 2026-03-05

### Added

- `.cloud-audit.yml` config file with suppressions (allowlist pattern)
- SARIF v2.1.0 output for GitHub Code Scanning integration
- Markdown report generator for PR comments
- `--format` flag (json, sarif, markdown, html)
- `--min-severity`, `--quiet`, `--role-arn`, `--config` CLI flags
- `list-checks` command
- 4 environment variables: `CLOUD_AUDIT_MIN_SEVERITY`, `CLOUD_AUDIT_EXCLUDE_CHECKS`, `CLOUD_AUDIT_ROLE_ARN`, `CLOUD_AUDIT_REGIONS`
- Exit codes: 0=clean, 1=findings, 2=errors
- Cross-account scanning via STS AssumeRole (`--role-arn`)
- 3 new checks: EC2 termination protection, RDS auto minor upgrade, unrestricted NACL (45 total)
- 168 tests passing

## [0.4.1] - 2026-03-04

### Fixed

- Use absolute image URLs in README for PyPI rendering

## [0.4.0] - 2026-03-04

### Added

- Lambda checks: public function URL, deprecated runtime, env var secrets
- ECS checks: privileged containers, missing logging, ECS Exec enabled
- SSM checks: unmanaged EC2, insecure parameters
- Secrets Manager checks: rotation disabled, unused secrets
- IAM: overly permissive policy (Action:*/Resource:*), weak password policy (CIS 1.8)
- S3: lifecycle policy (cost), access logging
- EC2: IMDSv1 enabled (SSRF risk)
- Version sourced from `importlib.metadata`
- 96 moto tests, 15 CIS controls mapped (42 checks total)

## [0.3.0] - 2026-03-04

### Added

- CloudTrail checks (3): multi-region trail, log validation, S3 logging
- GuardDuty checks (2): detector enabled, high-severity findings
- AWS Config checks (2): recorder enabled, delivery channel
- KMS checks (2): key rotation, unused keys
- CloudWatch check: root account usage alarm
- CIS Benchmark coverage expanded to 14 controls
- 66 moto tests

## [0.2.0] - 2026-03-03

### Added

- Structured remediation for all 17 checks - every finding includes:
  - Copy-paste AWS CLI command with real resource IDs
  - Terraform HCL snippet
  - AWS documentation link
  - Estimated effort level (LOW / MEDIUM / HIGH)
- CIS AWS Foundations Benchmark mapping (10 controls covered)
- `--remediation` / `-R` CLI flag - print fix details after scan summary
- `--export-fixes <path>` CLI flag - export all CLI commands as a dry-run bash script
- HTML report enhancements:
  - Expandable "How to fix" panel per finding with CLI and Terraform snippets
  - Copy-to-clipboard button for commands
  - CIS Benchmark coverage section
  - Compliance reference badges on findings
- Comprehensive moto-based test suite (45 tests covering all checks)

## [0.1.0] - 2026-03-03

### Added

- Initial release
- CLI interface with `scan` and `version` commands
- 17 AWS security, cost, and reliability checks:
  - **IAM:** Root MFA, user MFA, access key rotation, unused access keys
  - **S3:** Public buckets, encryption at rest, versioning
  - **EC2:** Public AMIs, unencrypted EBS volumes, stopped instances
  - **VPC:** Default VPC usage, open security groups, flow logs
  - **RDS:** Public instances, encryption at rest, Multi-AZ
  - **EIP:** Unattached Elastic IPs
- Health score (0-100) based on finding severity
- HTML report with dark-mode design
- JSON output for CI/CD integration
- Docker image support
- Rich terminal UI with progress bar and color-coded findings

[Unreleased]: https://github.com/gebalamariusz/cloud-audit/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/gebalamariusz/cloud-audit/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/gebalamariusz/cloud-audit/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/gebalamariusz/cloud-audit/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/gebalamariusz/cloud-audit/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/gebalamariusz/cloud-audit/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/gebalamariusz/cloud-audit/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/gebalamariusz/cloud-audit/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/gebalamariusz/cloud-audit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/gebalamariusz/cloud-audit/releases/tag/v0.1.0
