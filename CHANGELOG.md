# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/gebalamariusz/cloud-audit/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/gebalamariusz/cloud-audit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/gebalamariusz/cloud-audit/releases/tag/v0.1.0
