<div align="center">

# cloud-audit

**Fast, opinionated AWS security scanner. Curated checks. Zero noise. Copy-paste fixes.**

[![PyPI version](https://img.shields.io/pypi/v/cloud-audit?color=blue)](https://pypi.org/project/cloud-audit/)
[![Python versions](https://img.shields.io/pypi/pyversions/cloud-audit)](https://pypi.org/project/cloud-audit/)
[![CI](https://github.com/gebalamariusz/cloud-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/gebalamariusz/cloud-audit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Downloads](https://img.shields.io/pypi/dm/cloud-audit)](https://pypi.org/project/cloud-audit/)

</div>

---

```
$ cloud-audit scan --provider aws --output report.html

Running 17 checks on AWS...

 ━━━━━━━━━━━━━━━━━━━━━━━━━ 17/17 00:12

 ╭── Health Score ──╮
 │       62         │
 ╰──────────────────╯

 Provider          AWS
 Account           123456789012
 Resources scanned 147
 Checks passed     11
 Checks failed     6

 Findings by severity:
   ✖ CRITICAL: 2
   ✖ HIGH: 4
   ⚠ MEDIUM: 7
   ○ LOW: 3

 HTML report saved to report.html
```

## Why cloud-audit?

Most cloud security scanners give you hundreds of findings, and you end up ignoring all of them. cloud-audit takes a different approach:

- **17 curated, high-signal checks** — every check catches something an attacker would actually exploit
- **12 seconds, not 12 minutes** — scan completes before your coffee gets cold
- **Zero configuration** — uses your existing AWS credentials, works out of the box
- **Beautiful reports** — dark-mode HTML report you can send to your manager or client
- **Single `pip install`** — no Java, no Docker required, no 50-step setup guide

> **Positioning:** cloud-audit is not another Prowler. Prowler has 576 checks and takes hours. We have 17 checks and take seconds. Every finding matters. Every report is actionable.

## Quick Start

```bash
pip install cloud-audit
cloud-audit scan
```

That's it. You'll get a health score and findings in your terminal.

## Installation

### pip (recommended)

```bash
pip install cloud-audit
```

### pipx (isolated environment)

```bash
pipx install cloud-audit
```

### Docker

```bash
docker run -v ~/.aws:/root/.aws ghcr.io/gebalamariusz/cloud-audit scan
```

### From source

```bash
git clone https://github.com/gebalamariusz/cloud-audit.git
cd cloud-audit
pip install -e .
```

## What It Checks

### Security

| Check | ID | Severity | Description |
|-------|----|----------|-------------|
| Root account MFA | `aws-iam-001` | Critical | Root account without MFA is a single password away from total compromise |
| IAM users without MFA | `aws-iam-002` | High | Console users without MFA are vulnerable to credential theft |
| Access key rotation | `aws-iam-003` | Medium | Active access keys older than 90 days increase exposure window |
| Unused access keys | `aws-iam-004` | Medium | Keys unused for 30+ days are forgotten attack vectors |
| Public S3 buckets | `aws-s3-001` | High | S3 buckets without public access block expose data to the internet |
| S3 bucket encryption | `aws-s3-002` | Medium | Unencrypted buckets risk data exposure at rest |
| Public AMIs | `aws-ec2-001` | High | Publicly shared AMIs may contain secrets or proprietary code |
| Unencrypted EBS volumes | `aws-ec2-002` | Medium | EBS volumes without encryption expose data if disks are compromised |
| Open security groups | `aws-vpc-002` | Critical | Security groups open to 0.0.0.0/0 on sensitive ports (SSH, RDP, DB) |
| VPC flow logs disabled | `aws-vpc-003` | Medium | Without flow logs, you have zero network visibility for forensics |
| Public RDS instances | `aws-rds-001` | Critical | Publicly accessible databases are the #1 cause of cloud data breaches |
| RDS encryption at rest | `aws-rds-002` | High | Unencrypted databases risk data exposure in case of disk-level compromise |

### Cost

| Check | ID | Severity | Description |
|-------|----|----------|-------------|
| Unattached Elastic IPs | `aws-eip-001` | Low | Unattached EIPs cost ~$3.65/month each |
| Stopped EC2 instances | `aws-ec2-003` | Low | Stopped instances still incur EBS charges |

### Reliability

| Check | ID | Severity | Description |
|-------|----|----------|-------------|
| S3 bucket versioning | `aws-s3-003` | Low | Without versioning, accidental deletes are permanent |
| Default VPC in use | `aws-vpc-001` | Medium | Default VPCs have permissive defaults not suitable for production |
| RDS Multi-AZ disabled | `aws-rds-003` | Medium | Single-AZ RDS instances have no automatic failover |

## Usage

```bash
# Scan with default AWS profile and region
cloud-audit scan

# Specific profile and regions
cloud-audit scan --profile production --regions eu-central-1,eu-west-1

# Scan all enabled regions
cloud-audit scan --regions all

# Filter by category
cloud-audit scan --categories security,cost

# Show remediation details (CLI commands, Terraform, docs)
cloud-audit scan -R

# Export all fix commands as a dry-run bash script
cloud-audit scan --export-fixes fixes.sh

# Generate HTML report
cloud-audit scan --output report.html

# Generate JSON report (for CI/CD pipelines)
cloud-audit scan --output report.json

# Combine: remediation + HTML report
cloud-audit scan -R --output report.html

# Show version
cloud-audit version
```

## AWS Permissions

cloud-audit requires **read-only** access. Attach the AWS-managed `SecurityAudit` policy to your IAM user or role:

```bash
# For an IAM user
aws iam attach-user-policy \
  --user-name auditor \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit

# For an IAM role (recommended)
aws iam attach-role-policy \
  --role-name auditor-role \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

cloud-audit **never modifies** your infrastructure. It only makes read API calls.

## Health Score

The health score starts at 100 and decreases based on findings:

| Severity | Points deducted |
|----------|----------------|
| Critical | -20 |
| High | -10 |
| Medium | -5 |
| Low | -2 |

A score of **80+** is good, **50-79** needs attention, and **below 50** requires immediate action.

## How It Compares

| Feature | cloud-audit | Prowler | ScoutSuite |
|---------|-------------|---------|------------|
| Checks | 17 (curated) | 576 (AWS) | ~200 |
| Scan time | ~12 seconds | 1-4 hours | 30-60 minutes |
| Setup | `pip install` | `pip install` + config | `pip install` + config |
| Alert fatigue | Zero — every finding matters | High — hundreds of findings | Moderate |
| Remediation | Copy-paste CLI + Terraform | Text descriptions | None |
| HTML report | Dark-mode, client-ready | Functional | Interactive |
| Maintenance | Active | Active | Inactive (12+ months) |

## Development

```bash
# Clone and install in development mode
git clone https://github.com/gebalamariusz/cloud-audit.git
cd cloud-audit
pip install -e ".[dev]"

# Run tests
pytest -v

# Lint and format
ruff check src/ tests/
ruff format --check src/ tests/

# Type check
mypy src/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines.

## Roadmap

- ~~**v0.1.0** — 17 AWS checks, CLI, HTML/JSON reports~~
- ~~**v0.2.0** — Remediation engine (CLI + Terraform), CIS Benchmark mapping, 45 moto tests~~
- **v0.3.0** — CloudTrail, GuardDuty, Config, KMS, CloudWatch checks
- **v0.4.0** — Lambda, ECS, SSM, Secrets Manager checks + IAM/EC2/S3 expansions
- **v0.5.0** — SARIF output (GitHub Security integration), config file, baseline/suppress, cross-account scanning
- **v1.0.0** — Executive-ready reports, scan diff/compare, documentation site

## License

[MIT](LICENSE) — Mariusz Gebala / [HAIT](https://haitmg.pl)

## Author

Built by [Mariusz Gebala](https://github.com/gebalamariusz) at [HAIT](https://haitmg.pl) — Cloud Infrastructure & Security Consulting.
