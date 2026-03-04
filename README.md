<h1 align="center">cloud-audit</h1>

<p align="center">
  <strong>Fast, opinionated AWS security scanner. Curated checks. Zero noise. Copy-paste fixes.</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/cloud-audit/"><img src="https://img.shields.io/pypi/v/cloud-audit?style=flat" alt="PyPI version"></a>
  <a href="https://pypi.org/project/cloud-audit/"><img src="https://img.shields.io/pypi/pyversions/cloud-audit?style=flat" alt="Python versions"></a>
  <a href="https://github.com/gebalamariusz/cloud-audit/actions/workflows/ci.yml"><img src="https://github.com/gebalamariusz/cloud-audit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow?style=flat" alt="License: MIT"></a>
</p>

---

<p align="center">
  <img src="https://raw.githubusercontent.com/gebalamariusz/cloud-audit/main/assets/demo.gif" alt="cloud-audit terminal output showing health score, findings, and remediation" width="700">
</p>

## Why cloud-audit?

59% of cloud security teams receive **500+ alerts daily**. 55% admit to **missing critical ones** ([Forrester/HelpNetSecurity](https://www.helpnetsecurity.com/2023/10/cloud-alert-fatigue/)). Most scanners make this worse, not better. cloud-audit takes a different approach:

- **42 curated, high-signal checks** - every check catches something an attacker would actually exploit
- **Every finding = copy-paste fix** - AWS CLI command + Terraform HCL + docs link, ready to go
- **CIS Benchmark mapped** - 15 controls from CIS AWS Foundations Benchmark, compliance evidence included
- **12 seconds, not 12 minutes** - scan completes before your coffee gets cold
- **Zero configuration** - `pip install cloud-audit && cloud-audit scan` gives results immediately
- **Beautiful reports** - dark-mode HTML report you can send to your manager or client

<p align="center">
  <img src="https://raw.githubusercontent.com/gebalamariusz/cloud-audit/main/assets/report-preview.png" alt="cloud-audit dark-mode HTML report preview" width="700">
</p>

> cloud-audit is not another Prowler. Prowler has 576 checks and takes hours. We have 42 checks and take seconds. Every finding comes with a ready-to-use fix.

## Every Finding = A Fix

This is what makes cloud-audit different. Run with `-R` and every finding includes a ready-to-use remediation:

```
$ cloud-audit scan -R

  CRITICAL  Root account without MFA enabled
  Resource:   arn:aws:iam::123456789012:root
  Compliance: CIS 1.5
  Effort:     LOW
  CLI:        aws iam create-virtual-mfa-device --virtual-mfa-device-name root-mfa
  Terraform:  resource "aws_iam_virtual_mfa_device" "root" { ... }
  Docs:       https://docs.aws.amazon.com/IAM/latest/UserGuide/...

  CRITICAL  Security group open to 0.0.0.0/0 on port 22
  Resource:   sg-0a1b2c3d4e5f67890
  Compliance: CIS 5.2
  CLI:        aws ec2 revoke-security-group-ingress --group-id sg-... --port 22
  Terraform:  resource "aws_security_group_rule" "ssh_restricted" { ... }
```

Export all fixes as a bash script: `cloud-audit scan --export-fixes fixes.sh`

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
| CloudTrail not enabled | `aws-ct-001` | Critical | No multi-region trail means API activity goes unmonitored |
| CloudTrail log validation | `aws-ct-002` | High | Without log validation, attackers can modify logs undetected |
| CloudTrail bucket public | `aws-ct-003` | Critical | Public CloudTrail S3 bucket exposes all API logs |
| GuardDuty not enabled | `aws-gd-001` | High | No threat detection for malicious activity or unauthorized behavior |
| GuardDuty unresolved findings | `aws-gd-002` | Medium | Unresolved findings older than 30 days indicate ignored threats |
| AWS Config not enabled | `aws-cfg-001` | Medium | No configuration history or change tracking for resources |
| Config recorder stopped | `aws-cfg-002` | High | Config recorder exists but not recording changes |
| KMS key rotation disabled | `aws-kms-001` | Medium | Customer-managed keys without automatic rotation (CIS 3.6) |
| KMS wildcard key policy | `aws-kms-002` | High | Key policy with Principal: * allows any AWS principal to use the key |
| Root usage alarm missing | `aws-cw-001` | High | No CloudWatch alarm for root account usage (CIS 4.3) |
| Overly permissive IAM policy | `aws-iam-005` | Critical | IAM policy with Action: * and Resource: * grants full admin access |
| Weak password policy | `aws-iam-006` | Medium | Account password policy doesn't meet CIS requirements (CIS 1.8) |
| S3 access logging disabled | `aws-s3-005` | Medium | No server access logging to track bucket requests |
| EC2 IMDSv1 enabled | `aws-ec2-004` | High | Instance metadata v1 is vulnerable to SSRF credential theft |
| Lambda public function URL | `aws-lambda-001` | High | Lambda function URL with AuthType=NONE (unauthenticated) |
| Lambda deprecated runtime | `aws-lambda-002` | Medium | EOL runtime without security patches |
| Lambda env var secrets | `aws-lambda-003` | High | Potential secrets in Lambda environment variables |
| ECS privileged container | `aws-ecs-001` | Critical | Container runs with privileged mode (root host access) |
| ECS missing log config | `aws-ecs-002` | High | Container without logging makes debugging impossible |
| ECS Exec enabled | `aws-ecs-003` | Medium | Interactive shell access enabled (risky in production) |
| EC2 not managed by SSM | `aws-ssm-001` | Medium | Running instance not registered with Systems Manager |
| SSM insecure parameter | `aws-ssm-002` | High | Secret-like parameter stored as String instead of SecureString |
| Secret rotation disabled | `aws-sm-001` | Medium | Secrets Manager secret without automatic rotation |

### Cost

| Check | ID | Severity | Description |
|-------|----|----------|-------------|
| Unattached Elastic IPs | `aws-eip-001` | Low | Unattached EIPs cost ~$3.65/month each |
| Stopped EC2 instances | `aws-ec2-003` | Low | Stopped instances still incur EBS charges |
| S3 no lifecycle policy | `aws-s3-004` | Low | No lifecycle rules to transition/expire old objects |
| Unused secret | `aws-sm-002` | Low | Secret not accessed in 90+ days ($0.40/month) |

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

| Feature | cloud-audit | Prowler | ScoutSuite* |
|---------|-------------|---------|-------------|
| Checks | 42 (curated) | 576 (AWS) | ~200 |
| Scan time | ~12 seconds | 1-4 hours | 30-60 minutes |
| Setup | `pip install` | `pip install` + config | `pip install` + config |
| Alert fatigue | Zero - every finding matters | High - hundreds of findings | Moderate |
| **Terraform fix code** | **Yes (copy-paste)** | No | No |
| **CLI fix commands** | **Yes (copy-paste)** | Text descriptions | No |
| **CIS Benchmark mapping** | Yes (15 controls) | Yes (full) | No |
| HTML report | Dark-mode, client-ready | Functional | Interactive |
| Maintenance | Active | Active | Inactive (12+ months) |

\* ScoutSuite has had no releases in over 12 months and is effectively unmaintained.

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

- ~~**v0.1.0** - 17 AWS checks, CLI, HTML/JSON reports~~
- ~~**v0.2.0** - Remediation engine (CLI + Terraform), CIS Benchmark mapping, 45 moto tests~~
- ~~**v0.3.0** - CloudTrail, GuardDuty, Config, KMS, CloudWatch checks (27 total)~~
- ~~**v0.4.0** - Lambda, ECS, SSM, Secrets Manager checks (42 total)~~
- **v0.5.0** - SARIF output (GitHub Security integration), config file, baseline/suppress
- **v1.0.0** - Executive-ready reports, scan diff/compare, 45 curated checks

See [ROADMAP.md](ROADMAP.md) for the full plan.

## License

[MIT](LICENSE) - Mariusz Gebala / [HAIT](https://haitmg.pl)

## Author

Built by [Mariusz Gebala](https://github.com/gebalamariusz) at [HAIT](https://haitmg.pl) - Cloud Infrastructure & Security Consulting.
