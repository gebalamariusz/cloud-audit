<p align="center">
  <img src="assets/logo-nobg.png" alt="cloud-audit logo" width="200">
</p>

<!-- mcp-name: io.github.gebalamariusz/cloud-audit -->
<h1 align="center">cloud-audit</h1>

<p align="center">
  <a href="README.md">English</a> | <a href="README_zh-CN.md">简体中文</a>
</p>

<p align="center">
  <strong>Find AWS attack paths, IAM escalation routes, and the fixes that matter most.</strong>
</p>

<p align="center">
  Open-source, read-only AWS security scanner. It correlates findings into attack chains,
  ranks fixes by how many chains they break, and ships an <strong>AWS CLI + Terraform fix with
  every finding</strong>. No agent, no infrastructure, nothing written to your account.
</p>

<p align="center">
  <a href="https://pypi.org/project/cloud-audit/"><img src="https://img.shields.io/pypi/v/cloud-audit?style=flat" alt="PyPI version"></a>
  <a href="https://pypi.org/project/cloud-audit/"><img src="https://img.shields.io/pypi/pyversions/cloud-audit?style=flat" alt="Python versions"></a>
  <a href="https://github.com/gebalamariusz/cloud-audit/actions/workflows/ci.yml"><img src="https://github.com/gebalamariusz/cloud-audit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow?style=flat" alt="License: MIT"></a>
  <a href="https://ghcr.io/gebalamariusz/cloud-audit"><img src="https://img.shields.io/badge/Docker-GHCR-blue?style=flat&logo=docker" alt="Docker"></a>
  <a href="https://haitmg.pl/cloud-audit/"><img src="https://img.shields.io/badge/Docs-haitmg.pl-blue?style=flat" alt="Documentation"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> -
  <a href="#what-you-get">What You Get</a> -
  <a href="#installation">Installation</a> -
  <a href="#whats-checked">What's Checked</a> -
  <a href="https://haitmg.pl/cloud-audit/">Documentation</a>
</p>

## Quick Start

```bash
pip install cloud-audit
cloud-audit scan          # uses your default AWS credentials and region
```

No AWS account handy? Run a full sample report offline:

```bash
cloud-audit demo
```

cloud-audit is **read-only**. It never modifies your infrastructure; `SecurityAudit` is enough ([permissions](#aws-permissions)).

## Example Output

```
+---- Attack Chains (5 detected) -----------------------------------+
|  CRITICAL  Internet-Exposed Admin Instance                        |
|            i-0abc123 - public SG + admin IAM role + IMDSv1        |
|  CRITICAL  IAM Privilege Escalation via iam:PassRole              |
|            ci-deploy-role - 3-step path to admin                  |
|  CRITICAL  CI/CD to Admin Takeover                                |
|            github-deploy - OIDC without sub + admin policy        |
+-------------------------------------------------------------------+

+---- Remediation Plan ---------------------------------------------+
|  Fix 4 root causes, break 22 attack chains                        |
|  Quick wins (effort LOW, 14 chains):                              |
|    1. Restrict SG ingress on sg-0abc123   -> breaks 8 chains      |
|    2. Add OIDC sub condition              -> breaks 6 chains      |
+-------------------------------------------------------------------+
```

Preview a fix before you touch anything:

```bash
cloud-audit simulate --fix aws-vpc-002
# Score 34 -> 58 (+24)  |  Chains broken 8 of 22  |  Findings resolved 11
```

## What You Get

- **Attack chains** // 31 rules correlate individual findings into exploitable paths (MITRE ATT&CK + pathfinding.cloud). [docs](https://haitmg.pl/cloud-audit/features/attack-chains/)
- **Root-cause fixes** // groups findings by shared cause and ranks them: "fix 4 things, break 22 chains," with a what-if `simulate` to preview impact. [docs](https://haitmg.pl/cloud-audit/features/simulate/)
- **IAM privilege escalation** // 64 methods across 9 categories, including lateral movement through the AssumeRole graph. [docs](https://haitmg.pl/cloud-audit/features/iam-escalation/)
- **Blast radius** // walk outward from any resource to see what an attacker reaches; export JSON to the live [visualizer](https://blast-audit.haitmg.pl/). [docs](https://haitmg.pl/cloud-audit/features/blast-radius/)
- **Proof Mode** // `scan --verify` checks each escalation path against the IAM policy simulator (read-only) and flags the ones the principal can actually perform. [docs](https://haitmg.pl/cloud-audit/features/proof-mode/)
- **Data perimeter** // resource-policy checks for confused-deputy and cross-org exposure, evaluating condition *values* (not just their presence). [docs](https://haitmg.pl/cloud-audit/features/data-perimeter/)
- **AgentCore security** // checks for Amazon Bedrock AgentCore AI agents: network mode, MMDSv2, memory encryption, gateway authorizer. [docs](https://haitmg.pl/cloud-audit/features/agentcore/)
- **Threat Feed** // 10 detectors for active-abuse patterns from 2025-2026 incidents, each with a primary-source citation. [docs](https://haitmg.pl/cloud-audit/features/threat-feed/)
- **Remediation on every finding** // copy-paste AWS CLI + reviewable Terraform you apply yourself; security findings also carry a USD breach-cost estimate with sources.
- **Trend & drift** // `cloud-audit diff` catches ClickOps drift between scans; `cloud-audit trend` tracks posture over time.

<p align="center">
  <a href="https://blast-audit.haitmg.pl/">
    <img src="assets/blast-audit-boardroom.png" alt="blast-audit visualizer - executive briefing view" width="760">
  </a>
  <br>
  <sub>Drop a <code>cloud-audit blast-radius --format json</code> export into the open visualizer at
  <a href="https://blast-audit.haitmg.pl/">blast-audit.haitmg.pl</a> - everything runs in your browser.</sub>
</p>

## Reports

```bash
cloud-audit scan --format html  -o report.html    # client-ready
cloud-audit scan --format sarif -o results.sarif  # GitHub Code Scanning
cloud-audit scan --format json  -o report.json    # machine-readable
cloud-audit scan --format markdown -o report.md   # PR comments
```

## CI/CD

```yaml
- run: pip install cloud-audit
- run: cloud-audit scan --format sarif --output results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

`--quiet` exits with a code only: `0` clean, `1` findings, `2` error. Gate on severity with `--min-severity high`. Ready-made workflows: [basic scan](examples/github-actions.yml), [daily diff](examples/daily-scan-with-diff.yml), [post-deploy](examples/post-deploy-scan.yml).

## Installation

```bash
pip install cloud-audit                              # pip (recommended)
pipx install cloud-audit                             # isolated
docker run ghcr.io/gebalamariusz/cloud-audit scan   # Docker
```

Docker with credentials:

```bash
docker run -v ~/.aws:/home/cloudaudit/.aws:ro ghcr.io/gebalamariusz/cloud-audit scan
```

## AWS Permissions

Read-only. Attach the AWS-managed `SecurityAudit` policy (covers every check, including IAM escalation analysis):

```bash
aws iam attach-role-policy --role-name auditor \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

cloud-audit never modifies your infrastructure. `simulate` runs locally against scan data and makes no AWS calls.

## What's Checked

**110 checks across 25 AWS services** - IAM, S3, EC2, VPC, RDS, KMS, CloudTrail, GuardDuty, Lambda, Secrets Manager, Bedrock, SageMaker, Bedrock AgentCore, DynamoDB, and more. Run `cloud-audit list-checks`, or see the [full check reference](https://haitmg.pl/cloud-audit/checks/).

**6 compliance frameworks** via `scan --compliance <id>`: CIS AWS v3.0 and SOC 2 Type II (stable), plus ISO 27001:2022, HIPAA, NIS2, and BSI C5:2020 (beta). [docs](https://haitmg.pl/cloud-audit/compliance/overview/)

**MCP server** for AI agents - 6 read-only tools (`scan_aws`, `get_findings`, `get_attack_chains`, `get_remediation`, `get_health_score`, `list_checks`):

```bash
claude mcp add cloud-audit -- uvx --from cloud-audit cloud-audit-mcp
```

<details>
<summary>Common flags and configuration</summary>

```bash
cloud-audit scan -R                                      # show remediation inline
cloud-audit scan --profile prod --regions eu-central-1   # profile / region
cloud-audit scan --regions all                           # all enabled regions
cloud-audit scan --role-arn arn:aws:iam::...:role/audit  # cross-account
cloud-audit scan --export-fixes fixes.sh                 # export all fixes
```

Configure defaults in `.cloud-audit.yml` (regions, `min_severity`, `exclude_checks`, time-boxed `suppressions`). Environment variables (`CLOUD_AUDIT_REGIONS`, `CLOUD_AUDIT_MIN_SEVERITY`, ...) override the file; CLI flags override everything. See the [configuration guide](https://haitmg.pl/cloud-audit/configuration/config-file/).

</details>

## Documentation

Full documentation at **[haitmg.pl/cloud-audit](https://haitmg.pl/cloud-audit/)**: [getting started](https://haitmg.pl/cloud-audit/getting-started/installation/), [attack chains](https://haitmg.pl/cloud-audit/features/attack-chains/), [IAM escalation](https://haitmg.pl/cloud-audit/features/iam-escalation/), [blast radius](https://haitmg.pl/cloud-audit/features/blast-radius/), [Proof Mode](https://haitmg.pl/cloud-audit/features/proof-mode/), [data perimeter](https://haitmg.pl/cloud-audit/features/data-perimeter/), [AgentCore](https://haitmg.pl/cloud-audit/features/agentcore/), [compliance](https://haitmg.pl/cloud-audit/compliance/overview/), and the [full check reference](https://haitmg.pl/cloud-audit/checks/).

## Commercial Support

cloud-audit is free and stays free. If you want a human on the findings, the author offers professional services:

- **Scanner output review (free)** - send your cloud-audit / Prowler / Security Hub output, get a short written review of what actually matters and what to fix first
- **AWS security audit** - full account audit with a prioritized report and ready-to-apply fixes
- **Remediation support** - Terraform and IAM changes, verified against your workloads
- **Palo Alto VM-Series on AWS** - architecture and security review (GWLB/TGW, HA, routing)

Details: [haitmg.pl/cloud-audit-support](https://haitmg.pl/cloud-audit-support/?utm_source=github&utm_medium=readme) or email [kontakt@haitmg.pl](mailto:kontakt@haitmg.pl).

## Development

```bash
git clone https://github.com/gebalamariusz/cloud-audit.git
cd cloud-audit
pip install -e ".[dev]"
pytest -q && ruff check src/ tests/ && mypy src/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) to add a check. Past releases in [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE) - Mariusz Gebala / [HAIT](https://haitmg.pl)
