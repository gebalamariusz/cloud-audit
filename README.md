<p align="center">
  <img src="assets/logo-nobg.png" alt="cloud-audit logo" width="200">
</p>

<!-- mcp-name: io.github.gebalamariusz/cloud-audit -->
<h1 align="center">cloud-audit</h1>

<p align="center">
  <strong>Find AWS attack paths, IAM escalation routes, and the fixes that matter most.</strong>
</p>

<p align="center">
  Open-source CLI scanner that helps you decide what to fix first &mdash;<br>
  not just what's wrong.
</p>

<p align="center">
  Find attack chains and IAM escalation paths &nbsp;-&nbsp; Simulate fixes before you apply them &nbsp;-&nbsp; Fix root causes, not individual findings
</p>

<p align="center">
  <a href="https://pypi.org/project/cloud-audit/"><img src="https://img.shields.io/pypi/v/cloud-audit?style=flat" alt="PyPI version"></a>
  <a href="https://pypi.org/project/cloud-audit/"><img src="https://img.shields.io/pypi/pyversions/cloud-audit?style=flat" alt="Python versions"></a>
  <a href="https://github.com/gebalamariusz/cloud-audit/actions/workflows/ci.yml"><img src="https://github.com/gebalamariusz/cloud-audit/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow?style=flat" alt="License: MIT"></a>
  <a href="https://pypi.org/project/cloud-audit/"><img src="https://img.shields.io/pypi/dm/cloud-audit?style=flat" alt="PyPI downloads"></a>
  <a href="https://ghcr.io/gebalamariusz/cloud-audit"><img src="https://img.shields.io/badge/Docker-GHCR-blue?style=flat&logo=docker" alt="Docker"></a>
  <a href="https://www.helpnetsecurity.com/2026/03/11/cloud-audit-open-source-aws-security-scanner/"><img src="https://img.shields.io/badge/Featured_in-HelpNet_Security-blue?style=flat" alt="Featured in HelpNet Security"></a>
  <a href="https://glama.ai/mcp/servers/gebalamariusz/cloud-audit"><img src="https://glama.ai/mcp/servers/gebalamariusz/cloud-audit/badges/score.svg" alt="MCP Server Score"></a>
  <a href="https://haitmg.pl/cloud-audit/"><img src="https://img.shields.io/badge/Docs-haitmg.pl-blue?style=flat" alt="Documentation"></a>
</p>

<p align="center">
  <a href="https://haitmg.pl/cloud-audit/">Documentation</a> -
  <a href="https://haitmg.pl/cloud-audit/getting-started/quick-start/">Quick Start</a> -
  <a href="https://haitmg.pl/cloud-audit/compliance/overview/">Compliance</a> -
  <a href="https://haitmg.pl/cloud-audit/features/attack-chains/">Attack Chains</a> -
  <a href="https://haitmg.pl/cloud-audit/features/iam-escalation/">IAM Escalation</a> -
  <a href="https://haitmg.pl/cloud-audit/features/simulate/">Simulator</a> -
  <a href="https://haitmg.pl/cloud-audit/features/mcp-server/">MCP Server</a>
</p>

## Quick Start

```bash
pip install cloud-audit
cloud-audit scan
```

Uses your default AWS credentials and region. Try without an AWS account:

```bash
cloud-audit demo
```

---

## Why It's Different

Most scanners give you findings. cloud-audit helps you **decide what to fix first**.

```
+---- Attack Chains (5 detected) -----------------------------------+
|  CRITICAL  Internet-Exposed Admin Instance                         |
|            i-0abc123 - public SG + admin IAM role + IMDSv1         |
|                                                                    |
|  CRITICAL  IAM Privilege Escalation via iam:PassRole               |
|            ci-deploy-role - 3-step path to admin                   |
|                                                                    |
|  CRITICAL  CI/CD to Admin Takeover                                 |
|            github-deploy - OIDC no sub + admin policy              |
+--------------------------------------------------------------------+

+---- Remediation Plan -------------------------------------------+
|  Fix 4 root causes, break 22 attack chains                       |
|                                                                    |
|  Quick Wins (effort: LOW, chains broken: 14):                      |
|    1. Restrict SG ingress on sg-0abc123    -> breaks 8 chains      |
|    2. Add OIDC sub condition               -> breaks 6 chains      |
+--------------------------------------------------------------------+
```

Other tools give you 200 findings sorted by severity. cloud-audit groups them by root cause, shows which single fixes collapse the most attack paths, and lets you simulate the impact before you touch anything:

```bash
cloud-audit simulate --fix aws-vpc-002
# Score: 34 -> 58 (+24)  |  Chains broken: 8 of 22  |  Findings resolved: 11
```

94 checks across 23 AWS services. Every finding includes copy-paste AWS CLI + Terraform remediation.

<p align="center">
  <a href="https://www.youtube.com/watch?v=5uHoqggmTB8">
    <img src="https://img.youtube.com/vi/5uHoqggmTB8/hqdefault.jpg" alt="cloud-audit demo video" width="500">
  </a>
  <br>
  <sub>Watch the 1-minute demo</sub>
</p>

---

## What's New in 2.0

| Feature | What it does |
|---|---|
| **IAM Privilege Escalation** | 25 escalation methods across 6 categories. PMapper has been dead since 2022 -- this is its open-source replacement. |
| **What-If Simulator** | `cloud-audit simulate --fix aws-vpc-002` shows score change, chains broken, and risk reduction before you apply anything. |
| **Root Cause Grouping** | "Fix 4 things, break 22 chains." Groups findings by shared root cause and ranks by impact. |
| **Security Posture Trend** | `cloud-audit trend` tracks health score, chains, and risk over time with sparkline visualization. |
| **AI-SPM** | First open-source Bedrock + SageMaker scanner. 5 checks, 3 attack chains (model theft, LLMjacking, data poisoning). |

---

## Features

### Attack Chain Detection

31 rules correlate individual findings into exploitable attack paths.

```
  Internet --> Public SG --> EC2 (IMDSv1) --> Admin IAM Creds --> Account Takeover
               aws-vpc-002   aws-ec2-004       Detected: AC-01, AC-02
```

| Chain | What it catches |
|---|---|
| IAM Privilege Escalation | iam:PassRole + lambda:Create + iam:Attach = 3-step path to admin |
| Internet-Exposed Admin | Public SG + admin IAM role + IMDSv1 = account takeover |
| CI/CD to Admin Takeover | OIDC without sub condition + admin policy = pipeline hijack |
| LLMjacking | Bedrock no logging + no guardrails = undetected model abuse |

Based on [MITRE ATT&CK Cloud](https://attack.mitre.org/matrices/enterprise/cloud/) and [pathfinding.cloud](https://github.com/DataDog/pathfinding.cloud). [See all 31 rules](https://haitmg.pl/cloud-audit/features/attack-chains/).

### Remediation + Simulator

Every finding includes AWS CLI, Terraform HCL, and docs links. Export all fixes:

```bash
cloud-audit scan --export-fixes fixes.sh
```

Simulate before applying:

```bash
cloud-audit simulate --fix aws-vpc-002
# Score: 34 -> 58 (+24)  |  Chains broken: 8 of 22  |  Findings resolved: 11

cloud-audit simulate --fix aws-vpc-002,aws-ct-001,aws-iam-007
# Score: 34 -> 82 (+48)  |  Chains broken: 19 of 22
```

### Trend Tracking

```bash
cloud-audit diff yesterday.json today.json    # Catches ClickOps drift
cloud-audit trend                              # Posture over time
```

### 6 Compliance Frameworks

- **CIS AWS v3.0** - 62 controls, 55 automated (89%)
- **SOC 2 Type II** - 43 criteria, 24 automated (56%)
- **BSI C5:2020** `Beta` - 134 criteria, 57 automated/partial
- **ISO 27001:2022** `Beta` - 93 controls, 47 automated/partial
- **HIPAA Security Rule** `Beta` - 47 specs, 29 automated/partial
- **NIS2 Directive** `Beta` - 43 measures, 33 automated/partial

### Breach Cost Estimation

Every finding and chain includes a dollar-range risk estimate based on IBM/Verizon breach data, with source links.

### MCP Server for AI Agents

```bash
claude mcp add cloud-audit -- uvx --from cloud-audit cloud-audit-mcp
```

6 tools: `scan_aws`, `get_findings`, `get_attack_chains`, `get_remediation`, `get_health_score`, `list_checks`. Free and standalone.

---

## How It Compares

| Feature | Prowler | Trivy | cloud-audit |
|---------|---------|-------|-------------|
| Checks | 576 | 517 | **94** |
| Attack chains + root-cause grouping | No | No | **31 rules** |
| What-If remediation simulator | No | No | **Yes** |
| IAM privilege escalation | No | No | **25 methods** |
| Remediation per finding | CIS only | No | **100% (CLI + TF)** |
| AI-SPM (Bedrock/SageMaker) | No | No | **Yes** |
| Compliance frameworks | CIS | -- | **6** |

cloud-audit has fewer checks but goes deeper per finding: attack chain correlation, root-cause grouping, cost estimates, and a simulator that shows the impact of each fix before you apply it. If you need exhaustive multi-cloud compliance coverage, use Prowler. If you need to know what to fix first and why, cloud-audit is built for that.

<sub>Feature snapshot as of v2.0.0 (April 2026).</sub>

---

## Reports

```bash
cloud-audit scan --format html -o report.html     # Client-ready HTML
cloud-audit scan --format json -o report.json      # Machine-readable
cloud-audit scan --format sarif -o results.sarif   # GitHub Code Scanning
cloud-audit scan --format markdown -o report.md    # PR comments
```

## Installation

```bash
pip install cloud-audit          # pip (recommended)
pipx install cloud-audit         # pipx (isolated)
docker run ghcr.io/gebalamariusz/cloud-audit scan  # Docker
```

Docker with credentials:

```bash
docker run -v ~/.aws:/home/cloudaudit/.aws:ro ghcr.io/gebalamariusz/cloud-audit scan
```

## Usage

```bash
cloud-audit scan -R                                    # Show remediation
cloud-audit scan --profile prod --regions eu-central-1  # Specific profile/region
cloud-audit scan --regions all                          # All enabled regions
cloud-audit scan --min-severity high                   # Filter by severity
cloud-audit scan --role-arn arn:aws:iam::...:role/audit # Cross-account
cloud-audit scan --quiet                               # Exit code only (CI/CD)
cloud-audit simulate --fix aws-vpc-002                 # What-If simulator
cloud-audit trend                                      # Posture over time
cloud-audit list-checks                                # List all checks
```

| Exit code | Meaning |
|-----------|---------|
| 0 | No findings |
| 1 | Findings detected |
| 2 | Scan error |

<details>
<summary>Configuration file</summary>

Create `.cloud-audit.yml` in your project root:

```yaml
provider: aws
regions:
  - eu-central-1
  - eu-west-1
min_severity: medium
exclude_checks:
  - aws-eip-001
suppressions:
  - check_id: aws-vpc-001
    resource_id: vpc-abc123
    reason: "Legacy VPC, migration planned for Q3"
    accepted_by: "jane@example.com"
    expires: "2026-09-30"
  - check_id: "aws-cw-*"
    reason: "CloudWatch alarms managed by separate team"
    accepted_by: "ops@example.com"
```

</details>

<details>
<summary>Environment variables</summary>

| Variable | Example |
|----------|---------|
| `CLOUD_AUDIT_REGIONS` | `eu-central-1,eu-west-1` |
| `CLOUD_AUDIT_MIN_SEVERITY` | `high` |
| `CLOUD_AUDIT_EXCLUDE_CHECKS` | `aws-eip-001,aws-iam-001` |
| `CLOUD_AUDIT_ROLE_ARN` | `arn:aws:iam::...:role/auditor` |

Precedence: CLI flags > env vars > config file > defaults.

</details>

## CI/CD

```yaml
- run: pip install cloud-audit
- run: cloud-audit scan --format sarif --output results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Ready-to-use workflows: [basic scan](examples/github-actions.yml), [daily diff](examples/daily-scan-with-diff.yml), [post-deploy](examples/post-deploy-scan.yml).

## AWS Permissions

cloud-audit requires **read-only** access. Attach `SecurityAudit` (covers all checks including IAM escalation analysis):

```bash
aws iam attach-role-policy --role-name auditor --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

cloud-audit never modifies your infrastructure. The `simulate` command runs locally against scan data -- it does not call AWS APIs.

## What It Checks

94 checks across IAM, S3, EC2, VPC, RDS, EIP, EFS, CloudTrail, GuardDuty, KMS, CloudWatch, Lambda, ECS, SSM, Secrets Manager, AWS Config, Security Hub, Account, AWS Backup, Amazon Inspector, AWS WAF, Amazon Bedrock, and Amazon SageMaker.

[See all 94 checks by service](https://haitmg.pl/cloud-audit/checks/) or run `cloud-audit list-checks` locally.

## Documentation

Full docs at **[haitmg.pl/cloud-audit](https://haitmg.pl/cloud-audit/)**:

- **[Getting Started](https://haitmg.pl/cloud-audit/getting-started/installation/)** - installation, quick start, demo mode
- **[Attack Chains](https://haitmg.pl/cloud-audit/features/attack-chains/)** - all 31 rules with MITRE ATT&CK references
- **[IAM Escalation](https://haitmg.pl/cloud-audit/features/iam-escalation/)** - 25 methods, 6 categories
- **[What-If Simulator](https://haitmg.pl/cloud-audit/features/simulate/)** - simulate remediation impact
- **[Compliance](https://haitmg.pl/cloud-audit/compliance/overview/)** - 6 frameworks: CIS, SOC 2, BSI C5, ISO 27001, HIPAA, NIS2
- **[All 94 Checks](https://haitmg.pl/cloud-audit/checks/)** - full check reference by service

## What's Next

- Multi-account scanning (AWS Organizations)
- SCP + permission boundary evaluation in IAM escalation
- Terraform drift detection

Past releases: [CHANGELOG.md](CHANGELOG.md)

## Development

```bash
git clone https://github.com/gebalamariusz/cloud-audit.git
cd cloud-audit
pip install -e ".[dev]"

pytest -v                          # 496 tests
ruff check src/ tests/             # lint
mypy src/                          # type check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a new check.

## License

[MIT](LICENSE) - Mariusz Gebala / [HAIT](https://haitmg.pl)
