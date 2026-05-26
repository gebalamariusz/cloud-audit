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
  Open-source CLI scanner that helps you decide what to fix first -<br>
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
  <a href="https://haitmg.pl/cloud-audit/features/blast-radius/">Blast Radius</a> -
  <a href="https://blast-audit.haitmg.pl/">Live Visualizer</a> -
  <a href="https://haitmg.pl/cloud-audit/features/attack-chains/">Attack Chains</a> -
  <a href="https://haitmg.pl/cloud-audit/features/iam-escalation/">IAM Escalation</a> -
  <a href="https://haitmg.pl/cloud-audit/features/threat-feed/">Threat Feed</a> -
  <a href="https://haitmg.pl/cloud-audit/features/mcp-server/">MCP Server</a>
</p>

<p align="center">
  <a href="https://blast-audit.haitmg.pl/demo/capital-one-2019/?board=1">
    <img src="assets/blast-audit-boardroom.png" alt="blast-audit visualizer - executive briefing view of Snowflake 2024 breach: $28M exposure, 4 years to detect, fix = enforce MFA" width="820">
  </a>
  <br>
  <sub>Drop a <code>cloud-audit blast-radius</code> JSON into the live visualizer at <a href="https://blast-audit.haitmg.pl/">blast-audit.haitmg.pl</a> - or click the screenshot to explore the Snowflake 2024 breach interactively.</sub>
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

### NEW in v2.3: Blast Radius CLI + live visualizer

> *Walk outward from any AWS resource and show exactly what an attacker reaches
> if THAT resource is compromised.* The CLI runs offline against a saved scan
> (zero AWS API calls at blast-radius time); the matching open visualizer at
> [blast-audit.haitmg.pl](https://blast-audit.haitmg.pl/) renders the same JSON
> as an interactive attack graph with break-point highlighting, MITRE ATT&CK
> overlay, and an executive boardroom mode for CFO/CISO briefings.

Seeds: EC2 short id (`i-XXX`), IAM role/user ARN, Lambda ARN, S3 bucket ARN,
Secrets Manager secret ARN.

```bash
# 1. Run a scan once (saves to ~/.cloud-audit/last-scan.json)
cloud-audit scan

# 2. Inspect blast radius from any resource (uses the last scan automatically)
cloud-audit blast-radius --resource i-0abc123def456              # tree (default)
cloud-audit blast-radius --resource i-0abc123 --format mermaid   # for docs/slides
cloud-audit blast-radius --resource i-0abc123 --format markdown  # for PR comments

# 3. Export JSON and visualize it interactively
cloud-audit blast-radius --resource arn:aws:iam::123456789012:role/deploy \
                        --format json --output blast.json
# → open https://blast-audit.haitmg.pl/demo/upload/ → drop blast.json
```

<p align="center">
  <img src="assets/blast-audit-counterfactual.png" alt="Counterfactual view: applying the IAM fix collapses Capital One exposure from $270M to $0" width="820">
  <br>
  <sub>The visualizer's boardroom mode includes a one-click counterfactual -
  <em>"What stops this attack?"</em> - that animates the exposure tile to
  $0 when you preview the recommended IAM remediation.</sub>
</p>

Seven historical breach scenarios ship pre-loaded for context
(Capital One 2019, Cryptomining 2025, AgentCore 2026, Snowflake UNC5537 2024,
nx Supply Chain 2026, Codefinger SSE-C 2025, Trivy / TeamPCP 2026), each with
verified primary-source citations. See the [Blast Radius documentation](https://haitmg.pl/cloud-audit/features/blast-radius/)
for expansion rules, the BlastRadiusGraph v1.0 schema, and the risk-score heuristic.

### Also new since v2.0

| Version | Highlight |
|---|---|
| **v2.3.0** (May 2026) | **Blast Radius CLI** + live visualizer + 15 security-hardening fixes (Mermaid XSS escape, ID collision, BFS bounds, symlink-safe writes, URL scheme allow-list). 812 tests. |
| v2.2.1 (May 2026) | TF-001 SES phishing burst escalation + TF-004 defensive-tool exclusion. |
| v2.2.0 (May 2026) | **Threat Feed v1** - 10 active-abuse detectors from 2025-2026 incidents (cryptomining, leaked-cred scanners, MMDSv1, DataZone, Roles Anywhere, CloudTrail tampering). External research refs on every finding. |
| v2.1.0 (Apr 2026) | 64 IAM escalation methods, full pathfinding.cloud coverage. |
| v2.0.0 (Apr 2026) | IAM Escalation graph, What-If simulator, Trend tracking, AI-SPM (Bedrock + SageMaker). |

Detail per release in [CHANGELOG.md](CHANGELOG.md).

### NEW in v2.2: Threat Feed

Detect ACTIVE abuse patterns from 2025-2026 incidents (cryptomining campaigns,
SES phishing setup, leaked-credential scanner activity, AgentCore CVEs):

```bash
cloud-audit threat-feed              # scan all 10 patterns
cloud-audit threat-feed --list       # show registered patterns
cloud-audit threat-feed --pattern aws-tf-003   # one pattern only
```

Each pattern carries external research references (Wiz, Datadog Security Labs,
Unit 42, Permiso) on every finding. Exit code 1 when CRITICAL/HIGH detected
(CI gate friendly). See [Threat Feed docs](https://haitmg.pl/cloud-audit/features/threat-feed/).

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

## Feature matrix

| Capability | What it does |
|---|---|
| **Blast Radius CLI** (v2.3) | `cloud-audit blast-radius --resource <id>` walks outward from any AWS resource and emits the reachable attack graph as tree, JSON ([BlastRadiusGraph v1.0](https://haitmg.pl/cloud-audit/features/blast-radius/#output-json-blastradiusgraph-v10)), Mermaid, or Markdown. The JSON drops straight into the [live visualizer](https://blast-audit.haitmg.pl/) for interactive exploration. |
| **Threat Feed v1** (v2.2) | 10 active-abuse detectors from real 2025-2026 incidents - cryptomining, leaked-cred scanners, MMDSv1, DataZone overgrant, Roles Anywhere, CloudTrail tampering. Each detector ships with primary-source citation. |
| **IAM Privilege Escalation** (v2.1) | 64 escalation methods across 9 categories, including lateral movement detection via AssumeRole graph traversal. PMapper has been unmaintained since v1.1.5 (Jan 2022); cloud-audit offers a CLI-native alternative that covers additional escalation patterns beyond PMapper's IAM-principal scope. |
| **What-If Simulator** (v2.0) | `cloud-audit simulate --fix aws-vpc-002` shows score change, chains broken, and risk reduction before you apply anything. |
| **Root Cause Grouping** (v2.0) | "Fix 4 things, break 22 chains." Groups findings by shared root cause and ranks by impact. |
| **Security Posture Trend** (v2.0) | `cloud-audit trend` tracks health score, chains, and risk over time with sparkline visualization. |
| **AI-SPM** (v2.0) | Open-source Bedrock + SageMaker scanner. 5 checks, 3 attack chains (model theft, LLMjacking, data poisoning). |

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

[Prowler](https://github.com/prowler-cloud/prowler) is the AWS security standard: 600 checks across 84 services, 44 compliance frameworks (CIS, PCI-DSS, HIPAA, SOC2, NIST 800, ISO 27001, GDPR, FedRAMP, NIS2, MITRE ATT&CK and more), auto-remediation fixers, and graph-based attack path analysis in the Prowler App (Cartography + Neo4j). It also covers Azure, GCP, Kubernetes, M365, and several other providers.

cloud-audit is AWS-only and intentionally narrower (94 curated checks). It goes deep where Prowler goes wide: attack chain correlation and IAM escalation detection run in the free CLI with zero infrastructure, every finding ships with reviewable Terraform + AWS CLI remediation, and scan diff / drift tracking is built into the CLI.

| Feature | Prowler | cloud-audit |
|---------|---------|-------------|
| AWS checks | 600 across 84 services | 94 across 23 services |
| Compliance frameworks (AWS) | 44 (CIS, PCI-DSS, HIPAA, SOC2, NIST, ISO 27001, GDPR, FedRAMP, NIS2, ...) | 6 (CIS v3.0, SOC 2, BSI C5, ISO 27001, HIPAA, NIS2) |
| Auto-remediation | 55 fixers across 17 AWS services (direct API calls) | 94/94 findings with CLI + Terraform output (reviewable, you apply) |
| Attack path / graph analysis | Prowler App (Cartography + graph queries) | CLI-native (31 rules, no infra) |
| IAM privilege escalation graph | Prowler App | CLI-native (61 methods + AssumeRole graph) |
| What-If remediation simulator | No | Yes |
| AI/ML security checks (Bedrock + SageMaker) | ~20 checks | 5 checks + 3 attack chain rules |
| Scan diff / drift tracking | Prowler App | Built-in CLI (`cloud-audit diff`) |
| Breach cost estimates (USD) | No | Per-finding + per-chain |
| MCP Server | Free | Free |
| Multi-cloud | AWS + 13 others | AWS only |
| License | Apache 2.0 | MIT |

Use Prowler for compliance breadth, multi-cloud coverage, and graph-based attack path analysis. Use cloud-audit for fast CLI-native attack chain detection, reviewable Terraform remediation, and CI/CD drift tracking. They are complementary, not competitors - a common setup is Prowler for quarterly compliance evidence plus cloud-audit daily in CI/CD.

<sub>Prowler stats verified from github.com/prowler-cloud/prowler on 2026-05-25. cloud-audit snapshot as of v2.3.0.</sub>

### Blast radius specifically

Most existing AWS blast-radius tooling either lives behind paid SaaS, requires standing up Neo4j + Cartography, or has been unmaintained for years. `cloud-audit blast-radius` aims to be a lightweight CLI-native alternative: arbitrary AWS resource seeds (EC2, IAM, Lambda, S3, secret), a documented JSON contract (BlastRadiusGraph v1.0) that downstream tools can consume, and no infrastructure to stand up.

| Tool | Forward BFS from arbitrary AWS resource? | Pure CLI? | Last release |
|---|---|---|---|
| Wiz / Stream Security CloudTwin | yes | no (paid SaaS) | active |
| Prowler App | yes | no (needs Neo4j + Cartography) | active |
| Prowler CLI | no | yes | active |
| PMapper | IAM-only, optimised for privesc-to-admin | yes | v1.1.5, Jan 2022 (unmaintained) |
| Cloudsplaining | no (IAM policy analysis only) | yes | v0.8.2, Oct 2024 |
| CloudFox | no for AWS (`lateral-movement` GCP only) | yes | active |
| DetentionDodger | IAM-only, only post-quarantine users | yes | v1.0, Oct 2024 |
| awspx | partial (graph + web UI) | Docker | v1.3.4, Aug 2021 (unmaintained) |
| ScoutSuite | no | yes | v5.14.0, May 2024 |
| Cartography | no built-in (bring your own Cypher) | no (graph ingestor) | active |
| BloodHound CE | no for AWS (AD + Azure scope) | no (web app) | active |
| pathfinding.cloud | no (it's a catalog) | n/a | n/a |
| Trivy | no | yes | active |
| **cloud-audit blast-radius** | **yes** | **yes** | **v2.3.0, May 2026** |

The companion visualizer at [blast-audit.haitmg.pl](https://blast-audit.haitmg.pl/) consumes the same JSON without an account, install, or upload-to-cloud step. Everything stays in your browser.

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
- **[Blast Radius](https://haitmg.pl/cloud-audit/features/blast-radius/)** - forward BFS from arbitrary AWS resource, JSON schema, visualizer integration
- **[Attack Chains](https://haitmg.pl/cloud-audit/features/attack-chains/)** - all 31 rules with MITRE ATT&CK references
- **[IAM Escalation](https://haitmg.pl/cloud-audit/features/iam-escalation/)** - 64 methods, 9 categories (action-based + lateral AssumeRole graph)
- **[Threat Feed](https://haitmg.pl/cloud-audit/features/threat-feed/)** - 10 active-abuse detectors from 2025-2026 incidents
- **[What-If Simulator](https://haitmg.pl/cloud-audit/features/simulate/)** - simulate remediation impact
- **[Compliance](https://haitmg.pl/cloud-audit/compliance/overview/)** - 6 frameworks: CIS, SOC 2, BSI C5, ISO 27001, HIPAA, NIS2
- **[All 94 Checks](https://haitmg.pl/cloud-audit/checks/)** - full check reference by service

## Companion visualizer

The same BlastRadiusGraph v1.0 JSON that `cloud-audit blast-radius --format json` emits also drives the live visualizer at **[blast-audit.haitmg.pl](https://blast-audit.haitmg.pl/)** - no install, no signup, no upload to a third-party cloud (everything runs in your browser).

<p align="center">
  <a href="https://blast-audit.haitmg.pl/demo/capital-one-2019/">
    <img src="assets/blast-audit-hero.png" alt="blast-audit operator view of the Capital One 2019 attack chain with the break-point IAM role highlighted" width="820">
  </a>
</p>

Seven historical breach scenarios are pre-loaded with primary-source citations:

| Scenario | Year | One-line pitch | URL |
|---|---|---|---|
| Capital One | 2019 | SSRF → IMDSv1 → admin S3 (100M records, $190M total damage) | [/demo/capital-one-2019/](https://blast-audit.haitmg.pl/demo/capital-one-2019/) |
| Cryptomining | 2025 | Leaked AKID → 14 ASGs spinning in 10 minutes | [/demo/cryptomining-2025/](https://blast-audit.haitmg.pl/demo/cryptomining-2025/) |
| Bedrock AgentCore | 2026 | Sandbox bypass via DNS resolver (AWS classed "won't fix") | [/demo/agentcore-2026/](https://blast-audit.haitmg.pl/demo/agentcore-2026/) |
| Snowflake / UNC5537 | 2024 | Infostealer-harvested credentials replayed against no-MFA tenants (165 orgs, $28M+ AT&T settlement) | [/demo/snowflake-unc5537-2024/](https://blast-audit.haitmg.pl/demo/snowflake-unc5537-2024/) |
| nx Supply Chain / UNC6426 | 2026 | Trojanised npm → LLM stealer → GitHub OIDC → AWS Admin in &lt;72 h | [/demo/unc6426-nx-2026/](https://blast-audit.haitmg.pl/demo/unc6426-nx-2026/) |
| Codefinger | 2025 | AWS-native SSE-C ransomware (no key recovery from CloudTrail) | [/demo/codefinger-ssec-2025/](https://blast-audit.haitmg.pl/demo/codefinger-ssec-2025/) |
| Trivy / TeamPCP | 2026 | 76 of 77 GitHub Action tags force-pushed to a credential stealer | [/demo/trivy-teampcp-2026/](https://blast-audit.haitmg.pl/demo/trivy-teampcp-2026/) |

Boardroom mode (`?board=1` on any scenario) renders the same graph as a CFO/CISO briefing with the dollar exposure, time-to-detect, and recommended fix surfaced as 3 big tiles - click *"What stops this attack?"* and the exposure tile animates to $0.

## What's Next

- Multi-account scanning (AWS Organizations)
- SCP + permission boundary evaluation in IAM escalation
- Terraform drift detection
- Security Graph v3.0.0 (network reachability, cross-account propagation, permission-boundary semantics)

Past releases: [CHANGELOG.md](CHANGELOG.md)

## Development

```bash
git clone https://github.com/gebalamariusz/cloud-audit.git
cd cloud-audit
pip install -e ".[dev]"

pytest -v                          # 812 tests
ruff check src/ tests/             # lint
mypy src/                          # type check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a new check.

## License

[MIT](LICENSE) - Mariusz Gebala / [HAIT](https://haitmg.pl)
