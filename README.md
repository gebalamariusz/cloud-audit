<p align="center">
  <img src="assets/logo-nobg.png" alt="cloud-audit logo" width="200">
</p>

<!-- mcp-name: io.github.gebalamariusz/cloud-audit -->
<h1 align="center">cloud-audit</h1>

<p align="center">
  <a href="README.md">English</a> | <a href="README_zh-CN.md">简体中文</a>
</p>

<p align="center">
  <strong>What can a hijacked AI agent reach in your AWS account, and can you prove it?</strong>
</p>

<p align="center">
  Open-source, read-only AWS security scanner. 110 checks, 64 IAM privilege-escalation methods, 31 attack-chain
  rules, blast radius for any resource, and <code>agent-blast</code> for Bedrock Agents and AgentCore:
  what a prompt-injected or credential-stolen agent can reach, with the IAM policy simulator as the witness.
  Every finding ships an <strong>AWS CLI + Terraform fix</strong>. Nothing is written to your account.
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
  <a href="#thirty-seconds-no-aws-account-needed">30-second demo</a> -
  <a href="#agent-blast-what-a-hijacked-ai-agent-can-reach">agent-blast</a> -
  <a href="#a-full-scan">Full scan</a> -
  <a href="#whats-inside">What's inside</a> -
  <a href="#proof-mode-simulated-not-guessed">Proof Mode</a> -
  <a href="#installation">Installation</a> -
  <a href="https://haitmg.pl/cloud-audit/">Documentation</a>
</p>

## Thirty seconds, no AWS account needed

```bash
pip install cloud-audit

cloud-audit agent-blast --demo          # a hijacked Bedrock Agent, two threat models, one screen
cloud-audit demo --save demo.json       # a full sample scan, then explore it offline:
cloud-audit blast-radius --report demo.json --resource arn:aws:iam::123456789012:role/support-bot-ticket-role
cloud-audit simulate     --report demo.json --fix aws-iam-018
cloud-audit exposure     --report demo.json
```

The sample account is invented. Everything derived from it (attack chains, root causes, breach cost,
security graph, agent reach) is produced by the same engines a real scan uses.

With credentials, the real thing is one command and read-only. The AWS-managed `SecurityAudit`
policy covers every check ([permissions](#aws-permissions)):

```bash
cloud-audit scan                         # default profile and region
cloud-audit scan --verify                # plus IAM policy-simulator proof for escalation paths
cloud-audit agent-blast --verify         # then: what your agents can reach, simulator-confirmed
```

## agent-blast: what a hijacked AI agent can reach

An AI agent in AWS is a bundle of IAM identities: the role the agent runs as, the execution roles of
the Lambda functions behind its tools, the roles of its knowledge bases, gateways and sandboxes.
When the agent is hijacked, the attacker acts with *those* identities. `agent-blast` answers what
that means, per agent, under two threat models:

| Threat model | What the attacker has | What is in reach |
|---|---|---|
| **Identity takeover** | the credentials of a role the agent runs as (sandbox escape, metadata-service read, leaked session) | the full role: privilege-escalation methods, AssumeRole hops, data |
| **Behaviour takeover** | nothing but a prompt (indirect prompt injection through a document, a ticket, a web page) | what the agent's tools can do, bounded by the tools' own execution roles |

Real output for the sample agent (`cloud-audit agent-blast --demo -a support-bot`):

```
support-bot (bedrock_agent, eu-central-1)
├── A hijacked tool (tool: create-ticket) can escalate to account admin via PassRole+Lambda
├── status: PREPARED
├── Identity takeover (attacker holds the role's credentials)
│   └── support-bot-agent-role arn:aws:iam::123456789012:role/support-bot-agent-role
│       └── no escalation path; 3 reach(es) from policy grants, 1 on named resources (see Reach)
│           (risk 0/100, 1 nodes)
├── Behaviour takeover (prompt injection: the agent's tools, their roles)
│   ├── search-docs action_group_lambda -> support-bot-search-role
│   │   ├── 3 OpenAPI path(s) in apiSchema; state ENABLED
│   │   └── no escalation path; 4 reach(es) from policy grants, 4 on named resources (see Reach)
│   ├── create-ticket action_group_lambda -> support-bot-ticket-role
│   │   ├── 2 function(s) in functionSchema; state ENABLED
│   │   ├── reaches Account Takeover in 1 hop(s) via PassRole+Lambda (risk 72/100)
│   │   └── escalation: PassRole+Lambda
│   └── product-docs knowledge_base -> support-bot-kb-role
│       ├── 1 S3 data source(s)
│       └── no escalation path; 2 reach(es) from policy grants, 2 on named resources (see Reach)
├── Reach (13 action/resource pairs)
│   ├── tool: search-docs secretsmanager:GetSecretValue on
│   │   arn:aws:secretsmanager:eu-central-1:123456789012:secret:prod/db-credentials-Ab12Cd
│   │   unverified read secret values
│   ├── tool: create-ticket sts:AssumeRole on arn:aws:iam::123456789012:role/ops-admin unverified
│   │   assume IAM roles
│   ├── tool: create-ticket lambda:InvokeFunction on * unverified invoke Lambda functions
│   ├── tool: search-docs s3:PutObject on arn:aws:s3:::company-backups-2024/* unverified write S3
│   │   objects
│   ├── support-bot-agent-role s3:GetObject on arn:aws:s3:::kb-product-docs/* unverified read the
│   │   agent's knowledge base
│   ├── tool: search-docs s3:GetObject on arn:aws:s3:::company-backups-2024/* unverified read S3
│   │   objects
│   ...
├── Tags
│   ├── OWASP Agentic: ASI02 Tool Misuse and Exploitation, ASI03 Identity and Privilege Abuse,
│   │   ASI05 Unexpected Code Execution
│   └── MITRE ATLAS: AML.T0034 Cost Harvesting, AML.T0040 AI Model Inference API Access, AML.T0053
│       AI Agent Tool Invocation, AML.T0086 Exfiltration via AI Agent Tool Invocation
└── Simulated, not executed: identity policies, the attached permissions boundary and SCPs are
    evaluated by the IAM policy simulator; resource-based policies of the targets, RCPs and VPC
    endpoint policies are not. Tool reach is an upper bound set by the tool's role; what the tool
    code does with its inputs is narrower.
```

The story the output tells: the support bot itself is harmless, but a document that tricks it into
calling `create-ticket` runs code under a role that can pass an admin role to a new Lambda. The
`search-docs` tool, meant to read product docs, can also read the production database secret and
write into the backups bucket. Every line names the identity, the action and the resource, so the
fix is a policy statement, not a debate.

The same engine covers AgentCore. For the sample gateway (`--demo -a tools-gw`) the headline is a
cross-agent one:

```
tools-gw (agentcore_gateway, eu-central-1)
├── tool: crm-sync can write into agent 'support-bot' knowledge base (RAG poisoning): arn:aws:s3:::kb-product-docs/*
├── inbound authorizer: NONE; policy engine: none
...
│   ├── tool: crm-sync s3:PutObject on arn:aws:s3:::kb-product-docs/* unverified write into agent
│   │   'support-bot' knowledge base (RAG poisoning)
...
├── Coverage notes
│   └── tool 'erp-mcp' (gateway_target_mcp_server): backend identity unknown, not assessed - remote
│       MCP server; credential provider: OAUTH
```

What `agent-blast` reads (all list/get, no charge):

- **Bedrock Agents**: the agent resource role, every action group at the `DRAFT` version resolved to
  its Lambda and the Lambda's execution role, knowledge bases resolved to their S3 data-source buckets.
- **AgentCore**: runtime role and network mode, gateway role with authorizer, policy engine and every
  target (Lambda, remote MCP server, API Gateway, OpenAPI, Smithy) with its credential provider,
  code interpreter and browser execution roles.
- **IAM policies** of exactly those identities (inline, attached, group), kept raw: action, resource,
  effect, whether a `Condition` is present. Conditions are flagged, never guessed. The simulator
  decides.

Then, per identity: the 64 privilege-escalation methods, AssumeRole hops through the trust graph,
and every data, secret, lateral, code-execution and model-invocation grant matched against concrete
resources. A knowledge-base bucket is always a concrete target, even behind `s3:*` on `*`, and
write access to it is reported as RAG poisoning. Anything the scanner could not read (a denied
region, a tool without an IAM identity) is a **coverage note**, never a silent pass.

`--verify` asks `iam:SimulatePrincipalPolicy` about every concrete pair, with the context an attacker
really has (no MFA on the session, TLS transport), and marks each reach `PROVEN`, `DENIED` (with the
policy layer that denied: SCP, permissions boundary) or `not asserted`. Output formats: `tree`,
`json`, `markdown`. The MCP server exposes the same report as `get_agent_blast`.

## A full scan

`cloud-audit scan` runs 110 read-only checks across 25 AWS services, correlates the findings into
attack chains, ranks the fixes by how many chains they break and prices the exposure. This is the
sample account (`cloud-audit demo`), rendered by the same code as a real scan and trimmed for length:

```
┌─────── Health Score ───────┐
│ 15 / 100                   │
└────────────────────────────┘
  Provider             AWS
  Account              123456789012
  Regions              eu-central-1
  Resources scanned    80
  Checks passed        14
  Checks failed        6
  Attack chains        3
  Risk exposure        $572K - $12.5M  (IBM/Verizon data)
┌───────────────────────── Attack Chains (3 detected) ─────────────────────────┐
│   CRITICAL      PassRole Escalation to Admin (support-bot-ticket-role)       │
│                 Principal 'support-bot-ticket-role' has iam:PassRole and     │
│                 can create resources with privileged roles via:              │
│                 PassRole+Lambda. The attacker passes an admin role to a      │
│                 service, then uses that service to execute code with admin   │
│                 privileges.                                                  │
│                 Fix: Scope iam:PassRole for 'support-bot-ticket-role' to     │
│                 specific role ARNs                                           │
│                 Risk: $250K - $5.0M                                          │
│                                                                              │
│   CRITICAL      Internet-Exposed Admin Instance                              │
│                 i-0abc123def456789, sg-0a1b2c3d4e5f67890                     │
│                 Instance i-0abc123def456789 is reachable from the internet   │
│                 via open security group and has admin IAM role               │
│                 'prod-admin-role'. An attacker can reach the instance,       │
│                 access IMDS credentials, and gain full admin access to the   │
│                 AWS account.                                                 │
│                 Fix: Restrict security group sg-0a1b2c3d4e5f67890 to         │
│                 specific IPs (effort: LOW).                                  │
│                 Risk: $62K - $625K                                           │
│                                                                              │
│   CRITICAL      CI/CD to Admin Takeover                                      │
│                 Role 'github-deploy-role' trusts an OIDC provider without    │
│                 restricting the 'sub' claim AND has admin permissions. Any   │
│                 repository on the CI/CD platform can assume this role and    │
│                 gain full AWS admin access.                                  │
│                 Fix: Add 'sub' condition to the trust policy (effort:        │
│                 LOW).                                                        │
│                 Risk: $125K - $1.2M                                          │
└──────────────────────────────────────────────────────────────────────────────┘
┌────────────── Remediation Plan (fix 3 things, break 3 chains) ───────────────┐
│    #  Fix                             Effort     Chains   Findings  Risk Red │
│    1  Restrict security groups        LOW             1          1  $62.5K - │
│    2  Add OIDC 'sub' condition to     LOW             1          1  $125K -  │
│       trust policies                                                         │
│    3  Remove IAM privilege            MEDIUM          1          1  $250K -  │
│       escalation paths                                                       │
└──────────────────────────────────────────────────────────────────────────────┘
┌─────────────────── Quick Wins (break CRITICAL chains now) ───────────────────┐
│ 1. aws ec2 revoke-security-group-ingress --group-id sg-0a1b2c3d4e5f67890     │
│ --protocol tcp --port 22 --cidr 0.0.0.0/0                                    │
│    Breaks: AC-01 (Internet-Exposed Admin Instance)                           │
│                                                                              │
│ 2. aws iam update-assume-role-policy --role-name github-deploy-role          │
│ --policy-document file://trust-with-sub.json                                 │
│    Breaks: AC-07 (CI/CD to Admin Takeover)                                   │
└──────────────────────────────────────────────────────────────────────────────┘
```

Preview a fix before touching anything. `simulate` removes the findings a check would fix and
recomputes score, chains and exposure offline:

```
$ cloud-audit simulate --report demo.json --fix aws-iam-018

Simulation: Apply Remove IAM privilege escalation paths

┌────────────────────────────── Impact Analysis ───────────────────────────────┐
│   Metric                        Before                After          Delta   │
│   Health Score                  15/100               35/100            +20   │
│   Attack Chains                      3                    2             -1   │
│   Findings                           6                    5             -1   │
│   Risk Exposure         $572K - $12.5M      $187.5K - $1.9M           -85%   │
└──────────────────────────────────────────────────────────────────────────────┘

Chains broken (1):
  CRITICAL  PassRole Escalation to Admin (support-bot-ticket-role)  -> GONE

Chains remaining (2):
  CRITICAL  Internet-Exposed Admin Instance
  CRITICAL  CI/CD to Admin Takeover

Next recommended fix: Restrict security groups -> breaks 1 more chain(s)
```

Walk outward from any resource to see what its compromise reaches:

```
$ cloud-audit blast-radius --report demo.json --resource arn:aws:iam::123456789012:role/support-bot-ticket-role

┌────────────────────────────────────── Blast Radius ──────────────────────────────────────┐
│ Compromise of role/support-bot-ticket-role leads to Account Takeover via 2 hop(s).       │
│ Resource: arn:aws:iam::123456789012:role/support-bot-ticket-role                         │
│ Reachable: 3 | Paths to impact: 1 | Risk score: 72/100                                   │
└──────────────────────────────────────────────────────────────────────────────────────────┘

role/support-bot-ticket-role - IAM Role (assumed compromised)
├── Account Takeover - Full AWS admin (via grants admin, type=exploit) <high-value>
└── arn:aws:s3:::company-backups-2024 - S3 bucket (reachable via admin) (via s3:GetObject +
    ListBucket, type=data) <high-value>

Available fixes (from scan findings):
  - aws-iam-018 Role 'support-bot-ticket-role' can escalate via PassRole+Lambda (breaks chain, effort=MEDIUM)
  - aws-s3-001 Bucket 'company-backups-2024' has Block Public Access disabled (breaks chain, effort=LOW)
```

`--format json` drops straight into the open browser visualizer at
[blast-audit.haitmg.pl](https://blast-audit.haitmg.pl/); `--format mermaid` gives a diagram for a
wiki page. `exposure` ranks every node of the security graph by internet reachability and escalation:

```
$ cloud-audit exposure --report demo.json -n 6
   Score    Type              Label                       Why
      60    iam_role          prod-admin-role             internet-reachable
      41    internet          Internet                    internet-reachable
      41    ec2               i-0abc123def456789          internet-reachable
      41    security_group    sg-0a1b2c3d4e5f67890        internet-reachable
      20    iam_role          support-bot-ticket-role     escalation
      20    iam_role          support-bot-search-role     linked to others
```

<p align="center">
  <a href="https://blast-audit.haitmg.pl/">
    <img src="assets/blast-audit-boardroom.png" alt="blast-audit visualizer - executive briefing view" width="760">
  </a>
  <br>
  <sub>The visualizer runs entirely in your browser on a <code>blast-radius --format json</code> export.</sub>
</p>

## What's inside

| Capability | Size | Command |
|---|---|---|
| Configuration checks, each with an AWS CLI and Terraform fix | **110 checks, 25 services**: IAM, S3, EC2, VPC, RDS, KMS, CloudTrail, CloudWatch, GuardDuty, Config, Lambda, ECS, EFS, SSM, Secrets Manager, DynamoDB, Backup, Inspector, Security Hub, WAF, Bedrock, SageMaker, Bedrock AgentCore, Data Perimeter, account | `scan`, `list-checks` |
| IAM privilege escalation | **64 methods in 9 categories**: IAM self-mutation, credential access, PassRole to a service, Lambda code modification, trust-policy abuse, permission-boundary bypass, resource-policy abuse, compute hijack, lateral AssumeRole (BFS over the trust graph) | `scan` (`aws-iam-018`) |
| Attack chains | **31 rules** correlating findings and live relationships (EC2 to role, Lambda to role, OIDC to policy) into paths with MITRE ATT&CK references and a priority fix | `scan` |
| Root causes and quick wins | groups findings by the fix that removes them and ranks by chains broken | `scan` |
| What-If | before/after score, chains and exposure for any set of checks, offline | `simulate --fix` |
| Blast radius | forward BFS from an EC2 instance, IAM role or user, Lambda, S3 bucket or secret; JSON contract for the visualizer | `blast-radius` |
| Exposure ranking | every security-graph node scored by internet reachability and escalation | `exposure` |
| AI agents | inventory of Bedrock Agents and AgentCore runtimes, gateways, code interpreters, browsers with their IAM identities and tools; two-threat-model reach; OWASP Agentic and MITRE ATLAS tags; simulator proof | `agent-blast` |
| Proof Mode | `iam:SimulatePrincipalPolicy` on escalation paths (broad) and on concrete (principal, action, resource) triples (agent-blast) | `scan --verify`, `agent-blast --verify` |
| Threat feed | **10 detectors** of active abuse, each tied to a documented 2025-2026 incident pattern, versioned as a rules pack | `threat-feed` |
| Data perimeter | 5 checks on resource policies: confused deputy and cross-organization exposure, evaluating condition values | `scan` (`aws-dp-*`) |
| AgentCore configuration | 6 checks: code interpreter and runtime network mode, MMDSv2, memory KMS, gateway authorizer, gateway policy engine | `scan` (`aws-agc-*`) |
| Breach cost | USD range per finding and per chain with the public source behind each number | `scan` |
| Compliance | **6 frameworks** with per-control evidence: CIS AWS v3.0, SOC 2 Type II, ISO 27001:2022, HIPAA, NIS2, BSI C5:2020 | `scan --compliance`, `list-frameworks` |
| Drift and trend | diff two scans with exit codes; posture history with sparklines | `diff`, `trend` |
| Coverage gaps | a read the scanner was denied is reported as "not assessed", never as a pass | every command |
| Outputs | console, JSON, HTML report, SARIF (GitHub Code Scanning), Markdown | `scan --format` |
| MCP server | 7 read-only tools for Claude Code, Cursor and any MCP client, including `get_agent_blast` | `cloud-audit-mcp` |

The ten threat-feed detectors, as `cloud-audit threat-feed --list` prints them (rules pack `2026-Q2`):

| Pattern | Severity | What it catches |
|---|---|---|
| TF-001 | MEDIUM | SES recently verified identity (phishing setup precursor) |
| TF-002 | HIGH | Public Lambda Function URL (`AuthType=NONE`) |
| TF-003 | CRITICAL | AWS-attached credential quarantine policy |
| TF-004 | CRITICAL | Leaked-credentials scanner user-agent observed in CloudTrail |
| TF-005 | HIGH | Recently-created IAM role with cryptomining-style compute access |
| TF-006 | HIGH | EC2 or AgentCore using IMDSv1 / MMDSv1 (SSRF credential theft vector) |
| TF-007 | MEDIUM | CI/CD role at risk of whoAMI confusion attack |
| TF-008 | HIGH | CloudTrail tampering precursor (logging stopped or delivery failing) |
| TF-009 | HIGH | IAM Roles Anywhere trust anchor with external CA |
| TF-010 | HIGH | `AmazonDataZoneFullAccess` attached to a non-admin principal |

## Proof Mode: simulated, not guessed

Static analysis of IAM policies over-reports. Proof Mode asks AWS's own authorization engine,
`iam:SimulatePrincipalPolicy`, which is read-only and carries no per-call charge.

- `scan --verify` checks every detected escalation path. `verified: true` means the simulator allowed
  every required action; `false` means it denied one (the path is very likely a false positive);
  `null` means not asserted, with the reason in `verification_detail`.
- `agent-blast --verify` checks every concrete (principal, action, resource) reach, supplies the
  context an attacker with stolen or assumed credentials has, and names the layer that denied.

What the simulator evaluates as of 2026-07-30: identity policies, the attached permissions boundary,
the organization's SCPs including their condition keys, and the context keys you supply. What it does
not: resource control policies, VPC endpoint policies, role chaining, and resource-based policies for
IAM roles. cloud-audit says so on every verified line. A `true` proves the permission exists. It does
not prove an end-to-end attack; nothing is executed.

## Reports

```bash
cloud-audit scan --format html     -o report.html     # client-ready
cloud-audit scan --format sarif    -o results.sarif   # GitHub Code Scanning
cloud-audit scan --format json     -o report.json     # machine-readable, feeds every offline command
cloud-audit scan --format markdown -o report.md       # PR comments
cloud-audit scan --compliance cis_aws_v3 --format html -o cis.html
cloud-audit agent-blast --format markdown -o agents.md
```

## CI/CD

```yaml
- run: pip install cloud-audit
- run: cloud-audit scan --format sarif --output results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

`--quiet` exits with a code only: `0` clean, `1` findings, `2` error. Gate on severity with
`--min-severity high`. `cloud-audit diff old.json new.json --quiet` exits `1` on new findings, so a
daily scan catches ClickOps drift. The repository is also a composite GitHub Action
(`gebalamariusz/cloud-audit@v0`). Ready-made workflows: [basic scan](examples/github-actions.yml),
[daily diff](examples/daily-scan-with-diff.yml), [post-deploy](examples/post-deploy-scan.yml).

## Installation

```bash
pip install cloud-audit                               # pip (recommended)
pipx install cloud-audit                              # isolated
uvx --from cloud-audit cloud-audit scan               # no install
docker run ghcr.io/gebalamariusz/cloud-audit scan     # Docker (also on Docker Hub: haitmg/cloud-audit)
```

Docker with credentials:

```bash
docker run -v ~/.aws:/home/cloudaudit/.aws:ro ghcr.io/gebalamariusz/cloud-audit scan
```

Python 3.10 to 3.13. Dependencies: boto3, typer, rich, pydantic, jinja2, pyyaml, mcp.

## AWS permissions

Read-only. Attach the AWS-managed `SecurityAudit` policy; it covers every check, the IAM escalation
analysis, the agent inventory and Proof Mode:

```bash
aws iam attach-role-policy --role-name auditor \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

cloud-audit never modifies your infrastructure. `simulate`, `blast-radius`, `exposure`, `diff`,
`trend` and `agent-blast` run locally against a saved scan and make no AWS calls; `--verify` adds
simulator calls only. Regions where a service does not exist are skipped; regions where the scanner
is denied a read are listed as coverage gaps.

## MCP server

Seven read-only tools for AI assistants: `scan_aws`, `get_findings`, `get_attack_chains`,
`get_remediation`, `get_health_score`, `list_checks`, `get_agent_blast`.

```bash
claude mcp add cloud-audit -- uvx --from cloud-audit cloud-audit-mcp
```

Then ask: *"scan my AWS account and tell me what my Bedrock agents could reach if hijacked"*.

<details>
<summary>Common flags and configuration</summary>

```bash
cloud-audit scan -R                                      # show remediation inline
cloud-audit scan --profile prod --regions eu-central-1   # profile / region
cloud-audit scan --regions all                           # all enabled regions
cloud-audit scan --role-arn arn:aws:iam::...:role/audit  # cross-account
cloud-audit scan --export-fixes fixes.sh                 # every CLI fix as a script
cloud-audit scan --categories security,cost              # skip reliability/performance checks
cloud-audit agent-blast -a support-bot --profile prod --verify
```

Defaults live in `.cloud-audit.yml` (regions, `min_severity`, `exclude_checks`, time-boxed
`suppressions`). Environment variables (`CLOUD_AUDIT_REGIONS`, `CLOUD_AUDIT_MIN_SEVERITY`, ...)
override the file; CLI flags override everything. See the
[configuration guide](https://haitmg.pl/cloud-audit/configuration/config-file/).

</details>

## Documentation

Full documentation at **[haitmg.pl/cloud-audit](https://haitmg.pl/cloud-audit/)**:
[getting started](https://haitmg.pl/cloud-audit/getting-started/installation/),
[agent-blast](https://haitmg.pl/cloud-audit/features/agent-blast/),
[attack chains](https://haitmg.pl/cloud-audit/features/attack-chains/),
[IAM escalation](https://haitmg.pl/cloud-audit/features/iam-escalation/),
[blast radius](https://haitmg.pl/cloud-audit/features/blast-radius/),
[Proof Mode](https://haitmg.pl/cloud-audit/features/proof-mode/),
[threat feed](https://haitmg.pl/cloud-audit/features/threat-feed/),
[data perimeter](https://haitmg.pl/cloud-audit/features/data-perimeter/),
[AgentCore](https://haitmg.pl/cloud-audit/features/agentcore/),
[compliance](https://haitmg.pl/cloud-audit/compliance/overview/), and the
[full check reference](https://haitmg.pl/cloud-audit/checks/).

## Commercial support

cloud-audit is free and stays free. If you want a human on the findings, the author offers
professional services:

- **Scanner output review (free)**: send your cloud-audit, Prowler or Security Hub output, get a short written review of what actually matters and what to fix first
- **AWS security audit**: full account audit with a prioritized report and ready-to-apply fixes
- **AI agent access review**: what your Bedrock and AgentCore agents can reach, with the policy changes to narrow it
- **Remediation support**: Terraform and IAM changes, verified against your workloads
- **Palo Alto VM-Series on AWS**: architecture and security review (GWLB/TGW, HA, routing)

Details: [haitmg.pl/cloud-audit-support](https://haitmg.pl/cloud-audit-support/?utm_source=github&utm_medium=readme)
or email [kontakt@haitmg.pl](mailto:kontakt@haitmg.pl).

## Development

```bash
git clone https://github.com/gebalamariusz/cloud-audit.git
cd cloud-audit
pip install -e ".[dev]"
pytest -q && ruff check src/ tests/ && mypy src/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) to add a check. Releases in [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE) - Mariusz Gebala / [HAIT](https://haitmg.pl)
