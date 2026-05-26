# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.3.1] - 2026-05-26

### Added

- **DynamoDB hygiene module** - new `ddb.py` module adds 3 checks covering
  production-baseline DynamoDB configuration. cloud-audit previously had zero
  DynamoDB coverage across 23 services; v2.3.1 closes that gap.

  - **`aws-ddb-001` - Encryption at rest visibility** (tiered severity).
    Surfaces tables where `SSEDescription` is absent (AWS-owned default key,
    `LOW` - encryption is on but no CloudTrail audit trail, no rotation
    control, no incident-time revocation), `InaccessibleEncryptionDateTime`
    is set (`CRITICAL` - CMK was disabled or access revoked, table will be
    archived in 7 days), or `Status != ENABLED` on a steady-state table
    (`HIGH`). AWS-managed KMS (`alias/aws/dynamodb`) and customer-managed
    CMKs both pass. The AWS Security Hub managed standard has no equivalent
    control; cloud-audit is more opinionated because compliance auditors
    (SOC 2, HIPAA, ISO 27001) typically require an auditable key.
  - **`aws-ddb-002` - Point-in-time recovery enabled** (`MEDIUM`). Matches
    AWS Security Hub `DynamoDB.2` severity. Without PITR, accidental drops
    or mass conditional-update bugs are unrecoverable except from on-demand
    backups, which require explicit scheduling.
  - **`aws-ddb-003` - Autoscaling on PROVISIONED tables** (`MEDIUM`). Matches
    AWS Security Hub `DynamoDB.1` severity. PROVISIONED billing with manual
    capacity either over-provisions (cost waste, billed 24/7) or
    under-provisions (`ProvisionedThroughputExceededException`, client
    retries amplifying load). `PAY_PER_REQUEST` tables are skipped. Read-only
    or write-only autoscaling registrations produce a sub-finding identifying
    the missing dimension.

  All three checks include CLI + Terraform remediation. Pagination via
  `list_tables`. Application Auto Scaling targets are cached per-region for
  the duration of the scan (one API call returns every DDB target in the
  region).

- **`aws-cfg-003` - AWS Config recording group complete** (`MEDIUM`). Detects
  recorders that record only a subset of resource types - either via the
  legacy `allSupported=false` configuration or the modern
  `recordingStrategy.useOnly` set to `INCLUSION_BY_RESOURCE_TYPES` or
  `EXCLUSION_BY_RESOURCE_TYPES`. Also fires when `includeGlobalResourceTypes`
  is false, which silently drops every IAM/CloudFront/Route53 change from
  the configuration timeline. Filters out service-linked recorders
  (`recordingScope=INTERNAL`).

- **`aws-cfg-004` - AWS Config delivery channel exists and is configured**
  (tiered). Reports `HIGH` when a recorder exists but no delivery channel
  is configured (snapshots and configuration history items go nowhere).
  Reports `LOW` when the delivery channel exists but is throttled to the
  slowest `TwentyFour_Hours` snapshot frequency, or when `s3KmsKeyArn` is
  not set (delivery uses SSE-S3 instead of a CMK).

### Changed

- **`aws-s3-004` - Smarter S3 lifecycle check** (community feedback). The
  prior check only fired when a bucket had zero lifecycle rules - which
  missed the most expensive anti-pattern in production: a versioning-enabled
  bucket whose lifecycle rules don't include `NoncurrentVersionExpiration`.
  Without NCVE every object overwrite or delete retains the old version at
  full storage rates indefinitely. The check now cross-references bucket
  versioning state with lifecycle rules:

  - Versioning `Enabled` or `Suspended` + no `NoncurrentVersionExpiration` in
    any enabled rule -> `MEDIUM` (the storage runaway case; matches AWS
    Security Hub `S3.10`).
  - No enabled lifecycle on an unversioned bucket -> `LOW` (existing
    behaviour preserved).
  - No `AbortIncompleteMultipartUpload` rule -> `LOW` (new sub-finding;
    orphaned multipart uploads accumulate billable storage that never
    appears in regular object listings).

  Cross-check adds one `get_bucket_versioning` call per bucket; result is
  cached implicitly via the existing bucket-list cache pattern. Backward
  compatible: same check ID, no behaviour change for unversioned buckets.

- **`aws-cfg-001` and `aws-cfg-002` - service-linked recorder filtering**.
  Both existing checks now filter out service-linked recorders
  (`recordingScope=INTERNAL`), which are created by other AWS services
  (AWS Security Hub, AWS Audit Manager) and do not replace a
  customer-managed recorder.

### Tests

- 812 -> 836 (+24 net). New test files: `tests/aws/test_ddb.py` (12 tests
  covering all four encryption states, PITR enabled/disabled, autoscaling
  with read+write/read-only/none/pay-per-request). `tests/aws/test_config.py`
  expanded with 8 new tests for `aws-cfg-003` and `aws-cfg-004`.
  `tests/aws/test_s3.py` expanded with 4 new tests for the smart lifecycle
  cross-check (versioned without NCVE, versioned with NCVE, lifecycle
  rules-but-no-NCVE, AbortMPU missing).

### Compliance

Compliance framework mappings updated to cover the new check IDs:

- **SOC 2 Type II**: `aws-cfg-003` and `aws-cfg-004` added to CC2.1, CC3.4,
  CC4.1, CC7.1, CC8.1; `aws-ddb-001` mapped to CC6.1; `aws-ddb-002` mapped
  to A1.2.
- **HIPAA Security Rule**: `aws-cfg-003` and `aws-cfg-004` added to
  164.308(a)(1)(i) and 164.308(a)(8); `aws-ddb-001` to 164.312(a)(2)(iv);
  `aws-ddb-002` to 164.308(a)(7)(i).
- **ISO/IEC 27001:2022**: `aws-cfg-003` and `aws-cfg-004` added to A.5.9,
  A.5.23, A.5.36, A.8.9, A.8.32; `aws-ddb-001` to A.8.24; `aws-ddb-002` to
  A.8.13.
- **NIS2 Directive**: `aws-cfg-003` and `aws-cfg-004` added to NIS2-RM-01b,
  NIS2-RM-05, NIS2-RM-05b, NIS2-RM-06, NIS2-RM-06b, NIS2-GOV-01;
  `aws-ddb-001` to NIS2-RM-05b.
- **BSI C5:2020**: `aws-cfg-003` and `aws-cfg-004` added to AM-01, OPS-14,
  COS-07, COS-08, INQ-03; `aws-ddb-001` to CRY-04; `aws-ddb-002` to OPS-06.
- **CIS AWS Foundations Benchmark v3.0.0**: `aws-cfg-003` and `aws-cfg-004`
  added to control 3.3. CIS v3.0.0 has no DynamoDB controls; the gap is
  documented honestly rather than invented.

### Acknowledgments

These improvements were prompted by feedback received via community channels.

### Also in this release (carried over from prior unreleased work)

- **GitHub Action hardening** - `action.yml` now pins cloud-audit to a specific
  PyPI version via the new `cloud-audit-version` input (default tracks the
  action's release tag). Previously installed unpinned `cloud-audit` latest,
  which made builds non-reproducible. Version string is validated against
  `[0-9A-Za-z.+-]` before being passed to `pip install`.

- **GitHub Action shell injection prevention** - all `run:` blocks moved from
  direct `${{ inputs.* }}` interpolation to env-var pattern (`env:` map +
  bash arrays). `extra-args`, `regions`, `output`, and `diff-baseline` are
  now passed as argv entries to `cloud-audit`, not concatenated into shell
  strings. A malicious workflow author can still pass odd flag values but
  cannot break out of the cloud-audit invocation.

- **README polish** - dropped promotional "first/only" wording in three
  places (blast-radius section, AI-SPM row, IAM Privilege Escalation row).
  PMapper row reframed from "this is its open-source replacement" to a
  factual statement of PMapper's last release date and cloud-audit's
  distinct scope. Honest tone over marketing tone.

- **README Prowler comparison refreshed** - 572 checks / 83 services / 41
  frameworks updated to 600 / 84 / 44 (verified against
  github.com/prowler-cloud/prowler on 2026-05-25). Dropped unsubstantiated
  "55 fixers" reference and "10+ providers" puffery. Footnote datestamp
  changed from "April 2026" to "2026-05-25".

- **README broken links fixed** - two relative links to
  `docs/features/blast-radius.md` (gitignored - the file is published only
  via the docs site, not committed to git) replaced with absolute URLs
  pointing at `https://haitmg.pl/cloud-audit/features/blast-radius/`.

- **docs/features/blast-radius.md** - same "first pure-CLI open-source"
  wording softened to "aims to be a lightweight CLI-native alternative".

- **SECURITY.md supported versions matrix** - stale `1.1.x` / `1.2.x` rows
  replaced with `2.3.x` (current) / `2.2.x` (security fixes only) / `< 2.2`
  (no). The matrix had not been touched since the v1.x line was current.

## [2.3.0] - 2026-05-15

### Added

- **Blast Radius CLI** - new `cloud-audit blast-radius --resource <id>` command
  that walks outward from a single AWS resource and shows what an attacker
  could reach if THAT resource were compromised. Pure in-memory analysis
  against a saved scan - zero AWS API calls at blast-radius time.

  Seed resource types supported:
  - EC2 instance (short id `i-XXX`)
  - IAM Role / IAM User (full ARN)
  - Lambda function (full ARN)
  - S3 bucket (full ARN)
  - Secrets Manager secret (full ARN)

  Expansion rules:
  - Compute -> attached IAM role (via attack chain `viz_steps` from AC-01,
    AC-02, AC-05 etc.) -> reachable identities and data
  - Identity -> admin impact node when `escalation_paths` indicate admin
  - Identity -> AssumeRole chain targets from `iam_trust_graph`
  - Identity (admin) -> S3 buckets / Secrets Manager secrets present in
    findings as candidate exfiltration targets

  Output formats (`--format`):
  - `tree` (default) - Rich tree in CLI with color-coded node types
  - `json` - BlastRadiusGraph v1.0 schema, the wire-format contract with
    cloud-audit-demo's 3D visualization (camelCase fields preserved on purpose)
  - `mermaid` - Mermaid `graph TD` diagram with per-type styling
  - `markdown` - compact summary for PRs or reports

  Bounds:
  - `--max-depth N` (default 5) caps BFS hops
  - `--max-nodes N` (default 50) caps total nodes in the graph

  Pure CLI, no Neo4j, no Docker, no SaaS account. Built on top of the
  existing `iam_trust_graph` (524 lines, AssumeRole BFS), `iam_analyzer`
  (706 lines, 60 escalation methods catalog), `correlate` (1574 lines,
  31 attack-chain rules with `VizStep`s), and `cost_model` so the
  same fixes you see in `scan` show up under the same finding ids in the
  blast-radius output. Documented in `docs/features/blast-radius.md`.

- **`exposure` command** - new `cloud-audit exposure` rolls up findings by
  blast-impact heuristic (which identities/data would compound on the next
  hop). Complements `blast-radius` (single-seed) with an account-wide view.

### Changed

- **`ScanReport.security_graph`** - new optional field (`dict[str, object] | None`).
  Populated by the scanner for blast-radius / exposure consumers. Backwards-
  compatible: existing parsers that don't know the field will keep working
  thanks to `default=None`.

### Fixed

Nine issues addressed by the pre-release security audit (`SECURITY-AUDIT-2026-05-15.md`):

- **SEC-001** - Mermaid output now HTML-entity escapes user-controlled node
  labels (`<`, `>`, `&`, `"`, `\`, plus brackets, braces, pipes). Without this,
  a crafted scan label `</text>` would break out of the Mermaid SVG context
  when the diagram is rendered in a GitHub README.
- **SEC-002** - `_make_id` collision protection: when a sanitised candidate id
  exceeds 120 chars, a SHA-256(prefix + value) suffix is appended so two
  long-but-different inputs cannot collide post-truncation (CWE-345 / CWE-1023).
- **SEC-003** - AssumeRole cycle (A->B->A) no longer re-emits the seed role
  as a lateral target node. ARN-level dedup (`visited_arns`) catches the
  cross-prefix duplicate that graph-id dedup alone misses.
- **SEC-004** - `_find_execution_role_for_lambda` now refuses to return a
  role belonging to a different function (CWE-697 narrow-match): scan with
  chain for `fnA` and query for `fnB` returns `None`, not `fnA`'s role.
- **SEC-005** - `--max-depth` and `--max-nodes` are clamped to safe bounds
  (1..25 and 1..10_000) instead of accepting unbounded user input (DoS).
- **SEC-006** - `--format tree` + `--output FILE` returns an error instead of
  silently writing ANSI escape sequences to disk (CWE-684).
- **SEC-007** - Exception handler in the CLI wraps `OSError` with a friendly
  message instead of leaking a full Python traceback to stderr.
- **SEC-008** - Rich console rendering of node lines escapes Rich markup
  (`[red]...[/]`) found inside scan labels so a crafted scan can't recolor
  the terminal output.
- **SEC-009** - Scanner persists `escalation_paths` to the saved scan so
  blast-radius can read them without re-running the IAM analyzer.

Plus pre-release follow-ups from the second security pass:

- **F-S2-01** - HTML report templates (`report.html.j2`, `compliance_html.py`)
  now strip non-`http(s)` URL schemes from `finding.cost_estimate.source_url`
  and `finding.remediation.doc_url`. Without this, a `javascript:` URL in a
  crafted scan JSON would execute when the user clicks the link in the
  rendered HTML report.
- **F-S2-02** - All `--output` writers refuse to follow pre-existing symlinks
  (TOCTOU symlink attack protection on shared CI runners). The CLI raises a
  clear error instead of silently clobbering the symlink target.
- **F-S2-03** - Markdown output (`--format markdown`) now escapes markdown
  control characters in user-controlled labels so a crafted resource name
  cannot inject `[link](javascript:...)` into the rendered report.
- **F-S2-04** - `_resolve_role_arn` falls back to `report.all_findings` when
  the role isn't present in `escalation_paths` (an EC2 with an attached
  admin role but no separate escalation path previously returned a
  seed-only blast graph - now resolves and reports Account Takeover).
- **F-S2-05** - BFS `--max-depth=1` now surfaces Account Takeover for an
  EC2 seed with an attached admin role (was off-by-one: compute->role
  linkage previously consumed the depth budget).
- **F-S2-06** - Fix/detection matching no longer uses bare `endswith(label)`
  for short labels - now requires a `/` or `:` boundary, eliminating false
  positives where label `"admin"` matched `super-admin`.

### Tests

- 786 -> 812 (+26 net). New regression tests in `tests/test_blast_radius.py`
  and `tests/test_graph.py` cover: resource-type detection (8 regex patterns),
  empty-scan seed-only behaviour, IAM role -> impact node, EC2 with attached
  role linkage, Lambda with execution role, max-depth and max-nodes
  enforcement, Rich tree render, Mermaid `graph TD` shape, JSON schema
  spot-checks (top-level fields, camelCase preservation, node + edge type
  enums), fixes and detections pulled from findings, and a full
  `TestSecurityRegression` class for SEC-001 through SEC-009.

### Schema contract

The JSON output is the schema documented in
`cloud-audit-demo/src/types/blast-radius.ts` (`BlastRadiusGraph` v1.0).
Field names are camelCase by intent because the demo's TypeScript types
are the consumer. A per-file ruff exemption in `pyproject.toml` documents
this trade-off.

## [2.2.1] - 2026-05-12

### Changed

- **TF-001 (SES phishing setup)** - severity escalation logic rewritten.
  HIGH now requires BOTH out-of-sandbox AND a burst of >=2 recent
  identity verifications in the same account scan. The previous
  "email identity without matching domain" escalation has been removed:
  it modeled the wrong attacker behaviour. Wiz's September 2025 research
  documented attackers *"adding multiple domains as verified identities
  using the CreateEmailIdentity API"* in quick succession - a burst
  pattern, not a single typosquat email. The new logic matches what
  the source incident actually documented.

- **TF-004 (leaked-creds scanner UA)** - removed `cloudgrappler` and
  `detention-dodger` from the user-agent signature list. Both are
  Permiso DEFENSIVE tools - their UA appearing in CloudTrail means a
  defender is running them against the account, not that the account
  is under attack. The detector now only matches OFFENSIVE scanner
  signatures (`trufflehog`, `gitleaks`, `noseyparker`, `secretscanner`).
  Module docstring updated with an explicit detection caveat: scanners
  using stock AWS SDK / boto3 / aws-cli default user-agents look
  identical to legitimate traffic and will not trigger this pattern.

- **TF-004 references** - replaced a fabricated TruffleHog blog URL in
  the references list with the verified BleepingComputer / Kaspersky
  May 2026 SES abuse coverage and the official TruffleHog GitHub repo.

### Tests

- 742 -> 747 (+5 net). New regression tests:
  - `test_email_no_matching_domain_does_not_escalate` (TF-001) proves
    the removed typosquat heuristic does not return.
  - `test_burst_out_of_sandbox_escalates_to_high` and
    `test_burst_in_sandbox_stays_medium` cover the new escalation rule.
  - `test_burst_only_counts_recent_identities` verifies the burst
    counter respects the 14-day window.
  - `test_cloudgrappler_ua_not_flagged` and
    `test_detention_dodger_ua_not_flagged` (TF-004) prove defensive
    tools are now excluded.

## [2.2.0] - 2026-05-12

### Added

- **Threat Feed v1** - new `cloud-audit threat-feed` command and a dedicated
  detector pipeline (`providers/aws/threat_feed/`) that flags ACTIVE abuse
  indicators rather than misconfiguration. Each pattern has a versioned
  `TF-XXX` ID, maps to the new `Category.THREAT`, and carries external
  references (research reports, CVE links) on every Finding for credibility.
  Rules pack version: **2026-Q2**.

  Ten patterns shipped:

  - `TF-001-ses-phishing-setup` (MEDIUM/HIGH) - SES email/domain identities
    verified within the last 14 days, with severity escalating when an
    out-of-sandbox account hosts a typosquat-style email identity that has
    no matching domain identity. Tracks the Wiz May 2025 + BleepingComputer
    May 2026 SES abuse campaigns.
  - `TF-002-lambda-function-url-persistence` (HIGH/CRITICAL) - Lambda
    functions exposed via `AuthType=NONE` Function URLs, escalating to
    CRITICAL when the execution role grants admin-class permissions
    (matching the role profile of the Nov-Dec 2025 cryptomining campaign).
  - `TF-003-quarantine-policy` (CRITICAL) - IAM principals with
    `AWSCompromisedKeyQuarantineV1/V2/V3` attached. AWS auto-attaches these
    after detecting credential exposure (typically a public GitHub commit).
  - `TF-004-trufflehog-ua-cloudtrail` (CRITICAL) - `sts:GetCallerIdentity`
    calls in the last 24h whose user-agent matches known leaked-credentials
    discovery scanners (TruffleHog, gitleaks, CloudGrappler, DetentionDodger,
    NoseyParker). Confirmed credential validation by an external scanner.
  - `TF-005-cryptomining-role` (HIGH/CRITICAL) - IAM roles created within
    the last 48 hours that carry broad compute managed policies (EC2 Full,
    PowerUser, Admin, ECS Full, Lambda Full). Escalates to CRITICAL when
    the same role also has SES sending permissions (mining + email-spam
    combo from the documented late-2025 campaign cluster).
  - `TF-006-mmdsv1-in-use` (HIGH/CRITICAL) - EC2 instances where
    `HttpTokens != required` (IMDSv1 still callable) and Bedrock AgentCore
    agents on `metadataVersion=v1` (CRITICAL - addresses Unit 42 'Cracks in
    the Bedrock' research and the Feb 2026 MMDSv2 default).
  - `TF-007-whoami-confusion` (MEDIUM) - IAM roles trusted by CI/CD
    identities (codebuild service principals, GitHub OIDC, GitLab OIDC,
    Buildkite federation) that have a broad EC2 managed policy attached -
    the precondition for the Datadog Feb 2025 whoAMI confusion attack.
  - `TF-008-cloudtrail-tampering` (HIGH/CRITICAL) - CloudTrail trails with
    `IsLogging=False` (CRITICAL - canonical post-credential-theft attacker
    behaviour, AiTM phishing follow-on per Datadog March 2026) or with a
    populated `LatestDeliveryError` (HIGH - S3 destination broken).
  - `TF-009-roles-anywhere-abuse` (HIGH/MEDIUM) - IAM Roles Anywhere trust
    anchors with `sourceType=CERTIFICATE_BUNDLE` instead of the recommended
    AWS_ACM_PCA. Anyone able to issue a chain-valid cert can mint AWS
    credentials (fwd:cloudsec 2025 'Let's Encrypt for AWS Console').
  - `TF-010-datazone-overgrant` (HIGH) - `AmazonDataZoneFullAccess` attached
    to non-admin principals (the "easy" onboarding policy that bridges
    identity, Glue catalog, and S3 storage in a single grant).

  CLI: `cloud-audit threat-feed [--list] [--pattern <id>] [--regions ...]
  [--profile ...] [--threat-feed-version 2026-Q2]`. Exits 1 when CRITICAL
  or HIGH detected (CI gate friendly). Patterns also surface in standard
  `cloud-audit scan --categories threat` output (JSON, SARIF, HTML).

### Changed

- `Category` enum gains `THREAT` value for active-abuse findings (separate
  from `SECURITY` misconfiguration).
- `Finding` model gains `threat_pattern_id: str | None` and
  `references: list[str]` for backing research links.
- 23rd registered AWS check module (`threat_feed`) loaded by `AWSProvider`.

### Tests

- 638 -> 742 (+104). Each pattern ships 9-12 unit tests covering positive
  detection, negative cases, false-positive guards, severity escalation,
  multi-resource aggregation, AccessDenied resilience, and metadata
  exposure.

## [2.1.0] - 2026-04-28

### Added

- **IAM Privilege Escalation - Tier 1 + Tier 2 + Tier 3**: 39 new detection methods, total 64 across 9 categories (was 25/6). Coverage of all known IAM privilege escalation paths in pathfinding.cloud.

  Tier 1 (20 methods - PassRole variants + resource policy abuse + deny removal):
  - PassRole + Glue variants: `glue:CreateJob`, `glue:UpdateJob`, `glue:CreateSession`
  - PassRole + ECS variants: `ecs:UpdateService`, `ecs:RegisterTaskDefinition` (auto-deploy)
  - PassRole + CloudFormation: `cloudformation:UpdateStack`
  - PassRole + EC2 instance profile hijack: `ec2:AssociateIamInstanceProfile`, `ec2:ReplaceIamInstanceProfileAssociation`
  - PassRole + Lambda event source mapping
  - Instance profile role swap (no PassRole): `iam:RemoveRoleFromInstanceProfile` + `iam:AddRoleToInstanceProfile`
  - **NEW Resource Policy Abuse category**: `lambda:AddPermission`, `lambda:AddLayerVersionPermission`
  - IAM deny-removal patterns: `iam:DeleteRolePolicy`, `iam:DeleteUserPolicy`, `iam:DetachRolePolicy`, `iam:DetachUserPolicy`, `iam:CreateServiceLinkedRole`
  - Credential access extensions: `iam:UpdateAccessKey`, `iam:DeactivateMFADevice`, `iam:DeleteVirtualMFADevice` (MFA bypass paths)

  Tier 2 (12 methods - new compute primitives + SSM):
  - PassRole + new services: `codebuild:CreateProject`, `apprunner:CreateService`, `sagemaker:CreateNotebookInstance`, `sagemaker:CreateProcessingJob`, `bedrock:CreateAgent`, `states:CreateStateMachine`
  - **NEW Compute Hijack category**: `ssm:SendCommand`, `ssm:StartSession` (managed EC2 abuse), `ec2-instance-connect:SendSSHPublicKey` (60s SSH key push), `codebuild:UpdateProject` (hijack existing CI build), `apprunner:UpdateService` (replace running container)
  - Credential access extension: `ssm:GetParameter` (read secrets from Parameter Store)

  Tier 3 (4 methods - lateral movement via AssumeRole graph - NEW pipeline):
  - **NEW Lateral AssumeRole category** with new module `iam_trust_graph.py` parsing `AssumeRolePolicyDocument` and building a directed graph
  - `AssumeRole:Direct` - 1-hop assume from a principal to a role with admin permissions
  - `AssumeRole:Chain` - multi-hop assume chain (up to 4 hops) ending at admin
  - `AssumeRole:WildcardTrust` - any role with `Principal: "*"` trust policy
  - `AssumeRole:CrossAccountRoot` - any role trusting external account `:root`
  - Same-account root expansion: roles trusting `arn:aws:iam::SAME:root` are reachable by any principal in account with `sts:AssumeRole`
  - Bare 12-digit account IDs are normalized to `:root` ARNs
  - Trust conditions (MFA / ExternalId / SourceArn) are flagged but not semantically evaluated

## [2.0.1] - 2026-04-17

### Changed

- Canonical project Homepage in PyPI metadata now points to https://haitmg.pl/cloud-audit/ (was the GitHub repo URL). GitHub remains linked via the `Source` and `Repository` fields. No code changes.

## [2.0.0] - 2026-04-14

### Added

- **IAM Privilege Escalation Detection** - 25 escalation methods across 6 categories (IAM self-mutation, credential access, PassRole+service, Lambda code modification, trust policy abuse, permission boundary bypass). Replaces dead PMapper as the only maintained open-source IAM escalation scanner
- **What-If Remediation Simulator** - `cloud-audit simulate --fix aws-vpc-002` shows before/after impact on score, chains, and risk without changing anything in AWS
- **Security Posture Trend** - `cloud-audit trend` tracks health score, attack chains, and risk over time with sparkline visualization. Scan history auto-saved to `~/.cloud-audit/history/`
- **AI-SPM (Bedrock + SageMaker)** - 5 new checks: model invocation logging (aws-bedrock-001), guardrails (aws-bedrock-002), notebook root access (aws-sagemaker-001), notebook internet access (aws-sagemaker-002), endpoint encryption (aws-sagemaker-003)
- **Root Cause Grouping** - "fix 4 things, break 22 chains" prioritization. Groups findings by root cause and ranks by chain-breaking impact
- **Quick Wins** - CLI section showing LOW-effort fixes that break CRITICAL chains, with copy-paste commands
- **6 new attack chain rules** - AC-34 (PassRole escalation), AC-35 (IAM self-escalation), AC-36 (OIDC + escalation), AC-37 (AI model theft), AC-38 (LLMjacking), AC-39 (AI data poisoning)
- Compliance Beta labels for BSI C5, ISO 27001, HIPAA, NIS2 (CIS and SOC 2 remain Stable)
- `list-frameworks` shows Status column (Stable/Beta)

### Changed

- Remediation CLI commands now inject real AWS account ID (via `provider.get_account_id()`) instead of `ACCOUNT_ID` placeholders
- Terraform remediation snippets completed with missing dependent resources (IAM roles, S3 buckets, KMS keys, CloudWatch log groups)
- VPC flow logs Terraform scoped IAM policy to specific log group ARN (was `Resource: *`)
- `get_account_id()` cached in AWSProvider (1 STS call instead of 10+ per scan)
- Root cause computation moved after cost estimation (fixes risk aggregation)
- `get_account_id()` calls moved inside try/except in kms, iam, s3 checks

### Fixed

- Unicode characters (arrows, em-dashes, block characters) replaced with ASCII for Windows cp1250 compatibility

## [1.3.0] - 2026-04-03

### Added

- **BSI C5:2020 compliance framework** - 134 Cloud Computing Compliance Criteria mapped (20 automated, 37 partial, 77 manual), covering all 17 BSI domains (OIS, SP, HR, AM, PS, OPS, IDM, CRY, COM, PI, DEV, SIM, BCM, COS, INQ, PSS, LOG)
- **ISO/IEC 27001:2022 compliance framework** - 93 Annex A controls mapped (16 automated, 31 partial, 46 manual), covering Organizational (A.5), People (A.6), Physical (A.7), and Technological (A.8) controls
- **HIPAA Security Rule compliance framework** - 47 implementation specifications mapped (15 automated, 14 partial, 18 manual) across Administrative (§164.308), Physical (§164.310), and Technical (§164.312) safeguards
- **NIS2 Directive compliance framework** - 43 technical measures mapped (11 automated, 22 partial, 10 manual) covering Article 21(2)(a)-(j) minimum measures, Article 23 incident reporting, and Article 20 governance
- `--compliance bsi_c5_2020` CLI flag - BSI C5:2020 readiness assessment
- `--compliance iso27001_2022` CLI flag - ISO 27001:2022 Annex A readiness assessment
- `--compliance hipaa_security` CLI flag - HIPAA Security Rule readiness assessment
- `--compliance nis2_directive` CLI flag - NIS2 Directive readiness assessment
- All 20 attack chain rules mapped to controls in each new framework
- **8 new security checks** (80 -> 88 total):
  - `aws-backup-001` - AWS Backup vault with backup plan (Backup)
  - `aws-inspector-001` - Amazon Inspector v2 enabled (Inspector)
  - `aws-waf-001` - WAFv2 WebACL exists (WAF)
  - `aws-cw-016` - CloudWatch log group KMS encryption (CloudWatch)
  - `aws-ssm-003` - EC2 patch compliance via SSM (SSM)
  - `aws-vpc-006` - VPC subnet isolation (VPC)
  - `aws-iam-017` - IAM role max session duration (IAM)
  - `aws-ct-008` - CloudTrail delivers to CloudWatch Logs (CloudTrail)
- **5 new attack chain rules** (20 -> 25 total):
  - AC-29: Unpatched Instance Exposed to Internet (CRITICAL)
  - AC-30: Unpatched Instances Without Vulnerability Scanning (HIGH)
  - AC-31: Internet-Exposed Without WAF or Flow Logs (HIGH)
  - AC-32: CloudTrail Blind Spot - Alarms Non-Functional (HIGH)
  - AC-33: All-Public VPC Without Network Segmentation (HIGH)
- 3 new service modules: AWS Backup, Amazon Inspector, AWS WAF
- 67 new tests for framework validation (412 total)

### Changed

- Check count: 80 -> 88 across 21 AWS services (was 18)
- Attack chain count: 20 -> 25 rules
- `list-frameworks` now shows 6 frameworks (was 2)
- CLI help text updated with all 6 framework IDs
- pyproject.toml description updated to reflect 6 compliance frameworks
- 21 CIS controls corrected from Manual to Partial (had automated checks but wrong assessment type)

## [1.2.2] - 2026-04-01

### Added

- Parallel check execution via ThreadPoolExecutor for faster scans on large accounts
- Wildcard pattern support in suppressions (`aws-iam-*`, `arn:aws:*:*:*:role/deploy-*`)
- Debug logging in attack chain correlation engine for diagnosing collection failures
- Makefile with `make all` (lint + format + typecheck + test), `make test-cov`, `make security`
- `provider.client()` method with boto3 adaptive retry (max 5 attempts) and per-service client caching
- `_region_overlap()` helper for shared region-matching logic in attack chain rules
- 7 new tests for attack chains AC-25, AC-26, AC-27 and wildcard suppressions (345 total)

### Changed

- Thread-safe module-level caches in S3 and CloudTrail checks (threading.Lock)
- Cache reset abstracted into `BaseProvider.reset_caches()` (was hardcoded S3-only import)
- Scanner enforces canonical check_id from make_check metadata (single source of truth)
- `compute_summary()` optimized to single pass over findings (was 5+ iterations)
- IAM checks migrated to `provider.client()` for adaptive retry and client caching
- Demo command updated to show 80 checks (was 47)

### Fixed

- SARIF `artifactLocation.uri` now uses valid relative URI format (`checks/{check_id}`)
- Progress bar no longer advances past 100% in interactive mode
- Documentation URL in pyproject.toml points to docs site instead of GitHub README

## [1.2.1] - 2026-04-01

### Added

- **Attack chain visualization** in HTML reports - interactive SVG graphs showing attack paths with node-and-edge diagrams, color-coded by resource type (compute, identity, network, storage), animated edges, and glow effects on entry/impact nodes
- `VizStep` model with `Literal` type validation for node types
- 3 new tests for viz_steps validation (structure, types, edge labels)
- `viz_steps` field on `AttackChain` model (backward compatible, defaults to empty list)

### Changed

- `VizStep.type` constrained to Literal type (internet, compute, identity, network, storage, finding, impact) with Pydantic validation
- Attack chain cards in HTML report now have header/graph/body layout instead of flat text
- Sub-labels in visualization truncated to 22 characters to prevent overflow
- ROADMAP.md merged duplicate v1.3.0 sections into single entry
- SOC 2 docs clarified Automated column includes partially automated criteria

### Fixed

- Long resource IDs in visualization labels truncated to prevent SVG overflow

## [1.2.0] - 2026-04-01

### Added

- **SOC 2 Type II compliance framework** - 43 Trust Services Criteria mapped (AICPA 2017, revised 2022), 24 automated, 19 manual
- `--compliance soc2_type2` CLI flag - run SOC 2 readiness assessment alongside security scan
- SOC 2 compliance HTML and Markdown reports with per-control PASS/FAIL, evidence statements, and remediation
- 78 of 80 checks mapped to SOC 2 criteria across 12 categories (CC1-CC9, A1, C1, PI1)
- 20 attack chain rules mapped to SOC 2 controls they would violate
- SOC 2 documentation page in MkDocs site
- 32 new tests for SOC 2 framework validation

### Changed

- `--compliance` help text now references both `cis_aws_v3` and `soc2_type2`
- `show-framework` help text updated with SOC 2 example
- Compliance overview docs updated with SOC 2 as available

## [1.1.0] - 2026-03-27

### Added

- **CIS AWS Foundations Benchmark v3.0.0 compliance engine** - 62 controls mapped, 55 fully automated, per-control evidence templates, readiness scoring
- `--compliance cis_aws_v3` CLI flag - run compliance assessment alongside security scan
- `list-frameworks` command - show available compliance frameworks
- `show-framework` command - display control mappings without scanning
- Compliance HTML report - auditor-ready, per-control PASS/FAIL with evidence statements, remediation (CLI + Terraform), and attack chain violations
- Compliance Markdown report - same data for PR comments and documentation
- **33 new security checks** (47 -> 80 total) covering CIS v3.0 requirements:
  - IAM: root access keys (1.4), multiple active keys (1.13), direct user policies (1.15), support role (1.17), IAM Access Analyzer (1.20), expired certificates (1.19), CloudShell access (1.22), hardware MFA for root (1.6), EC2 instance roles (1.18)
  - S3: deny HTTP policy (2.1.1), MFA Delete (2.1.2)
  - VPC: default security group restricts all traffic (5.4), NACL admin port detection (5.1)
  - CloudTrail: S3 bucket access logging (3.4), KMS encryption (3.5), S3 object-level write logging (3.8), S3 object-level read logging (3.9)
  - CloudWatch: 14 CIS Section 4 monitoring checks (4.1-4.2, 4.4-4.15) using metric filter + alarm detection
  - EFS: encryption at rest (2.4.1)
  - Security Hub: enabled check (4.16)
  - Account: security alternate contact (1.2)
- **4 new attack chain rules** (16 -> 20 total):
  - AC-25: Root Access Keys Without Audit Trail
  - AC-26: Unmonitored Admin Escalation Path
  - AC-27: Default Network Access Without Logging
  - AC-28: External Access Without Analysis
- **3 new AWS service modules**: Account, EFS, Security Hub
- CloudTrail API call cache (7 -> 1 API call per scan for trail listing)
- MkDocs Material documentation site (25 pages) at haitmg.pl/cloud-audit/
- CIS control-to-attack-chain mapping (20 chains mapped to specific CIS controls)

### Changed

- Check count: 47 -> 80 across 18 AWS services (was 15)
- Attack chains: 16 -> 20 rules
- CIS coverage: 16 controls -> 62 controls (100% of automatable recommendations)
- `aws-iam-004` threshold changed from 30 to 45 days (CIS 1.12 compliance)
- `aws-iam-006` now validates password reuse prevention >= 24 (CIS 1.9)
- `aws-vpc-004` now detects admin ports (22, 3389) specifically (CIS 5.1)
- `aws-ct-003` compliance_refs cleared (CIS 3.3 removed in v3.0)
- `aws-iam-002` compliance_refs corrected from CIS 1.4 to CIS 1.10
- AccessDenied handling improved in check_support_role, check_iam_access_analyzer, check_cloudshell_access
- README.md fully rewritten with updated numbers and documentation links

### Fixed

- S3 deny HTTP check CLI remediation was a tuple instead of string (trailing comma)
- CloudTrail bucket access logging CLI remediation same issue
- S3 Advanced Event Selector parsing now validates resources.type = AWS::S3::Object
- Errored checks no longer counted as "passed" in compliance engine

## [1.0.1] - 2026-03-24

### Changed

- MCP is now a regular dependency (not optional) - install with `uvx cloud-audit-mcp`
- Updated pyproject.toml description and keywords for MCP discoverability

## [1.0.0] - 2026-03-24

### Added

- **Breach cost estimation** - every finding and attack chain includes an estimated financial risk range (low/high USD) based on IBM Cost of a Data Breach 2024, Verizon DBIR, and published enforcement actions
- Total risk exposure displayed in scan summary, CLI output, HTML report, and markdown report
- Attack chain cost estimates use a compound risk multiplier (chained vulnerabilities have higher impact)
- New `CostEstimateData` model for structured cost data in JSON output
- **MCP Server** - Model Context Protocol server for AI agent integration (Claude Code, Cursor, VS Code Copilot)
- 6 MCP tools: `scan_aws`, `get_findings`, `get_attack_chains`, `get_remediation`, `get_health_score`, `list_checks`
- One-liner install: `claude mcp add cloud-audit -- uvx cloud-audit-mcp`
- `cloud-audit-mcp` entry point for uvx/pipx
- `.mcp.json` project configuration for team-wide MCP setup
- `mcp` included as regular dependency (no extras needed)

### Changed

- Health Score panel now shows "Risk exposure: $X - $Y" when findings are present
- Attack chain display in CLI includes per-chain cost estimates
- Markdown report header includes total risk exposure
- Markdown attack chain table shows cost column instead of narrative
- Development Status classifier changed from Alpha to Beta

## [0.9.1] - 2026-03-19

### Added

- **GitHub Action** - reusable composite action for CI/CD (`gebalamariusz/cloud-audit@v0`) with SARIF upload, OIDC auth, and diff baseline support
- **pre-commit hooks** - `cloud-audit` and `cloud-audit-diff` hooks for the pre-commit framework (pre-push stage)
- GitHub Sponsors funding link
- YouTube demo video embedded in README

### Changed

- Lambda deprecated runtimes list extended with EOL dates (community contribution by @P-r-e-m-i-u-m, PR #18)
- GitHub Actions bumped: checkout v6, codeql-action v4, configure-aws-credentials v6

## [0.9.0] - 2026-03-18

### Added

- **Attack chain detection** - 16 rules correlating findings into exploitable multi-service attack paths
- Attack chains output in terminal (Rich panel), HTML report, markdown, and JSON
- Resource relationship collector (EC2->IAM role, Lambda->role, OIDC->policies)
- 4 attack chain tiers: Internet Exposure + Privilege, Missing Controls, Data Protection, Container/Secrets + CI/CD
- Rules based on MITRE ATT&CK Cloud Matrix, Datadog pathfinding.cloud, and AWS CIRT Threat Catalog
- New check: `aws-iam-007` - OIDC trust policy without sub condition (CRITICAL)
- New check: `aws-ec2-006` - EBS default encryption disabled (MEDIUM)
- Enhanced HTML report: executive summary, priority grouping (Fix Now/This Week/Next Sprint), CIS pass/fail indicators
- Logo added to README and HTML report
- Pre-commit hook for ruff format

### Changed

- Check count: 45 -> 47
- README: Attack Chains as primary feature, logo, updated tagline
- ROADMAP: v0.9.0 Attack Chains milestone added

### Fixed

- False-confidence tests: ECS exec (mocked), secrets unused (mocked), config recorder assertion
- New test scenarios: IPv6 ::/0 SG, RDP port 3389, multi-provider attack chains
- SECURITY.md: supported version updated to 0.8.x
- Bug report template: added WSL/Other OS options

## [0.8.0] - 2026-03-14

### Added

- `cloud-audit diff` command - compare two scan JSON files, show new/fixed/changed findings
- Diff output formats: terminal (Rich), markdown (`--format markdown`), JSON (`--format json`)
- Diff exit codes: 0 = no new findings, 1 = regression detected, 2 = error
- Scope warnings when comparing scans from different regions or accounts
- File size limit (50 MB) and `is_file()` validation on diff inputs
- Rich markup escaping for user-controlled strings in diff output
- Format auto-detection from `--output` file extension in diff command
- CI/CD example: `examples/daily-scan-with-diff.yml` (scheduled daily scan with cache-based baseline)
- CI/CD example: `examples/post-deploy-scan.yml` (pre/post terraform apply comparison)
- 35 new tests for diff engine, markdown output, and CLI integration
- 213 tests passing total

### Changed

- `unchanged_count` replaced with `unchanged_findings` list (shows what stayed the same)
- README: added "Track changes between scans" section with diff usage
- README: CI/CD section expanded with table of ready-to-use workflows
- README: S3 encryption check updated to reflect SSE-KMS vs SSE-S3 pivot (LOW severity)
- README: severity counts updated (7/14/16/8)

## [0.7.0] - 2026-03-14

### Changed

- SARIF: use `physicalLocation` + `logicalLocations` (fixes GitHub Code Scanning compatibility)
- SARIF: add `help.markdown` to rules (remediation now visible in GitHub Security tab)
- SARIF: add `semanticVersion` to tool driver
- S3 encryption check pivoted: SSE-S3 (AES-256) is now LOW severity, SSE-KMS = PASS (AWS auto-encrypts since Jan 2023)
- Markdown: escape pipes and newlines in all table columns
- Markdown: round duration to 1 decimal place
- HTML report: duration formatted consistently (1 decimal)
- HTML report: ARIA attributes on score ring (`role="meter"`) and severity badges
- Imports moved to top level in HTML report renderer
- Ruff: enabled `RUF`, `PIE`, `RET` rule groups; `S101` now per-file for tests only

### Fixed

- SARIF `physicalLocation` missing caused GitHub Code Scanning to reject uploads
- S3 encryption check false positives on buckets using default SSE-S3
- Extracted `_kms_encryption_remediation()` helper (DRY)

### Tests

- 179 tests passing (+5 new)
- New SARIF tests: `semanticVersion`, `help.markdown`, `logicalLocations`, `physicalLocation`
- New S3 tests: SSE-KMS pass, SSE-S3 LOW with compliance_refs, DSSE-KMS pass

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

[Unreleased]: https://github.com/gebalamariusz/cloud-audit/compare/v2.3.1...HEAD
[2.3.1]: https://github.com/gebalamariusz/cloud-audit/compare/v2.3.0...v2.3.1
[1.3.0]: https://github.com/gebalamariusz/cloud-audit/compare/v1.2.2...v1.3.0
[1.2.2]: https://github.com/gebalamariusz/cloud-audit/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/gebalamariusz/cloud-audit/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/gebalamariusz/cloud-audit/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/gebalamariusz/cloud-audit/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/gebalamariusz/cloud-audit/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/gebalamariusz/cloud-audit/compare/v0.9.1...v1.0.0
[0.9.1]: https://github.com/gebalamariusz/cloud-audit/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/gebalamariusz/cloud-audit/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/gebalamariusz/cloud-audit/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/gebalamariusz/cloud-audit/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/gebalamariusz/cloud-audit/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/gebalamariusz/cloud-audit/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/gebalamariusz/cloud-audit/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/gebalamariusz/cloud-audit/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/gebalamariusz/cloud-audit/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/gebalamariusz/cloud-audit/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/gebalamariusz/cloud-audit/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/gebalamariusz/cloud-audit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/gebalamariusz/cloud-audit/releases/tag/v0.1.0
