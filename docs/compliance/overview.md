# Compliance

cloud-audit includes a built-in compliance engine that maps scan findings to specific compliance framework controls. Each control gets a PASS/FAIL/PARTIAL assessment with evidence statements and per-control remediation.

## Supported Frameworks

| Framework | Status | Controls | Automated |
|-----------|--------|----------|-----------|
| [CIS AWS v3.0](cis-aws-v3.md) | Stable | 62 | 55 (89%) |
| [SOC 2 Type II](soc2-type2.md) | Stable | 43 | 24 (56%) |
| [ISO 27001:2022](iso27001-2022.md) | Beta | 93 | 48 (52%) |
| [BSI C5:2020](bsi-c5-2020.md) | Beta | 134 | 76 (57%) |
| [HIPAA Security Rule](hipaa-security.md) | Beta | 47 | 28 (60%) |
| [NIS2 Directive](nis2-directive.md) | Beta | 43 | 26 (60%) |

## How It Works

1. cloud-audit runs all 94 checks against your AWS account
2. The compliance engine maps findings to framework controls
3. Each control gets a status: PASS, FAIL, PARTIAL, or NOT_ASSESSED
4. Evidence statements are generated per control
5. A readiness score shows your compliance posture

## Compliance Output

The compliance report includes:

- **Readiness score** - percentage of assessed controls passing
- **Per-control status** - PASS/FAIL with evidence statements
- **Attack chain violations** - which chains violate which controls
- **Remediation per control** - AWS CLI + Terraform code grouped by control
- **Manual review items** - controls that require human verification

!!! note "Compliance is not certification"
    cloud-audit generates evidence and readiness assessments. It does not constitute official compliance certification. Work with a qualified auditor for formal assessments.

## Architecture

Compliance mappings are stored as JSON files in `src/cloud_audit/compliance/frameworks/`. Each file maps cloud-audit check IDs to framework controls with evidence templates and remediation context.

Community contributions of new framework mappings are welcome. See [Contributing](../contributing.md).
