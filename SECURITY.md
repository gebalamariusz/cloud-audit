# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.5.x   | Yes       |
| < 0.5   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in cloud-audit, **please do not open a public issue**.

Instead, report it privately:

1. **Email:** [kontakt@haitmg.pl](mailto:kontakt@haitmg.pl)
2. **Subject:** `[SECURITY] cloud-audit vulnerability report`

Please include:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment:** Within 48 hours
- **Assessment:** Within 7 days
- **Fix release:** Within 30 days for critical issues

## Scope

The following are in scope:

- Code execution vulnerabilities in cloud-audit itself
- Dependency vulnerabilities that affect cloud-audit users
- Credential exposure or leakage through cloud-audit output

The following are out of scope:

- AWS misconfigurations found by cloud-audit (those are features, not bugs)
- Issues in upstream dependencies that don't affect cloud-audit

## Recognition

Security researchers who responsibly disclose vulnerabilities will be credited in the release notes (unless they prefer to remain anonymous).
