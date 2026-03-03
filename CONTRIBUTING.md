# Contributing to cloud-audit

Thank you for your interest in contributing to cloud-audit! This document provides guidelines and instructions for contributing.

## How to Contribute

1. **Fork** the repository
2. **Create a branch** from `main` for your changes
3. **Make your changes** following the guidelines below
4. **Run checks** to ensure code quality
5. **Submit a pull request** to `main`

## Development Setup

```bash
git clone https://github.com/<your-username>/cloud-audit.git
cd cloud-audit
pip install -e ".[dev]"
```

## Code Quality Checks

Before submitting a PR, make sure all checks pass:

```bash
# Lint
ruff check src/ tests/

# Format
ruff format --check src/ tests/

# Type check
mypy src/

# Tests
pytest -v
```

## Adding a New AWS Check

This is the most common contribution. Follow these steps:

### 1. Create or edit a check module

Check modules live in `src/cloud_audit/providers/aws/checks/`. Each module covers one AWS service.

```python
# src/cloud_audit/providers/aws/checks/cloudtrail.py

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Finding, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider


def check_cloudtrail_enabled(provider: AWSProvider) -> CheckResult:
    """Check if CloudTrail is enabled with multi-region logging."""
    result = CheckResult(
        check_id="aws-ct-001",
        check_name="CloudTrail enabled",
    )

    client = provider.session.client("cloudtrail")
    trails = client.describe_trails()["trailList"]
    result.resources_scanned = len(trails)

    # ... check logic ...

    return result


def get_checks(provider: AWSProvider) -> list[partial[CheckResult]]:
    checks = [
        partial(check_cloudtrail_enabled, provider),
    ]
    for check in checks:
        check.category = Category.SECURITY  # type: ignore[attr-defined]
    return checks
```

### 2. Register the module

Add the module name to `_CHECK_MODULES` in `src/cloud_audit/providers/aws/provider.py`:

```python
_CHECK_MODULES = [
    "iam", "s3", "ec2", "vpc", "rds", "eip",
    "cloudtrail",  # <-- add here
]
```

### 3. Add tests

Write tests using moto for AWS mocking:

```python
# tests/unit/aws/test_cloudtrail.py

import boto3
from moto import mock_aws

def test_cloudtrail_enabled_pass():
    """CloudTrail enabled should produce no findings."""
    with mock_aws():
        # Setup: create a trail
        client = boto3.client("cloudtrail", region_name="eu-central-1")
        client.create_trail(Name="main", S3BucketName="logs")
        client.start_logging(Name="main")

        # Run check and assert no findings
        ...

def test_cloudtrail_enabled_fail():
    """No CloudTrail should produce a CRITICAL finding."""
    with mock_aws():
        # No trails created
        # Run check and assert finding exists
        ...
```

### 4. Update documentation

- Add the check to the table in `README.md`
- Add the check to `CHANGELOG.md` under `[Unreleased]`

### 5. Submit

Run all checks, then open a pull request.

## Check Design Guidelines

Every check in cloud-audit must follow these principles:

1. **High-signal only** - Would an attacker exploit this? If not, don't add it.
2. **Clear severity** - CRITICAL means "fix today", LOW means "nice to have".
3. **Actionable recommendation** - Tell the user exactly what to do, not "consider enabling encryption".
4. **Tested** - Every check needs at least one PASS and one FAIL test case.

## Code Conventions

- **Python 3.10+** - Use `from __future__ import annotations` in every file
- **Pydantic v2** - All data models use Pydantic with immutable config
- **Ruff** - Handles both linting and formatting (config in `pyproject.toml`)
- **mypy strict** - All code must pass `mypy --strict`
- **Line length** - 120 characters max

## Reporting Bugs

Use the [bug report template](https://github.com/gebalamariusz/cloud-audit/issues/new?template=bug_report.yml) on GitHub.

## Suggesting Features

Use the [feature request template](https://github.com/gebalamariusz/cloud-audit/issues/new?template=feature_request.yml) on GitHub.

## Security Vulnerabilities

**Do not open a public issue.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
