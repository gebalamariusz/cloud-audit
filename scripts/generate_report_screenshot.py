"""Generate a mock HTML report and take a screenshot for README."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cloud_audit.models import (
    Category,
    CheckResult,
    Effort,
    Finding,
    Remediation,
    ScanReport,
    Severity,
)
from cloud_audit.reports.html import render_html

# Build mock findings
findings = [
    Finding(
        check_id="aws-iam-001",
        title="Root account without MFA enabled",
        severity=Severity.CRITICAL,
        category=Category.SECURITY,
        resource_type="AWS::IAM::User",
        resource_id="arn:aws:iam::123456789012:root",
        description="Root account does not have MFA enabled. A single compromised password gives full account access.",
        recommendation="Enable MFA on the root account immediately.",
        remediation=Remediation(
            cli="aws iam create-virtual-mfa-device --virtual-mfa-device-name root-mfa --outfile /tmp/qr.png --bootstrap-method QRCodePNG",
            terraform='resource "aws_iam_virtual_mfa_device" "root" {\n  virtual_mfa_device_name = "root-mfa"\n}',
            doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html",
            effort=Effort.LOW,
        ),
        compliance_refs=["CIS 1.5"],
    ),
    Finding(
        check_id="aws-vpc-002",
        title="Security group sg-0a1b2c3d open to 0.0.0.0/0 on port 22",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        resource_type="AWS::EC2::SecurityGroup",
        resource_id="sg-0a1b2c3d4e5f67890",
        region="eu-central-1",
        description="Security group allows SSH (port 22) from 0.0.0.0/0. Any IP on the internet can attempt to connect.",
        recommendation="Restrict SSH access to specific IP ranges.",
        remediation=Remediation(
            cli="aws ec2 revoke-security-group-ingress --group-id sg-0a1b2c3d4e5f67890 --protocol tcp --port 22 --cidr 0.0.0.0/0 --region eu-central-1",
            terraform='resource "aws_security_group_rule" "ssh_restricted" {\n  type              = "ingress"\n  from_port         = 22\n  to_port           = 22\n  protocol          = "tcp"\n  cidr_blocks       = ["10.0.0.0/8"]\n  security_group_id = aws_security_group.main.id\n}',
            doc_url="https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",
            effort=Effort.LOW,
        ),
        compliance_refs=["CIS 5.2"],
    ),
    Finding(
        check_id="aws-ct-001",
        title="CloudTrail 'main-trail' is not multi-region",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        resource_type="AWS::CloudTrail::Trail",
        resource_id="main-trail",
        description="Trail 'main-trail' only logs events in its home region. Activity in other regions goes unmonitored.",
        recommendation="Enable multi-region logging on the trail.",
        remediation=Remediation(
            cli="aws cloudtrail update-trail --name main-trail --is-multi-region-trail",
            terraform='resource "aws_cloudtrail" "main" {\n  # ...\n  is_multi_region_trail = true\n}',
            doc_url="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html",
            effort=Effort.LOW,
        ),
        compliance_refs=["CIS 3.1"],
    ),
    Finding(
        check_id="aws-iam-003",
        title="Access key for 'ci-user' is 142 days old",
        severity=Severity.MEDIUM,
        category=Category.SECURITY,
        resource_type="AWS::IAM::AccessKey",
        resource_id="AKIA3EXAMPLE12345678",
        description="Access key for user 'ci-user' was created 142 days ago (threshold: 90 days).",
        recommendation="Rotate access keys every 90 days.",
        remediation=Remediation(
            cli="aws iam create-access-key --user-name ci-user && aws iam delete-access-key --user-name ci-user --access-key-id AKIA3EXAMPLE12345678",
            terraform="# Access keys are not typically managed in Terraform.\n# Rotate manually or use AWS Secrets Manager.",
            doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
            effort=Effort.LOW,
        ),
        compliance_refs=["CIS 1.14"],
    ),
    Finding(
        check_id="aws-eip-001",
        title="Unattached Elastic IP: 52.29.134.77",
        severity=Severity.LOW,
        category=Category.COST,
        resource_type="AWS::EC2::EIP",
        resource_id="eipalloc-0abc123def456",
        region="eu-central-1",
        description="Elastic IP 52.29.134.77 is not attached to any instance. Costs ~$3.65/month.",
        recommendation="Release the Elastic IP or attach it to an instance.",
        remediation=Remediation(
            cli="aws ec2 release-address --allocation-id eipalloc-0abc123def456 --region eu-central-1",
            terraform="# Remove the aws_eip resource from your Terraform config.",
            doc_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html",
            effort=Effort.LOW,
        ),
    ),
]

# Build mock check results
results = []
for f in findings:
    cr = CheckResult(check_id=f.check_id, check_name=f.title)
    cr.resources_scanned = 1
    cr.findings = [f]
    results.append(cr)

# Add some passing checks
for name in ["S3 encryption", "EBS encryption", "RDS encryption", "RDS Multi-AZ", "VPC flow logs", "GuardDuty enabled", "Config enabled", "Config recorder", "KMS key rotation", "Root usage alarm", "S3 versioning", "Public AMIs", "Default VPC", "RDS public access", "IAM users MFA", "CloudTrail bucket"]:
    cr = CheckResult(check_id="pass", check_name=name)
    cr.resources_scanned = 3
    results.append(cr)

report = ScanReport(
    provider="aws",
    account_id="123456789012",
    regions=["eu-central-1", "eu-west-1"],
    results=results,
    timestamp=datetime(2026, 3, 4, 14, 32, 0, tzinfo=timezone.utc),
    duration_seconds=11,
)
report.compute_summary()

html = render_html(report)

output_dir = Path(__file__).parent.parent / "assets"
output_dir.mkdir(exist_ok=True)
html_path = output_dir / "mock-report.html"
html_path.write_text(html, encoding="utf-8")
print(f"HTML report written to {html_path}")
print(f"Open in browser to verify, then take screenshot.")
