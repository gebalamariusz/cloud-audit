"""VPC security checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_audit.models import Category, CheckResult, Effort, Finding, Remediation, Severity

if TYPE_CHECKING:
    from cloud_audit.providers.aws.provider import AWSProvider
    from cloud_audit.providers.base import CheckFn


def check_default_vpc_in_use(provider: AWSProvider) -> CheckResult:
    """Check if the default VPC has any resources."""
    result = CheckResult(check_id="aws-vpc-001", check_name="Default VPC usage")

    try:
        for region in provider.regions:
            ec2 = provider.session.client("ec2", region_name=region)
            vpcs = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"]

            for vpc in vpcs:
                vpc_id = vpc["VpcId"]
                result.resources_scanned += 1

                # Check if any ENIs exist in the default VPC (indicates resources are using it)
                enis = ec2.describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
                    "NetworkInterfaces"
                ]

                if enis:
                    eni_count = len(enis)
                    count_prefix = "at least " if eni_count >= 1000 else ""
                    result.findings.append(
                        Finding(
                            check_id="aws-vpc-001",
                            title=f"Default VPC in {region} has {count_prefix}{eni_count} network interface(s)",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            resource_type="AWS::EC2::VPC",
                            resource_id=vpc_id,
                            region=region,
                            description=f"The default VPC ({vpc_id}) in {region} has active resources. Default VPCs have overly permissive networking defaults.",
                            recommendation="Migrate resources to a custom VPC with proper network segmentation and security groups.",
                            remediation=Remediation(
                                cli=(
                                    f"# WARNING: Ensure no resources depend on the default VPC first!\n"
                                    f"# Migrate resources to a custom VPC, then:\n"
                                    f"aws ec2 delete-default-vpc --region {region}\n"
                                    f"# Note: Default VPC can be recreated with:\n"
                                    f"aws ec2 create-default-vpc --region {region}"
                                ),
                                terraform=(
                                    "# Create a custom VPC with proper network segmentation:\n"
                                    'resource "aws_vpc" "main" {\n'
                                    '  cidr_block           = "10.0.0.0/16"\n'
                                    "  enable_dns_hostnames = true\n"
                                    "  enable_dns_support   = true\n"
                                    "}"
                                ),
                                doc_url="https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html",
                                effort=Effort.HIGH,
                            ),
                            compliance_refs=["CIS 5.3"],
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def check_open_security_groups(provider: AWSProvider) -> CheckResult:
    """Check for security groups with unrestricted inbound access (0.0.0.0/0)."""
    result = CheckResult(check_id="aws-vpc-002", check_name="Open security groups")

    # Ports that should never be open to the internet
    sensitive_ports = {
        22: "SSH",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "MSSQL",
        6379: "Redis",
        27017: "MongoDB",
        9200: "Elasticsearch",
        5601: "Kibana",
    }

    try:
        for region in provider.regions:
            ec2 = provider.session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_security_groups")

            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    sg_id = sg["GroupId"]
                    sg_name = sg["GroupName"]
                    result.resources_scanned += 1

                    for rule in sg.get("IpPermissions", []):
                        from_port = rule.get("FromPort", 0)
                        to_port = rule.get("ToPort", 65535)

                        # Collect all open CIDRs (IPv4 + IPv6)
                        open_cidrs: list[str] = []
                        for ip_range in rule.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                open_cidrs.append("0.0.0.0/0")
                        for ipv6_range in rule.get("Ipv6Ranges", []):
                            if ipv6_range.get("CidrIpv6") == "::/0":
                                open_cidrs.append("::/0")

                        if not open_cidrs:
                            continue

                        cidr_display = ", ".join(open_cidrs)

                        # Check if all traffic is allowed
                        if rule.get("IpProtocol") == "-1":
                            # Build revoke commands for each open CIDR (IPv4 and IPv6 separately)
                            revoke_cmds = []
                            if "0.0.0.0/0" in open_cidrs:
                                revoke_cmds.append(
                                    f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol -1 --cidr 0.0.0.0/0 --region {region}"
                                )
                            if "::/0" in open_cidrs:
                                revoke_cmds.append(
                                    f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --ip-permissions IpProtocol=-1,Ipv6Ranges=[{{CidrIpv6=::/0}}] --region {region}"
                                )
                            result.findings.append(
                                Finding(
                                    check_id="aws-vpc-002",
                                    title=f"Security group '{sg_name}' allows ALL inbound traffic from internet",
                                    severity=Severity.CRITICAL,
                                    category=Category.SECURITY,
                                    resource_type="AWS::EC2::SecurityGroup",
                                    resource_id=sg_id,
                                    region=region,
                                    description=f"Security group {sg_id} ({sg_name}) allows all inbound traffic from {cidr_display}.",
                                    recommendation="Restrict inbound rules to specific ports and source IP ranges.",
                                    remediation=Remediation(
                                        cli="\n".join(revoke_cmds),
                                        terraform=(
                                            f"# Restrict to specific ports and IPs:\n"
                                            f'resource "aws_security_group_rule" "restrict" {{\n'
                                            f'  type              = "ingress"\n'
                                            f'  security_group_id = "{sg_id}"\n'
                                            f"  from_port         = 443\n"
                                            f"  to_port           = 443\n"
                                            f'  protocol          = "tcp"\n'
                                            f'  cidr_blocks       = ["YOUR_IP/32"]\n'
                                            f"}}"
                                        ),
                                        doc_url="https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",
                                        effort=Effort.LOW,
                                    ),
                                    compliance_refs=["CIS 5.2"],
                                )
                            )
                            continue

                        # Check sensitive ports - report only the highest-severity match per rule
                        exposed = [
                            (port, service) for port, service in sensitive_ports.items() if from_port <= port <= to_port
                        ]
                        if exposed:
                            # Pick the most critical port for the primary finding
                            critical_ports = {22, 3389, 3306, 5432}
                            best_port, _best_service = next(
                                ((p, s) for p, s in exposed if p in critical_ports),
                                exposed[0],
                            )
                            severity = Severity.CRITICAL if best_port in critical_ports else Severity.HIGH
                            exposed_names = ", ".join(f"{s} ({p})" for p, s in exposed)
                            # Build revoke commands for the primary port
                            revoke_cmds = []
                            if "0.0.0.0/0" in open_cidrs:
                                revoke_cmds.append(
                                    f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol tcp --port {best_port} --cidr 0.0.0.0/0 --region {region}"
                                )
                            if "::/0" in open_cidrs:
                                revoke_cmds.append(
                                    f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --ip-permissions IpProtocol=tcp,FromPort={best_port},ToPort={best_port},Ipv6Ranges=[{{CidrIpv6=::/0}}] --region {region}"
                                )
                            result.findings.append(
                                Finding(
                                    check_id="aws-vpc-002",
                                    title=f"Security group '{sg_name}' exposes {exposed_names} to internet",
                                    severity=severity,
                                    category=Category.SECURITY,
                                    resource_type="AWS::EC2::SecurityGroup",
                                    resource_id=sg_id,
                                    region=region,
                                    description=f"Security group {sg_id} ({sg_name}) allows inbound {exposed_names} from {cidr_display}.",
                                    recommendation="Restrict access to specific IP ranges. Use a bastion host or VPN for remote access.",
                                    remediation=Remediation(
                                        cli="\n".join(revoke_cmds),
                                        terraform=(
                                            f"# Restrict access to known IPs:\n"
                                            f'resource "aws_security_group_rule" "restrict" {{\n'
                                            f'  type              = "ingress"\n'
                                            f'  security_group_id = "{sg_id}"\n'
                                            f"  from_port         = {best_port}\n"
                                            f"  to_port           = {best_port}\n"
                                            f'  protocol          = "tcp"\n'
                                            f'  cidr_blocks       = ["YOUR_VPN_IP/32"]\n'
                                            f"}}"
                                        ),
                                        doc_url="https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html",
                                        effort=Effort.LOW,
                                    ),
                                    compliance_refs=["CIS 5.2"],
                                )
                            )
    except Exception as e:
        result.error = str(e)

    return result


def check_vpc_flow_logs(provider: AWSProvider) -> CheckResult:
    """Check if VPC flow logs are enabled."""
    result = CheckResult(check_id="aws-vpc-003", check_name="VPC flow logs")

    try:
        account_id = provider.get_account_id()
        for region in provider.regions:
            ec2 = provider.session.client("ec2", region_name=region)
            vpcs = ec2.describe_vpcs()["Vpcs"]

            for vpc in vpcs:
                # NOTE: CIS 3.7 says "all VPCs" but we skip default VPCs to reduce noise.
                # Default VPCs without user resources are not a real risk.
                # If strict CIS compliance is needed, remove this skip.
                if vpc.get("IsDefault", False):
                    continue

                vpc_id = vpc["VpcId"]
                result.resources_scanned += 1

                flow_logs = ec2.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [vpc_id]}])["FlowLogs"]

                if not flow_logs:
                    name_tag = next(
                        (t["Value"] for t in vpc.get("Tags", []) if t["Key"] == "Name"),
                        vpc_id,
                    )
                    result.findings.append(
                        Finding(
                            check_id="aws-vpc-003",
                            title=f"VPC '{name_tag}' has no flow logs enabled",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            resource_type="AWS::EC2::VPC",
                            resource_id=vpc_id,
                            region=region,
                            description=f"VPC {vpc_id} does not have flow logs configured. Network traffic is not being logged.",
                            recommendation="Enable VPC flow logs to CloudWatch Logs or S3 for network traffic monitoring and incident response.",
                            remediation=Remediation(
                                cli=(
                                    f"aws ec2 create-flow-logs --resource-type VPC --resource-ids {vpc_id} "
                                    f"--traffic-type ALL --log-destination-type cloud-watch-logs "
                                    f"--log-group-name /aws/vpc/flow-logs/{vpc_id} "
                                    f"--deliver-logs-permission-arn arn:aws:iam::{account_id}:role/vpc-flow-log-role "
                                    f"--region {region}"
                                ),
                                terraform=(
                                    f'resource "aws_cloudwatch_log_group" "flow_log" {{\n'
                                    f'  name              = "/aws/vpc/flow-logs/{vpc_id}"\n'
                                    f"  retention_in_days = 365\n"
                                    f"}}\n"
                                    f"\n"
                                    f'resource "aws_iam_role" "flow_log" {{\n'
                                    f'  name = "vpc-flow-log-role"\n'
                                    f"\n"
                                    f"  assume_role_policy = jsonencode({{\n"
                                    f'    Version = "2012-10-17"\n'
                                    f"    Statement = [{{\n"
                                    f'      Effect = "Allow"\n'
                                    f'      Principal = {{ Service = "vpc-flow-logs.amazonaws.com" }}\n'
                                    f'      Action = "sts:AssumeRole"\n'
                                    f"    }}]\n"
                                    f"  }})\n"
                                    f"}}\n"
                                    f"\n"
                                    f'resource "aws_iam_role_policy" "flow_log" {{\n'
                                    f'  name = "vpc-flow-log-policy"\n'
                                    f"  role = aws_iam_role.flow_log.id\n"
                                    f"\n"
                                    f"  policy = jsonencode({{\n"
                                    f'    Version = "2012-10-17"\n'
                                    f"    Statement = [{{\n"
                                    f'      Effect = "Allow"\n'
                                    f"      Action = [\n"
                                    f'        "logs:CreateLogStream",\n'
                                    f'        "logs:PutLogEvents",\n'
                                    f'        "logs:DescribeLogGroups",\n'
                                    f'        "logs:DescribeLogStreams"\n'
                                    f"      ]\n"
                                    f'      Resource = "${{aws_cloudwatch_log_group.flow_log.arn}}:*"\n'
                                    f"    }}]\n"
                                    f"  }})\n"
                                    f"}}\n"
                                    f"\n"
                                    f'resource "aws_flow_log" "this" {{\n'
                                    f'  vpc_id          = "{vpc_id}"\n'
                                    f'  traffic_type    = "ALL"\n'
                                    f"  log_destination = aws_cloudwatch_log_group.flow_log.arn\n"
                                    f"  iam_role_arn    = aws_iam_role.flow_log.arn\n"
                                    f"}}"
                                ),
                                doc_url="https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html",
                                effort=Effort.MEDIUM,
                            ),
                            compliance_refs=["CIS 3.7"],
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def check_unrestricted_nacl(provider: AWSProvider) -> CheckResult:
    """Check for Network ACLs that allow all inbound traffic from 0.0.0.0/0."""
    result = CheckResult(check_id="aws-vpc-004", check_name="Unrestricted NACL")

    try:
        for region in provider.regions:
            ec2 = provider.session.client("ec2", region_name=region)
            nacls = ec2.describe_network_acls()["NetworkAcls"]

            for nacl in nacls:
                # NOTE: CIS 5.1 does not exclude default NACLs, but AWS default NACLs
                # allow all traffic by design. Flagging every default NACL would produce
                # noise without actionable value. If strict CIS compliance is needed,
                # remove this skip.
                if nacl.get("IsDefault", False):
                    continue

                nacl_id = nacl["NetworkAclId"]
                result.resources_scanned += 1

                for entry in nacl.get("Entries", []):
                    # Only check inbound rules (Egress=False) that ALLOW traffic
                    if entry.get("Egress", True):
                        continue
                    if entry.get("RuleAction") != "allow":
                        continue

                    cidr = entry.get("CidrBlock", "")
                    ipv6_cidr = entry.get("Ipv6CidrBlock", "")
                    protocol = entry.get("Protocol", "")

                    is_internet = cidr == "0.0.0.0/0" or ipv6_cidr == "::/0"
                    if not is_internet:
                        continue

                    # Protocol "-1" = all traffic; "6" = TCP, "17" = UDP
                    port_range = entry.get("PortRange", {})
                    from_port = port_range.get("From", 0)
                    to_port = port_range.get("To", 65535)
                    is_all_traffic = protocol == "-1"
                    is_wide_port_range = protocol in ("6", "17") and from_port == 0 and to_port == 65535
                    # CIS 5.1: specifically check admin ports (SSH 22, RDP 3389)
                    admin_ports = {22, 3389}
                    exposes_admin_port = protocol in ("6", "17", "-1") and any(
                        from_port <= p <= to_port for p in admin_ports
                    )

                    if is_all_traffic or is_wide_port_range or exposes_admin_port:
                        open_cidr = cidr if cidr == "0.0.0.0/0" else ipv6_cidr
                        if is_all_traffic:
                            proto_desc = "all traffic"
                        elif is_wide_port_range:
                            proto_desc = "all TCP" if protocol == "6" else "all UDP"
                        else:
                            exposed_admin = [p for p in admin_ports if from_port <= p <= to_port]
                            port_names = {22: "SSH", 3389: "RDP"}
                            proto_desc = ", ".join(f"{port_names.get(p, p)} ({p})" for p in exposed_admin)
                        result.findings.append(
                            Finding(
                                check_id="aws-vpc-004",
                                title=f"NACL '{nacl_id}' allows {proto_desc} inbound from {open_cidr}",
                                severity=Severity.MEDIUM,
                                category=Category.SECURITY,
                                resource_type="AWS::EC2::NetworkAcl",
                                resource_id=nacl_id,
                                region=region,
                                description=f"Network ACL {nacl_id} has an inbound rule allowing {proto_desc} from {open_cidr}. This bypasses security group restrictions at the subnet level.",
                                recommendation="Restrict NACL inbound rules to specific ports and IP ranges needed for your workloads.",
                                remediation=Remediation(
                                    cli=(
                                        f"aws ec2 replace-network-acl-entry --network-acl-id {nacl_id} "
                                        f"--rule-number {entry.get('RuleNumber', 100)} "
                                        f"--protocol -1 --rule-action deny --ingress "
                                        f"--cidr-block 0.0.0.0/0 --region {region}"
                                    ),
                                    terraform=(
                                        'resource "aws_network_acl_rule" "restrict_inbound" {\n'
                                        f'  network_acl_id = "{nacl_id}"\n'
                                        "  rule_number    = 100\n"
                                        "  egress         = false\n"
                                        '  protocol       = "tcp"\n'
                                        '  rule_action    = "allow"\n'
                                        '  cidr_block     = "10.0.0.0/8"  # Restrict to your CIDR\n'
                                        "  from_port      = 443\n"
                                        "  to_port        = 443\n"
                                        "}"
                                    ),
                                    doc_url="https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html",
                                    effort=Effort.MEDIUM,
                                ),
                            )
                        )
                        break  # One finding per NACL is enough
    except Exception as e:
        result.error = str(e)

    return result


def check_default_sg_restricts_all(provider: AWSProvider) -> CheckResult:
    """Check if the default security group of every VPC restricts all traffic (CIS 5.4)."""
    result = CheckResult(check_id="aws-vpc-005", check_name="Default security group restricts all traffic")

    try:
        for region in provider.regions:
            ec2 = provider.session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_security_groups")

            for page in paginator.paginate(Filters=[{"Name": "group-name", "Values": ["default"]}]):
                for sg in page["SecurityGroups"]:
                    sg_id = sg["GroupId"]
                    vpc_id = sg.get("VpcId", "unknown")
                    result.resources_scanned += 1

                    has_ingress = len(sg.get("IpPermissions", [])) > 0
                    has_egress = len(sg.get("IpPermissionsEgress", [])) > 0

                    if has_ingress or has_egress:
                        rule_count = len(sg.get("IpPermissions", [])) + len(sg.get("IpPermissionsEgress", []))
                        result.findings.append(
                            Finding(
                                check_id="aws-vpc-005",
                                title=f"Default SG in VPC {vpc_id} ({region}) has {rule_count} rule(s)",
                                severity=Severity.MEDIUM,
                                category=Category.SECURITY,
                                resource_type="AWS::EC2::SecurityGroup",
                                resource_id=sg_id,
                                region=region,
                                description=(
                                    f"The default security group ({sg_id}) in VPC {vpc_id} has "
                                    f"active inbound/outbound rules. Default security groups should "
                                    f"restrict all traffic to prevent unintended network access when "
                                    f"resources are launched without a specific security group."
                                ),
                                recommendation="Remove all inbound and outbound rules from the default security group.",
                                remediation=Remediation(
                                    cli=(
                                        f"# List current rules:\n"
                                        f"aws ec2 describe-security-groups --group-ids {sg_id} --region {region}\n"
                                        f"# Remove default self-referencing ingress rule:\n"
                                        f"aws ec2 revoke-security-group-ingress --group-id {sg_id} "
                                        f"--source-group {sg_id} --protocol all --region {region}\n"
                                        f"# Remove default egress allow-all rule:\n"
                                        f"aws ec2 revoke-security-group-egress --group-id {sg_id} "
                                        f'--ip-permissions \'[{{"IpProtocol":"-1","IpRanges":[{{"CidrIp":"0.0.0.0/0"}}]}}]\' '
                                        f"--region {region}"
                                    ),
                                    terraform=(
                                        "# Terraform can manage default SG rules:\n"
                                        f'resource "aws_default_security_group" "default" {{\n'
                                        f'  vpc_id = "{vpc_id}"\n'
                                        f"  # Empty ingress/egress blocks = deny all\n"
                                        f"}}"
                                    ),
                                    doc_url="https://docs.aws.amazon.com/vpc/latest/userguide/default-security-group.html",
                                    effort=Effort.LOW,
                                ),
                                compliance_refs=["CIS 5.4"],
                            )
                        )
    except Exception as e:
        result.error = str(e)

    return result


def check_vpc_subnet_segmentation(provider: AWSProvider) -> CheckResult:
    """Check if non-default VPCs have proper public/private subnet segmentation."""
    result = CheckResult(check_id="aws-vpc-006", check_name="VPC subnet segmentation")

    try:
        for region in provider.regions:
            ec2 = provider.session.client("ec2", region_name=region)

            # Get non-default VPCs
            vpcs = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["false"]}]).get("Vpcs", [])

            for vpc in vpcs:
                vpc_id = vpc["VpcId"]
                name_tag = next(
                    (t["Value"] for t in vpc.get("Tags", []) if t["Key"] == "Name"),
                    vpc_id,
                )

                # Get all subnets for this VPC
                subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]).get("Subnets", [])

                if not subnets:
                    continue

                result.resources_scanned += 1

                public_count = 0
                private_count = 0
                for subnet in subnets:
                    if subnet.get("MapPublicIpOnLaunch", False):
                        public_count += 1
                    else:
                        private_count += 1

                # Finding: all subnets are public (no private subnets)
                if public_count > 0 and private_count == 0:
                    result.findings.append(
                        Finding(
                            check_id="aws-vpc-006",
                            title=f"VPC '{name_tag}' has only public subnets ({public_count} subnet(s))",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY,
                            resource_type="AWS::EC2::VPC",
                            resource_id=vpc_id,
                            region=region,
                            description=(
                                f"VPC {vpc_id} ({name_tag}) in {region} has {public_count} public "
                                f"subnet(s) but no private subnets. All resources in this VPC receive "
                                f"public IPs by default, increasing the attack surface. Databases, "
                                f"application servers, and internal services should run in private subnets."
                            ),
                            recommendation="Create private subnets for backend resources and use NAT Gateway for outbound internet access.",
                            remediation=Remediation(
                                cli=(
                                    f"# Create a private subnet:\n"
                                    f"aws ec2 create-subnet \\\n"
                                    f"  --vpc-id {vpc_id} \\\n"
                                    f"  --cidr-block 10.0.128.0/20 \\\n"
                                    f"  --availability-zone {region}a \\\n"
                                    f"  --region {region}\n"
                                    f"# Private subnets do NOT auto-assign public IPs by default"
                                ),
                                terraform=(
                                    "# Add private subnets alongside public ones:\n"
                                    'resource "aws_subnet" "private" {\n'
                                    f'  vpc_id                  = "{vpc_id}"\n'
                                    '  cidr_block              = "10.0.128.0/20"\n'
                                    f'  availability_zone       = "{region}a"\n'
                                    "  map_public_ip_on_launch = false\n"
                                    "\n"
                                    "  tags = {\n"
                                    '    Name = "private-subnet"\n'
                                    "  }\n"
                                    "}"
                                ),
                                doc_url="https://docs.aws.amazon.com/vpc/latest/userguide/configure-subnets.html",
                                effort=Effort.MEDIUM,
                            ),
                            compliance_refs=[],
                        )
                    )
    except Exception as e:
        result.error = str(e)

    return result


def get_checks(provider: AWSProvider) -> list[CheckFn]:
    """Return all VPC checks bound to the provider."""
    from cloud_audit.providers.base import make_check

    return [
        make_check(check_default_vpc_in_use, provider, check_id="aws-vpc-001", category=Category.SECURITY),
        make_check(check_open_security_groups, provider, check_id="aws-vpc-002", category=Category.SECURITY),
        make_check(check_vpc_flow_logs, provider, check_id="aws-vpc-003", category=Category.SECURITY),
        make_check(check_unrestricted_nacl, provider, check_id="aws-vpc-004", category=Category.SECURITY),
        make_check(check_default_sg_restricts_all, provider, check_id="aws-vpc-005", category=Category.SECURITY),
        make_check(check_vpc_subnet_segmentation, provider, check_id="aws-vpc-006", category=Category.SECURITY),
    ]
