"""Tests for blast radius analysis."""

from __future__ import annotations

import json
from typing import Any

import pytest

from cloud_audit.blast_radius import (
    BlastRadiusResult,
    compute_blast_radius,
    detect_resource_type,
    to_json_str,
    to_mermaid,
    to_tree,
)
from cloud_audit.models import (
    AttackChain,
    Category,
    CheckResult,
    Effort,
    EscalationCategory,
    EscalationPath,
    Finding,
    Remediation,
    ScanReport,
    Severity,
    VizStep,
)


def _make_finding(
    check_id: str,
    resource_id: str,
    severity: Severity = Severity.HIGH,
    title: str | None = None,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title or f"Finding for {check_id}",
        severity=severity,
        category=Category.SECURITY,
        resource_type="AWS::Test::Resource",
        resource_id=resource_id,
        region="eu-central-1",
        description="test",
        recommendation="test",
        remediation=Remediation(
            cli=f"aws fix {check_id}",
            terraform=f'resource "fix" "{check_id}" {{}}',
            doc_url="https://docs.aws.amazon.com/test",
            effort=Effort.LOW,
        ),
    )


def _make_report(
    findings: list[Finding] | None = None,
    chains: list[AttackChain] | None = None,
    escalation_paths: list[EscalationPath] | None = None,
    account_id: str = "123456789012",
) -> ScanReport:
    report = ScanReport(provider="aws", account_id=account_id, regions=["eu-central-1"])
    if findings:
        report.results.append(
            CheckResult(
                check_id="test",
                check_name="Test",
                findings=findings,
                resources_scanned=len(findings),
            )
        )
    report.attack_chains = chains or []
    report.escalation_paths = escalation_paths or []
    report.compute_summary()
    return report


# ---------------------------------------------------------------------------
# detect_resource_type
# ---------------------------------------------------------------------------


class TestDetectResourceType:
    def test_ec2_short_id(self) -> None:
        assert detect_resource_type("i-0abc123def456ffff") == "ec2"

    def test_iam_role_arn(self) -> None:
        assert detect_resource_type("arn:aws:iam::123456789012:role/admin-role") == "iam_role"

    def test_iam_user_arn(self) -> None:
        assert detect_resource_type("arn:aws:iam::123456789012:user/alice") == "iam_user"

    def test_lambda_arn(self) -> None:
        assert detect_resource_type("arn:aws:lambda:us-east-1:123456789012:function:my-fn") == "lambda"

    def test_s3_bucket_arn(self) -> None:
        assert detect_resource_type("arn:aws:s3:::my-bucket") == "s3_bucket"

    def test_secret_arn(self) -> None:
        assert detect_resource_type("arn:aws:secretsmanager:us-east-1:123456789012:secret:prod-db") == "secret"

    def test_unknown_pattern(self) -> None:
        assert detect_resource_type("garbage-id") == "unknown"

    def test_short_form_user_name_unknown(self) -> None:
        # Names alone are not recognized - require full ARN
        assert detect_resource_type("alice") == "unknown"


# ---------------------------------------------------------------------------
# compute_blast_radius - basic shapes
# ---------------------------------------------------------------------------


class TestComputeBlastRadius:
    def test_empty_report_returns_seed_only(self) -> None:
        report = _make_report([])
        result = compute_blast_radius(report, "i-0abc123def456ffff")
        assert isinstance(result, BlastRadiusResult)
        assert len(result.nodes) == 1
        assert result.nodes[0].bfsStep == 0
        assert result.summary.nodes_reachable == 1
        assert result.summary.paths_found == 0

    def test_iam_role_admin_reaches_impact(self) -> None:
        role_arn = "arn:aws:iam::123456789012:role/admin-fleet"
        finding = _make_finding(
            "aws-iam-001",
            role_arn,
            severity=Severity.CRITICAL,
            title="Admin role attached AdministratorAccess",
        )
        path = EscalationPath(
            principal_arn=role_arn,
            principal_name="admin-fleet",
            principal_type="Role",
            method="AttachRolePolicy",
            category=EscalationCategory.IAM_SELF_MUTATION,
            required_actions=["iam:AttachRolePolicy"],
            target_privilege="Admin via attaching AdministratorAccess to self",
            severity=Severity.CRITICAL,
        )
        report = _make_report([finding], escalation_paths=[path])
        result = compute_blast_radius(report, role_arn)

        impact = [n for n in result.nodes if n.type == "impact"]
        assert len(impact) == 1
        assert impact[0].label == "Account Takeover"
        assert result.summary.paths_found == 1
        assert result.summary.risk_score >= 50

    def test_ec2_with_attached_role_links_to_iam(self) -> None:
        instance_id = "i-0abc123def456fff1"
        sg_finding = _make_finding("aws-vpc-002", "sg-0open", Severity.CRITICAL)
        chain = AttackChain(
            chain_id="AC-01",
            name="Internet-Exposed Admin Instance",
            severity=Severity.CRITICAL,
            findings=[sg_finding],
            attack_narrative="x",
            priority_fix="restrict sg",
            resources=[instance_id, "sg-0open"],
            viz_steps=[
                VizStep(label="Internet", sub="Entry Point", type="internet"),
                VizStep(label="sg-0open", sub="Security Group", type="network"),
                VizStep(label=instance_id, sub="EC2 Instance", type="compute"),
                VizStep(label="admin-fleet", sub="IAM Role (admin)", type="identity"),
                VizStep(label="Account Takeover", sub="Full AWS Access", type="impact"),
            ],
        )
        report = _make_report([sg_finding], chains=[chain])
        result = compute_blast_radius(report, instance_id)

        labels = {n.label for n in result.nodes}
        assert instance_id in labels
        assert "admin-fleet" in labels

    def test_lambda_with_exec_role_links_to_role(self) -> None:
        lambda_arn = "arn:aws:lambda:eu-central-1:123456789012:function:processor"
        chain = AttackChain(
            chain_id="AC-05",
            name="Public Lambda Admin",
            severity=Severity.CRITICAL,
            findings=[],
            attack_narrative="x",
            priority_fix="restrict",
            resources=[lambda_arn],
            viz_steps=[
                VizStep(label=lambda_arn, sub="Lambda", type="compute"),
                VizStep(label="processor-role", sub="Execution Role", type="identity"),
            ],
        )
        report = _make_report([], chains=[chain])
        result = compute_blast_radius(report, lambda_arn)
        labels = {n.label for n in result.nodes}
        assert "processor-role" in labels

    def test_max_depth_enforced(self) -> None:
        role_arn = "arn:aws:iam::123456789012:role/r"
        path1 = EscalationPath(
            principal_arn=role_arn,
            principal_name="r",
            principal_type="Role",
            method="AssumeRole:Chain",
            category=EscalationCategory.LATERAL_ASSUME_ROLE,
            required_actions=["sts:AssumeRole"],
            target_privilege="Admin via AssumeRole chain: r -> mid -> admin",
            severity=Severity.CRITICAL,
        )
        report = _make_report(
            [_make_finding("aws-iam-001", role_arn, title="Admin")],
            escalation_paths=[path1],
        )
        result = compute_blast_radius(report, role_arn, max_depth=1)
        # max_depth=1 means seed expands once - we should still see seed plus
        # at most one round of expansion
        assert len(result.nodes) <= 5

    def test_max_nodes_enforced(self) -> None:
        role_arn = "arn:aws:iam::123456789012:role/r"
        many_findings = [_make_finding("aws-s3-007", f"arn:aws:s3:::bucket-{i}", Severity.HIGH) for i in range(40)]
        many_findings.append(_make_finding("aws-iam-001", role_arn, severity=Severity.CRITICAL, title="Admin"))
        report = _make_report(many_findings)
        result = compute_blast_radius(report, role_arn, max_nodes=10)
        assert len(result.nodes) <= 10

    def test_unknown_resource_still_returns_seed(self) -> None:
        report = _make_report([])
        result = compute_blast_radius(report, "blob-of-junk")
        assert len(result.nodes) == 1
        assert result.nodes[0].bfsStep == 0


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------


class TestOutputFormatters:
    def _admin_role_result(self) -> BlastRadiusResult:
        role_arn = "arn:aws:iam::123456789012:role/admin-fleet"
        finding = _make_finding(
            "aws-iam-001",
            role_arn,
            severity=Severity.CRITICAL,
            title="Admin role with AdministratorAccess",
        )
        path = EscalationPath(
            principal_arn=role_arn,
            principal_name="admin-fleet",
            principal_type="Role",
            method="AttachRolePolicy",
            category=EscalationCategory.IAM_SELF_MUTATION,
            required_actions=["iam:AttachRolePolicy"],
            target_privilege="Admin via attaching AdministratorAccess to self",
            severity=Severity.CRITICAL,
        )
        report = _make_report([finding], escalation_paths=[path])
        return compute_blast_radius(report, role_arn)

    def test_to_tree_renders_without_crash(self) -> None:
        from rich.console import Console

        result = self._admin_role_result()
        tree = to_tree(result)
        # Render to capturing console - must not throw
        console = Console(record=True, width=120)
        console.print(tree)
        output = console.export_text()
        assert "admin-fleet" in output or "Account Takeover" in output

    def test_to_mermaid_includes_graph_td_header(self) -> None:
        result = self._admin_role_result()
        diagram = to_mermaid(result)
        assert diagram.startswith("graph TD")
        # Has at least one edge (-->)
        assert "-->" in diagram

    def test_to_json_str_serializes_to_schema_v1(self) -> None:
        result = self._admin_role_result()
        payload = to_json_str(result)
        data = json.loads(payload)
        assert data["schema_version"] == "1.0"
        assert "generated_at" in data
        assert data["generator"]["name"] == "cloud-audit"
        assert "graph" in data
        assert "nodes" in data["graph"]
        assert "edges" in data["graph"]
        assert isinstance(data["summary"], dict)
        assert "headline" in data["summary"]


# ---------------------------------------------------------------------------
# BlastRadiusGraph v1.0 schema compatibility
# ---------------------------------------------------------------------------


REQUIRED_TOP_LEVEL = {"schema_version", "generated_at", "generator", "source", "summary", "graph", "narrative", "fixes"}


class TestSchemaCompatibility:
    def test_required_top_level_keys(self) -> None:
        role_arn = "arn:aws:iam::123456789012:role/r"
        report = _make_report(
            [_make_finding("aws-iam-001", role_arn, severity=Severity.CRITICAL, title="Admin")],
        )
        result = compute_blast_radius(report, role_arn)
        data: dict[str, Any] = json.loads(to_json_str(result))
        missing = REQUIRED_TOP_LEVEL - set(data.keys())
        assert not missing, f"Missing required schema fields: {missing}"

    def test_nodes_use_camel_case_fields(self) -> None:
        """BlastRadiusGraph v1.0 uses camelCase (highValue, bfsStep, actionTitle...)
        because it's a wire-format contract with the TypeScript demo consumer."""
        role_arn = "arn:aws:iam::123456789012:role/r"
        report = _make_report(
            [_make_finding("aws-iam-001", role_arn, severity=Severity.CRITICAL, title="Admin")],
        )
        result = compute_blast_radius(report, role_arn)
        data: dict[str, Any] = json.loads(to_json_str(result))
        node = data["graph"]["nodes"][0]
        # Required fields
        assert "id" in node
        assert "type" in node
        assert "label" in node
        assert "sub" in node
        assert "status" in node
        # No snake_case Pydantic leakage
        assert "high_value" not in node
        assert "bfs_step" not in node
        assert "action_title" not in node

    def test_node_types_within_enum(self) -> None:
        role_arn = "arn:aws:iam::123456789012:role/r"
        report = _make_report(
            [_make_finding("aws-iam-001", role_arn, severity=Severity.CRITICAL, title="Admin")],
        )
        result = compute_blast_radius(report, role_arn)
        valid_types = {"internet", "compute", "identity", "network", "storage", "finding", "impact"}
        for node in result.nodes:
            assert node.type in valid_types

    def test_edge_types_within_enum(self) -> None:
        instance_id = "i-0aaaaaaaabbbbbccc"
        chain = AttackChain(
            chain_id="AC-01",
            name="Internet-Exposed Admin",
            severity=Severity.CRITICAL,
            findings=[],
            attack_narrative="x",
            priority_fix="x",
            resources=[instance_id],
            viz_steps=[
                VizStep(label=instance_id, sub="EC2", type="compute"),
                VizStep(label="role-x", sub="IAM Role", type="identity"),
            ],
        )
        report = _make_report([], chains=[chain])
        result = compute_blast_radius(report, instance_id)
        valid_edge_types = {"network", "iam", "data", "exploit"}
        for edge in result.edges:
            assert edge.type in valid_edge_types


# ---------------------------------------------------------------------------
# Fixes + detections collection
# ---------------------------------------------------------------------------


class TestFixesAndDetections:
    def test_fixes_pulled_from_findings(self) -> None:
        role_arn = "arn:aws:iam::123456789012:role/admin-fleet"
        finding = _make_finding(
            "aws-iam-005",
            role_arn,
            severity=Severity.CRITICAL,
            title="Admin role wildcard",
        )
        report = _make_report([finding])
        result = compute_blast_radius(report, role_arn)
        fix_ids = {f.id for f in result.fixes}
        assert "aws-iam-005" in fix_ids

    def test_detections_emit_check_ids(self) -> None:
        role_arn = "arn:aws:iam::123456789012:role/admin-fleet"
        finding = _make_finding(
            "aws-iam-007",
            role_arn,
            severity=Severity.HIGH,
            title="OIDC role without sub condition",
        )
        report = _make_report([finding])
        result = compute_blast_radius(report, role_arn)
        det_ids = {d.check_id for d in result.cloud_audit_detects}
        assert "aws-iam-007" in det_ids


@pytest.mark.parametrize(
    "resource_id,expected_type",
    [
        ("i-1234567890abcdef0", "ec2"),
        ("arn:aws:iam::123456789012:role/MyRole", "iam_role"),
        ("arn:aws:s3:::my-bucket", "s3_bucket"),
        ("arn:aws:lambda:us-east-1:123456789012:function:fn", "lambda"),
    ],
)
def test_detect_resource_type_parametrized(resource_id: str, expected_type: str) -> None:
    assert detect_resource_type(resource_id) == expected_type


# ---------------------------------------------------------------------------
# Security regression tests (from security audit 2026-05-15)
# ---------------------------------------------------------------------------


class TestSecurityRegression:
    """Regression tests for security findings #1 - #6 from 2026-05-15 audit."""

    def test_mermaid_escapes_html_special_chars(self) -> None:
        """SEC-001: Mermaid output must HTML-encode untrusted content (CWE-79)."""
        from datetime import datetime, timezone

        from cloud_audit.blast_radius import BlastEdge, BlastNode, BlastSource, BlastSummary

        result = BlastRadiusResult(
            generated_at=datetime.now(timezone.utc).isoformat(),
            source=BlastSource(type="live-scan", resource_id="x"),
            summary=BlastSummary(headline="x"),
            nodes=[
                BlastNode(
                    id="n1",
                    type="compute",
                    label='evil"><script>alert(1)</script>',
                    sub="line1\nline2",
                    status="compromised",
                ),
                BlastNode(id="n2", type="impact", label="`backtick`", sub="ok", status="stolen"),
            ],
            edges=[BlastEdge(source="n1", target="n2", label="]script[", step=1, type="iam")],
        )
        out = to_mermaid(result)
        assert "<script>" not in out
        assert "&lt;script&gt;" in out
        assert "&#96;" in out  # backtick encoded
        # Newline in label must be flattened to space
        assert "line1\nline2" not in out
        # Square brackets escaped to prevent Mermaid shape confusion
        # Input "]script[" -> "]" becomes &#93;, "[" becomes &#91;
        assert "&#93;script&#91;" in out
        # Neither raw bracket should appear inside edge labels (only as
        # Mermaid shape delimiters around nodes)
        assert '"]script[' not in out

    def test_make_id_no_collision_after_truncation(self) -> None:
        """SEC-002: Two long but different inputs must produce different ids (CWE-345)."""
        from cloud_audit.blast_radius import _make_id

        long1 = "arn:aws:iam::123456789012:role/" + "a" * 200 + "_1"
        long2 = "arn:aws:iam::123456789012:role/" + "a" * 200 + "_2"
        assert _make_id("role", long1) != _make_id("role", long2)
        # Both still bounded
        assert len(_make_id("role", long1)) <= 120
        assert len(_make_id("role", long2)) <= 120
        # Hash suffix deterministic
        assert _make_id("role", long1) == _make_id("role", long1)

    def test_cycle_in_assume_role_does_not_duplicate_seed(self) -> None:
        """SEC-003: A->B->A AssumeRole cycle must not re-emit the seed as a
        lateral node (CWE-1023)."""
        role_a = "arn:aws:iam::123456789012:role/role-a"
        role_b = "arn:aws:iam::123456789012:role/role-b"
        admin_a = _make_finding("aws-iam-001", role_a, severity=Severity.CRITICAL, title="Admin a")
        admin_b = _make_finding("aws-iam-001", role_b, severity=Severity.CRITICAL, title="Admin b")
        path_ab = EscalationPath(
            principal_arn=role_a,
            principal_name="role-a",
            principal_type="Role",
            method="AssumeRole:Direct",
            category=EscalationCategory.LATERAL_ASSUME_ROLE,
            required_actions=["sts:AssumeRole"],
            target_privilege=role_b,
            severity=Severity.CRITICAL,
        )
        path_ba = EscalationPath(
            principal_arn=role_b,
            principal_name="role-b",
            principal_type="Role",
            method="AssumeRole:Direct",
            category=EscalationCategory.LATERAL_ASSUME_ROLE,
            required_actions=["sts:AssumeRole"],
            target_privilege=role_a,
            severity=Severity.CRITICAL,
        )
        report = _make_report([admin_a, admin_b], escalation_paths=[path_ab, path_ba])
        result = compute_blast_radius(report, role_a, max_depth=10, max_nodes=50)
        # The fix prevents emitting the seed role-a a second time as a lateral
        # target reached from role-b. Verify by:
        #   1. exactly one node carries the role_a ARN as resource_arn (the seed)
        #   2. no lateral-prefixed node points back at role_a
        a_arn_refs = sum(1 for n in result.nodes if (n.resource_arn or "").lower() == role_a.lower())
        assert a_arn_refs == 1, (
            f"Expected exactly one role-a ARN reference, found {a_arn_refs}: "
            f"{[(n.id, n.label, n.resource_arn) for n in result.nodes]}"
        )
        lateral_to_a = [
            n for n in result.nodes if n.id.startswith("lateral_") and (n.resource_arn or "").lower() == role_a.lower()
        ]
        assert lateral_to_a == [], f"Cycle dedup failed: lateral nodes pointing back at seed = {lateral_to_a}"

    def test_lambda_role_lookup_does_not_pick_wrong_function(self) -> None:
        """SEC-004: Looking up role for fnB when scan has chain for fnA must
        return None, not fnA's role (CWE-697)."""
        from cloud_audit.blast_radius import _find_execution_role_for_lambda

        fn_a = "arn:aws:lambda:us-east-1:123:function:fnA"
        fn_b = "arn:aws:lambda:us-east-1:123:function:fnB"
        chain_a = AttackChain(
            chain_id="AC-05",
            name="public lambda admin",
            severity=Severity.CRITICAL,
            findings=[],
            attack_narrative="x",
            priority_fix="x",
            resources=[fn_a],
            viz_steps=[
                VizStep(label=fn_a, sub="Lambda A", type="compute"),
                VizStep(label="roleA", sub="exec", type="identity"),
            ],
        )
        report = _make_report([], chains=[chain_a])
        # Looking up fnB must NOT return roleA
        assert _find_execution_role_for_lambda(report, fn_b) is None
        # Looking up fnA must still work
        assert _find_execution_role_for_lambda(report, fn_a) == "roleA"

    def test_make_id_hash_suffix_when_truncating(self) -> None:
        """SEC-002 corollary: oversize inputs receive a hash suffix marker."""
        from cloud_audit.blast_radius import _make_id

        long_value = "x" * 300
        result = _make_id("seed", long_value)
        assert len(result) == 120
        # Last 11 chars look like "_<10 hex chars>"
        assert result[-11] == "_"
        # SHA-256 hex chars
        suffix = result[-10:]
        assert all(c in "0123456789abcdef" for c in suffix)


# ---------------------------------------------------------------------------
# Fuzzing / robustness
# ---------------------------------------------------------------------------


class TestRobustness:
    def test_zero_max_depth_returns_seed_only(self) -> None:
        report = _make_report([])
        result = compute_blast_radius(report, "i-0abc123def456fff0", max_depth=0)
        assert len(result.nodes) == 1

    def test_negative_max_depth_returns_seed_only(self) -> None:
        report = _make_report([])
        result = compute_blast_radius(report, "i-0abc123def456fff0", max_depth=-5)
        assert len(result.nodes) == 1

    def test_50kb_target_privilege_does_not_explode(self) -> None:
        """Massive target_privilege text must be safely truncated."""
        role = "arn:aws:iam::123456789012:role/x"
        finding = _make_finding("aws-iam-001", role, severity=Severity.CRITICAL, title="Admin")
        big = "A" * 50_000
        path = EscalationPath(
            principal_arn=role,
            principal_name="x",
            principal_type="Role",
            method="AssumeRole:Chain",
            category=EscalationCategory.LATERAL_ASSUME_ROLE,
            required_actions=["sts:AssumeRole"],
            target_privilege=big,
            severity=Severity.CRITICAL,
        )
        report = _make_report([finding], escalation_paths=[path])
        result = compute_blast_radius(report, role)
        # Labels must be truncated; ids must respect the 120-char cap
        for n in result.nodes:
            assert len(n.label) <= 64
            assert len(n.id) <= 120
        # Resulting JSON must remain reasonable size
        js = to_json_str(result)
        assert len(js) < 200_000  # not 50KB * however-many-nodes

    def test_huge_max_depth_with_no_paths_terminates_fast(self) -> None:
        import time

        report = _make_report([])
        t0 = time.time()
        result = compute_blast_radius(report, "i-0deadbeef", max_depth=10000, max_nodes=10000)
        elapsed = time.time() - t0
        assert elapsed < 1.0
        assert len(result.nodes) == 1

    def test_max_nodes_enforces_hard_cap_on_admin_with_many_buckets(self) -> None:
        """200 candidate S3 nodes + admin role must stop at max_nodes."""
        role = "arn:aws:iam::123456789012:role/admin"
        findings = [_make_finding("aws-iam-001", role, severity=Severity.CRITICAL, title="Admin")]
        for i in range(200):
            findings.append(_make_finding("aws-s3-007", f"arn:aws:s3:::bucket-{i}", Severity.HIGH))
        report = _make_report(findings)
        result = compute_blast_radius(report, role, max_nodes=15)
        assert len(result.nodes) <= 15

    def test_rich_markup_in_label_does_not_get_reinterpreted(self) -> None:
        """SEC-008: Tree formatter must escape rich markup from labels (CWE-79)."""
        from cloud_audit.blast_radius import BlastNode, _format_node_line

        n = BlastNode(
            id="x",
            type="compute",
            label="[red]EVIL[/red]",
            sub="[blue]subsub[/blue]",
            status="compromised",
        )
        line = _format_node_line(n, edge=None)
        # The raw "[red]EVIL[/red]" segment must not appear unescaped
        # (it would be reinterpreted by Rich as a color directive).
        # rich.markup.escape uses backslash-prefix escaping.
        assert "\\[red]" in line
        assert "\\[blue]" in line
