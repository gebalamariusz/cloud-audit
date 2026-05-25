"""Tests for the Security Graph backbone (graph.py)."""

from __future__ import annotations

from cloud_audit.graph import (
    INTERNET_NODE_ID,
    GraphEdge,
    GraphNode,
    SecurityGraph,
    build_from_scan_artifacts,
)
from cloud_audit.models import (
    Category,
    Effort,
    EscalationCategory,
    EscalationPath,
    Finding,
    Remediation,
    Severity,
)


def _make_finding(check_id: str, resource_id: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        check_id=check_id,
        title=f"finding {check_id}",
        severity=severity,
        category=Category.SECURITY,
        resource_type="AWS::Test::X",
        resource_id=resource_id,
        region="eu-central-1",
        description="x",
        recommendation="x",
        remediation=Remediation(cli="x", terraform="x", doc_url="https://x", effort=Effort.LOW),
    )


class TestGraphBasics:
    def test_empty_graph_has_internet_sentinel(self) -> None:
        g = SecurityGraph()
        assert g.node_count() == 1
        assert g.has_node(INTERNET_NODE_ID)
        assert g.get_node(INTERNET_NODE_ID).type == "internet"  # type: ignore[union-attr]

    def test_add_node_and_edge(self) -> None:
        g = SecurityGraph()
        g.add_node(GraphNode(id="role-1", type="iam_role", label="admin"))
        g.add_node(GraphNode(id="user-1", type="iam_user", label="alice"))
        g.add_edge(GraphEdge(source="user-1", target="role-1", type="iam_assume"))
        assert g.node_count() == 3
        assert g.edge_count() == 1

    def test_add_edge_deduplicates_same_triple(self) -> None:
        g = SecurityGraph()
        g.add_node(GraphNode(id="a", type="iam_user", label="a"))
        g.add_node(GraphNode(id="b", type="iam_role", label="b"))
        g.add_edge(GraphEdge(source="a", target="b", type="iam_assume"))
        g.add_edge(GraphEdge(source="a", target="b", type="iam_assume"))
        assert g.edge_count() == 1

    def test_add_edge_allows_different_types_between_same_pair(self) -> None:
        g = SecurityGraph()
        g.add_node(GraphNode(id="ec2-1", type="ec2", label="ec2"))
        g.add_node(GraphNode(id="role-1", type="iam_role", label="r"))
        g.add_edge(GraphEdge(source="ec2-1", target="role-1", type="service_instance"))
        g.add_edge(GraphEdge(source="ec2-1", target="role-1", type="iam_pass_role"))
        assert g.edge_count() == 2

    def test_add_node_merges_attrs(self) -> None:
        g = SecurityGraph()
        g.add_node(GraphNode(id="r", type="iam_role", label="r", attrs={"is_admin": True}))
        g.add_node(GraphNode(id="r", type="iam_role", label="r", attrs={"has_escalation": True}))
        n = g.get_node("r")
        assert n is not None
        assert n.attrs == {"is_admin": True, "has_escalation": True}

    def test_freeze_blocks_mutation(self) -> None:
        g = SecurityGraph()
        g.freeze()
        import pytest

        with pytest.raises(RuntimeError):
            g.add_node(GraphNode(id="x", type="iam_role", label="x"))
        with pytest.raises(RuntimeError):
            g.add_edge(GraphEdge(source=INTERNET_NODE_ID, target=INTERNET_NODE_ID, type="network_route"))

    def test_add_edge_materializes_missing_endpoints(self) -> None:
        g = SecurityGraph()
        g.add_edge(GraphEdge(source="ghost-1", target="ghost-2", type="iam_assume"))
        assert g.has_node("ghost-1")
        assert g.has_node("ghost-2")


class TestTraversal:
    def _three_hop(self) -> SecurityGraph:
        g = SecurityGraph()
        g.add_node(GraphNode(id="sg-open", type="security_group", label="sg-open"))
        g.add_node(GraphNode(id="ec2-1", type="ec2", label="ec2-1"))
        g.add_node(GraphNode(id="role-admin", type="iam_role", label="admin", attrs={"is_admin": True}))
        g.add_node(GraphNode(id="bucket-prod", type="s3_bucket", label="prod"))
        g.add_edge(GraphEdge(source=INTERNET_NODE_ID, target="sg-open", type="network_route"))
        g.add_edge(GraphEdge(source="sg-open", target="ec2-1", type="network_attach"))
        g.add_edge(GraphEdge(source="ec2-1", target="role-admin", type="service_instance"))
        g.add_edge(GraphEdge(source="role-admin", target="bucket-prod", type="iam_action"))
        return g

    def test_forward_reach_returns_all_downstream(self) -> None:
        g = self._three_hop()
        reach = g.forward_reach(INTERNET_NODE_ID, max_hops=10)
        ids = {n for n, _ in reach}
        assert ids == {"sg-open", "ec2-1", "role-admin", "bucket-prod"}

    def test_forward_reach_respects_max_hops(self) -> None:
        g = self._three_hop()
        reach = g.forward_reach(INTERNET_NODE_ID, max_hops=2)
        ids = {n for n, _ in reach}
        # internet -> sg-open (hop 1) -> ec2-1 (hop 2). role-admin is hop 3, excluded.
        assert ids == {"sg-open", "ec2-1"}

    def test_forward_reach_respects_max_nodes(self) -> None:
        g = self._three_hop()
        reach = g.forward_reach(INTERNET_NODE_ID, max_hops=10, max_nodes=3)
        # visited includes source, so 3 nodes means 2 added beyond source
        assert len(reach) <= 3

    def test_backward_reach_finds_predecessors(self) -> None:
        g = self._three_hop()
        reach = g.backward_reach("bucket-prod", max_hops=10)
        ids = {n for n, _ in reach}
        assert "role-admin" in ids
        assert "ec2-1" in ids
        assert INTERNET_NODE_ID in ids

    def test_shortest_path(self) -> None:
        g = self._three_hop()
        path = g.shortest_path(INTERNET_NODE_ID, "bucket-prod")
        assert path is not None
        assert len(path) == 4
        # First edge starts at internet, last ends at bucket
        assert path[0].source == INTERNET_NODE_ID
        assert path[-1].target == "bucket-prod"

    def test_paths_from_internet_helper(self) -> None:
        g = self._three_hop()
        path = g.paths_from_internet("bucket-prod")
        assert path is not None
        assert len(path) == 4

    def test_no_path_returns_none(self) -> None:
        g = SecurityGraph()
        g.add_node(GraphNode(id="isolated", type="s3_bucket", label="b"))
        assert g.paths_from_internet("isolated") is None
        assert g.shortest_path("missing-1", "missing-2") is None

    def test_cycle_does_not_loop(self) -> None:
        g = SecurityGraph()
        g.add_node(GraphNode(id="a", type="iam_role", label="a"))
        g.add_node(GraphNode(id="b", type="iam_role", label="b"))
        g.add_edge(GraphEdge(source="a", target="b", type="iam_assume"))
        g.add_edge(GraphEdge(source="b", target="a", type="iam_assume"))
        reach = g.forward_reach("a", max_hops=10)
        ids = {n for n, _ in reach}
        assert ids == {"b"}


class TestExposureScore:
    def test_admin_internet_reachable_high_value_gets_high_score(self) -> None:
        g = SecurityGraph()
        g.add_node(GraphNode(id="sg", type="security_group", label="sg"))
        g.add_node(GraphNode(id="ec2", type="ec2", label="ec2"))
        g.add_node(GraphNode(id="role", type="iam_role", label="admin", attrs={"is_admin": True}))
        g.add_edge(GraphEdge(source=INTERNET_NODE_ID, target="sg", type="network_route"))
        g.add_edge(GraphEdge(source="sg", target="ec2", type="network_attach"))
        g.add_edge(GraphEdge(source="ec2", target="role", type="service_instance"))
        # role is reachable from internet, is admin (+30), is high-value iam_role (+20),
        # has 0 outgoing edges. Internet reachable +40 + admin +30 + high value +20 = 90.
        score = g.effective_exposure_score("role")
        assert score >= 80
        assert score <= 100

    def test_isolated_node_gets_lower_score(self) -> None:
        g = SecurityGraph()
        g.add_node(GraphNode(id="iso", type="iam_user", label="iso"))
        score = g.effective_exposure_score("iso")
        # iam_user is in high-value types -> +20; not internet reachable, not admin
        assert score == 20

    def test_unknown_node_scores_zero(self) -> None:
        g = SecurityGraph()
        assert g.effective_exposure_score("ghost") == 0

    def test_top_exposed_returns_sorted_desc(self) -> None:
        g = SecurityGraph()
        g.add_node(GraphNode(id="admin-role", type="iam_role", label="a", attrs={"is_admin": True}))
        g.add_node(GraphNode(id="plain-role", type="iam_role", label="p"))
        g.add_edge(GraphEdge(source=INTERNET_NODE_ID, target="admin-role", type="network_route"))
        top = g.top_exposed(limit=10)
        # admin-role must rank above plain-role
        admin_idx = next(i for i, (n, _) in enumerate(top) if n.id == "admin-role")
        plain_idx = next(i for i, (n, _) in enumerate(top) if n.id == "plain-role")
        assert admin_idx < plain_idx


class TestSerialization:
    def test_to_dict_round_trip(self) -> None:
        g = SecurityGraph()
        g.add_node(GraphNode(id="r", type="iam_role", label="r", attrs={"is_admin": True}))
        g.add_node(GraphNode(id="u", type="iam_user", label="u"))
        g.add_edge(GraphEdge(source="u", target="r", type="iam_assume", attrs={"has_conditions": True}))
        data = g.to_dict()
        g2 = SecurityGraph.from_dict(data)
        assert g2.node_count() == g.node_count()
        assert g2.edge_count() == g.edge_count()
        assert g2.get_node("r") is not None
        assert g2.get_node("r").attrs["is_admin"] is True  # type: ignore[union-attr]
        # Edge round-trip
        out = g2.out_edges("u")
        assert len(out) == 1
        assert out[0].type == "iam_assume"
        assert out[0].attrs["has_conditions"] is True

    def test_to_dict_schema_version_present(self) -> None:
        g = SecurityGraph()
        data = g.to_dict()
        assert data["schema_version"] == "1"
        assert isinstance(data["nodes"], list)
        assert isinstance(data["edges"], list)


class TestBuildFromArtifacts:
    def test_empty_artifacts_still_returns_frozen_graph(self) -> None:
        g = build_from_scan_artifacts(
            escalation_paths=[],
            iam_trust_graph=None,
            resource_relationships=None,
            findings=[],
        )
        assert g.frozen is True
        assert g.has_node(INTERNET_NODE_ID)

    def test_escalation_paths_materialize_principals(self) -> None:
        ep = EscalationPath(
            principal_arn="arn:aws:iam::123:user/alice",
            principal_name="alice",
            principal_type="User",
            method="AttachUserPolicy",
            category=EscalationCategory.IAM_SELF_MUTATION,
            required_actions=["iam:AttachUserPolicy"],
            target_privilege="Admin via attaching policy",
            severity=Severity.CRITICAL,
        )
        g = build_from_scan_artifacts(
            escalation_paths=[ep],
            iam_trust_graph=None,
            resource_relationships=None,
            findings=[],
        )
        node = g.get_node("arn:aws:iam::123:user/alice")
        assert node is not None
        assert node.type == "iam_user"
        assert node.attrs.get("has_escalation") is True

    def test_public_sg_finding_creates_internet_route(self) -> None:
        f = _make_finding("aws-vpc-002", "sg-0open", severity=Severity.CRITICAL)
        g = build_from_scan_artifacts(
            escalation_paths=[],
            iam_trust_graph=None,
            resource_relationships=None,
            findings=[f],
        )
        # Internet -> sg-0open route must exist
        out = g.out_edges(INTERNET_NODE_ID, edge_type="network_route")
        assert any(e.target == "sg-0open" for e in out)

    def test_s3_bucket_finding_creates_data_node(self) -> None:
        f = _make_finding("aws-s3-001", "arn:aws:s3:::sensitive-data")
        g = build_from_scan_artifacts(
            escalation_paths=[],
            iam_trust_graph=None,
            resource_relationships=None,
            findings=[f],
        )
        node = g.get_node("arn:aws:s3:::sensitive-data")
        assert node is not None
        assert node.type == "s3_bucket"

    def test_secret_finding_creates_data_node(self) -> None:
        f = _make_finding("aws-sm-002", "arn:aws:secretsmanager:us-east-1:123:secret:db-creds")
        g = build_from_scan_artifacts(
            escalation_paths=[],
            iam_trust_graph=None,
            resource_relationships=None,
            findings=[f],
        )
        node = g.get_node("arn:aws:secretsmanager:us-east-1:123:secret:db-creds")
        assert node is not None
        assert node.type == "secret"
