"""Security Graph backbone - unified in-memory graph of AWS infrastructure.

A typed, directed multigraph consolidating relationships that previously lived
in three separate data structures:

- ``iam_trust_graph.AssumeRoleGraph`` (TrustEdge list, BFS reachability)
- ``correlate.ResourceRelationships`` (EC2 -> role, EC2 -> SG, Lambda -> role)
- ``iam_analyzer.ResolvedPrincipal`` (allowed/denied actions per principal)

Everything is held in plain Python dictionaries - no ``networkx`` or ``Neo4j``
dependency. The graph is built during ``scan`` (post-checks, zero extra API
calls), serialized into ``ScanReport.security_graph``, and consumed by
``blast_radius`` and any downstream feature.

Node and edge schemas are stable across the v3.x release line; new node types
or edge types can be added without breaking older readers.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Literal

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

NodeType = Literal[
    "internet",
    "vpc",
    "subnet",
    "security_group",
    "internet_gateway",
    "nat_gateway",
    "vpc_peering",
    "ec2",
    "lambda",
    "ecs_task",
    "iam_user",
    "iam_role",
    "iam_group",
    "oidc_provider",
    "s3_bucket",
    "secret",
    "kms_key",
    "rds_instance",
]

EdgeType = Literal[
    "network_route",  # internet -> subnet (when public route), peering, NAT routes
    "network_attach",  # sg -> ec2, subnet -> ec2/lambda
    "iam_assume",  # principal -> role (via trust policy)
    "iam_action",  # principal -> resource (via allowed action)
    "iam_pass_role",  # principal -> role (via iam:PassRole + service)
    "service_instance",  # ec2 -> role (via instance profile attachment)
    "data_resource_policy",  # bucket/secret -> principal (via resource-based policy)
]

INTERNET_NODE_ID = "::internet"

_BFS_MAX_FANOUT = 10_000  # hard ceiling to keep memory bounded on adversarial inputs


@dataclass(frozen=True)
class GraphNode:
    """A single node in the security graph.

    Attributes:
        id: Stable identifier (ARN, instance-id, sg-id, etc.). ``::internet``
            for the sentinel internet node.
        type: One of ``NodeType``.
        label: Short human-readable label for display.
        attrs: Free-form attributes (CIDR, encryption flag, etc.). Must be
            JSON-serializable; the graph is persisted into ``ScanReport``.
    """

    id: str
    type: NodeType
    label: str
    attrs: dict[str, Any] = field(default_factory=dict, hash=False)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "type": self.type, "label": self.label, "attrs": self.attrs}


@dataclass(frozen=True)
class GraphEdge:
    """A directed edge between two nodes.

    Multiple edges between the same pair of nodes are allowed, distinguished
    by ``type`` (e.g. EC2 has both a ``network_attach`` to its SG and a
    ``service_instance`` to its IAM role).
    """

    source: str
    target: str
    type: EdgeType
    attrs: dict[str, Any] = field(default_factory=dict, hash=False)

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "target": self.target, "type": self.type, "attrs": self.attrs}


# Resource types that count as "high value" for exposure scoring. These also
# anchor the "what's reachable from the internet?" calculation.
_HIGH_VALUE_TYPES = frozenset({"s3_bucket", "secret", "kms_key", "rds_instance", "iam_role", "iam_user"})


class SecurityGraph:
    """Typed in-memory graph backbone shared across features.

    Construction is one-shot from scan data. After ``freeze()`` no further
    mutations are accepted; the graph is then queried by blast-radius, the
    exposure scorer, attack-chain rules (future), and the JSON exporter.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        # adjacency lists, both directions, keyed by source/target id
        self._out: dict[str, list[GraphEdge]] = {}
        self._in: dict[str, list[GraphEdge]] = {}
        self._frozen: bool = False
        # Ensure the internet sentinel always exists
        self.add_node(GraphNode(id=INTERNET_NODE_ID, type="internet", label="Internet"))

    # ------------------------------------------------------------------
    # Construction (mutation API; locked once freeze() is called)
    # ------------------------------------------------------------------
    def add_node(self, node: GraphNode) -> None:
        if self._frozen:
            raise RuntimeError("SecurityGraph is frozen; no further mutations allowed.")
        # If the node already exists, merge attrs (last write wins per key) so
        # collectors can be called in any order without clobbering metadata.
        if node.id in self._nodes:
            existing = self._nodes[node.id]
            merged_attrs = {**existing.attrs, **node.attrs}
            self._nodes[node.id] = GraphNode(
                id=existing.id, type=existing.type, label=node.label or existing.label, attrs=merged_attrs
            )
            return
        self._nodes[node.id] = node
        self._out.setdefault(node.id, [])
        self._in.setdefault(node.id, [])

    def add_edge(self, edge: GraphEdge) -> None:
        if self._frozen:
            raise RuntimeError("SecurityGraph is frozen; no further mutations allowed.")
        # Ensure endpoints exist; if a caller adds an edge before its target
        # node, create a minimal placeholder so the graph stays consistent.
        for endpoint in (edge.source, edge.target):
            if endpoint not in self._nodes:
                # Heuristic: unknown id is a placeholder typed as the closest
                # match. Real type can still be added later via add_node().
                self.add_node(GraphNode(id=endpoint, type="iam_role", label=endpoint))
        # Deduplicate exact (source, target, type) triples to keep edge count
        # bounded on repeated calls (collectors can run on overlapping data).
        existing = self._out.get(edge.source, [])
        for e in existing:
            if e.target == edge.target and e.type == edge.type:
                return
        self._out.setdefault(edge.source, []).append(edge)
        self._in.setdefault(edge.target, []).append(edge)

    def freeze(self) -> None:
        """Lock the graph against further mutations. Idempotent."""
        self._frozen = True

    # ------------------------------------------------------------------
    # Read API
    # ------------------------------------------------------------------
    @property
    def frozen(self) -> bool:
        return self._frozen

    def node_count(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return sum(len(e) for e in self._out.values())

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def get_node(self, node_id: str) -> GraphNode | None:
        return self._nodes.get(node_id)

    def nodes_by_type(self, node_type: NodeType) -> list[GraphNode]:
        return [n for n in self._nodes.values() if n.type == node_type]

    def out_edges(self, node_id: str, edge_type: EdgeType | None = None) -> list[GraphEdge]:
        edges = self._out.get(node_id, [])
        return [e for e in edges if edge_type is None or e.type == edge_type]

    def in_edges(self, node_id: str, edge_type: EdgeType | None = None) -> list[GraphEdge]:
        edges = self._in.get(node_id, [])
        return [e for e in edges if edge_type is None or e.type == edge_type]

    # ------------------------------------------------------------------
    # Traversal
    # ------------------------------------------------------------------
    def forward_reach(
        self,
        source_id: str,
        max_hops: int = 6,
        max_nodes: int = 500,
        allow_edge_types: tuple[EdgeType, ...] | None = None,
    ) -> list[tuple[str, int]]:
        """Return ``(node_id, hop_count)`` pairs reachable from ``source_id``.

        BFS forward. Bounded by ``max_hops`` and ``max_nodes`` so adversarial
        inputs cannot blow up memory.
        """
        if source_id not in self._nodes:
            return []
        visited: dict[str, int] = {source_id: 0}
        queue: deque[tuple[str, int]] = deque([(source_id, 0)])
        result: list[tuple[str, int]] = []
        while queue and len(visited) < min(max_nodes, _BFS_MAX_FANOUT):
            current, hops = queue.popleft()
            if hops >= max_hops:
                continue
            for edge in self._out.get(current, []):
                if allow_edge_types is not None and edge.type not in allow_edge_types:
                    continue
                if edge.target in visited:
                    continue
                visited[edge.target] = hops + 1
                result.append((edge.target, hops + 1))
                queue.append((edge.target, hops + 1))
        return result

    def backward_reach(
        self,
        target_id: str,
        max_hops: int = 6,
        max_nodes: int = 500,
        allow_edge_types: tuple[EdgeType, ...] | None = None,
    ) -> list[tuple[str, int]]:
        """Return ``(node_id, hop_count)`` pairs that can reach ``target_id``."""
        if target_id not in self._nodes:
            return []
        visited: dict[str, int] = {target_id: 0}
        queue: deque[tuple[str, int]] = deque([(target_id, 0)])
        result: list[tuple[str, int]] = []
        while queue and len(visited) < min(max_nodes, _BFS_MAX_FANOUT):
            current, hops = queue.popleft()
            if hops >= max_hops:
                continue
            for edge in self._in.get(current, []):
                if allow_edge_types is not None and edge.type not in allow_edge_types:
                    continue
                if edge.source in visited:
                    continue
                visited[edge.source] = hops + 1
                result.append((edge.source, hops + 1))
                queue.append((edge.source, hops + 1))
        return result

    def shortest_path(
        self,
        source_id: str,
        target_id: str,
        max_hops: int = 8,
    ) -> list[GraphEdge] | None:
        """BFS shortest path source -> target. Returns edges in order or None."""
        if source_id not in self._nodes or target_id not in self._nodes:
            return None
        if source_id == target_id:
            return []
        # parent map: node -> edge that reached it
        parent: dict[str, GraphEdge | None] = {source_id: None}
        queue: deque[tuple[str, int]] = deque([(source_id, 0)])
        while queue:
            current, hops = queue.popleft()
            if hops >= max_hops:
                continue
            for edge in self._out.get(current, []):
                if edge.target in parent:
                    continue
                parent[edge.target] = edge
                if edge.target == target_id:
                    # reconstruct
                    chain: list[GraphEdge] = []
                    cursor: str | None = target_id
                    while cursor is not None and parent.get(cursor) is not None:
                        e = parent[cursor]
                        if e is None:
                            break
                        chain.append(e)
                        cursor = e.source
                    return list(reversed(chain))
                queue.append((edge.target, hops + 1))
        return None

    def paths_from_internet(self, target_id: str, max_hops: int = 8) -> list[GraphEdge] | None:
        """Shortest path from the internet sentinel to ``target_id``.

        Used for "is this resource reachable from the internet?" questions
        and for the public-exposure component of the effective exposure score.
        """
        return self.shortest_path(INTERNET_NODE_ID, target_id, max_hops=max_hops)

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------
    def effective_exposure_score(self, node_id: str) -> int:
        """Heuristic 0-100 score combining network reach + privilege + value.

        Documented heuristic. Not a calibrated CVSS-style metric; surfaces
        nodes that warrant investigation, not absolute risk.

        - +40 if reachable from the internet via ``paths_from_internet``
        - +30 if the node is admin (iam_role / iam_user attrs.is_admin=True)
        - +20 if node type is in the "high value" set
        - +1 per outgoing edge up to 10 (proxy for "how much it can touch")
        """
        node = self.get_node(node_id)
        if node is None:
            return 0
        score = 0
        if self.paths_from_internet(node_id, max_hops=6) is not None:
            score += 40
        if node.attrs.get("is_admin") is True:
            score += 30
        if node.type in _HIGH_VALUE_TYPES:
            score += 20
        score += min(10, len(self._out.get(node_id, [])))
        return min(100, score)

    def top_exposed(self, limit: int = 20) -> list[tuple[GraphNode, int]]:
        """Return top-N nodes ranked by ``effective_exposure_score`` descending."""
        scored = [(n, self.effective_exposure_score(n.id)) for n in self._nodes.values()]
        scored.sort(key=lambda x: -x[1])
        return scored[:limit]

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict embedded in ScanReport."""
        return {
            "schema_version": "1",
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for edges in self._out.values() for e in edges],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecurityGraph:
        g = cls()
        # Skip the internet sentinel from the input; it's already added by __init__.
        for raw in data.get("nodes", []):
            node_id = raw.get("id")
            if node_id == INTERNET_NODE_ID:
                # Update attrs if any were persisted
                g.add_node(
                    GraphNode(
                        id=INTERNET_NODE_ID,
                        type="internet",
                        label=raw.get("label", "Internet"),
                        attrs=raw.get("attrs", {}),
                    )
                )
                continue
            g.add_node(
                GraphNode(
                    id=raw["id"],
                    type=raw["type"],
                    label=raw.get("label", raw["id"]),
                    attrs=raw.get("attrs", {}),
                )
            )
        for raw in data.get("edges", []):
            g.add_edge(
                GraphEdge(
                    source=raw["source"],
                    target=raw["target"],
                    type=raw["type"],
                    attrs=raw.get("attrs", {}),
                )
            )
        return g


# ---------------------------------------------------------------------------
# Construction helpers - populate from scan artifacts produced elsewhere
# ---------------------------------------------------------------------------
def build_from_scan_artifacts(
    *,
    escalation_paths: list[Any],
    iam_trust_graph: Any | None,
    resource_relationships: Any | None,
    findings: list[Any],
) -> SecurityGraph:
    """Assemble a SecurityGraph from existing scan-time data structures.

    Inputs (all optional; the function copes with ``None`` / empty inputs):

    - ``escalation_paths``: ``list[EscalationPath]`` from ``iam_analyzer``
    - ``iam_trust_graph``: ``AssumeRoleGraph`` from ``iam_trust_graph``
    - ``resource_relationships``: ``ResourceRelationships`` from ``correlate``
    - ``findings``: full list of ``Finding`` objects from the report

    No AWS API calls. Pure transformation. Returns a frozen graph.
    """
    g = SecurityGraph()

    # ---------- Identity layer ---------------------------------------------
    if iam_trust_graph is not None:
        for role_arn, role_name in getattr(iam_trust_graph, "role_arn_to_name", {}).items():
            is_admin = bool(getattr(iam_trust_graph, "role_admin_status", {}).get(role_arn, False))
            g.add_node(
                GraphNode(
                    id=role_arn,
                    type="iam_role",
                    label=role_name,
                    attrs={"is_admin": is_admin},
                )
            )
        for edge in getattr(iam_trust_graph, "edges", []):
            # Skip the trusted-principal side if it's a wildcard / external root;
            # those are best-effort represented as separate nodes for visibility.
            source_arn = edge.source_arn
            if source_arn == "*":
                # Represent "Principal: *" with a sentinel that the operator
                # can spot in the output.
                g.add_node(GraphNode(id="::any-aws-principal", type="iam_role", label="* (any AWS principal)"))
                source_arn = "::any-aws-principal"
            elif source_arn.endswith(":root"):
                # External account root - keep as iam_user node with attrs.
                g.add_node(GraphNode(id=source_arn, type="iam_user", label=source_arn))
            g.add_edge(
                GraphEdge(
                    source=source_arn,
                    target=edge.target_role_arn,
                    type="iam_assume",
                    attrs={"has_conditions": edge.has_conditions},
                )
            )

    # Escalation paths surface "what does this principal effectively get?".
    # Treat any non-admin principal that has an escalation path as an admin
    # candidate for graph purposes (the path itself is the privilege gain).
    for ep in escalation_paths:
        principal_id = getattr(ep, "principal_arn", None)
        if not principal_id:
            continue
        existing = g.get_node(principal_id)
        if existing is None:
            # Materialize the principal if it's not already on the graph
            principal_type: NodeType = "iam_user" if getattr(ep, "principal_type", "Role") == "User" else "iam_role"
            g.add_node(
                GraphNode(
                    id=principal_id,
                    type=principal_type,
                    label=getattr(ep, "principal_name", principal_id),
                    attrs={"has_escalation": True},
                )
            )
        else:
            # Merge has_escalation flag onto the existing node
            g.add_node(
                GraphNode(
                    id=existing.id,
                    type=existing.type,
                    label=existing.label,
                    attrs={**existing.attrs, "has_escalation": True},
                )
            )

    # ---------- Compute / network layer (best-effort from relationships) ---
    if resource_relationships is not None:
        # EC2 -> Security Group attach + EC2 -> IAM role instance profile
        for instance_id, sg_ids in getattr(resource_relationships, "ec2_sgs", {}).items():
            g.add_node(GraphNode(id=instance_id, type="ec2", label=instance_id))
            for sg_id in sg_ids:
                g.add_node(GraphNode(id=sg_id, type="security_group", label=sg_id))
                g.add_edge(GraphEdge(source=sg_id, target=instance_id, type="network_attach"))
        for instance_id, role_name in getattr(resource_relationships, "ec2_roles", {}).items():
            # role_name is just the name; without ARN we can't link reliably to
            # iam_role nodes. We add a service_instance edge that uses the name
            # so callers can still navigate; if a matching ARN node exists, a
            # second edge keyed on ARN is also added.
            g.add_node(GraphNode(id=instance_id, type="ec2", label=instance_id))
            g.add_node(
                GraphNode(id=f"role-name:{role_name}", type="iam_role", label=role_name, attrs={"name_only": True})
            )
            g.add_edge(GraphEdge(source=instance_id, target=f"role-name:{role_name}", type="service_instance"))
            # Try to link to a real role ARN node by matching label
            for role_node in g.nodes_by_type("iam_role"):
                if role_node.label == role_name and role_node.id != f"role-name:{role_name}":
                    g.add_edge(GraphEdge(source=instance_id, target=role_node.id, type="service_instance"))
                    break

        for fn_name, role_arn in getattr(resource_relationships, "lambda_roles", {}).items():
            fn_id = f"lambda:{fn_name}"
            g.add_node(GraphNode(id=fn_id, type="lambda", label=fn_name))
            if role_arn:
                # role_arn might be the full ARN; add a service_instance edge
                if not g.has_node(role_arn):
                    g.add_node(GraphNode(id=role_arn, type="iam_role", label=role_arn.rsplit("/", 1)[-1]))
                g.add_edge(GraphEdge(source=fn_id, target=role_arn, type="service_instance"))

    # ---------- Internet edges from findings ------------------------------
    # Public SG findings (aws-vpc-002) imply an internet -> SG network route
    open_sg_ids: set[str] = set()
    for f in findings:
        check_id = getattr(f, "check_id", "")
        rid = getattr(f, "resource_id", "")
        if check_id == "aws-vpc-002" and rid.startswith("sg-"):
            open_sg_ids.add(rid)
        # Lambda Function URL public (aws-lambda-001 / TF-002)
        if rid and check_id in ("aws-lambda-001", "TF-002-lambda-function-url-persistence"):
            fn_id = rid if rid.startswith("lambda:") else f"lambda:{rid.rsplit(':', 1)[-1]}"
            if not g.has_node(fn_id):
                g.add_node(GraphNode(id=fn_id, type="lambda", label=rid.rsplit(":", 1)[-1]))
            g.add_edge(GraphEdge(source=INTERNET_NODE_ID, target=fn_id, type="network_route"))

    for sg_id in open_sg_ids:
        if not g.has_node(sg_id):
            g.add_node(GraphNode(id=sg_id, type="security_group", label=sg_id))
        g.add_edge(GraphEdge(source=INTERNET_NODE_ID, target=sg_id, type="network_route"))

    # ---------- Data layer (best-effort placeholder nodes from findings) ---
    # S3 buckets and secrets referenced in findings get materialised so blast
    # radius can show admin-reaches-data scenarios. Resource-policy parsing is
    # deferred to v3.x; today we represent the resource node only.
    seen_data: set[str] = set()
    for f in findings:
        rid = getattr(f, "resource_id", "")
        if rid.startswith("arn:aws:s3:::") and rid not in seen_data:
            g.add_node(GraphNode(id=rid, type="s3_bucket", label=rid.rsplit(":::", 1)[-1]))
            seen_data.add(rid)
        elif rid.startswith("arn:aws:secretsmanager:") and rid not in seen_data:
            label = rid.rsplit(":", 1)[-1]
            g.add_node(GraphNode(id=rid, type="secret", label=label))
            seen_data.add(rid)
        elif rid.startswith("arn:aws:kms:") and rid not in seen_data:
            g.add_node(GraphNode(id=rid, type="kms_key", label=rid.rsplit(":", 1)[-1]))
            seen_data.add(rid)

    g.freeze()
    return g
