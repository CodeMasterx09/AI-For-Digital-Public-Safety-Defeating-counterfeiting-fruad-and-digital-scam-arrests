"""
Fraud Network Graph Intelligence — zero external dependencies.
Builds an adjacency model, finds fraud rings via weight-thresholded
connected components, scores risk, and generates intel-package summaries.
"""

class Graph:
    def __init__(self):
        self.nodes = {}            # id -> attrs dict
        self.adj = {}              # id -> {neighbor_id: edge_attrs}

    def add_node(self, nid, **attrs):
        self.nodes.setdefault(nid, {}).update(attrs)
        self.adj.setdefault(nid, {})

    def add_edge(self, u, v, **attrs):
        self.add_node(u); self.add_node(v)
        self.adj[u][v] = attrs
        self.adj[v][u] = attrs

    def edges(self):
        seen = set()
        for u, neighbors in self.adj.items():
            for v, attrs in neighbors.items():
                key = tuple(sorted((u, v)))
                if key not in seen:
                    seen.add(key)
                    yield u, v, attrs

    def number_of_nodes(self):
        return len(self.nodes)

    def number_of_edges(self):
        return sum(1 for _ in self.edges())


def build_graph(nodes, edges):
    G = Graph()
    for n in nodes:
        G.add_node(n["id"], **{k: v for k, v in n.items() if k != "id"})
    for e in edges:
        G.add_edge(e["source"], e["target"], weight=e.get("weight", 1.0), relation=e.get("relation"))
    return G


def _connected_components(G, weight_threshold=0.45):
    """Components using only edges above a confidence threshold — keeps
    high-confidence fraud-ring links separate from weak/noisy links."""
    visited = set()
    components = []
    for start in G.nodes:
        if start in visited:
            continue
        stack, comp = [start], set()
        while stack:
            cur = stack.pop()
            if cur in comp:
                continue
            comp.add(cur)
            for nbr, attrs in G.adj.get(cur, {}).items():
                if attrs.get("weight", 1.0) >= weight_threshold and nbr not in comp:
                    stack.append(nbr)
        visited |= comp
        components.append(comp)
    return components


def detect_clusters(G, min_size=3, weight_threshold=0.45):
    components = _connected_components(G, weight_threshold)
    clusters = []
    for idx, comp in enumerate(components):
        if len(comp) < min_size:
            continue
        # use ALL edges among members (not just thresholded ones) for density/strength
        sub_edges = [(u, v, a) for u, v, a in G.edges() if u in comp and v in comp]
        n = len(comp)
        max_possible = n * (n - 1) / 2 if n > 1 else 1
        density = len(sub_edges) / max_possible
        avg_weight = sum(a.get("weight", 1.0) for _, _, a in sub_edges) / len(sub_edges) if sub_edges else 0
        risk_score = round(min(100, density * 60 + avg_weight * 40), 1)
        clusters.append({
            "cluster_id": idx,
            "members": list(comp),
            "size": n,
            "density": round(density, 2),
            "avg_link_strength": round(avg_weight, 2),
            "risk_score": risk_score,
            "risk_level": "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 30 else "LOW",
        })
    clusters.sort(key=lambda c: c["risk_score"], reverse=True)
    return clusters


def generate_intel_package(cluster, G):
    members = set(cluster["members"])
    linkages = [
        {"from": u, "to": v, "relation": a.get("relation"), "weight": a.get("weight")}
        for u, v, a in G.edges() if u in members and v in members
    ]
    return {
        "cluster_id": cluster["cluster_id"],
        "risk_level": cluster["risk_level"],
        "risk_score": cluster["risk_score"],
        "entity_count": cluster["size"],
        "entities": [{"id": m, "type": G.nodes.get(m, {}).get("type")} for m in cluster["members"]],
        "linkages": linkages,
        "summary": (
            f"Cluster {cluster['cluster_id']} contains {cluster['size']} linked entities with "
            f"{cluster['risk_level']} coordinated-fraud risk (score {cluster['risk_score']}/100), "
            f"based on link density and connection strength across shared devices/accounts."
        ),
    }


if __name__ == "__main__":
    from data_generator import generate_fraud_graph
    nodes, edges = generate_fraud_graph()
    G = build_graph(nodes, edges)
    clusters = detect_clusters(G)
    print(f"nodes={G.number_of_nodes()} edges={G.number_of_edges()} clusters={len(clusters)}")
    for c in clusters[:2]:
        print(c["cluster_id"], c["risk_level"], c["risk_score"], c["size"])
    if clusters:
        print(generate_intel_package(clusters[0], G)["summary"])
