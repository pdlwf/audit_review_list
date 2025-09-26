from __future__ import annotations

from typing import Dict, Iterable, List, Tuple

from cim.graph.graph_builder import ImpactGraphBuilder


def _edge_weights(builder: ImpactGraphBuilder) -> Tuple[Dict[str, List[Tuple[str, float]]], Dict[str, List[Tuple[str, float]]]]:
    forward: Dict[str, List[Tuple[str, float]]] = {}
    reverse: Dict[str, List[Tuple[str, float]]] = {}
    for node in builder.nodes_payload():
        forward.setdefault(node.id, [])
        reverse.setdefault(node.id, [])
    for edge in builder.edges_payload():
        weight = 1.0 if edge.strength == "strong" else 0.5
        forward.setdefault(edge.source, []).append((edge.target, weight))
        reverse.setdefault(edge.target, []).append((edge.source, weight))
    return forward, reverse


def compute_metrics(builder: ImpactGraphBuilder) -> Dict[str, Dict[str, float]]:
    nodes = [node.id for node in builder.nodes_payload()]
    if not nodes:
        return {}
    forward, reverse = _edge_weights(builder)
    in_degree = {node: float(len(reverse.get(node, []))) for node in nodes}
    out_degree = {node: float(len(forward.get(node, []))) for node in nodes}

    n = len(nodes)
    scores = {node: 1.0 / n for node in nodes}
    damping = 0.85
    if n == 1:
        scores[nodes[0]] = 1.0
    else:
        for _ in range(20):
            new_scores = {node: (1 - damping) / n for node in nodes}
            for src in nodes:
                neighbors = forward.get(src, [])
                if not neighbors:
                    spread = scores[src] / n
                    for node in nodes:
                        new_scores[node] += damping * spread
                    continue
                weight_sum = sum(weight for _, weight in neighbors) or 1.0
                for dst, weight in neighbors:
                    new_scores[dst] += damping * scores[src] * (weight / weight_sum)
            scores = new_scores

    metrics: Dict[str, Dict[str, float]] = {}
    for node in nodes:
        metrics[node] = {
            "inDegree": in_degree.get(node, 0.0),
            "outDegree": out_degree.get(node, 0.0),
            "centrality": round(scores.get(node, 0.0), 6),
            "betweenness": 0.0,
        }
    return metrics


def hotspots_from_metrics(metrics: Dict[str, Dict[str, float]], hotspots: Dict[str, Dict[str, float]]) -> Dict[str, Dict[str, float]]:
    results: Dict[str, Dict[str, float]] = {}
    for node, meta in metrics.items():
        entry = {"centrality": meta.get("centrality", 0.0)}
        if node in hotspots:
            entry.update(hotspots[node])
        if entry.get("centrality") or entry.get("hotScore"):
            results[node] = entry
    return results


__all__ = ["compute_metrics", "hotspots_from_metrics"]
