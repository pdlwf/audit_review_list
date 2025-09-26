from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable

from cim.graph.graph_builder import EdgePayload, ImpactGraphBuilder
from cim.graph.metrics import compute_metrics, hotspots_from_metrics
from cim.utils import timestamp


def build_json_report(output_path: Path, builder: ImpactGraphBuilder, hotspots: Dict[str, Dict[str, float]]) -> Dict[str, object]:
    metrics = compute_metrics(builder)
    hotspot_scores = hotspots_from_metrics(metrics, hotspots)
    nodes_payload = []
    for node in builder.nodes_payload():
        meta = {
            "id": node.id,
            "type": node.type,
        }
        if node.path:
            meta["path"] = node.path
        if node.lang:
            meta["lang"] = node.lang
        if node.file:
            meta["file"] = node.file
        if node.tags:
            meta["tags"] = node.tags
        meta.update(node.attributes)
        meta.update(metrics.get(node.id, {}))
        nodes_payload.append(meta)

    edges_payload = []
    for edge in builder.edges_payload():
        payload = {
            "from": edge.source,
            "to": edge.target,
            "kind": edge.kind,
            "strength": edge.strength,
        }
        if edge.note:
            payload["note"] = edge.note
        if edge.rule:
            payload["rule"] = edge.rule
        edges_payload.append(payload)

    reverse_deps = {}
    reverse_adj = builder.reverse_adjacency()
    for node, neighbors in reverse_adj.items():
        if neighbors:
            reverse_deps[node] = sorted(neighbors)

    hotspots_list = [
        {"id": node, **data}
        for node, data in hotspot_scores.items()
        if data.get("centrality") or data.get("hotScore")
    ]
    hotspots_list.sort(key=lambda item: (item.get("hotScore", 0), item.get("centrality", 0)), reverse=True)

    report = {
        "version": "1.0",
        "generatedAt": timestamp(),
        "nodes": nodes_payload,
        "edges": edges_payload,
        "reverseDependencies": reverse_deps,
        "hotspots": hotspots_list[:50],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    return report


__all__ = ["build_json_report"]
