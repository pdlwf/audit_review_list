from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List

from cim.graph.graph_builder import ImpactGraphBuilder
from cim.utils import load_yaml


@dataclass
class RuleEdge:
    to: List[str]
    kind: str
    strength: str
    note: str | None = None


@dataclass
class FileCondition:
    include: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)


@dataclass
class Rule:
    name: str
    when: FileCondition
    edges: List[RuleEdge]


class RulesEngine:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.rules: List[Rule] = []

    def load(self, paths: Iterable[Path]) -> None:
        for path in paths:
            if not path.exists():
                continue
            data = load_yaml(path)
            name = data.get("name", path.stem)
            when_block = data.get("when", {}).get("file", {})
            include = when_block.get("include", [])
            exclude = when_block.get("exclude", [])
            edges = []
            for edge_def in data.get("addsEdges", []):
                targets = edge_def.get("to")
                if isinstance(targets, str):
                    to_patterns = [item.strip() for item in targets.split(",") if item.strip()]
                else:
                    to_patterns = targets or []
                edges.append(
                    RuleEdge(
                        to=to_patterns,
                        kind=edge_def.get("kind", "rule"),
                        strength=edge_def.get("strength", "weak"),
                        note=edge_def.get("note"),
                    )
                )
            rule = Rule(name=name, when=FileCondition(include=include, exclude=exclude), edges=edges)
            self.rules.append(rule)

    def apply(self, builder: ImpactGraphBuilder) -> None:
        for rule in self.rules:
            for node_id, payload in builder.nodes.items():
                if payload.type != "file":
                    continue
                if not self._matches(payload.path or node_id, rule.when):
                    continue
                for edge in rule.edges:
                    targets = self._expand_targets(edge.to, builder)
                    for target in targets:
                        builder.add_edge(node_id, target, kind=edge.kind, strength=edge.strength, note=edge.note, rule=rule.name)

    def _matches(self, path: str, condition: FileCondition) -> bool:
        rel = Path(path)
        include_patterns = self._expand_pattern_variants(condition.include)
        if include_patterns and not any(rel.match(pattern) for pattern in include_patterns):
            return False
        exclude_patterns = self._expand_pattern_variants(condition.exclude)
        if any(rel.match(pattern) for pattern in exclude_patterns):
            return False
        return True

    def _expand_targets(self, patterns: Iterable[str], builder: ImpactGraphBuilder) -> List[str]:
        targets: List[str] = []
        for pattern in patterns:
            variants = self._expand_pattern_variants([pattern])
            matched = [
                node_id
                for node_id, payload in builder.nodes.items()
                if payload.type == "file" and any(Path(payload.path or node_id).match(var) for var in variants)
            ]
            if matched:
                targets.extend(matched)
            else:
                targets.append(builder.ensure_virtual_node(pattern, "pattern"))
        return targets

    @staticmethod
    def _expand_pattern_variants(patterns: Iterable[str]) -> List[str]:
        variants: List[str] = []
        for pattern in patterns:
            variants.append(pattern)
            if "**/" in pattern:
                variants.append(pattern.replace("**/", ""))
        return variants


__all__ = ["RulesEngine"]
