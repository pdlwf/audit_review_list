from __future__ import annotations

import fnmatch
import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from cim.parsers.config_parser import ConfigParseResult
from cim.parsers.js_ts_parser import JsParseResult
from cim.parsers.python_parser import PythonParseResult, SymbolRecord
from cim.utils import Config, classify_language, normalize_path, tag_for_path


@dataclass
class NodePayload:
    id: str
    type: str
    path: Optional[str] = None
    lang: Optional[str] = None
    file: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    attributes: Dict[str, object] = field(default_factory=dict)


@dataclass
class EdgePayload:
    source: str
    target: str
    kind: str
    strength: str
    note: Optional[str] = None
    rule: Optional[str] = None


class ImpactGraphBuilder:
    def __init__(self, config: Config, known_files: Iterable[Path], hotspots: Dict[str, Dict[str, float]]) -> None:
        self.config = config
        self.root = config.project_root
        self.hotspots = hotspots
        self.nodes: Dict[str, NodePayload] = {}
        self.edge_keys: Set[Tuple[str, str, str, str]] = set()
        self.known_files = {normalize_path(path, self.root): path for path in known_files}
        self.alias_map = self._build_alias_map(config.aliases.get("tsconfigPaths", []))
        self.symbol_defs: Dict[str, List[str]] = {}
        self.symbol_details: Dict[str, SymbolRecord] = {}
        self.edges: List[EdgePayload] = []
        self.adj: Dict[str, Set[str]] = defaultdict(set)
        self.rev_adj: Dict[str, Set[str]] = defaultdict(set)

    def _build_alias_map(self, entries: Iterable[str]) -> Dict[str, str]:
        mapping: Dict[str, str] = {}
        for entry in entries:
            if ":" not in entry:
                continue
            prefix, target = entry.split(":", 1)
            prefix = prefix.rstrip("/*")
            target = target.rstrip("/*")
            mapping[prefix] = target
        return mapping

    def ensure_file_node(self, path: Path) -> str:
        rel = normalize_path(path, self.root)
        if rel not in self.nodes:
            lang = classify_language(path)
            node = NodePayload(
                id=rel,
                type="file",
                path=rel,
                lang=lang,
                tags=tag_for_path(path, self.root),
            )
            hot_info = self.hotspots.get(rel)
            if hot_info:
                node.attributes.update(hot_info)
                node.attributes["hotScore"] = hot_info.get("hotScore")
            self.nodes[rel] = node
        return rel

    def ensure_virtual_node(self, node_id: str, node_type: str, attributes: Optional[Dict[str, object]] = None) -> str:
        if node_id not in self.nodes:
            payload = NodePayload(id=node_id, type=node_type, attributes=attributes or {})
            self.nodes[node_id] = payload
        return node_id

    def ensure_symbol_node(self, file_node: str, symbol: SymbolRecord) -> str:
        symbol_id = f"{file_node}::{symbol.name}"
        if symbol_id not in self.nodes:
            payload = NodePayload(
                id=symbol_id,
                type="symbol",
                file=file_node,
                lang=self.nodes[file_node].lang,
                attributes={"kind": symbol.kind, "lineno": symbol.lineno},
            )
            self.nodes[symbol_id] = payload
            self.symbol_details[symbol_id] = symbol
            self.symbol_defs.setdefault(symbol.name, []).append(symbol_id)
        return symbol_id

    def add_edge(self, source: str, target: str, kind: str, strength: str = "strong", note: Optional[str] = None, rule: Optional[str] = None) -> None:
        signature = (source, target, kind, strength)
        if signature in self.edge_keys:
            return
        self.edge_keys.add(signature)
        edge_payload = EdgePayload(source=source, target=target, kind=kind, strength=strength, note=note, rule=rule)
        self.edges.append(edge_payload)
        self.adj[source].add(target)
        self.rev_adj[target].add(source)

    # --- ingest results -------------------------------------------------

    def ingest_python(self, result: PythonParseResult) -> None:
        file_node = self.ensure_file_node(result.file_path)
        for symbol in result.symbols:
            self.ensure_symbol_node(file_node, symbol)
        for item in result.imports:
            targets = self._resolve_python_import(result.file_path, item)
            for target in targets:
                self.add_edge(file_node, target, kind="import", strength="strong")
        for ref in result.references:
            targets = self._resolve_symbol_reference(ref.name)
            for symbol_id in targets:
                self.add_edge(file_node, symbol_id, kind="symbol_ref", strength="strong")
        for resource in result.resources:
            res_id = self.ensure_virtual_node(f"resource:{resource.kind}:{resource.value}", "resource", {"kind": resource.kind, "value": resource.value})
            self.add_edge(file_node, res_id, kind="resource", strength="weak")

    def ingest_js(self, result: JsParseResult) -> None:
        file_node = self.ensure_file_node(result.file_path)
        for export in result.exports:
            symbol = SymbolRecord(name=export.name or "default", kind=f"export:{export.kind}", lineno=1)
            self.ensure_symbol_node(file_node, symbol)
        for item in result.imports:
            target = self._resolve_js_import(result.file_path, item.source)
            self.add_edge(file_node, target, kind=item.kind, strength="strong")
        for component in result.components:
            targets = self._resolve_symbol_reference(component)
            for symbol_id in targets:
                self.add_edge(file_node, symbol_id, kind="component_usage", strength="weak")
        for resource in result.resources:
            res_id = self.ensure_virtual_node(f"resource:{resource.kind}:{resource.value}", "resource", {"kind": resource.kind, "value": resource.value})
            self.add_edge(file_node, res_id, kind="resource", strength="weak")

    def ingest_config(self, result: ConfigParseResult) -> None:
        file_node = self.ensure_file_node(result.file_path)
        for dependency in result.dependencies:
            target = self._resolve_resource_path(result.file_path, dependency)
            self.add_edge(file_node, target, kind="config", strength="weak")
        for resource in result.resources:
            res_id = self.ensure_virtual_node(f"resource:{resource['kind']}:{resource['value']}", "resource", resource)
            self.add_edge(file_node, res_id, kind="resource", strength="weak")

    # --- resolution helpers ---------------------------------------------

    def _resolve_python_import(self, origin: Path, record) -> List[str]:
        targets: Set[str] = set()
        if record.level:
            rel_base = origin.parent
            for _ in range(record.level - 1):
                rel_base = rel_base.parent
            module_path = rel_base
            if record.module:
                module_path = module_path / record.module.replace(".", "/")
            for name in record.names:
                candidate = module_path / f"{name}.py"
                normalized = normalize_path(candidate, self.root)
                if normalized in self.known_files:
                    self.ensure_file_node(self.known_files[normalized])
                    targets.add(normalized)
            if record.module and not targets:
                normalized = normalize_path(module_path.with_suffix(".py"), self.root)
                if normalized in self.known_files:
                    self.ensure_file_node(self.known_files[normalized])
                    targets.add(normalized)
        if record.module and not targets:
            module_path = self._module_to_path(record.module)
            if module_path:
                targets.add(module_path)
        for name in record.names:
            lookup = self._module_to_path(name)
            if lookup:
                targets.add(lookup)
        if not targets:
            module = record.module or (record.names[0] if record.names else "")
            if module:
                targets.add(self.ensure_virtual_node(f"module:{module}", "module"))
        return list(targets)

    def _module_to_path(self, module: str) -> Optional[str]:
        candidate = module.replace(".", "/")
        for suffix in (".py", "/__init__.py"):
            rel = f"{candidate}{suffix}"
            if rel in self.known_files:
                self.ensure_file_node(self.known_files[rel])
                return rel
        return None

    def _resolve_symbol_reference(self, name: str) -> List[str]:
        name = name.split(".")[-1]
        return self.symbol_defs.get(name, [])

    def _resolve_js_import(self, origin: Path, specifier: str) -> str:
        if specifier.startswith("."):
            resolved = self._resolve_relative(origin.parent, specifier)
            if resolved:
                return resolved
        alias = self._resolve_alias(specifier)
        if alias:
            return alias
        return self.ensure_virtual_node(f"pkg:{specifier}", "package")

    def _resolve_relative(self, base: Path, specifier: str) -> str | None:
        candidate = (base / specifier).resolve()
        if candidate.is_dir():
            for suffix in ("index.ts", "index.tsx", "index.js", "index.jsx"):
                rel = normalize_path(candidate / suffix, self.root)
                if rel in self.known_files:
                    self.ensure_file_node(self.known_files[rel])
                    return rel
            return None
        for ext in ("", ".ts", ".tsx", ".js", ".jsx", ".json"):
            rel = normalize_path(Path(str(candidate) + ext), self.root)
            if rel in self.known_files:
                self.ensure_file_node(self.known_files[rel])
                return rel
        return None

    def _resolve_alias(self, specifier: str) -> Optional[str]:
        for prefix, target in self.alias_map.items():
            if specifier.startswith(prefix):
                suffix = specifier[len(prefix) :].lstrip("/")
                candidate = normalize_path(self.root / target / suffix, self.root)
                if candidate in self.known_files:
                    self.ensure_file_node(self.known_files[candidate])
                    return candidate
        return None

    def _resolve_resource_path(self, origin: Path, resource: str) -> str:
        if resource.startswith("."):
            resolved = self._resolve_relative(origin.parent, resource)
            if resolved:
                return resolved
        if resource in self.known_files:
            self.ensure_file_node(self.known_files[resource])
            return resource
        return self.ensure_virtual_node(f"resource:{resource}", "resource")

    # --- export ---------------------------------------------------------

    def nodes_payload(self) -> List[NodePayload]:
        return list(self.nodes.values())

    def edges_payload(self) -> List[EdgePayload]:
        return list(self.edges)

    def adjacency(self) -> Dict[str, Set[str]]:
        return self.adj

    def reverse_adjacency(self) -> Dict[str, Set[str]]:
        return self.rev_adj
