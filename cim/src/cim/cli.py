from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from cim.graph.graph_builder import ImpactGraphBuilder
from cim.graph.rules_engine import RulesEngine
from cim.parsers.config_parser import ConfigParseResult, parse_json_or_yaml, parse_markdown
from cim.parsers.js_ts_parser import JsParseResult, JsParserError, parse_js
from cim.parsers.python_parser import (
    ImportRecord,
    PythonParseResult,
    ReferenceRecord,
    ResourceRecord,
    SymbolRecord,
    parse_python,
)
from cim.reporters.html_reporter import build_html_report
from cim.reporters.json_reporter import build_json_report
from cim.reporters.md_reporter import build_markdown_report
from cim.utils import (
    CacheState,
    Config,
    classify_language,
    compute_git_hotspots,
    digest_file,
    list_files,
    load_config,
    normalize_path,
)


class CliError(RuntimeError):
    """Raised when CLI input is invalid or incomplete."""


def _resolve_config(path: Optional[str]) -> Path:
    if path:
        config_path = Path(path)
        if config_path.exists():
            return config_path
        raise CliError(f"配置文件不存在：{config_path}")
    cwd = Path.cwd()
    candidate = cwd / "cim" / "cim.config.yaml"
    if candidate.exists():
        return candidate
    alt = Path(__file__).resolve().parent / ".." / "cim.config.yaml"
    alt = alt.resolve()
    if alt.exists():
        return alt
    raise CliError("无法找到 cim.config.yaml，请使用 --config 指定路径")


def _serialize_python(result: PythonParseResult) -> Dict[str, object]:
    return {
        "type": "python",
        "imports": [
            {"module": imp.module, "names": imp.names, "lineno": imp.lineno, "level": imp.level}
            for imp in result.imports
        ],
        "symbols": [
            {"name": sym.name, "kind": sym.kind, "lineno": sym.lineno}
            for sym in result.symbols
        ],
        "references": [
            {"name": ref.name, "lineno": ref.lineno, "context": ref.context}
            for ref in result.references
        ],
        "resources": [
            {"kind": res.kind, "value": res.value, "lineno": res.lineno}
            for res in result.resources
        ],
    }


def _deserialize_python(path: Path, payload: Dict[str, object]) -> PythonParseResult:
    imports = [
        ImportRecord(
            module=item.get("module", ""),
            names=list(item.get("names", [])),
            lineno=int(item.get("lineno", 0)),
            level=int(item.get("level", 0)),
        )
        for item in payload.get("imports", [])
    ]
    symbols = [
        SymbolRecord(name=item.get("name", ""), kind=item.get("kind", ""), lineno=int(item.get("lineno", 0)))
        for item in payload.get("symbols", [])
    ]
    references = [
        ReferenceRecord(name=item.get("name", ""), lineno=int(item.get("lineno", 0)), context=item.get("context", ""))
        for item in payload.get("references", [])
    ]
    resources = [
        ResourceRecord(kind=item.get("kind", ""), value=item.get("value", ""), lineno=int(item.get("lineno", 0)))
        for item in payload.get("resources", [])
    ]
    return PythonParseResult(file_path=path, imports=imports, symbols=symbols, references=references, resources=resources)


def _serialize_js(result: JsParseResult) -> Dict[str, object]:
    return {
        "type": "js",
        "language": result.language,
        "imports": [{"source": item.source, "kind": item.kind} for item in result.imports],
        "exports": [
            {"name": item.name, "kind": item.kind, "isDefault": item.is_default}
            for item in result.exports
        ],
        "components": result.components,
        "resources": [{"kind": item.kind, "value": item.value} for item in result.resources],
    }


def _deserialize_js(path: Path, payload: Dict[str, object]) -> JsParseResult:
    from cim.parsers.js_ts_parser import JsExportRecord, JsImportRecord, JsResourceRecord

    imports = [JsImportRecord(source=item.get("source", ""), kind=item.get("kind", "")) for item in payload.get("imports", [])]
    exports = [
        JsExportRecord(name=item.get("name", ""), kind=item.get("kind", ""), is_default=item.get("isDefault", False))
        for item in payload.get("exports", [])
    ]
    resources = [
        JsResourceRecord(kind=item.get("kind", ""), value=item.get("value", ""))
        for item in payload.get("resources", [])
    ]
    return JsParseResult(
        file_path=path,
        language=payload.get("language", "js"),
        imports=imports,
        exports=exports,
        components=payload.get("components", []),
        resources=resources,
    )


def _serialize_config(result: ConfigParseResult) -> Dict[str, object]:
    return {
        "type": "config",
        "dependencies": result.dependencies,
        "resources": result.resources,
    }


def _deserialize_config(path: Path, payload: Dict[str, object]) -> ConfigParseResult:
    return ConfigParseResult(
        file_path=path,
        dependencies=list(payload.get("dependencies", [])),
        resources=list(payload.get("resources", [])),
    )


def _parse_with_cache(path: Path, rel_path: str, config: Config, cache: CacheState) -> Tuple[str, Dict[str, object], bool] | None:
    digest = digest_file(path)
    entry = cache.get(rel_path)
    if entry and cache.is_fresh(rel_path, digest):
        return entry.get("parser", ""), entry.get("payload", {}), True  # type: ignore[return-value]

    language = classify_language(path)
    if language == "python" and config.features.get("parsePython", True):
        result = parse_python(path)
        payload = _serialize_python(result)
        cache.update(rel_path, digest, {"parser": "python", "payload": payload})
        return "python", payload, False
    if language in {"js", "ts"} and config.features.get("parseJSTS", True):
        try:
            result = parse_js(path)
        except JsParserError:
            result = parse_js(path)  # fallback already handled inside parser
        payload = _serialize_js(result)
        cache.update(rel_path, digest, {"parser": "js", "payload": payload})
        return "js", payload, False
    if language in {"json", "yaml", "yml"} and config.features.get("parseConfig", True):
        result = parse_json_or_yaml(path)
        payload = _serialize_config(result)
        cache.update(rel_path, digest, {"parser": "config", "payload": payload})
        return "config", payload, False
    if language in {"markdown", "md", "mdx"} and config.features.get("parseConfig", True):
        result = parse_markdown(path)
        payload = _serialize_config(result)
        cache.update(rel_path, digest, {"parser": "config", "payload": payload})
        return "config", payload, False
    return None


def _git_changed_files(root: Path) -> Set[str]:
    try:
        proc = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return set()
    changed: Set[str] = set()
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        path = line[3:]
        changed.add(path.strip())
    return changed


def _load_report(cfg: Config) -> Dict[str, object]:
    json_path = cfg.config_dir / "out" / "impact_map.json"
    if not json_path.exists():
        raise CliError("请先运行 `cim build` 生成图数据")
    return json.loads(json_path.read_text(encoding="utf-8"))


def _impact_targets(report: Dict[str, object], targets: List[str], depth: int) -> Dict[str, List[str]]:
    edges = report.get("edges", [])
    adjacency: Dict[str, List[str]] = {}
    for edge in edges:
        adjacency.setdefault(edge.get("from"), []).append(edge.get("to"))
    results: Dict[str, List[str]] = {}
    for target in targets:
        visited = {target}
        frontier = [target]
        level = 0
        collected: List[str] = []
        while frontier and level < depth:
            next_frontier: List[str] = []
            for node in frontier:
                for neighbor in adjacency.get(node, []):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        next_frontier.append(neighbor)
                        collected.append(neighbor)
            frontier = next_frontier
            level += 1
        results[target] = collected
    return results


def _run_build(args: argparse.Namespace) -> int:
    config_path = _resolve_config(args.config)
    cfg = load_config(config_path.parent)
    files = list_files(cfg)
    cache = CacheState.load(cfg.config_dir)
    hotspots = compute_git_hotspots(cfg.project_root) if cfg.features.get("gitHotspot", False) else {}

    changed_set: Set[str] = set()
    if args.changed_only:
        changed_set = _git_changed_files(cfg.project_root)

    python_results: List[PythonParseResult] = []
    js_results: List[JsParseResult] = []
    config_results: List[ConfigParseResult] = []

    parsed_count = 0
    reused_count = 0

    for path in files:
        rel = normalize_path(path, cfg.project_root)
        if args.changed_only and rel not in changed_set:
            entry = cache.get(rel)
            if entry:
                parser_name = entry.get("parser")
                payload = entry.get("payload", {})
                if parser_name == "python":
                    python_results.append(_deserialize_python(path, payload))
                elif parser_name == "js":
                    js_results.append(_deserialize_js(path, payload))
                elif parser_name == "config":
                    config_results.append(_deserialize_config(path, payload))
                reused_count += 1
                continue
        parsed = _parse_with_cache(path, rel, cfg, cache)
        if parsed is None:
            continue
        parser_name, payload, reused = parsed
        if reused:
            reused_count += 1
        else:
            parsed_count += 1
        if parser_name == "python":
            python_results.append(_deserialize_python(path, payload))
        elif parser_name == "js":
            js_results.append(_deserialize_js(path, payload))
        elif parser_name == "config":
            config_results.append(_deserialize_config(path, payload))

    builder = ImpactGraphBuilder(cfg, files, hotspots)

    for result in python_results:
        file_node = builder.ensure_file_node(result.file_path)
        for symbol in result.symbols:
            builder.ensure_symbol_node(file_node, symbol)
    for result in js_results:
        file_node = builder.ensure_file_node(result.file_path)
        for export in result.exports:
            symbol = SymbolRecord(name=export.name or "default", kind=export.kind, lineno=1)
            builder.ensure_symbol_node(file_node, symbol)
    for result in config_results:
        builder.ensure_file_node(result.file_path)

    for result in python_results:
        builder.ingest_python(result)
    for result in js_results:
        builder.ingest_js(result)
    for result in config_results:
        builder.ingest_config(result)

    rules_engine = RulesEngine(cfg.config_dir)
    rule_paths = [cfg.config_dir / Path(path) for path in cfg.rules.get("load", [])]
    rules_engine.load(rule_paths)
    rules_engine.apply(builder)

    out_dir = cfg.config_dir / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "impact_map.json"
    report = build_json_report(json_path, builder, hotspots)
    md_path = out_dir / "impact_map.md"
    build_markdown_report(md_path, report)
    html_path = out_dir / "impact_graph.html"
    build_html_report(html_path, report)

    cache.save(cfg.config_dir)

    node_count = len(report.get("nodes", []))
    edge_count = len(report.get("edges", []))
    hotspot_count = len(report.get("hotspots", []))

    print(f"解析完成：节点 {node_count}，边 {edge_count}，热点 {hotspot_count}")
    print(f"缓存复用 {reused_count}，重新解析 {parsed_count}")
    print(f"输出：{json_path} / {md_path} / {html_path}")
    return 0


def _run_impact(args: argparse.Namespace) -> int:
    config_path = _resolve_config(args.config)
    cfg = load_config(config_path.parent)
    report = _load_report(cfg)

    nodes = {node['id']: node for node in report.get('nodes', [])}
    if not args.target:
        raise CliError('必须通过 --target 指定文件、模块或符号')

    depth = max(args.depth, 1)
    impact_map = _impact_targets(report, args.target, depth)

    if not args.include_tests:
        for key, values in impact_map.items():
            impact_map[key] = [node_id for node_id in values if 'tests' not in (nodes.get(node_id, {}).get('tags') or [])]

    if args.format == 'json':
        print(json.dumps(impact_map, indent=2, ensure_ascii=False))
        return 0

    lines: List[str] = []
    for item in args.target:
        lines.append(f"## 目标：{item}")
        affected = impact_map.get(item, [])
        if not affected:
            lines.append("- 未发现直接或间接依赖")
            continue
        for node_id in affected:
            node = nodes.get(node_id, {})
            note = node.get('type', 'unknown')
            if node.get('tags'):
                note += f" | 标签: {', '.join(node['tags'])}"
            lines.append(f"- `{node_id}` ({note})")
        lines.append("- 易漏检查：数据模型、路由、配置、i18n、事件等相关组件")
    print("\n".join(lines))
    return 0


def _run_open(args: argparse.Namespace) -> int:
    config_path = _resolve_config(args.config)
    cfg = load_config(config_path.parent)
    html_path = cfg.config_dir / "out" / "impact_graph.html"
    if not html_path.exists():
        raise CliError("找不到 impact_graph.html，请先运行 `cim build`")
    print(f"Graph available at: {html_path}")
    try:
        subprocess.run(["open", str(html_path)], check=False)
    except FileNotFoundError:
        print("请手动在浏览器打开该文件")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cim", description="Change Impact Map generator")
    subparsers = parser.add_subparsers(dest="command")

    build_cmd = subparsers.add_parser("build", help="构建全量影响图")
    build_cmd.add_argument("--config", help="配置文件路径", default=None)
    build_cmd.add_argument("--changed-only", action="store_true", help="仅解析变更文件")
    build_cmd.set_defaults(func=_run_build)

    impact_cmd = subparsers.add_parser("impact", help="查询指定目标的影响范围")
    impact_cmd.add_argument("--config", help="配置文件路径", default=None)
    impact_cmd.add_argument("--target", "-t", action="append", default=[], help="目标文件或符号，可多次指定")
    impact_cmd.add_argument("--depth", type=int, default=2, help="向外探索层数")
    impact_cmd.add_argument("--include-tests", action="store_true", help="包含测试文件节点")
    impact_cmd.add_argument("--format", choices=["md", "json"], default="md", help="输出格式")
    impact_cmd.set_defaults(func=_run_impact)

    open_cmd = subparsers.add_parser("open-graph", help="打开交互式依赖图")
    open_cmd.add_argument("--config", help="配置文件路径", default=None)
    open_cmd.set_defaults(func=_run_open)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    try:
        return args.func(args)
    except CliError as exc:  # pragma: no cover - simple CLI guard
        print(f"错误：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


__all__ = ["main"]
