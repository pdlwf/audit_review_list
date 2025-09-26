from __future__ import annotations

from pathlib import Path

from cim.graph.graph_builder import ImpactGraphBuilder
from cim.graph.rules_engine import RulesEngine
from cim.parsers.python_parser import PythonParseResult
from cim.utils import Config


def make_config(tmp_path: Path) -> Config:
    config_dir = tmp_path / "cim"
    config_dir.mkdir(parents=True, exist_ok=True)
    return Config(
        project_root=tmp_path,
        config_dir=config_dir,
        include=["src/**/*.py"],
        exclude=[],
        features={"parsePython": True, "parseJSTS": False, "parseConfig": False, "gitHotspot": False},
        aliases={"pythonPackageRoots": [], "tsconfigPaths": []},
        rules={"load": []},
        impact={"defaultDepth": 2},
        version=1,
    )


def test_rules_engine_adds_rule_edges(tmp_path: Path) -> None:
    project_root = tmp_path
    file_routes = project_root / "routes" / "index.ts"
    file_pages = project_root / "pages" / "home.tsx"
    file_routes.parent.mkdir()
    file_pages.parent.mkdir()
    file_routes.write_text("export const routes = []", encoding="utf-8")
    file_pages.write_text("export const Home = () => null", encoding="utf-8")

    rule_path = project_root / "cim" / "rules" / "routing.yaml"
    rule_path.parent.mkdir(parents=True)
    rule_path.write_text(
        """
name: routing
when:
  file:
    include:
      - "routes/**/*.ts"
addsEdges:
  - to: "pages/**/*.tsx"
    kind: rule
    strength: weak
    note: update pages when routes change
""",
        encoding="utf-8",
    )

    config = make_config(project_root)
    builder = ImpactGraphBuilder(config, [file_routes, file_pages], hotspots={})
    builder.ensure_file_node(file_routes)
    builder.ensure_file_node(file_pages)

    engine = RulesEngine(config.config_dir)
    engine.load([rule_path])
    engine.apply(builder)

    edges = list(builder.edges_payload())
    assert any(edge.kind == "rule" and edge.rule == "routing" for edge in edges)
