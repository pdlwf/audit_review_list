from __future__ import annotations

from pathlib import Path

from cim.graph.graph_builder import ImpactGraphBuilder
from cim.parsers.python_parser import ImportRecord, PythonParseResult, ReferenceRecord, ResourceRecord, SymbolRecord
from cim.utils import Config


def make_config(tmp_path: Path) -> Config:
    config_dir = tmp_path / "cim"
    config_dir.mkdir(parents=True, exist_ok=True)
    return Config(
        project_root=tmp_path,
        config_dir=config_dir,
        include=["**/*.py"],
        exclude=[],
        features={"parsePython": True, "parseJSTS": False, "parseConfig": False, "gitHotspot": False},
        aliases={"pythonPackageRoots": [], "tsconfigPaths": []},
        rules={"load": []},
        impact={"defaultDepth": 2},
        version=1,
    )


def test_graph_builder_edges(tmp_path: Path) -> None:
    project_root = tmp_path
    file_a = project_root / "src" / "a.py"
    file_b = project_root / "src" / "b.py"
    file_a.parent.mkdir(parents=True)
    file_a.write_text("import src.b\nfrom src.b import helper\nhelper()\n", encoding="utf-8")
    file_b.write_text("def helper():\n    return 1\n", encoding="utf-8")

    config = make_config(project_root)
    builder = ImpactGraphBuilder(config, [file_a, file_b], hotspots={})

    result_a = PythonParseResult(
        file_path=file_a,
        imports=[ImportRecord(module="src.b", names=["src.b"], lineno=1)],
        symbols=[SymbolRecord(name="run", kind="function", lineno=10)],
        references=[ReferenceRecord(name="helper", lineno=3, context="call")],
        resources=[ResourceRecord(kind="env", value="APP_TOKEN", lineno=5)],
    )
    result_b = PythonParseResult(
        file_path=file_b,
        imports=[],
        symbols=[SymbolRecord(name="helper", kind="function", lineno=1)],
        references=[],
        resources=[],
    )

    for result in (result_a, result_b):
        file_node = builder.ensure_file_node(result.file_path)
        for symbol in result.symbols:
            builder.ensure_symbol_node(file_node, symbol)

    builder.ingest_python(result_a)
    builder.ingest_python(result_b)

    edges = list(builder.edges_payload())
    assert any(edge.source == "src/a.py" and edge.kind == "import" for edge in edges)
    assert any(edge.kind == "resource" and edge.source == "src/a.py" for edge in edges)
    assert any(edge.kind == "symbol_ref" and edge.target.endswith("::helper") for edge in edges)
