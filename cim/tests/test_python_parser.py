from __future__ import annotations

from pathlib import Path

from cim.parsers.python_parser import parse_python


def test_parse_python_imports_and_symbols(tmp_path: Path) -> None:
    code = """
import json
import os
from package.module import Service

class Demo:
    pass

async def load_config(path):
    token = os.environ["API_TOKEN"]
    title = i18n.t("app.title")
    return Service(path, token, title)
"""
    file_path = tmp_path / "sample.py"
    file_path.write_text(code, encoding="utf-8")

    result = parse_python(file_path)

    modules = {name for imp in result.imports for name in imp.names if name}
    assert "json" in modules
    assert any(symbol.name == "Demo" and symbol.kind == "class" for symbol in result.symbols)
    assert any(symbol.name == "load_config" for symbol in result.symbols)

    reference_names = {ref.name for ref in result.references}
    assert "Service" in reference_names
    assert any(res.kind == "env" and res.value == "API_TOKEN" for res in result.resources)
    assert any(res.kind == "i18n" and res.value == "app.title" for res in result.resources)
