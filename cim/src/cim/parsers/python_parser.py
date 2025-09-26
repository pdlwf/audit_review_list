from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List


@dataclass
class ImportRecord:
    module: str
    names: List[str]
    lineno: int
    level: int = 0


@dataclass
class SymbolRecord:
    name: str
    kind: str
    lineno: int


@dataclass
class ReferenceRecord:
    name: str
    lineno: int
    context: str


@dataclass
class ResourceRecord:
    kind: str
    value: str
    lineno: int


@dataclass
class PythonParseResult:
    file_path: Path
    imports: List[ImportRecord] = field(default_factory=list)
    symbols: List[SymbolRecord] = field(default_factory=list)
    references: List[ReferenceRecord] = field(default_factory=list)
    resources: List[ResourceRecord] = field(default_factory=list)


class _Analyzer(ast.NodeVisitor):
    def __init__(self) -> None:
        self.imports: List[ImportRecord] = []
        self.symbols: List[SymbolRecord] = []
        self.references: List[ReferenceRecord] = []
        self.resources: List[ResourceRecord] = []
        self._scopes: List[Dict[str, str]] = [{}]

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        modules = []
        for alias in node.names:
            modules.append(alias.name)
            self._scopes[-1][alias.asname or alias.name.split(".")[-1]] = "module"
        self.imports.append(ImportRecord(module="", names=modules, lineno=node.lineno))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        module = node.module or ""
        names = [alias.name for alias in node.names]
        for alias in node.names:
            local = alias.asname or alias.name
            self._scopes[-1][local] = "module"
        self.imports.append(ImportRecord(module=module, names=names, lineno=node.lineno, level=node.level))
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self.symbols.append(SymbolRecord(name=node.name, kind="function", lineno=node.lineno))
        self._scopes.append({arg.arg: "arg" for arg in node.args.args})
        self.generic_visit(node)
        self._scopes.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self.visit_FunctionDef(node)  # type: ignore[arg-type]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        self.symbols.append(SymbolRecord(name=node.name, kind="class", lineno=node.lineno))
        self._scopes.append({b.id: "base" for b in node.bases if isinstance(b, ast.Name)})
        self.generic_visit(node)
        self._scopes.pop()

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.symbols.append(SymbolRecord(name=target.id, kind="variable", lineno=node.lineno))
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:  # noqa: N802
        if isinstance(node.ctx, ast.Load):
            if not self._is_local(node.id):
                self.references.append(ReferenceRecord(name=node.id, lineno=node.lineno, context="load"))
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:  # noqa: N802
        full = self._attribute_to_str(node)
        if full:
            self.references.append(ReferenceRecord(name=full, lineno=node.lineno, context="attr"))
            if full.startswith("os.environ"):
                key = self._extract_env_key(node)
                if key:
                    self.resources.append(ResourceRecord(kind="env", value=key, lineno=node.lineno))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        func_name = self._call_name(node.func)
        if func_name:
            self.references.append(ReferenceRecord(name=func_name, lineno=node.lineno, context="call"))
            if func_name.endswith(".getenv") and node.args:
                key = self._literal_arg(node.args[0])
                if key:
                    self.resources.append(ResourceRecord(kind="env", value=key, lineno=node.lineno))
            if func_name.endswith((".get", ".t")) and node.args and func_name.startswith("i18n"):
                key = self._literal_arg(node.args[0])
                if key:
                    self.resources.append(ResourceRecord(kind="i18n", value=key, lineno=node.lineno))
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:  # noqa: N802
        if isinstance(node.value, ast.Attribute):
            full = self._attribute_to_str(node.value)
            if full == "os.environ":
                key = self._literal_arg(node.slice)
                if key:
                    self.resources.append(ResourceRecord(kind="env", value=key, lineno=node.lineno))
        self.generic_visit(node)

    def _is_local(self, name: str) -> bool:
        return any(name in scope for scope in reversed(self._scopes))

    def _attribute_to_str(self, node: ast.Attribute) -> str:
        parts: List[str] = []
        current: ast.AST | None = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))

    def _call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return self._attribute_to_str(node)
        return ""

    def _literal_arg(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    def _extract_env_key(self, node: ast.Attribute) -> str | None:
        if isinstance(node.value, ast.Subscript):
            subs = node.value
            if isinstance(subs.slice, ast.Constant) and isinstance(subs.slice.value, str):
                return subs.slice.value
        return None


def parse_python(path: Path) -> PythonParseResult:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    analyzer = _Analyzer()
    analyzer.visit(tree)
    return PythonParseResult(
        file_path=path,
        imports=analyzer.imports,
        symbols=analyzer.symbols,
        references=analyzer.references,
        resources=analyzer.resources,
    )


__all__ = [
    "ImportRecord",
    "SymbolRecord",
    "ReferenceRecord",
    "ResourceRecord",
    "PythonParseResult",
    "parse_python",
]
