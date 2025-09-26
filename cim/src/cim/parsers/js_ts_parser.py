from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

_IMPORT_RE = r"import\\s+(?:[^'\";]+?)\\s+from\\s+['\"]([^'\"]+)['\"]"
_IMPORT_SE_RE = r"import\\s+['\"]([^'\"]+)['\"]"
_REQUIRE_RE = r"require\\((['\"])([^'\"]+)\\1\)"
_EXPORT_DECL_RE = r"export\\s+(?:default\\s+)?(?:class|function|const|let|var)\\s+([A-Za-z0-9_]+)"
_COMPONENT_RE = r"<([A-Z][A-Za-z0-9_]*)\\b"
_PROCESS_ENV_RE = r"process\\.env\\.([A-Z0-9_]+)"
_I18N_RE = r"i18n\\.(?:t|get)\\((['\"])([^'\"]+)\\1"


@dataclass
class JsImportRecord:
    source: str
    kind: str


@dataclass
class JsExportRecord:
    name: str
    kind: str
    is_default: bool


@dataclass
class JsResourceRecord:
    kind: str
    value: str


@dataclass
class JsParseResult:
    file_path: Path
    language: str
    imports: List[JsImportRecord] = field(default_factory=list)
    exports: List[JsExportRecord] = field(default_factory=list)
    components: List[str] = field(default_factory=list)
    resources: List[JsResourceRecord] = field(default_factory=list)


class JsParserError(RuntimeError):
    pass


def _parse_via_node(script_path: Path, source_path: Path) -> Dict[str, object]:
    try:
        proc = subprocess.run(
            ["node", str(script_path), str(source_path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise JsParserError("node executable not found") from exc
    except subprocess.CalledProcessError as exc:
        raise JsParserError(exc.stderr or exc.stdout) from exc
    if not proc.stdout:
        return {}
    return json.loads(proc.stdout)


def _parse_fallback(source_path: Path) -> Dict[str, object]:
    text = source_path.read_text(encoding="utf-8")
    import_matches = re.findall(_IMPORT_RE, text)
    se_imports = re.findall(_IMPORT_SE_RE, text)
    requires = [match[1] for match in re.findall(_REQUIRE_RE, text)]
    exports = [
        {"name": name, "kind": "decl", "isDefault": False}
        for name in re.findall(_EXPORT_DECL_RE, text)
    ]
    components = re.findall(_COMPONENT_RE, text)
    resources = [
        {"kind": "env", "value": key}
        for key in re.findall(_PROCESS_ENV_RE, text)
    ]
    resources.extend(
        {"kind": "i18n", "value": match[1]}
        for match in re.findall(_I18N_RE, text)
    )
    imports = (
        [{"source": item, "kind": "import"} for item in import_matches]
        + [{"source": item, "kind": "import"} for item in se_imports]
        + [{"source": item, "kind": "require"} for item in requires]
    )
    unique = {json.dumps(entry, sort_keys=True): entry for entry in imports}
    return {
        "imports": list(unique.values()),
        "exports": exports,
        "components": list(dict.fromkeys(components)),
        "resources": resources,
    }


def parse_js(path: Path) -> JsParseResult:
    script = Path(__file__).with_name("js_ts_parser.js")
    try:
        data = _parse_via_node(script, path)
    except JsParserError:
        data = _parse_fallback(path)
    imports = [JsImportRecord(**item) for item in data.get("imports", [])]
    exports = [
        JsExportRecord(name=item.get("name", ""), kind=item.get("kind", ""), is_default=item.get("isDefault", False))
        for item in data.get("exports", [])
    ]
    resources = [
        JsResourceRecord(kind=item.get("kind", "resource"), value=item.get("value", ""))
        for item in data.get("resources", [])
    ]
    components = list(dict.fromkeys(data.get("components", [])))
    for export in exports:
        if export.name and export.name[0].isupper():
            components.append(export.name)
    components = list(dict.fromkeys(components))
    return JsParseResult(
        file_path=path,
        language="ts" if path.suffix.lower() in {".ts", ".tsx"} else "js",
        imports=imports,
        exports=exports,
        components=components,
        resources=resources,
    )


__all__ = ["JsParseResult", "parse_js", "JsParserError"]
