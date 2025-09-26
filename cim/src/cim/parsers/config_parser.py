from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List

from cim.utils import load_yaml


@dataclass
class ConfigParseResult:
    file_path: Path
    dependencies: List[str] = field(default_factory=list)
    resources: List[Dict[str, str]] = field(default_factory=list)


_IMPORT_RE = re.compile(r"^\s*import\s+(?:[^';]+)\s+from\s+['\"]([^'\"]+)['\"]", re.MULTILINE)
_PATH_LIKE = re.compile(r"[\w\-_/]+\.[a-zA-Z0-9]{1,6}")


def parse_json_or_yaml(path: Path) -> ConfigParseResult:
    try:
        if path.suffix.lower() == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
        else:
            data = load_yaml(path)
    except (json.JSONDecodeError, ValueError):
        return ConfigParseResult(file_path=path)
    resources: List[Dict[str, str]] = []
    dependencies: List[str] = []

    def walk(obj: object, prefix: str = "") -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                key_path = f"{prefix}.{key}" if prefix else str(key)
                resources.append({"kind": "config_key", "value": key_path})
                walk(value, key_path)
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                walk(item, f"{prefix}[{idx}]")
        elif isinstance(obj, str):
            if _PATH_LIKE.fullmatch(obj):
                dependencies.append(obj)

    walk(data)
    return ConfigParseResult(file_path=path, dependencies=sorted(set(dependencies)), resources=resources)


def parse_markdown(path: Path) -> ConfigParseResult:
    text = path.read_text(encoding="utf-8")
    imports = _IMPORT_RE.findall(text)
    code_fences = re.findall(r"```(?:[jt]sx?|ts|tsx|python)?\n(.*?)```", text, flags=re.DOTALL)
    resources: List[Dict[str, str]] = []
    for fence in code_fences:
        match = _PATH_LIKE.search(fence)
        if match:
            resources.append({"kind": "snippet_path", "value": match.group(0)})
    return ConfigParseResult(file_path=path, dependencies=sorted(set(imports)), resources=resources)


__all__ = ["ConfigParseResult", "parse_json_or_yaml", "parse_markdown"]
