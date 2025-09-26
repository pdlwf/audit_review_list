from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:  # pragma: no cover - optional dependency
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - fallback path
    yaml = None


CACHE_FILE = ".cim_cache.json"


@dataclass
class Config:
    project_root: Path
    config_dir: Path
    include: List[str]
    exclude: List[str]
    features: Dict[str, bool]
    aliases: Dict[str, List[str]]
    rules: Dict[str, List[str]]
    impact: Dict[str, object]
    version: int = 1

    def resolved_include(self) -> List[str]:
        return self.include or ["**/*"]

    def should_include(self, path: Path) -> bool:
        rel = normalize_path(path, self.project_root)
        rel_path = Path(rel)
        patterns = self.resolved_include()
        expanded = patterns + [pattern.replace("**/", "") for pattern in patterns if "**/" in pattern]
        included = any(rel_path.match(pattern) for pattern in expanded)
        if not included:
            return False
        exclusions = self.exclude + [pattern.replace("**/", "") for pattern in self.exclude if "**/" in pattern]
        return not any(rel_path.match(pattern) for pattern in exclusions)


@dataclass
class CacheState:
    entries: Dict[str, Dict[str, object]] = field(default_factory=dict)

    @classmethod
    def load(cls, root: Path) -> "CacheState":
        cache_path = root / CACHE_FILE
        if not cache_path.exists():
            return cls()
        try:
            with cache_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            return cls(entries=data)
        except (json.JSONDecodeError, OSError):
            return cls()

    def save(self, root: Path) -> None:
        cache_path = root / CACHE_FILE
        with cache_path.open("w", encoding="utf-8") as fh:
            json.dump(self.entries, fh, indent=2)

    def is_fresh(self, rel_path: str, digest: str) -> bool:
        entry = self.entries.get(rel_path)
        return bool(entry and entry.get("digest") == digest)

    def update(self, rel_path: str, digest: str, meta: Dict[str, object]) -> None:
        payload = {"digest": digest, **meta}
        self.entries[rel_path] = payload

    def get(self, rel_path: str) -> Dict[str, object] | None:
        return self.entries.get(rel_path)


def normalize_path(path: Path, root: Path) -> str:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    return str(rel).replace(os.sep, "/")


def load_yaml(path: Path) -> Dict[str, object]:
    text = path.read_text(encoding="utf-8")
    if yaml:  # pragma: no branch - prefer PyYAML when available
        return yaml.safe_load(text) or {}
    return _simple_yaml(text)


def _simple_yaml(text: str) -> Dict[str, object]:
    lines: List[Tuple[int, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        lines.append((indent, line.lstrip()))

    def parse_block(index: int, indent: int) -> Tuple[object, int]:
        items: Dict[str, object] = {}
        while index < len(lines):
            current_indent, content = lines[index]
            if current_indent < indent:
                break
            if content.startswith("- "):
                values, index = parse_list(index, indent)
                return values, index
            if ":" not in content:
                raise ValueError(f"Unsupported YAML content: {content}")
            key, rest = content.split(":", 1)
            key = key.strip()
            rest = rest.strip()
            index += 1
            if rest:
                items[key] = _parse_scalar(rest)
            else:
                value, index = parse_block(index, indent + 2)
                items[key] = value
        return items, index

    def parse_list(index: int, indent: int) -> Tuple[List[object], int]:
        values: List[object] = []
        while index < len(lines):
            current_indent, content = lines[index]
            if current_indent < indent or not content.startswith("- "):
                break
            rest = content[2:].strip()
            index += 1
            if not rest:
                value, index = parse_block(index, indent + 2)
                values.append(value)
                continue
            if ":" in rest:
                key, immediate = rest.split(":", 1)
                item: Dict[str, object] = {key.strip(): _parse_scalar(immediate.strip())}
                if index < len(lines) and lines[index][0] > indent:
                    nested, index = parse_block(index, indent + 2)
                    if isinstance(nested, dict):
                        item.update(nested)
                    else:
                        item[key.strip()] = nested
                values.append(item)
            else:
                values.append(_parse_scalar(rest))
        return values, index

    parsed, _ = parse_block(0, 0)
    if isinstance(parsed, dict):
        return parsed
    raise ValueError("Top-level YAML must be a mapping")


def _parse_scalar(value: str) -> object:
    if value in {"true", "True"}:
        return True
    if value in {"false", "False"}:
        return False
    if value in {"null", "None", "~"}:
        return None
    if value in {"[]"}:
        return []
    if value in {"{}"}:
        return {}
    if value.startswith(("'", '"')) and value.endswith(("'", '"')):
        return value[1:-1]
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def load_config(config_dir: Path) -> Config:
    config_path = config_dir / "cim.config.yaml"
    data = load_yaml(config_path) if config_path.exists() else {}
    include = data.get("include", ["**/*"])
    exclude = data.get("exclude", [])
    features = {
        "parsePython": True,
        "parseJSTS": True,
        "parseConfig": True,
        "gitHotspot": False,
    }
    features.update(data.get("features", {}))
    aliases = {
        "pythonPackageRoots": data.get("aliases", {}).get("pythonPackageRoots", []),
        "tsconfigPaths": data.get("aliases", {}).get("tsconfigPaths", []),
    }
    rules = data.get("rules", {"load": []})
    impact = data.get("impact", {"defaultDepth": 2, "includeTestsByDefault": False})

    project_root = config_dir.parent

    if not aliases["pythonPackageRoots"]:
        aliases["pythonPackageRoots"] = discover_python_roots(project_root)
    if not aliases["tsconfigPaths"]:
        aliases["tsconfigPaths"] = discover_ts_paths(project_root)

    return Config(
        project_root=project_root,
        config_dir=config_dir,
        include=include,
        exclude=exclude,
        features=features,
        aliases=aliases,
        rules=rules,
        impact=impact,
        version=int(data.get("version", 1)),
    )


def discover_python_roots(root: Path) -> List[str]:
    roots: Set[str] = set()
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            content = pyproject.read_text(encoding="utf-8")
            for line in content.splitlines():
                if line.strip().startswith("packages ="):
                    roots.add("src")
        except OSError:
            pass
    for candidate in ["src", "basic_knowledge"]:
        if (root / candidate).exists():
            roots.add(candidate)
    return sorted(roots)


def discover_ts_paths(root: Path) -> List[str]:
    tsconfig = root / "tsconfig.json"
    if not tsconfig.exists():
        return []
    try:
        data = json.loads(tsconfig.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    compiler = data.get("compilerOptions", {})
    paths = compiler.get("paths", {})
    aliases: List[str] = []
    for key, values in paths.items():
        if values:
            aliases.append(f"{key}:{values[0]}")
    return aliases


def list_files(config: Config) -> List[Path]:
    files: List[Path] = []
    for pattern in config.resolved_include():
        for match in config.project_root.glob(pattern):
            if match.is_file() and config.should_include(match):
                files.append(match)
    return sorted(set(files))


def digest_file(path: Path) -> str:
    h = hashlib.sha1()
    with path.open("rb") as fh:
        while chunk := fh.read(8192):
            h.update(chunk)
    return h.hexdigest()


def compute_git_hotspots(root: Path) -> Dict[str, Dict[str, float]]:
    try:
        proc = subprocess.run(
            ["git", "log", "--pretty=format:", "--name-only"],
            cwd=root,
            check=True,
            text=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return {}
    counts: Dict[str, int] = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        counts[line] = counts.get(line, 0) + 1
    if not counts:
        return {}
    max_count = max(counts.values()) or 1
    return {
        path: {
            "gitChangeCount": float(count),
            "hotScore": round(count / max_count, 4),
        }
        for path, count in counts.items()
    }


def timestamp() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def classify_language(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".py"}:
        return "python"
    if suffix in {".ts", ".tsx"}:
        return "ts"
    if suffix in {".js", ".jsx"}:
        return "js"
    if suffix in {".json"}:
        return "json"
    if suffix in {".yaml", ".yml"}:
        return "yaml"
    if suffix in {".md", ".mdx"}:
        return "markdown"
    return suffix.lstrip(".") or "unknown"


def tag_for_path(path: Path, root: Path) -> List[str]:
    rel = normalize_path(path, root)
    tags: List[str] = []
    if "test" in rel or rel.endswith("_test.py"):
        tags.append("tests")
    if "docs" in rel:
        tags.append("docs")
    return tags
