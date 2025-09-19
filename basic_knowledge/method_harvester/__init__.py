"""Method harvester package."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from . import manifest, normalize, parser, registry, renderer

__all__ = [
    "parser",
    "normalize",
    "registry",
    "manifest",
    "renderer",
    "load_registry",
]


def load_registry(base_path: Path) -> dict[str, Any]:
    """Convenience wrapper to load the registry from ``base_path``."""
    from .registry import load_registry

    index_dir = base_path / "basic_knowledge" / "_index"
    registry_path = index_dir / "registry.json"
    return load_registry(registry_path)

