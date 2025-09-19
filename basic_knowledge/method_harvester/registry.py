"""Registry persistence and merging logic."""
from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, MutableMapping
from pathlib import Path
from typing import Any, cast

from .normalize import (
    NormalizedItem,
    build_signature,
    normalize_key,
    now_iso,
)
from .normalize import (
    merge_items as merge_normalized,
)

REGISTRY_HISTORY_LIMIT = 200


def ensure_registry() -> dict[str, Any]:
    timestamp = now_iso()
    return {
        "metadata": {
            "created_at": timestamp,
            "updated_at": timestamp,
            "item_count": 0,
        },
        "items": {},
        "history": [],
    }


def load_registry(path: Path) -> dict[str, Any]:
    if not path.exists():
        return ensure_registry()
    with path.open("r", encoding="utf-8") as fh:
        return cast(dict[str, Any], json.load(fh))


def save_registry(path: Path, registry: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(registry, fh, indent=2, sort_keys=True)


def build_indexes(items: Mapping[str, MutableMapping[str, Any]]) -> dict[str, dict[str, str]]:
    name_index: dict[str, str] = {}
    signature_index: dict[str, str] = {}
    for item_id, data in items.items():
        name_key = normalize_key(str(data.get("name", "")))
        if name_key:
            name_index[name_key] = item_id
        for alias in data.get("aka", []) or []:
            alias_key = normalize_key(str(alias))
            if alias_key:
                name_index.setdefault(alias_key, item_id)
        signature = build_signature(data)
        signature_index.setdefault(signature, item_id)
    return {"by_name": name_index, "by_signature": signature_index}


def update_indexes(
    indexes: dict[str, dict[str, str]], item_id: str, item: Mapping[str, Any]
) -> None:
    name_key = normalize_key(str(item.get("name", "")))
    if name_key:
        indexes["by_name"][name_key] = item_id
    for alias in item.get("aka", []) or []:
        alias_key = normalize_key(str(alias))
        if alias_key:
            indexes["by_name"][alias_key] = item_id
    signature = build_signature(item)
    indexes["by_signature"][signature] = item_id


def find_duplicate(indexes: dict[str, dict[str, str]], item: NormalizedItem) -> str | None:
    name_key = normalize_key(item.name)
    if name_key and name_key in indexes["by_name"]:
        return indexes["by_name"][name_key]
    for alias in item.aka:
        alias_key = normalize_key(alias)
        if alias_key and alias_key in indexes["by_name"]:
            return indexes["by_name"][alias_key]
    signature = build_signature(item.to_dict())
    if signature in indexes["by_signature"]:
        return indexes["by_signature"][signature]
    return None


def merge_into_registry(
    registry: dict[str, Any],
    new_items: Iterable[NormalizedItem],
) -> tuple[list[str], list[str]]:
    items = cast(dict[str, MutableMapping[str, Any]], registry.setdefault("items", {}))
    history = cast(list[MutableMapping[str, Any]], registry.setdefault("history", []))
    indexes = build_indexes(items)
    added: list[str] = []
    updated: list[str] = []
    for item in new_items:
        duplicate_id = find_duplicate(indexes, item)
        if duplicate_id:
            existing = items[duplicate_id]
            if merge_normalized(existing, item):
                updated.append(duplicate_id)
                history.append(
                    {
                        "item_id": duplicate_id,
                        "change": "updated",
                        "timestamp": now_iso(),
                        "name": existing.get("name"),
                        "sources": item.sources,
                    }
                )
                update_indexes(indexes, duplicate_id, existing)
        else:
            items[item.item_id] = item.to_dict()
            added.append(item.item_id)
            history.append(
                {
                    "item_id": item.item_id,
                    "change": "added",
                    "timestamp": now_iso(),
                    "name": item.name,
                    "sources": item.sources,
                }
            )
            update_indexes(indexes, item.item_id, items[item.item_id])
    if len(history) > REGISTRY_HISTORY_LIMIT:
        del history[:-REGISTRY_HISTORY_LIMIT]
    registry_metadata = cast(dict[str, Any], registry.setdefault("metadata", {}))
    registry_metadata["updated_at"] = now_iso()
    registry_metadata["item_count"] = len(items)
    return added, updated


def prune_registry(registry: dict[str, Any], active_files: set[str]) -> list[str]:
    items = cast(dict[str, MutableMapping[str, Any]], registry.get("items", {}))
    history = cast(list[MutableMapping[str, Any]], registry.setdefault("history", []))
    removed: list[str] = []
    for item_id, data in list(items.items()):
        sources = data.get("sources", [])
        if not sources:
            continue
        valid = False
        for source in sources:
            if isinstance(source, Mapping):
                source_file = str(source.get("file", ""))
                if source_file in active_files:
                    valid = True
                    break
        if not valid:
            removed.append(item_id)
            items.pop(item_id)
            history.append(
                {
                    "item_id": item_id,
                    "change": "removed",
                    "timestamp": now_iso(),
                    "name": data.get("name"),
                    "sources": sources,
                }
            )
    if removed:
        metadata = cast(dict[str, Any], registry.setdefault("metadata", {}))
        metadata["updated_at"] = now_iso()
        metadata["item_count"] = len(items)
    return removed

