"""Normalization helpers."""
from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, MutableMapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import sha1
from typing import Any

from .parser import ParsedItem

logger = logging.getLogger(__name__)


@dataclass
class NormalizedItem:
    item_id: str
    name: str
    aka: list[str]
    type: str
    one_liner: str
    when_to_use: list[str]
    inputs: list[str]
    steps: list[str]
    decision_rules: list[str]
    anti_patterns: list[str]
    evidence_examples: list[str]
    tags: list[str]
    sources: list[dict[str, str | None]]
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def normalize_key(value: str) -> str:
    return " ".join(value.lower().strip().split())


def ensure_list(values: Iterable[str]) -> list[str]:
    seen = set()
    result: list[str] = []
    for value in values:
        cleaned = value.strip()
        if not cleaned:
            continue
        if cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
    return result


def ensure_lower_list(values: Iterable[str]) -> list[str]:
    seen = set()
    result: list[str] = []
    for value in values:
        cleaned = value.strip()
        if not cleaned:
            continue
        normalized = cleaned.lower()
        if normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def limit_length(value: str, max_length: int = 180) -> str:
    if len(value) <= max_length:
        return value
    return value[: max_length - 3].rstrip() + "..."


def build_source_entry(parsed: ParsedItem) -> dict[str, str | None]:
    base = f"{parsed.source_file}:{parsed.anchor or ''}:{parsed.name}"
    source_hash = sha1(base.encode("utf-8")).hexdigest()
    entry: dict[str, str | None] = {
        "file": parsed.source_file,
        "anchor": f"#{parsed.anchor}" if parsed.anchor else None,
        "hash": source_hash,
    }
    if parsed.file_sha:
        entry["file_sha256"] = parsed.file_sha
    return entry


def generate_item_id(name: str, steps: list[str], one_liner: str, when_to_use: list[str]) -> str:
    normalized_name = normalize_key(name)
    steps_key = "|".join(normalize_key(step) for step in steps)
    purpose_key = "|".join(normalize_key(item) for item in [one_liner, *when_to_use])
    payload = (normalized_name + steps_key + purpose_key).encode("utf-8")
    return sha1(payload).hexdigest()


def normalize_item(parsed: ParsedItem, timestamp: str | None = None) -> NormalizedItem:
    created_at = timestamp or now_iso()
    updated_at = created_at
    name = parsed.name.strip() if parsed.name.strip() else "Untitled"
    one_liner = parsed.one_liner.strip() if parsed.one_liner else ""
    if not one_liner and parsed.when_to_use:
        one_liner = parsed.when_to_use[0]
    if not one_liner and parsed.steps:
        one_liner = parsed.steps[0]
    one_liner = limit_length(one_liner or "", 180)
    item_type = parsed.type.strip().lower() if parsed.type else "thinking_model"
    when_to_use = ensure_list(parsed.when_to_use)
    inputs = ensure_list(parsed.inputs)
    steps = ensure_list(parsed.steps)
    decision_rules = ensure_list(parsed.decision_rules)
    anti_patterns = ensure_list(parsed.anti_patterns)
    evidence_examples = ensure_list(parsed.evidence_examples)
    tags = ensure_lower_list(parsed.tags)
    aka = ensure_list(parsed.aka)
    item_id = generate_item_id(name, steps, one_liner, when_to_use)
    sources = [build_source_entry(parsed)]
    return NormalizedItem(
        item_id=item_id,
        name=name,
        aka=aka,
        type=item_type,
        one_liner=one_liner,
        when_to_use=when_to_use,
        inputs=inputs,
        steps=steps,
        decision_rules=decision_rules,
        anti_patterns=anti_patterns,
        evidence_examples=evidence_examples,
        tags=tags,
        sources=sources,
        created_at=created_at,
        updated_at=updated_at,
    )


def merge_items(existing: MutableMapping[str, Any], new: NormalizedItem) -> bool:
    changed = False
    if existing.get("name") != new.name:
        existing["name"] = new.name
        changed = True
    if merge_string(existing, "type", new.type):
        changed = True
    if merge_string(existing, "one_liner", new.one_liner, prefer_longer=True):
        changed = True
    for field in [
        "aka",
        "when_to_use",
        "inputs",
        "steps",
        "decision_rules",
        "anti_patterns",
        "evidence_examples",
        "tags",
    ]:
        if merge_list(existing, field, getattr(new, field)):
            changed = True
    if merge_sources(existing, new.sources):
        changed = True
    if changed:
        existing["updated_at"] = now_iso()
    return changed


def merge_string(
    existing: MutableMapping[str, Any],
    key: str,
    value: str,
    *,
    prefer_longer: bool = False,
) -> bool:
    current = existing.get(key)
    if not current:
        existing[key] = value
        return True
    if prefer_longer and len(str(value)) > len(str(current)):
        existing[key] = value
        return True
    return False


def merge_list(existing: MutableMapping[str, Any], key: str, values: list[str]) -> bool:
    if not values:
        return False
    current = existing.get(key)
    if not current:
        existing[key] = list(dict.fromkeys(values))
        return True
    changed = False
    assert isinstance(current, list)
    seen = {item: None for item in current}
    for value in values:
        if value not in seen:
            current.append(value)
            seen[value] = None
            changed = True
    return changed


def merge_sources(
    existing: MutableMapping[str, Any],
    sources: list[dict[str, str | None]],
) -> bool:
    if not sources:
        return False
    current = existing.get("sources")
    if current is None:
        existing["sources"] = sources
        return True
    assert isinstance(current, list)
    existing_hashes = {entry.get("hash") for entry in current if isinstance(entry, dict)}
    changed = False
    for source in sources:
        if source.get("hash") not in existing_hashes:
            current.append(source)
            existing_hashes.add(source.get("hash"))
            changed = True
    return changed


def build_signature(item: Mapping[str, Any]) -> str:
    name = normalize_key(str(item.get("name", "")))
    aka = [normalize_key(alias) for alias in item.get("aka", [])]
    steps = [normalize_key(step) for step in item.get("steps", [])]
    one_liner = normalize_key(str(item.get("one_liner", "")))
    when_to_use = [normalize_key(value) for value in item.get("when_to_use", [])]
    payload = "|".join([name, *aka, *steps, one_liner, *when_to_use])
    return sha1(payload.encode("utf-8")).hexdigest()

