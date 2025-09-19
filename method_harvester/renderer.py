"""Rendering utilities for the registry summary."""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from . import manifest, registry


def render_summary(registry_path: Path, manifest_path: Path, output_path: Path) -> str:
    registry_data = registry.load_registry(registry_path)
    manifest.load_manifest(manifest_path)  # ensure file exists
    items = cast(dict[str, Mapping[str, Any]], registry_data.get("items", {}))
    history_entries_raw = cast(Iterable[Mapping[str, Any]], registry_data.get("history", []))
    type_counts: Counter[str] = Counter()
    tag_counts: Counter[str] = Counter()
    for data in items.values():
        item_type = str(data.get("type", "unknown")) or "unknown"
        type_counts[item_type] += 1
        for tag in data.get("tags", []) or []:
            tag_counts[str(tag)] += 1
    now = datetime.now(UTC).replace(microsecond=0).isoformat()
    lines = ["# Method Framework Knowledge Base", "", f"_Last build: {now}_", ""]
    lines.append(f"**Total items:** {len(items)}")
    lines.append("")
    if type_counts:
        type_summary = ", ".join(
            f"{typ} ({count})" for typ, count in sorted(type_counts.items())
        )
        lines.append(f"**By type:** {type_summary}")
        lines.append("")
    if tag_counts:
        top_tags = tag_counts.most_common(20)
        tag_text = ", ".join(f"{tag} ({count})" for tag, count in top_tags)
        lines.append("**Top tags:** " + tag_text)
        lines.append("")
    lines.append("## Cheat Sheet")
    lines.append("")
    lines.append("| Name | Type | One-liner | When to use | Steps | Tags | Sources |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for item in sorted(items.values(), key=lambda data: str(data.get("name", "")).lower()):
        lines.append(format_item_row(item))
    lines.append("")
    lines.append("## Changelog")
    lines.append("")
    history_entries = list(history_entries_raw)[-30:]
    if not history_entries:
        lines.append("_No changes recorded yet._")
    else:
        for entry in reversed(history_entries):
            timestamp = entry.get("timestamp", "")
            change = entry.get("change", "")
            name = entry.get("name", "Unknown")
            sources_raw = cast(Iterable[Mapping[str, Any]], entry.get("sources", []) or [])
            source_links = format_sources(sources_raw)
            lines.append(f"- {timestamp}: **{name}** ({change}) {source_links}")
    lines.append("")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(lines)
    output_path.write_text(content, encoding="utf-8")
    return content


def format_item_row(item: Mapping[str, Any]) -> str:
    name = str(item.get("name", ""))
    item_type = str(item.get("type", ""))
    one_liner = escape_cell(str(item.get("one_liner", "")))
    when_to_use = format_list(cast(Iterable[Any], item.get("when_to_use", [])))
    steps = format_list(cast(Iterable[Any], item.get("steps", [])), limit=4)
    tags = format_list(
        cast(Iterable[Any], item.get("tags", [])), separator=", "
    )
    sources = format_sources(cast(Iterable[Mapping[str, Any]], item.get("sources", []) or []))
    return (
        "| "
        f"{escape_cell(name)} | {escape_cell(item_type)} | {one_liner} | {when_to_use} | "
        f"{steps} | {tags} | {sources} |"
    )


def escape_cell(value: str) -> str:
    return value.replace("|", "\\|")


def format_list(values: Iterable[Any], limit: int | None = None, separator: str = "<br>") -> str:
    results = []
    for index, value in enumerate(values):
        if limit is not None and index >= limit:
            break
        if not value:
            continue
        results.append(escape_cell(str(value)))
    return separator.join(results)


def format_sources(sources: Iterable[Mapping[str, Any]]) -> str:
    links = []
    for source in sources:
        file_path = str(source.get("file", ""))
        anchor = str(source.get("anchor", "")) if source.get("anchor") else ""
        display = file_path.rsplit("/", 1)[-1]
        href = f"{file_path}{anchor}" if anchor else file_path
        if file_path:
            links.append(f"[{escape_cell(display)}]({href})")
    return "<br>".join(links)

