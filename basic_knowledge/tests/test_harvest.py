from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, cast

import pytest

from basic_knowledge.method_harvester import (
    manifest,
    normalize,
    parser,
    registry,
    renderer,
)


@pytest.fixture()
def sandbox(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    target = root / "basic_knowledge" / "method_frame"
    target.mkdir(parents=True)
    sample_dir = (
        Path(__file__).resolve().parents[2]
        / "basic_knowledge"
        / "method_frame"
        / "_samples"
    )
    for sample_file in sample_dir.glob("*.md"):
        shutil.copy(sample_file, target / sample_file.name)
    return root


def test_scan_extracts_items(sandbox: Path) -> None:
    target = sandbox / "basic_knowledge" / "method_frame"
    items, files = parser.scan_directory(target, sandbox)
    assert len(items) >= 4
    names = {item.name for item in items}
    assert "5 Whys Method" in names
    assert "RICE Scoring Model" in names
    assert files
    first_item = items[0]
    assert first_item.source_file.startswith("basic_knowledge/method_frame")
    assert first_item.file_sha is not None


def test_registry_idempotency(sandbox: Path) -> None:
    target = sandbox / "basic_knowledge" / "method_frame"
    items, _ = parser.scan_directory(target, sandbox)
    timestamp = normalize.now_iso()
    normalized_items = [normalize.normalize_item(item, timestamp=timestamp) for item in items]
    index_dir = sandbox / "basic_knowledge" / "_index"
    registry_path = index_dir / "registry.json"
    registry_data = registry.ensure_registry()
    added, updated = registry.merge_into_registry(registry_data, normalized_items)
    assert len(added) == len(normalized_items)
    assert updated == []
    registry.save_registry(registry_path, registry_data)
    # second merge should not add or update anything
    added_again, updated_again = registry.merge_into_registry(registry_data, normalized_items)
    assert added_again == []
    assert updated_again == []


def test_manifest_updates_status(sandbox: Path) -> None:
    target = sandbox / "basic_knowledge" / "method_frame"
    _, files = parser.scan_directory(target, sandbox)
    manifest_data = manifest.ensure_manifest()
    timestamp = normalize.now_iso()
    manifest.update_manifest(manifest_data, files, timestamp)
    files_data = cast(dict[str, dict[str, Any]], manifest_data["files"])
    assert all(entry["status"] == "new" for entry in files_data.values())
    manifest.update_manifest(manifest_data, files, normalize.now_iso())
    assert all(entry["status"] == "unchanged" for entry in files_data.values())


def test_renderer_outputs_table(sandbox: Path, tmp_path: Path) -> None:
    target = sandbox / "basic_knowledge" / "method_frame"
    items, files = parser.scan_directory(target, sandbox)
    timestamp = normalize.now_iso()
    normalized_items = [normalize.normalize_item(item, timestamp=timestamp) for item in items]
    reg = registry.ensure_registry()
    registry.merge_into_registry(reg, normalized_items)
    index_dir = sandbox / "basic_knowledge" / "_index"
    index_dir.mkdir(parents=True, exist_ok=True)
    registry_path = index_dir / "registry.json"
    manifest_path = index_dir / "manifest.json"
    summary_path = index_dir / "SUMMARY.md"
    registry.save_registry(registry_path, reg)
    manifest_data = manifest.ensure_manifest()
    manifest.update_manifest(manifest_data, files, timestamp)
    manifest.save_manifest(manifest_path, manifest_data)
    content = renderer.render_summary(registry_path, manifest_path, summary_path)
    assert "| 5 Whys Method" in content
    assert summary_path.exists()

