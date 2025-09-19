"""Manifest management utilities."""
from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, cast

from .normalize import now_iso
from .parser import FileScanResult


def ensure_manifest() -> dict[str, Any]:
    return {
        "metadata": {
            "created_at": now_iso(),
            "updated_at": now_iso(),
            "file_count": 0,
        },
        "files": {},
    }


def load_manifest(path: Path) -> dict[str, Any]:
    if not path.exists():
        return ensure_manifest()
    with path.open("r", encoding="utf-8") as fh:
        return cast(dict[str, Any], json.load(fh))


def save_manifest(path: Path, manifest: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)


def update_manifest(
    manifest: dict[str, Any],
    scan_results: Mapping[str, FileScanResult],
    run_timestamp: str,
) -> dict[str, Any]:
    files = cast(dict[str, dict[str, Any]], manifest.setdefault("files", {}))
    seen = set()
    for file_path, result in scan_results.items():
        previous = files.get(file_path)
        status = determine_status(previous, result)
        seen.add(file_path)
        if status in {"new", "modified"}:
            last_ingested = run_timestamp
        elif previous:
            last_ingested = str(previous.get("last_ingested_at", run_timestamp))
        else:
            last_ingested = run_timestamp
        entry = {
            "file": file_path,
            "sha256": result.sha256,
            "mtime": result.mtime,
            "extracted_count": result.extracted_count,
            "last_ingested_at": last_ingested,
            "status": status,
            "error": result.error,
        }
        files[file_path] = entry
    # Mark missing files
    for file_path, data in list(files.items()):
        if file_path not in seen:
            data["status"] = "missing"
    manifest_metadata = cast(dict[str, Any], manifest.setdefault("metadata", {}))
    manifest_metadata["updated_at"] = run_timestamp
    manifest_metadata["file_count"] = len(files)
    manifest_metadata["last_run"] = run_timestamp
    return manifest


def determine_status(previous: dict[str, Any] | None, result: FileScanResult) -> str:
    if result.status == "error":
        return "error"
    if previous is None:
        return "new"
    if previous.get("sha256") != result.sha256:
        return "modified"
    return "unchanged"


def manifest_table(manifest: Mapping[str, Any]) -> Iterable[dict[str, Any]]:
    files = manifest.get("files", {})
    yield from files.values()

