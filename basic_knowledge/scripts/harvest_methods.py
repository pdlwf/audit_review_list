#!/usr/bin/env python3
"""CLI entrypoint for the method framework harvester."""
from __future__ import annotations

import argparse
import json
import logging
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, cast

from basic_knowledge.method_harvester import (
    manifest,
    normalize,
    parser,
    registry,
    renderer,
)
from basic_knowledge.method_harvester.normalize import NormalizedItem

DEFAULT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TARGET = DEFAULT_ROOT / "basic_knowledge" / "method_frame"
DEFAULT_INDEX = DEFAULT_ROOT / "basic_knowledge" / "_index"


class HarvesterPaths:
    def __init__(self, root: Path, target: Path, index_dir: Path | None = None) -> None:
        self.root = root
        self.target = target
        if root == DEFAULT_ROOT:
            default_index = DEFAULT_INDEX
        else:
            default_index = root / "basic_knowledge" / "_index"
        self.index_dir = (index_dir or default_index).resolve()
        self.harvest_dir = self.index_dir
        self.extracted_path = self.index_dir / "extracted.jsonl"
        self.scan_report_path = self.index_dir / "scan_report.json"
        self.registry_path = self.index_dir / "registry.json"
        self.manifest_path = self.index_dir / "manifest.json"
        self.summary_path = self.index_dir / "SUMMARY.md"

logger = logging.getLogger("basic_knowledge.method_harvester.cli")


def configure_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )


def resolve_root(path: str | None) -> Path:
    if path:
        return Path(path).expanduser().resolve()
    return DEFAULT_ROOT


def resolve_target(root: Path, target: str | None) -> Path:
    if target:
        resolved = Path(target).expanduser().resolve()
    else:
        if root == DEFAULT_ROOT:
            resolved = DEFAULT_TARGET
        else:
            resolved = root / "basic_knowledge" / "method_frame"
    if not resolved.exists():
        raise SystemExit(f"Target directory not found: {resolved}")
    return resolved


def command_scan(args: argparse.Namespace) -> None:
    root = resolve_root(args.root)
    target = resolve_target(root, args.target)
    paths = HarvesterPaths(root, target)
    logger.info("Scanning %s", target)
    paths.harvest_dir.mkdir(parents=True, exist_ok=True)
    pdf_backends = parse_backend_list(getattr(args, "pdf_backends", None))
    min_pdf_chars = parser.resolve_min_pdf_chars(getattr(args, "min_pdf_chars", None))
    items, files = parser.scan_directory(
        target,
        root,
        min_pdf_chars=min_pdf_chars,
        pdf_backends=pdf_backends,
    )
    timestamp = normalize.now_iso()
    normalized_items = [normalize.normalize_item(item, timestamp=timestamp) for item in items]
    write_jsonl(paths.extracted_path, [item.to_dict() for item in normalized_items])
    write_scan_report(paths, files, timestamp)
    logger.info("Extracted %d items from %d files", len(normalized_items), len(files))


def command_update(args: argparse.Namespace) -> None:
    root = resolve_root(args.root)
    target = resolve_target(root, args.target)
    paths = HarvesterPaths(root, target)
    if not paths.extracted_path.exists():
        raise SystemExit("No extraction output found. Run 'scan' first.")
    logger.info("Updating registry from %s", paths.extracted_path)
    extracted_items = list(read_jsonl(paths.extracted_path))
    normalized_items = [NormalizedItem(**item) for item in extracted_items]
    registry_data = registry.load_registry(paths.registry_path)
    added, updated = registry.merge_into_registry(registry_data, normalized_items)
    scan_report = load_scan_report(paths)
    if not scan_report:
        raise SystemExit("No scan report found. Run 'scan' first.")
    file_results = {
        file_path: parser.FileScanResult(
            file=entry.get("file", file_path),
            sha256=entry.get("sha256", ""),
            mtime=int(entry.get("mtime", 0)),
            extracted_count=int(entry.get("extracted_count", 0)),
            status=entry.get("status", "pending"),
            error=entry.get("error"),
            pdf_meta=entry.get("pdf_meta"),
        )
        for file_path, entry in (scan_report.get("files", {}) if scan_report else {}).items()
    }
    active_files = {
        path for path, result in file_results.items() if result.extracted_count > 0
    }
    removed = registry.prune_registry(registry_data, active_files)
    registry.save_registry(paths.registry_path, registry_data)
    manifest_data = manifest.load_manifest(paths.manifest_path)
    timestamp = normalize.now_iso()
    manifest.update_manifest(manifest_data, file_results, timestamp)
    manifest.save_manifest(paths.manifest_path, manifest_data)
    logger.info(
        "Registry updated. Added: %d, Updated: %d, Removed: %d",
        len(added),
        len(updated),
        len(removed),
    )


def command_render(args: argparse.Namespace) -> None:
    root = resolve_root(args.root)
    target = resolve_target(root, args.target)
    paths = HarvesterPaths(root, target)
    paths.index_dir.mkdir(parents=True, exist_ok=True)
    content = renderer.render_summary(paths.registry_path, paths.manifest_path, paths.summary_path)
    logger.info("Summary written to %s (%d characters)", paths.summary_path, len(content))


def command_check(args: argparse.Namespace) -> None:
    root = resolve_root(args.root)
    target = resolve_target(root, args.target)
    paths = HarvesterPaths(root, target)
    manifest_data = manifest.load_manifest(paths.manifest_path)
    pdf_backends = parse_backend_list(getattr(args, "pdf_backends", None))
    min_pdf_chars = parser.resolve_min_pdf_chars(getattr(args, "min_pdf_chars", None))
    _, scan_results = parser.scan_directory(
        target,
        root,
        min_pdf_chars=min_pdf_chars,
        pdf_backends=pdf_backends,
    )
    statuses = []
    for file_path, result in scan_results.items():
        previous = manifest_data.get("files", {}).get(file_path)
        status = manifest.determine_status(previous, result)
        statuses.append((file_path, status, result.extracted_count))
    missing = [path for path in (manifest_data.get("files", {}) or {}) if path not in scan_results]
    pdf_rollup = format_pdf_rollup(scan_results, min_pdf_chars)
    print_status_table(statuses, missing, manifest_data, pdf_rollup=pdf_rollup)


def write_jsonl(path: Path, items: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for item in items:
            fh.write(json.dumps(item, ensure_ascii=False))
            fh.write("\n")


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def write_scan_report(
    paths: HarvesterPaths, files: dict[str, parser.FileScanResult], timestamp: str
) -> None:
    if paths.target.is_relative_to(paths.root):
        target_path = str(paths.target.relative_to(paths.root))
    else:
        target_path = str(paths.target)
    report = {
        "timestamp": timestamp,
        "target": target_path,
        "files": {file: data.to_dict() for file, data in files.items()},
        "counts": {
            "files": len(files),
            "items": sum(result.extracted_count for result in files.values()),
        },
    }
    paths.scan_report_path.parent.mkdir(parents=True, exist_ok=True)
    with paths.scan_report_path.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)


def load_scan_report(paths: HarvesterPaths) -> dict[str, Any]:
    if not paths.scan_report_path.exists():
        return {}
    with paths.scan_report_path.open("r", encoding="utf-8") as fh:
        return cast(dict[str, Any], json.load(fh))


def print_status_table(
    statuses: list[tuple[str, str, int]],
    missing: list[str],
    manifest_data: Mapping[str, Any],
    *,
    pdf_rollup: str | None = None,
) -> None:
    print("File".ljust(70), "Status".ljust(12), "Extracted")
    print("-" * 95)
    for file_path, status, count in sorted(statuses):
        print(file_path.ljust(70), status.ljust(12), str(count))
    for missing_path in missing:
        print(missing_path.ljust(70), "missing".ljust(12), "-")
    if pdf_rollup:
        print("\n" + pdf_rollup)
    metadata = manifest_data.get("metadata", {})
    print("\nLast run:", metadata.get("last_run", "never"))


def parse_backend_list(value: str | None) -> list[str] | None:
    if not value:
        return None
    parts = [entry.strip() for entry in value.split(",") if entry.strip()]
    return parts or None


def format_pdf_rollup(
    scan_results: Mapping[str, parser.FileScanResult],
    min_pdf_chars: int,
) -> str | None:
    pdf_entries = [
        (path, result)
        for path, result in scan_results.items()
        if path.lower().endswith(".pdf")
    ]
    if not pdf_entries:
        return None
    ok = short = error = 0
    backend_counter: Counter[str] = Counter()
    for _, result in pdf_entries:
        meta = result.pdf_meta or {}
        backend = str(meta.get("backend", "none"))
        chars = int(meta.get("chars", 0) or 0)
        error_message = meta.get("error")
        if result.status == "error" or error_message:
            error += 1
            continue
        if backend == "none" or chars < min_pdf_chars:
            short += 1
            continue
        ok += 1
        backend_counter[backend] += 1
    total = len(pdf_entries)
    if backend_counter:
        top_backend, top_count = backend_counter.most_common(1)[0]
    else:
        top_backend, top_count = ("none", 0)
    return (
        f"PDF: {total} files | ok: {ok} | short: {short} | error: {error} "
        f"| top backend: {top_backend} ({top_count}x)"
    )


def build_parser() -> argparse.ArgumentParser:
    parser_obj = argparse.ArgumentParser(description="Harvest method frameworks")
    parser_obj.add_argument("--root", help="Repository root (defaults to script location)")
    parser_obj.add_argument("--target", help="Override target directory for knowledge base")
    parser_obj.add_argument("--verbose", action="store_true", help="Enable debug logging")
    subparsers = parser_obj.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan for method frameworks")
    scan_parser.add_argument(
        "--pdf-backends",
        help="Comma-separated PDF extraction backend order (overrides HARVEST_PDF_BACKENDS)",
    )
    scan_parser.add_argument(
        "--min-pdf-chars",
        type=int,
        help="Minimum characters required from a PDF (overrides HARVEST_MIN_PDF_CHARS)",
    )
    scan_parser.set_defaults(func=command_scan)

    update_parser = subparsers.add_parser("update", help="Update registry from latest scan")
    update_parser.set_defaults(func=command_update)

    render_parser = subparsers.add_parser("render", help="Render Markdown summary")
    render_parser.set_defaults(func=command_render)

    check_parser = subparsers.add_parser("check", help="Dry-run status check")
    check_parser.add_argument(
        "--pdf-backends",
        help="Comma-separated PDF extraction backend order (overrides HARVEST_PDF_BACKENDS)",
    )
    check_parser.add_argument(
        "--min-pdf-chars",
        type=int,
        help="Minimum characters required from a PDF (overrides HARVEST_MIN_PDF_CHARS)",
    )
    check_parser.set_defaults(func=command_check)

    return parser_obj


def main(argv: list[str] | None = None) -> None:
    parser_obj = build_parser()
    args = parser_obj.parse_args(argv)
    if not getattr(args, "command", None):
        parser_obj.print_help()
        return
    configure_logging(args.verbose)
    args.func(args)


if __name__ == "__main__":
    main()

