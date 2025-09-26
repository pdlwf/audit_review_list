#!/usr/bin/env python3
"""Export question texts from module JSON files into a CSV for manual editing."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Iterable, Iterator, Sequence

CSV_HEADER = (
    "source_file",
    "module_key",
    "module_name_zh",
    "module_name_en",
    "question_id",
    "question_index",
    "question_text_zh",
    "question_text_en",
)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Export question text from data/*.json into a flat CSV. "
            "The CSV can be edited and re-imported later to update the JSON sources."
        )
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("data"),
        help="Directory containing module JSON files (default: data).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/exports/questions.csv"),
        help="Output CSV path (default: data/exports/questions.csv).",
    )
    parser.add_argument(
        "--module",
        dest="modules",
        action="append",
        default=None,
        help="Limit export to the specified module key (repeatable).",
    )
    return parser.parse_args(argv)


def iter_module_files(data_dir: Path) -> Iterator[Path]:
    if not data_dir.exists():
        raise FileNotFoundError(f"Data directory not found: {data_dir}")
    yield from sorted(path for path in data_dir.glob("*.json") if path.is_file())


def load_module(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fp:
        return json.load(fp)


def ensure_output_parent(output_path: Path) -> None:
    parent = output_path.parent
    if parent and not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)


def extract_rows(
    modules: Iterable[tuple[Path, dict]],
    allowed_modules: set[str] | None,
) -> Iterator[list[str]]:
    for module_path, module_payload in modules:
        module_key = str(module_payload.get("key", module_path.stem))
        if allowed_modules and module_key not in allowed_modules:
            continue

        name_payload = module_payload.get("name", {})
        module_name_zh = str(name_payload.get("zh", "").strip())
        module_name_en = str(name_payload.get("en", "").strip())

        questions = module_payload.get("questions", [])
        for index, question in enumerate(questions, start=1):
            question_id = str(question.get("id", "").strip())
            text_payload = question.get("text", {})

            text_zh = str(text_payload.get("zh", "").strip())
            text_en = str(text_payload.get("en", "").strip())

            yield [
                module_path.name,
                module_key,
                module_name_zh,
                module_name_en,
                question_id,
                str(index),
                text_zh,
                text_en,
            ]


def export_questions(args: argparse.Namespace) -> tuple[Path, int]:
    allowed_modules = set(args.modules) if args.modules else None
    module_files = ((path, load_module(path)) for path in iter_module_files(args.data_dir))
    rows = list(extract_rows(module_files, allowed_modules))

    if not rows:
        raise SystemExit("No questions found to export with the provided criteria.")

    ensure_output_parent(args.output)

    with args.output.open("w", encoding="utf-8", newline="") as csvfile:
        writer = csv.writer(csvfile, lineterminator="\n")
        writer.writerow(CSV_HEADER)
        writer.writerows(rows)

    return args.output, len(rows)


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)
    output_path, count = export_questions(args)
    print(f"Exported {count} questions to {output_path}")


if __name__ == "__main__":
    main()
