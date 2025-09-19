"""Parsing utilities for harvesting method frameworks."""
from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

from bs4 import BeautifulSoup
from docx import Document
from pypdf import PdfReader

logger = logging.getLogger(__name__)

SUPPORTED_EXTENSIONS = {
    ".md",
    ".markdown",
    ".txt",
    ".html",
    ".htm",
    ".pdf",
    ".docx",
}

KEYWORD_PATTERN = re.compile(
    r"(model|framework|method|canvas|matrix|ladder|cycle|loop|map|analysis|heuristic)",
    re.IGNORECASE,
)

HEADING_RE = re.compile(r"^(#{1,6})\s+(.+)$")
FIELD_RE = re.compile(r"^([A-Za-z][A-Za-z \-/]+):\s*(.*)$")
LIST_PREFIX_RE = re.compile(r"^(?:[-*+]\s+|\d+\.|\d+\))\s*(.*)$")

LIST_FIELDS = {
    "aka",
    "when_to_use",
    "inputs",
    "steps",
    "decision_rules",
    "anti_patterns",
    "evidence_examples",
    "tags",
}

FIELD_ALIASES: dict[str, str] = {
    "aka": "aka",
    "also known as": "aka",
    "aliases": "aka",
    "type": "type",
    "category": "type",
    "model type": "type",
    "framework type": "type",
    "one-liner": "one_liner",
    "one liner": "one_liner",
    "summary": "one_liner",
    "description": "one_liner",
    "purpose": "when_to_use",
    "when to use": "when_to_use",
    "use when": "when_to_use",
    "best for": "when_to_use",
    "applications": "when_to_use",
    "inputs": "inputs",
    "requires": "inputs",
    "steps": "steps",
    "process": "steps",
    "how to": "steps",
    "how-to": "steps",
    "procedure": "steps",
    "decision rules": "decision_rules",
    "criteria": "decision_rules",
    "guardrails": "decision_rules",
    "anti-patterns": "anti_patterns",
    "antipatterns": "anti_patterns",
    "pitfalls": "anti_patterns",
    "watch-outs": "anti_patterns",
    "warnings": "anti_patterns",
    "examples": "evidence_examples",
    "evidence": "evidence_examples",
    "case": "evidence_examples",
    "tags": "tags",
    "keywords": "tags",
}


@dataclass
class ParsedItem:
    """Structured representation extracted from a single file."""

    name: str
    source_file: str
    anchor: str | None
    aka: list[str] = field(default_factory=list)
    type: str | None = None
    one_liner: str | None = None
    when_to_use: list[str] = field(default_factory=list)
    inputs: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    decision_rules: list[str] = field(default_factory=list)
    anti_patterns: list[str] = field(default_factory=list)
    evidence_examples: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    file_sha: str | None = None


@dataclass
class FileScanResult:
    """Metadata captured during scanning of a single file."""

    file: str
    sha256: str
    mtime: int
    extracted_count: int
    status: str = "pending"
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "file": self.file,
            "sha256": self.sha256,
            "mtime": self.mtime,
            "extracted_count": self.extracted_count,
            "status": self.status,
            "error": self.error,
        }


def iter_supported_files(root: Path) -> Iterator[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part == "_index" for part in path.parts):
            continue
        if path.suffix.lower() in SUPPORTED_EXTENSIONS:
            yield path


def slugify(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9\s-]", "", text.strip().lower())
    cleaned = re.sub(r"\s+", "-", cleaned)
    cleaned = re.sub(r"-+", "-", cleaned)
    return cleaned


def parse_file(path: Path, base_path: Path) -> list[ParsedItem]:
    suffix = path.suffix.lower()
    if suffix in {".md", ".markdown"}:
        text = path.read_text(encoding="utf-8", errors="ignore")
        return parse_markdown(text, path, base_path)
    if suffix == ".txt":
        text = path.read_text(encoding="utf-8", errors="ignore")
        return parse_plain_text(text, path, base_path)
    if suffix in {".html", ".htm"}:
        text = path.read_text(encoding="utf-8", errors="ignore")
        return parse_html(text, path, base_path)
    if suffix == ".pdf":
        return parse_pdf(path, base_path)
    if suffix == ".docx":
        return parse_docx(path, base_path)
    return []


def parse_markdown(text: str, path: Path, base_path: Path) -> list[ParsedItem]:
    sections: list[tuple[str, list[str]]] = []
    current_heading: str | None = None
    buffer: list[str] = []
    for raw_line in text.splitlines():
        match = HEADING_RE.match(raw_line)
        if match:
            level = len(match.group(1))
            heading_text = match.group(2).strip()
            if level <= 2:
                if current_heading is not None:
                    sections.append((current_heading, buffer))
                current_heading = heading_text
                buffer = []
            else:
                # Treat deeper headings as field indicators within the section.
                buffer.append(f"{heading_text}:")
            continue
        buffer.append(raw_line)
    if current_heading is not None:
        sections.append((current_heading, buffer))

    items: list[ParsedItem] = []
    rel_file = str(path.relative_to(base_path).as_posix())
    for heading, lines in sections:
        if not is_candidate_heading(heading, lines):
            continue
        list_fields, scalar_fields = extract_fields(lines)
        name = heading.strip()
        anchor = slugify(name) if name else None
        has_substance = bool(scalar_fields.get("one_liner")) or any(
            list_fields.get(key) for key in ("aka", "when_to_use", "steps", "inputs", "tags")
        )
        if not has_substance:
            continue
        item = ParsedItem(
            name=name,
            source_file=rel_file,
            anchor=anchor,
            aka=list_fields.get("aka", []),
            type=scalar_fields.get("type"),
            one_liner=scalar_fields.get("one_liner"),
            when_to_use=list_fields.get("when_to_use", []),
            inputs=list_fields.get("inputs", []),
            steps=list_fields.get("steps", []),
            decision_rules=list_fields.get("decision_rules", []),
            anti_patterns=list_fields.get("anti_patterns", []),
            evidence_examples=list_fields.get("evidence_examples", []),
            tags=list_fields.get("tags", []),
        )
        items.append(item)
    return items


def parse_plain_text(text: str, path: Path, base_path: Path) -> list[ParsedItem]:
    lines = text.splitlines()
    rel_file = str(path.relative_to(base_path).as_posix())
    content = " ".join(line.strip() for line in lines if line.strip())
    if not content:
        return []
    lowered = content.lower()
    if not any(keyword in lowered for keyword in [
        "when to use",
        "steps",
        "inputs",
        "tags",
        "aka",
    ]):
        return []
    # Look for uppercase titles followed by colon patterns as heuristics.
    title_match = re.search(r"([A-Z][A-Za-z0-9\s]+(?:model|method|framework))", content)
    if not title_match:
        return []
    name = title_match.group(1).strip()
    anchor = slugify(name)
    one_liner = content[:180]
    return [
        ParsedItem(
            name=name,
            source_file=rel_file,
            anchor=anchor,
            one_liner=one_liner,
        )
    ]


def parse_html(text: str, path: Path, base_path: Path) -> list[ParsedItem]:
    soup = BeautifulSoup(text, "lxml")
    rel_file = str(path.relative_to(base_path).as_posix())
    items: list[ParsedItem] = []
    for heading_tag in soup.find_all(["h1", "h2"]):
        heading = heading_tag.get_text(strip=True)
        if not heading:
            continue
        if not KEYWORD_PATTERN.search(heading):
            continue
        anchor = slugify(heading)
        section_text = []
        for sibling in heading_tag.next_siblings:
            if getattr(sibling, "name", None) in {"h1", "h2"}:
                break
            if hasattr(sibling, "get_text"):
                section_text.append(sibling.get_text(" ", strip=True))
            else:
                section_text.append(str(sibling))
        body = "\n".join(section_text)
        list_fields, scalar_fields = extract_fields(body.splitlines())
        items.append(
            ParsedItem(
                name=heading,
                source_file=rel_file,
                anchor=anchor,
                one_liner=scalar_fields.get("one_liner"),
                when_to_use=list_fields.get("when_to_use", []),
                steps=list_fields.get("steps", []),
                tags=list_fields.get("tags", []),
            )
        )
    return items


def parse_pdf(path: Path, base_path: Path) -> list[ParsedItem]:
    try:
        reader = PdfReader(str(path))
    except Exception as exc:  # pragma: no cover - heavy dependency errors
        logger.warning("Failed to read PDF %s: %s", path, exc)
        return []
    text_chunks = []
    for page in reader.pages:
        try:
            text_chunks.append(page.extract_text() or "")
        except Exception:  # pragma: no cover - upstream behaviour
            continue
    text = "\n".join(text_chunks)
    return parse_plain_text(text, path, base_path)


def parse_docx(path: Path, base_path: Path) -> list[ParsedItem]:
    try:
        document = Document(str(path))
    except Exception as exc:  # pragma: no cover - dependency errors
        logger.warning("Failed to read DOCX %s: %s", path, exc)
        return []
    text = "\n".join(paragraph.text for paragraph in document.paragraphs)
    return parse_plain_text(text, path, base_path)


def is_candidate_heading(heading: str, lines: list[str]) -> bool:
    if KEYWORD_PATTERN.search(heading):
        return True
    snippet = " ".join(line.strip() for line in lines[:4])
    if KEYWORD_PATTERN.search(snippet):
        return True
    # Accept headings that are fully uppercase (often a name) if section has cues.
    if heading.isupper() and any("step" in line.lower() for line in lines):
        return True
    return False


def extract_fields(lines: Iterable[str]) -> tuple[dict[str, list[str]], dict[str, str]]:
    list_fields: dict[str, list[str]] = {}
    scalar_fields: dict[str, str] = {}
    current_field: str | None = None
    current_is_list = False
    collected_summary: list[str] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            current_field = None
            current_is_list = False
            continue
        heading_match = HEADING_RE.match(raw_line)
        if heading_match:
            alias = heading_match.group(2).strip().lower()
            mapped = FIELD_ALIASES.get(alias)
            if mapped:
                current_field = mapped
                current_is_list = mapped in LIST_FIELDS
                if current_is_list:
                    list_fields.setdefault(mapped, [])
                else:
                    scalar_fields.setdefault(mapped, "")
                continue
        match = FIELD_RE.match(line)
        if match:
            alias = match.group(1).strip().lower()
            mapped = FIELD_ALIASES.get(alias)
            if not mapped:
                current_field = None
                current_is_list = False
                continue
            value = match.group(2).strip()
            if mapped in LIST_FIELDS:
                list_fields[mapped] = split_list(value)
                current_is_list = True
            else:
                scalar_fields[mapped] = value
                current_is_list = False
            current_field = mapped
            continue
        if current_field and current_is_list:
            list_match = LIST_PREFIX_RE.match(line)
            if list_match:
                value = list_match.group(1).strip()
                if value:
                    list_fields.setdefault(current_field, [])
                    list_fields[current_field].append(value)
                continue
        if current_field and current_is_list:
            # Continuation lines for previous bullet
            values = list_fields.get(current_field)
            if values:
                values[-1] = f"{values[-1]} {line}".strip()
                continue
        if not scalar_fields.get("one_liner") and line:
            collected_summary.append(line)
    if collected_summary and "one_liner" not in scalar_fields:
        summary = " ".join(collected_summary).strip()
        scalar_fields["one_liner"] = summary[:180]
    for field_name in LIST_FIELDS:
        list_fields.setdefault(field_name, [])
    return list_fields, scalar_fields


def split_list(value: str) -> list[str]:
    if not value:
        return []
    parts = re.split(r",|;|/|\\|\|", value)
    cleaned = [part.strip() for part in parts if part.strip()]
    return cleaned


def scan_directory(
    target_dir: Path, base_path: Path
) -> tuple[list[ParsedItem], dict[str, FileScanResult]]:
    items: list[ParsedItem] = []
    files: dict[str, FileScanResult] = {}
    for file_path in iter_supported_files(target_dir):
        rel_file = str(file_path.relative_to(base_path).as_posix())
        try:
            raw_bytes = file_path.read_bytes()
        except Exception as exc:  # pragma: no cover - disk errors
            logger.error("Failed to read %s: %s", file_path, exc)
            sha_value = ""
            file_meta = FileScanResult(
                file=rel_file,
                sha256=sha_value,
                mtime=0,
                extracted_count=0,
                status="error",
                error=str(exc),
            )
            files[rel_file] = file_meta
            continue
        file_sha = sha256(raw_bytes).hexdigest()
        mtime = int(file_path.stat().st_mtime)
        try:
            parsed = parse_file(file_path, base_path)
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Failed to parse %s", file_path)
            files[rel_file] = FileScanResult(
                file=rel_file,
                sha256=file_sha,
                mtime=mtime,
                extracted_count=0,
                status="error",
                error=str(exc),
            )
            continue
        for item in parsed:
            item.file_sha = file_sha
            items.append(item)
        files[rel_file] = FileScanResult(
            file=rel_file,
            sha256=file_sha,
            mtime=mtime,
            extracted_count=len(parsed),
        )
    return items, files

