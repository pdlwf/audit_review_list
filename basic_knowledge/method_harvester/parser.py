"""Parsing utilities for harvesting method frameworks."""
from __future__ import annotations

import logging
import os
import re
import tempfile
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup
from docx import Document

logger = logging.getLogger(__name__)

DEFAULT_PDF_BACKENDS = [
    "pypdf",
    "pdfminer",
    "pikepdf+pypdf",
    "pikepdf+pdfminer",
]

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

_PDF_FIELD_NAMES = sorted({alias for alias in FIELD_ALIASES}, key=len, reverse=True)
_PDF_FIELD_PATTERN = (
    "|".join(re.escape(name) for name in _PDF_FIELD_NAMES) if _PDF_FIELD_NAMES else None
)
_PDF_FIELD_LEADING_RE = (
    re.compile(rf"(?<!\n)(?P<alias>(?:{_PDF_FIELD_PATTERN})):", re.IGNORECASE)
    if _PDF_FIELD_PATTERN
    else None
)
_PDF_FIELD_BREAK_RE = (
    re.compile(rf"(?i)(?P<alias>(?:{_PDF_FIELD_PATTERN})):(?!\s*\n)")
    if _PDF_FIELD_PATTERN
    else None
)

PDF_TITLE_STOPWORDS = {
    "and",
    "or",
    "the",
    "of",
    "for",
    "to",
    "a",
    "an",
    "in",
    "on",
    "with",
    "at",
    "by",
    "from",
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
    pdf_meta: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "file": self.file,
            "sha256": self.sha256,
            "mtime": self.mtime,
            "extracted_count": self.extracted_count,
            "status": self.status,
            "error": self.error,
        }
        if self.pdf_meta is not None:
            data["pdf_meta"] = self.pdf_meta
        return data


@dataclass
class ParseOutcome:
    """Result of parsing a file, including optional PDF metadata."""

    items: list[ParsedItem]
    pdf_meta: dict[str, Any] | None = None


def _resolve_backend_order(prefer_backends: Iterable[str] | None) -> list[str]:
    if prefer_backends:
        order = [backend.strip() for backend in prefer_backends if backend and backend.strip()]
    else:
        env_value = os.environ.get("HARVEST_PDF_BACKENDS")
        if env_value:
            order = [backend.strip() for backend in env_value.split(",") if backend.strip()]
        else:
            order = list(DEFAULT_PDF_BACKENDS)
    seen = set()
    unique_order: list[str] = []
    for backend in order:
        if backend not in seen:
            unique_order.append(backend)
            seen.add(backend)
    return unique_order or list(DEFAULT_PDF_BACKENDS)


def _dedupe(sequence: Iterable[str]) -> list[str]:
    seen = set()
    result: list[str] = []
    for item in sequence:
        if item and item not in seen:
            result.append(item)
            seen.add(item)
    return result


def _is_xref_issue(message: str | None) -> bool:
    if not message:
        return False
    lowered = message.lower()
    return "xref" in lowered or "cross" in lowered


def resolve_min_pdf_chars(value: int | None) -> int:
    if value is not None:
        return max(value, 0)
    env_value = os.environ.get("HARVEST_MIN_PDF_CHARS")
    if env_value:
        try:
            return max(int(env_value), 0)
        except ValueError:
            logger.debug("Invalid HARVEST_MIN_PDF_CHARS value: %s", env_value)
    return 200


def extract_pdf_text(
    path: str | Path,
    *,
    min_chars: int = 200,
    prefer_backends: Iterable[str] | None = None,
) -> tuple[str, dict[str, Any]]:
    """Extract text from a PDF using a cascading set of backends."""

    pdf_path = Path(path)
    try:
        byte_size = pdf_path.stat().st_size
    except OSError:
        byte_size = 0

    backend_order = _resolve_backend_order(prefer_backends)
    best_text = ""
    best_chars = 0
    best_backend = "none"
    best_repaired = False
    best_warnings: list[str] = []
    last_error: str | None = None
    all_warnings: list[str] = []
    any_repaired = False
    needs_repair_hint = False
    attempts_had_output = False

    with tempfile.TemporaryDirectory(prefix="harvest_pdf_") as tmp_dir:
        repair_info: tuple[Path, list[str]] | None = None
        repair_error: str | None = None

        for backend_name in backend_order:
            backend_name = backend_name.strip()
            if not backend_name:
                continue

            use_repair = backend_name.startswith("pikepdf+")
            base_backend = backend_name.split("+", 1)[-1] if use_repair else backend_name
            attempt_warnings: list[str] = []
            attempt_error: str | None = None
            repaired = False
            target_path = pdf_path

            if use_repair:
                if repair_info is None and repair_error is None:
                    try:
                        repair_info = _repair_pdf_with_pikepdf(pdf_path, Path(tmp_dir))
                    except Exception as exc:  # pragma: no cover - pikepdf optional
                        repair_error = str(exc)
                        logger.debug("pikepdf repair failed for %s: %s", pdf_path, exc)
                if repair_info is None:
                    attempt_error = repair_error or "pikepdf repair unavailable"
                    attempt_warnings.append(f"pikepdf repair failed: {attempt_error}")
                    all_warnings.extend(
                        f"{backend_name}: {warning}" for warning in attempt_warnings
                    )
                    last_error = attempt_error
                    continue
                target_path, repair_warnings = repair_info
                attempt_warnings.extend(repair_warnings)
                repaired = True
                any_repaired = True

            try:
                text, backend_warnings = _extract_with_backend(base_backend, target_path)
                attempt_warnings.extend(backend_warnings)
            except Exception as exc:  # pragma: no cover - backend errors depend on deps
                attempt_error = str(exc)
                if _is_xref_issue(attempt_error):
                    needs_repair_hint = True
                logger.debug("PDF backend %s failed for %s: %s", base_backend, pdf_path, exc)
                text = ""

            chars = len(text)
            if text.strip():
                attempts_had_output = True
                if chars > best_chars:
                    best_chars = chars
                    best_text = text
                    best_backend = backend_name
                    best_repaired = repaired
                    best_warnings = list(attempt_warnings)
            else:
                attempt_warnings.append("extracted text empty")

            if chars < min_chars and text.strip():
                attempt_warnings.append(
                    f"extracted text shorter than min_chars ({chars} < {min_chars})"
                )

            if any(_is_xref_issue(message) for message in attempt_warnings):
                needs_repair_hint = True

            if attempt_error:
                last_error = attempt_error

            all_warnings.extend(f"{backend_name}: {warning}" for warning in attempt_warnings)

            if chars >= min_chars and text.strip() and not needs_repair_hint and not attempt_error:
                break

        if best_chars >= min_chars and best_text.strip():
            meta = {
                "backend": best_backend,
                "bytes": byte_size,
                "chars": best_chars,
                "warnings": _dedupe(best_warnings),
                "repaired": best_repaired,
                "error": None,
            }
            return best_text, meta

    warnings_out = list(_dedupe(all_warnings))
    if best_chars and best_chars < min_chars:
        warnings_out.append(f"best text shorter than min_chars ({best_chars} < {min_chars})")
    if not attempts_had_output and not last_error:
        warnings_out.append("no backend produced text")
    meta = {
        "backend": "none",
        "bytes": byte_size,
        "chars": best_chars,
        "warnings": _dedupe(warnings_out),
        "repaired": any_repaired,
        "error": last_error,
    }
    return "", meta


def _extract_with_backend(backend: str, path: Path) -> tuple[str, list[str]]:
    if backend == "pypdf":
        return _extract_with_pypdf(path)
    if backend == "pdfminer":
        return _extract_with_pdfminer(path)
    raise RuntimeError(f"unknown backend: {backend}")


def _extract_with_pypdf(path: Path) -> tuple[str, list[str]]:
    warnings: list[str] = []
    try:
        from pypdf import PdfReader
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("pypdf is not installed") from exc

    try:
        reader = PdfReader(str(path))
    except Exception as exc:  # pragma: no cover - upstream errors vary
        raise RuntimeError(str(exc)) from exc

    text_chunks: list[str] = []
    for page_number, page in enumerate(reader.pages, start=1):
        try:
            text = page.extract_text() or ""
        except Exception as exc:  # pragma: no cover - depends on document
            warnings.append(f"page {page_number}: {exc}")
            text = ""
        text_chunks.append(text)
    return "\n".join(text_chunks), warnings


def _extract_with_pdfminer(path: Path) -> tuple[str, list[str]]:
    try:
        from pdfminer.high_level import extract_text
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("pdfminer.six is not installed") from exc

    try:
        text = extract_text(str(path))
    except Exception as exc:  # pragma: no cover - upstream errors vary
        raise RuntimeError(str(exc)) from exc
    return text or "", []


def _repair_pdf_with_pikepdf(source: Path, temp_dir: Path) -> tuple[Path, list[str]]:
    try:
        from pikepdf import Pdf  # type: ignore[attr-defined]
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("pikepdf is not installed") from exc

    repaired_path = Path(temp_dir) / "repaired.pdf"
    warnings: list[str] = ["pikepdf repair applied"]
    try:
        with Pdf.open(str(source)) as pdf:
            pdf.save(str(repaired_path))
    except Exception as exc:  # pragma: no cover - upstream errors vary
        raise RuntimeError(str(exc)) from exc
    return repaired_path, warnings


def _insert_pdf_field_breaks(text: str) -> str:
    if not text:
        return text
    updated = text
    if _PDF_FIELD_LEADING_RE is not None:
        def add_leading(match: re.Match[str]) -> str:
            alias = match.group("alias")
            prefix = "" if match.start() == 0 else "\n"
            return f"{prefix}{alias}:"

        updated = _PDF_FIELD_LEADING_RE.sub(add_leading, updated)
    if _PDF_FIELD_BREAK_RE is not None:
        def ensure_break(match: re.Match[str]) -> str:
            alias = match.group("alias")
            return f"{alias}:\n"

        updated = _PDF_FIELD_BREAK_RE.sub(ensure_break, updated)
    return updated


def _normalise_pdf_text(text: str) -> str:
    cleaned = _insert_pdf_field_breaks(text)
    lines = cleaned.splitlines()
    if not lines:
        return cleaned
    _move_list_items_after_field(
        lines,
        (
            "anti-patterns",
            "antipatterns",
            "pitfalls",
            "watch-outs",
            "warnings",
        ),
    )
    output: list[str] = []
    seen_heading = False
    pending_steps: list[str] = []
    seen_steps_field = False
    release_pending_after_number = False
    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped:
            output.append(raw_line)
            continue
        if (
            not seen_steps_field
            and stripped[:1].isdigit()
            and LIST_PREFIX_RE.match(stripped)
        ):
            pending_steps.append(raw_line)
            continue
        lowered = stripped.lower()
        if lowered.startswith("steps:"):
            seen_steps_field = True
            release_pending_after_number = bool(pending_steps)
            output.append(raw_line)
            continue
        if (
            release_pending_after_number
            and stripped[:1].isdigit()
            and LIST_PREFIX_RE.match(stripped)
        ):
            output.append(raw_line)
            if pending_steps:
                output.extend(
                    sorted(pending_steps, key=_numbered_line_key)
                )
                pending_steps.clear()
            release_pending_after_number = False
            continue
        if not seen_heading:
            heading = stripped.lstrip("#").strip()
            if not heading:
                heading = stripped
            output.append(f"## {heading}")
            seen_heading = True
            continue
        if stripped.startswith("###") and not stripped.endswith(":"):
            heading = stripped.lstrip("#").strip()
            if heading and not KEYWORD_PATTERN.search(heading):
                output.append(f"## {heading}")
                continue
        output.append(raw_line)
    if pending_steps:
        output.extend(pending_steps)
    _move_list_items_after_field(
        output,
        (
            "anti-patterns",
            "antipatterns",
            "pitfalls",
            "watch-outs",
            "warnings",
        ),
    )
    return "\n".join(output)


def _rotate_pdf_lines(text: str) -> str:
    lines = text.splitlines()
    if not lines:
        return text
    def find_candidate(skip_hash: bool) -> int | None:
        for index, raw_line in enumerate(lines):
            stripped = raw_line.strip()
            if not stripped:
                continue
            if skip_hash and stripped.startswith("#"):
                continue
            if _looks_like_pdf_title(raw_line):
                return index
        return None

    best_index = find_candidate(True)
    if best_index is None:
        best_index = find_candidate(False)
    if best_index is None:
        for index, raw_line in enumerate(lines):
            stripped = raw_line.strip()
            if not stripped:
                continue
            if stripped.endswith(":"):
                continue
            if stripped[0] in "-*•" or stripped[:1].isdigit():
                continue
            best_index = index
            break
    if best_index is None or best_index == 0:
        return text
    rotated = lines[best_index:] + lines[:best_index]
    return "\n".join(rotated)


def _looks_like_pdf_title(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if stripped[0] in "-*•":
        return False
    if stripped[:1].isdigit():
        return False
    base = stripped.lstrip("#").strip()
    base = re.sub(r"^[\-•*]+\s*", "", base)
    base = re.sub(r"^[\d\.\)]+\s*", "", base)
    if not base:
        return False
    if any(char in base for char in (":", "|")):
        return False
    if any(char in base for char in ".!?"):
        return False
    tokens = [re.sub(r"[^A-Za-z0-9']", "", token) for token in base.split()]
    tokens = [token for token in tokens if token]
    if not tokens:
        return False
    has_alpha = False
    for token in tokens:
        if token.isdigit():
            continue
        if not any(char.isalpha() for char in token):
            continue
        has_alpha = True
        lower = token.lower()
        if lower in PDF_TITLE_STOPWORDS:
            continue
        if token.isupper() or token[0].isupper():
            continue
        return False
    return has_alpha


def _numbered_line_key(line: str) -> int:
    match = re.match(r"\s*(\d+)", line)
    if match:
        try:
            return int(match.group(1))
        except ValueError:  # pragma: no cover - defensive
            return 0
    return 0


def _move_list_items_after_field(lines: list[str], aliases: Iterable[str]) -> None:
    alias_prefixes = [alias.lower().rstrip(":") for alias in aliases]
    if not alias_prefixes:
        return
    for index, raw_line in enumerate(list(lines)):
        stripped = raw_line.strip()
        if not stripped:
            continue
        lowered = stripped.lower()
        matched_alias = next(
            (alias for alias in alias_prefixes if lowered.startswith(alias)), None
        )
        if not matched_alias:
            continue
        removal_indices: list[int] = []
        moved: list[str] = []
        scan_index = index - 1
        while scan_index >= 0:
            candidate = lines[scan_index]
            candidate_stripped = candidate.strip()
            if not candidate_stripped:
                scan_index -= 1
                continue
            if candidate_stripped.startswith(('-', '*', '•')):
                moved.append(candidate)
                removal_indices.append(scan_index)
                scan_index -= 1
                continue
            break
        if not moved:
            return
        for position in sorted(removal_indices):
            lines.pop(position)
        field_index = index - len(removal_indices)
        insertion_index = field_index + 1
        for line_value in reversed(moved):
            lines.insert(insertion_index, line_value)
            insertion_index += 1
        return


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


def parse_file(
    path: Path,
    base_path: Path,
    *,
    min_pdf_chars: int | None = None,
    pdf_backends: Iterable[str] | None = None,
) -> ParseOutcome:
    suffix = path.suffix.lower()
    if suffix in {".md", ".markdown"}:
        text = path.read_text(encoding="utf-8", errors="ignore")
        return ParseOutcome(parse_markdown(text, path, base_path))
    if suffix == ".txt":
        text = path.read_text(encoding="utf-8", errors="ignore")
        return ParseOutcome(parse_plain_text(text, path, base_path))
    if suffix in {".html", ".htm"}:
        text = path.read_text(encoding="utf-8", errors="ignore")
        return ParseOutcome(parse_html(text, path, base_path))
    if suffix == ".pdf":
        effective_min = resolve_min_pdf_chars(min_pdf_chars)
        return parse_pdf(path, base_path, min_chars=effective_min, pdf_backends=pdf_backends)
    if suffix == ".docx":
        return ParseOutcome(parse_docx(path, base_path))
    return ParseOutcome([])


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


def parse_pdf(
    path: Path,
    base_path: Path,
    *,
    min_chars: int,
    pdf_backends: Iterable[str] | None,
) -> ParseOutcome:
    text, meta = extract_pdf_text(path, min_chars=min_chars, prefer_backends=pdf_backends)
    if not text.strip():
        return ParseOutcome([], meta)

    ordered_text = _rotate_pdf_lines(text)
    candidates = [ordered_text]
    normalised = _normalise_pdf_text(ordered_text)
    if normalised != ordered_text:
        candidates.insert(0, normalised)

    items: list[ParsedItem] = []
    for candidate in candidates:
        items = parse_markdown(candidate, path, base_path)
        if items:
            break
    if not items:
        items = parse_plain_text(ordered_text, path, base_path)
    return ParseOutcome(items, meta)


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
    for line in lines[:8]:
        stripped = line.strip().rstrip(":").lower()
        if stripped in FIELD_ALIASES:
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
    target_dir: Path,
    base_path: Path,
    *,
    min_pdf_chars: int | None = None,
    pdf_backends: Iterable[str] | None = None,
) -> tuple[list[ParsedItem], dict[str, FileScanResult]]:
    items: list[ParsedItem] = []
    files: dict[str, FileScanResult] = {}
    resolved_min = resolve_min_pdf_chars(min_pdf_chars)
    resolved_backends = list(pdf_backends) if pdf_backends else None
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
            parsed = parse_file(
                file_path,
                base_path,
                min_pdf_chars=resolved_min,
                pdf_backends=resolved_backends,
            )
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
        for item in parsed.items:
            item.file_sha = file_sha
            items.append(item)
        files[rel_file] = FileScanResult(
            file=rel_file,
            sha256=file_sha,
            mtime=mtime,
            extracted_count=len(parsed.items),
            pdf_meta=parsed.pdf_meta,
        )
    return items, files

