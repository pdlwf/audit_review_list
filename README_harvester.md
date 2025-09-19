# Method Framework Harvester

The harvester keeps a structured index of thinking models and methods stored in
`basic_knowledge/method_frame`. It scans Markdown, HTML, plain text, PDF and
DOCX files, normalises the content, and records a consolidated registry for
humans and automation.

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
python basic_knowledge/scripts/harvest_methods.py scan
python basic_knowledge/scripts/harvest_methods.py update
python basic_knowledge/scripts/harvest_methods.py render
```

For richer PDF extraction install the optional backends:

```bash
pip install pypdf pdfminer.six pikepdf
```

Use `--root` to point the CLI to another checkout or sandbox. The `check`
command performs a dry-run to show which files would be parsed and whether they
changed since the last update.

```bash
python basic_knowledge/scripts/harvest_methods.py check --verbose
```

## Workflow

1. Run `scan` to parse the knowledge base. Results are written to
   `basic_knowledge/_index/extracted.jsonl` and
   `basic_knowledge/_index/scan_report.json`.
2. Run `update` to merge the extracted methods into the persistent registry at
   `basic_knowledge/_index/registry.json` and refresh
   `manifest.json`.
3. Run `render` to rebuild the human-oriented cheat sheet in
   `basic_knowledge/_index/SUMMARY.md`.

The registry enforces stable item IDs and merges duplicates by comparing names,
aliases, and behavioural signatures. Per-file manifests record the SHA-256
fingerprint of each source so the next run only re-processes modified files.

## Makefile targets

The repository includes `make` targets for common tasks:

```bash
make venv     # create a virtual environment in .venv
make install  # install editable project with dev dependencies
make scan     # python basic_knowledge/scripts/harvest_methods.py scan
make update   # python basic_knowledge/scripts/harvest_methods.py update
make render   # python basic_knowledge/scripts/harvest_methods.py render
make check    # python basic_knowledge/scripts/harvest_methods.py check
make test     # run ruff, mypy, and pytest
```

## Troubleshooting

- **Missing dependencies** – install via `pip install -e .[dev]` to pull in
  `beautifulsoup4`, `lxml`, `pypdf`, `python-docx`, and tooling. Add
  `pdfminer.six` and `pikepdf` for resilient PDF extraction.
- **PDF extraction is empty** – not all PDFs contain embedded text. The harvester
  logs a warning and continues without blocking the run.
- **No items detected** – ensure section headings contain words such as
  "method", "model", or "framework", or add explicit metadata fields (Type,
  Steps, When to use, Tags, etc.).
- **Idempotency checks failing** – remove `basic_knowledge/_index/extracted.jsonl`
  and rerun `scan`
  to refresh the extracted cache before updating.

