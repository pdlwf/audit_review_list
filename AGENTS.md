# Repository Guidelines

## Project Structure & Module Organization
`basic_knowledge/method_harvester/` contains the ingestion pipeline modules (`manifest.py`, `parser.py`, `renderer.py`, `registry.py`) and should host new harvest logic. Shared utilities live in `basic_knowledge/method_frame/`, while runnable scripts sit under `basic_knowledge/scripts/`. Fixtures, seed inputs, and generated artifacts belong in `data/`; keep checked-in assets lightweight. Tests reside in `basic_knowledge/tests/`, mirroring the package layout to keep unit coverage close to the code paths they exercise.

## Build, Test, and Development Commands
- `make venv` creates a local Python 3.11 virtual environment; activate it before installing.
- `make install` installs the package in editable mode with dev extras (`ruff`, `mypy`, `pytest`).
- `make scan|update|render|check` run `basic_knowledge/scripts/harvest_methods.py` with the matching subcommand; use these to verify data ingestion from new sources.
- `make test` executes the quality gate: `ruff check .`, `mypy .`, and `pytest`.

## Coding Style & Naming Conventions
Adopt Python 3.11 features with 4-space indentation and type hints everywhere `mypy --strict` would require them. Respect the Ruff line length of 100 and rely on `ruff check --fix` for routine formatting. Module and function names follow `snake_case`; classes use `CapWords`. Keep manifest files declarative and avoid side effects at import time.

## Testing Guidelines
Add unit tests beside the code they cover inside `basic_knowledge/tests/` using `pytest` naming (`test_<unit>.py` and `test_*` functions). Include factories or fixtures under `basic_knowledge/tests/conftest.py` when sharing setup. Run `make test` before posting review; ensure new ingestion rules exercise both happy path and parsing failure scenarios.

## Commit & Pull Request Guidelines
Follow Conventional Commits (`feat:`, `fix:`, `docs(ci):` etc.) as seen in the Git history. Scope commits narrowly and document user-facing impacts or data migrations in the body. Pull requests must explain the motivation, list test evidence (paste the `make test` summary), and reference tracking issues. Attach rendered diffs or screenshots when modifying harvested outputs.

## Harvesting Workflow Tips
When prototyping new sources, run `PYTHONPATH=. python basic_knowledge/scripts/harvest_methods.py scan --source <name>` to validate connectors without mutating manifests. Check updated artifacts into `data/` only after `make check` reports a clean registry.
