.PHONY: venv install scan update render check test

venv:
	python3 -m venv .venv

install:
	python -m pip install -e .[dev]

scan:
	python scripts/harvest_methods.py scan

update:
	python scripts/harvest_methods.py update

render:
	python scripts/harvest_methods.py render

check:
	python scripts/harvest_methods.py check

test:
	ruff check .
	mypy .
	pytest
