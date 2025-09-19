.PHONY: venv install scan update render check test

venv:
	python3 -m venv .venv

install:
	python3 -m pip install -e .[dev]

scan:
	PYTHONPATH=. python3 basic_knowledge/scripts/harvest_methods.py scan

update:
	PYTHONPATH=. python3 basic_knowledge/scripts/harvest_methods.py update

render:
	PYTHONPATH=. python3 basic_knowledge/scripts/harvest_methods.py render

check:
	PYTHONPATH=. python3 basic_knowledge/scripts/harvest_methods.py check

test:
	ruff check .
	mypy .
	pytest
