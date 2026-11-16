.PHONY: install format format-check lint type test test-spec test-structure invariants cli-smoke check build

install:
	python -m pip install -e ".[dev]"

format:
	python -m ruff format .

format-check:
	python -m ruff format --check .

lint:
	python -m ruff check .

type:
	python -m mypy src

test:
	python -m pytest

# Specification tests only: behavior, without source-structure or document-wording pins.
test-spec:
	python -m pytest -m "not inspection and not docs_contract"

# Tests that read project source or published documentation (see docs/test-strategy.md).
test-structure:
	python -m pytest -m "inspection or docs_contract"

invariants:
	python scripts/check_forbidden_smtp.py

cli-smoke:
	python -m emailcheck --version

check: lint format-check type test invariants cli-smoke

build:
	python -m build
	python -m twine check dist/*
	python scripts/check_artifacts.py
