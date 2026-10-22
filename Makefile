.PHONY: install format format-check lint type test invariants cli-smoke check build

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

invariants:
	python scripts/check_forbidden_smtp.py

cli-smoke:
	python -m emailcheck --version

check: lint format-check type test invariants cli-smoke

build:
	python -m build
	python -m twine check dist/*
	python scripts/check_artifacts.py
