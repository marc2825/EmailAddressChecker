.PHONY: install format lint type test invariants claude-config cli-smoke check

install:
	python -m pip install -e ".[dev]"

format:
	python -m ruff format .

lint:
	python -m ruff check .

type:
	python -m mypy src

test:
	python -m pytest

invariants:
	python scripts/check_forbidden_smtp.py

claude-config:
	python scripts/check_claude_config.py

cli-smoke:
	python -m emailcheck --version

check: lint type test invariants claude-config cli-smoke
