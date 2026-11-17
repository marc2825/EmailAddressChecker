# Contributing

Contributions are welcome if they keep the project's conservative verdicts and network-safety boundaries. Please read the [README](README.md) and [project status](STATUS.md) first.

## Setup

Python 3.12 or later is required.

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -e '.[dev]'
```

## Checks

Run all local checks before opening a pull request:

```bash
make check
```

Without `make`, run them one by one:

```bash
python -m ruff check .
python -m ruff format --check .
python -m mypy src
python -m pytest
python scripts/check_forbidden_smtp.py
python -m emailcheck --version
```

Tests must not query public DNS or contact third-party SMTP servers. Use deterministic fakes or the guarded loopback fixtures for network behavior.

## Safety requirements

Every change must keep these rules:

- Verdicts: delivery is estimated, never proven. Ambiguous or unsupported evidence must not become `invalid` or `likely_deliverable`. A bare SMTP `250` does not prove that a mailbox exists, and a bare `550` does not prove that a recipient is invalid. Risk flags stay separate from delivery status.
- SMTP: never send message content or issue `DATA`, `AUTH`, `VRFY`, or `EXPN`. An ordinary verification touches at most one recipient across failures, retries, and restarts, and never replays after the recipient stage. Never rewrite the recipient's local part. Production active deployments require TLS.
- Network access: validate every candidate destination and the connected peer. Keep blocking private and reserved addresses, and keep operator restrictions, authentication, and rate limits. Never add account registration, password reset, or provider-specific enumeration as a verification method.
- Privacy: do not expose full email addresses or credentials in ordinary logs, public errors, or diagnostic output. Keep account isolation, retention, and deletion fences in every persistent store.

A change to any of these needs focused regression tests and a security review. See the [threat model](docs/threat-model.md), the [SMTP state machine](docs/smtp-state-machine.md), and the [status model](docs/status-model.md).

## Code and documentation

Follow the dependency structure in [architecture.md](docs/architecture.md): domain rules and ports do not depend on entry points or concrete adapters. Bound every network operation, return structured public errors, and justify new dependencies.

- Add tests for behavior changes, especially in SMTP retries, DNS or destination validation, authorization, caching, persistence, and deletion. Prefer tests that exercise behavior. A test that reads source code or documentation must carry the `inspection` or `docs_contract` marker; see the [test strategy](docs/test-strategy.md#specification-tests-and-structural-tests).
- Use Python 3.12+, annotate every public function, and prefer immutable domain values.
- Keep time in UTC and serialize it with an explicit offset.
- Do not expose network exception text in public errors, silently broaden the accepted email syntax, or add a production dependency without an ADR.
- Tests use fake clocks and deterministic randomness. Do not weaken a timing assertion to hide a failure.
- Update the relevant documentation when behavior changes, and record lasting design decisions in an [ADR](docs/adr/).

## Pull requests

Keep each pull request focused. Say what changed, why, how it was tested, and how it affects safety, compatibility, or documented behavior. If a proposal conflicts with a safety requirement, explain the conflict instead of working around the guard.
