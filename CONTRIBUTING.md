# Contributing

Contributions are welcome, provided they preserve the project's conservative verdicts and network-safety boundaries. Please read the [README](README.md) and [project status](STATUS.md) before proposing changes.

## Development setup

Python 3.12 or newer is required.

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -e '.[dev]'
```

## Checks

Run the full local checks before opening a pull request:

```bash
make check
```

If `make` is unavailable, run the commands individually:

```bash
python -m ruff check .
python -m ruff format --check .
python -m mypy src
python -m pytest
python scripts/check_forbidden_smtp.py
python -m emailcheck --version
```

Tests must not query public DNS or contact third-party SMTP servers. Use deterministic fakes or explicitly guarded loopback fixtures for network behavior.

## Safety requirements

Changes must preserve these invariants:

- **Verdicts:** Delivery is estimated, not proven. Ambiguous or unsupported evidence must not become `invalid` or `likely_deliverable`. A bare SMTP `250` does not prove mailbox existence, and a bare `550` does not establish recipient invalidity. Keep risk flags separate from delivery status.
- **SMTP:** Never send message content or issue `DATA`, `AUTH`, `VRFY` or `EXPN`. Limit an ordinary verification operation to one recipient touch across failures, retries and restarts; never replay after the recipient stage. Do not rewrite the recipient's local part. Production active deployments require TLS.
- **Network access:** Validate every candidate destination and the connected peer. Preserve private/reserved-address blocking, operator restrictions, authentication and rate limits. Never add account-registration, password-reset or provider-specific enumeration as a verification method.
- **Privacy:** Do not expose full email addresses or credentials in ordinary logs, public errors or diagnostic output. Preserve account isolation, retention and deletion fences across persistent stores.

Changes to any of these boundaries require focused regression tests and a security review. See the [threat model](docs/threat-model.md), [SMTP protocol contract](docs/smtp-state-machine.md) and [status model](docs/status-model.md).

## Code and documentation

The code follows the dependency structure described in [architecture.md](docs/architecture.md): domain rules and ports remain independent of application entry points and concrete adapters. Keep network operations bounded, public errors structured, and new dependencies justified.

Add tests for behavior changes, particularly in SMTP retries, DNS or destination validation, authorization, caching, persistence and deletion. Prefer tests that exercise behavior; a test that reads source code or documentation must carry the `inspection` or `docs_contract` marker (see [test strategy](docs/test-strategy.md#specification-tests-and-structural-tests)). Update the relevant documentation when behavior changes; use an [architecture decision record](docs/adr/) for durable design decisions.

Use Python 3.12+, full public-function annotations and immutable domain values.
Keep time in UTC and serialize explicit offsets. Do not expose network exception
text through public errors, silently broaden email syntax, or add production
dependencies without an ADR. Tests use fake clocks and deterministic randomness;
do not weaken timing assertions to mask a failure.

## Pull requests

Keep each pull request focused. Describe what changed, why it is needed, how it was tested, and any impact on safety, compatibility or documented behavior. If a proposal conflicts with a safety requirement, explain the conflict rather than bypassing the guard.
