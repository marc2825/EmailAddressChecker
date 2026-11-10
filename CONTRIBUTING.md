# Contributing

Thanks for your interest. This project is deliberately conservative: it makes a
narrow claim about email addresses and refuses to make a wider one. Most of the
guidance below exists to keep that true.

## Development setup

Python 3.12 or newer.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
```

## Before opening a pull request

```bash
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy src
python scripts/check_forbidden_smtp.py
make check
```

`make check` runs the same sequence. The default test path is **offline**: it
opens no external socket, resolves no public name, and contacts no third-party
mail exchanger. Tests that need a server bind to loopback; tests that need DNS
or SMTP use fakes, scripted transports, fake clocks, and deterministic
randomness. Please keep it that way — a suite that reaches the network is a
suite that probes strangers' infrastructure every time CI runs.

## Safety invariants

These are not style preferences. A change that weakens one needs an explicit
security review and an ADR, not a passing test run.

**What the project may claim**

- Deliverability is *estimated*. Mailbox existence, ownership, use, and
  guaranteed delivery are never proven and must never be claimed.
- A bare `250` is not high-confidence mailbox existence.
- A bare `550` is not mailbox-not-found. Only an authoritative enhanced code
  supports `invalid`.
- Unknown or ambiguous evidence resolves to `unknown` or `temporary_unknown` —
  never to an optimistic verdict.
- Deliverability status and risk flags stay separate, and raw evidence stays
  separate from normalized reason codes and final verdicts.

**What the SMTP path may do**

- Never implement `DATA`. Never implement `VRFY` or `EXPN`. Never `AUTH`.
- Never send message headers, bodies, attachments, or delivery-status probes.
- At most **one recipient touch per ordinary verification operation**, in
  total — across MX fallback, temporary replies, lost replies, partial writes,
  retries, and restarts.
- Never replay at the recipient stage. A retry is available only to an attempt
  that provably did not reach the recipient.
- Never rewrite the local part for probing.
- TLS is required for active SMTP under the current policy.
- Never add account-registration, login, password-reset, or provider-specific
  enumeration endpoints as verification methods.
- Never rotate IPs or identities to bypass a remote limit.

**Destination safety**

- Private, reserved, and otherwise unsafe addresses are rejected; the selected
  IP and the actual peer are both validated.
- Operator domain and exchanger blocks, and the lab destination allowlist,
  apply to **every** candidate a path could reach, not only the first.
- Active checks in service profiles require authentication and rate limiting.

**Privacy and persistence**

- Never log a complete email address in normal application logs.
- Persistent account-owned writes preserve the account-generation fencing
  semantics: the write and its generation check happen in the same store
  transaction, and every persistent store binds to one deletion authority.

`docs/threat-model.md` explains why these exist; `docs/status-model.md` defines
the verdict vocabulary; `docs/architecture.md` describes the layering.

## Architecture

```
apps → application → ports/domain ← adapters
                          ↑
                    composition.py
```

- **domain** — pure values and rules. No FastAPI, Redis, SQLAlchemy, dnspython,
  or socket implementations; no clock, no I/O.
- **ports** — protocols for network, storage, cache, rate limiting, time, and
  randomness.
- **adapters** — implement ports, and must be replaceable in tests.
- **application** — orchestration.
- **composition.py** — the only place the graph is assembled.

`domain/` and `ports/` must not import `application/`, `apps/`, `adapters/`, or
`composition`. Every external operation carries an explicit timeout. A new
production dependency needs a short ADR.

## Coding standards

Python 3.12+, full type annotations on public functions and methods, immutable
dataclasses for domain values, enums for stable status and reason codes. Keep
library exceptions behind adapter boundaries — never expose network-library
exception text through the public API. UTC internally, timestamps serialized
with explicit offsets. Do not silently broaden accepted email syntax.

## Tests

Add tests with the change, not after it. Anything touching the following needs a
focused regression test that would fail without the fix:

- SMTP recipient touch, retry, or replay behaviour;
- DNS or destination safety, including fallback candidates;
- account deletion, generation fencing, or store authority binding;
- persistence, idempotency, or restart/recovery semantics.

Omitting timeout, redaction, or rate-limit tests is grounds for rejection on its
own.

## A note on historical citations

Docstrings, tests, and ADRs cite internal development material that is not part
of the public repository:

- `prompts/NN-*.md` — the phase-by-phase implementation briefs the project was
  built from. "Phase N" in a comment or test name refers to one of them.
- `plans/*.md` — the execution plans written for those phases.
- `AGENTS.md` — the internal engineering rules. Every rule it held that a change
  must preserve is restated in [Safety invariants](#safety-invariants) and
  [Coding standards](#coding-standards) above, so "`AGENTS.md` says" can be read
  as "the invariants in this file say".
- `IMPLEMENTATION_STATUS.md` — the internal progress log. Its public successor is
  [STATUS.md](STATUS.md) together with [CHANGELOG.md](CHANGELOG.md).

A citation records *why* a decision was made and is safe to read as provenance —
the durable contract it refers to always lives in `docs/` or in this file, and
that is the version to trust. New code should cite the public document rather
than any of the above.

## Documentation

When behaviour changes, update the closest relevant document in `docs/`. When a
durable decision changes, add or supersede an ADR in `docs/adr/`.

## Pull requests

Keep the scope coherent — one change, or one narrowly scoped defect. Explain the
rationale, include the tests, and state the safety impact explicitly when the
change touches any invariant above. If a request conflicts with one of them,
please say so in the PR rather than implementing around it.
