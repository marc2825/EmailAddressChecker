# Test strategy

Tests must demonstrate **correctness, conservative verdicts, and absence of unsafe network behavior**. A passing suite is evidence about the tested implementation, not authorization to contact third-party mail servers or approval of a production deployment.

This document describes the maintained test approach. Detailed behavioral contracts live in the [status model](status-model.md), [SMTP state machine](smtp-state-machine.md), [threat model](threat-model.md), and [architecture](architecture.md).

## 1. Principles

- No external DNS or SMTP traffic in automated tests.
- Reproducible fixtures and replaceable network dependencies.
- Safety properties measured at the wire, storage, or public-output boundary.
- Controlled network evaluation only with explicitly authorized targets.
- Correctness reported by evidence class, not an unsupported single accuracy score.
- Test-owned SQLite connections must close explicitly after committing or rolling
  back. A connection's transaction context does not close its handle; use an
  outer `contextlib.closing` or `finally`, as the production adapters do.
  Resource warnings and pytest's unraisable-exception reports fail the suite;
  leaking handles must not leave CI green.

## Run the checks

Use Python 3.12 or newer in a virtual environment:

```bash
python -m pip install -e '.[dev]'
make check
```

`make check` runs Ruff linting and formatting checks, mypy, pytest, the forbidden-SMTP-command scanner, and a CLI smoke check. `make test-spec` and `make test-structure` run the two halves of the suite separately; see [Specification tests and structural tests](#specification-tests-and-structural-tests). To run an individual check:

```bash
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy src
python scripts/check_forbidden_smtp.py
python -m emailcheck --version
```

Packaging and release smoke tests are separate; see [releasing](releasing.md). The CI matrix, not a historical report, is the source for which platforms and interpreter versions have actually passed.

## Network safety

**Automated tests must not contact third-party DNS servers or mail exchangers.** Use fake resolvers, scripted SMTP transports, fake clocks, and deterministic data. A test needing an actual socket must use explicitly guarded loopback fixtures only.

`tests/conftest.py` blocks external resolution, stream connections, datagram sends, and asyncio transports. `tests/test_no_network.py` verifies that this guard stays effective. A forbidden network attempt must fail the test rather than be converted into an ordinary DNS or SMTP error. Network guards must never be relaxed merely to make a failing test pass.

Manual integration with real infrastructure requires a separately authorized environment, owned targets, documented scope, rate limits, and the [operational readiness checklist](readiness-checklist.md). It is not part of CI.

## 2. Test layers

| Layer | Primary responsibility | Typical tests |
| --- | --- | --- |
| Unit | Pure parsing and policy decisions | Address grammar, normalization, DNS mapping, status precedence, rate-limit arithmetic |
| Property / fuzz | Invariants across many inputs | CR/LF injection, malformed strings, order-independent aggregation, bounded encoders |
| Adapter | I/O boundary behavior | DNS resolver mapping, SMTP transport, TLS, SQLite, HTTP client, timeouts |
| Application | Orchestration across ports | Recipient-contact budget, bounded fallback, quotas, retry, cancellation, cache, deletion |
| Composition / CLI | Public behavior and dependency wiring | No local SMTP component, CLI formats, auth, process limits, package smoke |
| Contract / inspection | Invariants not captured by examples | Forbidden SMTP verbs, dependency direction, reason-code/doc sync, public field allowlists |

Changes to an interface should add tests at the closest layer and, where safety depends on wiring, one composition-level regression test. Tests must fail on the corresponding unsafe behavior; an assertion that merely restates a mock's configured return value is insufficient.

### Specification tests and structural tests

Contract and inspection tests read the code or the documents instead of running the code, so a harmless refactor or rewording can fail them. They are kept apart from specification tests by two registered pytest markers:

| Marker | Applies to | Typical failure after a harmless change |
| --- | --- | --- |
| `inspection` | Tests that read project source or its syntax tree | A function moved or was renamed; an import was restructured |
| `docs_contract` | Tests that read published documentation | A sentence or table in `docs/` or a README was reworded |

Everything else is a specification test: it exercises behavior through public functions, ports, fakes, or loopback fixtures.

```bash
make test-spec        # python -m pytest -m "not inspection and not docs_contract"
make test-structure   # python -m pytest -m "inspection or docs_contract"
make test             # both; CI runs the two groups as separate steps
```

Rules:

- **Prefer a specification test.** Use an inspection test only for a property that no example can show: the absence of a code path (no `DATA`, no unverified TLS context), dependency direction, or a single construction point. Its docstring names the invariant it protects.
- **Assert the property, not the spelling.** Check imports, calls, or names in the syntax tree rather than exact source lines, so a reformatted line does not fail the test.
- **When a refactor fails a structural test**, confirm the invariant still holds and the specification tests pass, then update the inspection in the same change. Never delete or weaken a guard only to make the run green; a change that actually removes the property is a real failure.
- **Mark every new structural test.** A module named `*_inspection.py` or `test_docs_*.py` carries the marker module-wide; elsewhere, mark the individual test. `tests/test_test_taxonomy.py` scans the suite and fails when a test that reads source or documentation is unmarked, or when a per-test marker would move a specification test out of the specification run. Its `NOT_STRUCTURAL` list records, with reasons, the few tests the broad scan flags that are not structural (for example, the SMTP-command scanner's own specification, which feeds it synthetic source).

## Coverage by subsystem

### Parsing, DNS, and classification

Cover valid, invalid, and unsupported address forms; IDNA domains; control-character injection; overlong inputs; and stable normalized identity. Unsupported syntax must not silently become `invalid`.

DNS fixtures should include:

- MX ordering, equal preference, multiple exchangers, and trailing-dot hostnames.
- Null MX, NXDOMAIN, missing MX with eligible implicit A/AAAA, and authoritative absence of a route.
- SERVFAIL, timeout, malformed or contradictory responses, and per-candidate resolution failures.
- Positive/negative TTLs, TTL zero, bounded cache entries, and concurrent request coalescing.
- Mixed safe/unsafe resolved addresses, unexpected peers, and blocked fallback candidates.

Classification fixtures should cover role-name normalization, disposable overrides, free-mail independence from MX providers, label-bounded provider matching, ambiguous providers, malformed metadata, missing datasets, and dataset fingerprint changes. **Classification must never decide deliverability.**

### Evidence and verdicts

Assert the published statuses, reason codes, confidence categories, and risk flags against the [status model](status-model.md). In particular:

- Target-specific, non-temporary hard-negative evidence is required for `invalid`.
- A route plus qualifying acceptance, with no stronger blocker, is required for `likely_deliverable`.
- Bare SMTP `250` is not mailbox-existence proof; bare `550` is not automatically recipient-not-found; `252` is not acceptance.
- Evidence order and duplicate observations do not change the verdict.
- Risk-only flags do not change status; a temporary condition does not become `invalid` because a retry budget expires.
- Errors in this service, storage, or admission do not masquerade as mailbox evidence.
- Public output excludes raw SMTP text, secrets, internal exceptions, and uncalibrated numerical probabilities.

The published reason-code list and enum must remain synchronized; existing document contract tests enforce this.

### SMTP transport and dialogue

Use scripted SMTP peers and deliberately failing transports. Exercise normal replies (`250`, `251`, `252`), temporary replies (`450`–`452`), explicit recipient absence (`550 5.1.1`), policy rejection (`550 5.7.1`), ambiguous `550`, accept-all behavior, malformed multiline replies, oversized lines, slow banners, connection drops, and interrupted writes.

Verify the protocol's *safety properties*, not only returned statuses:

1. Production code can construct only the permitted encoded commands. No `DATA`, `AUTH`, `VRFY`, `EXPN`, or message body reaches the wire.
2. One ordinary verification touches **at most one recipient in total**, across candidate fallback, retries, timeouts, and restarts. Inspect wire events, not just in-memory counters.
3. Fallback and retries are allowed only when recipient contact has provably not occurred. A lost reply or partially written RCPT command must not cause another recipient attempt.
4. STARTTLS negotiation and hostname/certificate verification obey production policy; TLS failure is terminal and never results in plaintext continuation or an `invalid` mailbox verdict.
5. Destination selection and actual connected peers obey the same policy; unsafe, private/reserved, unapproved, or mismatched endpoints are refused.
6. Every connect/read/write and whole probe has bounded resource use; cancellation releases connections and held permits.
7. A cleanup error after a recipient reply does not overwrite that observation.

See [SMTP state machine](smtp-state-machine.md) and [ADR 0019](adr/0019-operation-recipient-budget-and-atomic-job-identity.md) for the exact recipient-contact rules.

### Quotas, jobs, and caches

Test global admission, per-principal queue share, domain/MX pacing shared across accounts, per-account/API-key quotas, and cancellation. Budget exhaustion must refuse work before network activity. Tokens and concurrency permits must be released on failure; exhausted destination state must not be evicted to reset capacity.

Verify idempotency under duplicate submissions and concurrent workers, including the gap between job creation and executor admission. A cache hit must enqueue no work and trigger no SMTP connection. Cached verdicts must be scoped by account, target, ruleset, sender identity, dataset fingerprint, and expiry; DNS TTLs must not restart on each hit.

Retry tests must use recorded recipient-contact state rather than status labels. Recovery from interrupted work must not replay an already touched recipient.

### Persistence, deletion, and privacy

Use multiple service instances against controlled local stores to test cross-replica races. Cover:

- Account-owned writes and local store fences checked **within the same transaction**.
- Durable account-generation advancement before deletion, including a writer paused between admission and commit.
- Store authority mismatch, missing persistent account-state authority, and old-schema rejection.
- Partial deletion failure reporting and safe retry; no false `complete` result.
- Retention expiry, bounded scheduled sweeps, failure reporting, and plaintext removal.
- No complete email addresses, raw remote replies, credentials, or unstable exception text in routine output, logs, or metrics.
- Explicit opt-in for addresses in local output, CSV formula escaping, and atomic output replacement on normal failure/cancellation.

Deletion tests establish logical-store behavior. They do **not** establish forensic erasure of SQLite WAL, backups, or snapshots; see [privacy](privacy.md).

### CLI, local batch, and packaging

Test the single-address legacy syntax, new `check` and `batch` commands, CSV/TXT parsing, row ordering, malformed rows, output formats, duplicate policies, `--start-row`, progress, exit codes, and input/quota bounds. Confirm the local path has no SMTP component and offline `expand` creates candidates without DNS or SMTP.

Candidate generation tests should cover multiple wildcards, per-slot choices, deduplication, candidate-count overflow, Unicode restrictions, empty tokens, invalid later candidates, and unchanged output files after failure. Source/wheel installation smoke tests should run outside the working tree; see [releasing](releasing.md).

## 3. SMTP fixtures

Maintain scripted scenarios for `250`, `251`, `252`, recipient-specific `550 5.1.1`, policy `550 5.7.1`, bare `550`, temporary `450`/`451`/`452`, full-mailbox conditions, accept-all behavior, delayed or malformed replies, mid-command disconnects, and STARTTLS success or failure. A fixture records the commands and connection count so protocol-safety tests can assert actual contact, not inferred status.

## Fixtures and determinism

Fixtures must be small, reproducible, and safe to run on a developer machine:

- **DNS:** table-driven fake answers with explicit TTLs and resolver failures.
- **SMTP:** scripted reply sequence, recorded wire commands, configurable partial writes, delays, and disconnects.
- **Time:** fake wall and monotonic clocks, and a fake sleeper. Do not use real sleeps to assert retry or pacing behavior.
- **Storage:** isolated temporary SQLite files and multiple instances when testing concurrency. Avoid shared global state between tests.
- **TLS:** loopback test certificates and throwaway public fixture keys; never reuse them as deployment credentials.
- **Classification:** local, explicitly versioned test data; never fetch live provider lists during a test.

No CI fixture should send a probe to a mailbox that belongs to someone else.

## 4. Invariants

- An automated test attempting third-party network access must fail.
- Neither risk-only classification nor non-target evidence may create a decisive mailbox verdict.
- Evidence aggregation is deterministic and independent of input order and duplicates.
- A normal verification performs no more than one recipient contact across all sessions and retries.
- Forbidden SMTP verbs never reach the wire; each network operation and queue has a bound.
- Destination and peer checks are enforced before probing, and pacing is acquired before connecting.
- No full address in routine logs or rate-limit keys; data deletion cannot be undone by stale writes.
- Retry exhaustion, cancellation, or service failure does not create an `invalid` verdict.

## Review checklist

A change is ready for review when:

- [ ] The relevant behavior and failure cases have regression tests.
- [ ] `make check` passes, or each failure is documented with its cause.
- [ ] The offline network guard remains enabled.
- [ ] SMTP recipient-touch, command, TLS, and destination restrictions remain intact.
- [ ] Timeouts, admission, quotas, and cancellation have explicit coverage where changed.
- [ ] Public output and logs reveal no additional personal or secret data.
- [ ] Documentation and stable output vocabulary are updated when behavior changes.
- [ ] Real external probing is not used as a substitute for deterministic tests.

## 5. Metrics and evaluation beyond unit tests

In a separately authorized study, measure hard-invalid precision, unknown/temporary rates, consistency of recipient responses, policy blocks, and timeouts by evidence class. Track latency, outbound connections per request, cache reuse, and resource bounds. Do not advertise a calibrated deliverability probability or an accuracy guarantee without representative ground truth and a documented study.
