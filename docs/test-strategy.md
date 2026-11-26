# Test strategy

Tests must show correct behavior, conservative verdicts, and the absence of unsafe network behavior. A passing suite is evidence about the tested code. It does not authorize contacting third-party mail servers and does not approve a production deployment.

The behavior being tested is defined in the [status model](status-model.md), [SMTP state machine](smtp-state-machine.md), [threat model](threat-model.md), and [architecture](architecture.md).

## Running the checks

Use Python 3.12 or later in a virtual environment:

```bash
python -m pip install -e '.[dev]'
make check
```

`make check` runs Ruff linting and formatting checks, mypy, pytest, the forbidden-SMTP-command scanner, and a CLI smoke check. `make test-spec` and `make test-structure` run the two halves of the suite separately (see [Specification tests and structural tests](#specification-tests-and-structural-tests)). Individually:

```bash
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy src
python scripts/check_forbidden_smtp.py
python -m emailcheck --version
```

Packaging and release smoke tests are described in [releasing](releasing.md). The CI matrix, not an old report, shows which platforms and Python versions currently pass.

## 1. Principles

- No external DNS or SMTP traffic in automated tests.
- Reproducible fixtures and replaceable network dependencies.
- Safety properties are measured at the wire, storage, or public-output boundary.
- Real network evaluation only against explicitly authorized targets.
- Correctness is reported per evidence class, never as a single accuracy score.
- Test-owned SQLite connections are closed explicitly after commit or rollback. A connection's transaction context does not close the handle, so use `contextlib.closing` or `finally`, as the production adapters do. Resource warnings and pytest's unraisable-exception reports fail the suite.

### Network safety

Automated tests must not contact third-party DNS servers or mail exchangers. Use fake resolvers, scripted SMTP transports, fake clocks, and deterministic data; a test that needs a real socket uses the guarded loopback fixtures only.

`tests/conftest.py` blocks external name resolution, stream connections, datagram sends, and asyncio transports, and `tests/test_no_network.py` checks that the guard works. A forbidden network attempt must fail the test, not turn into an ordinary DNS or SMTP error. Never relax a guard to make a failing test pass.

Integration with real infrastructure needs a separately authorized environment, owned targets, a documented scope, rate limits, and the [readiness checklist](readiness-checklist.md). It is not part of CI.

## 2. Test layers

| Layer | Responsibility | Typical tests |
| --- | --- | --- |
| Unit | Pure parsing and policy decisions | Address grammar, normalization, DNS mapping, status precedence, rate-limit arithmetic |
| Property / fuzz | Invariants across many inputs | CR/LF injection, malformed strings, order-independent aggregation, bounded encoders |
| Adapter | I/O boundaries | DNS resolver mapping, SMTP transport, TLS, SQLite, HTTP client, timeouts |
| Application | Orchestration across ports | Recipient-contact budget, bounded fallback, quotas, retry, cancellation, cache, deletion |
| Composition / CLI | Public behavior and wiring | No SMTP component in Passive Mode, Active Mode through scripted DNS and SMTP (`tests/unit/apps/test_local_active_mode.py`), CLI formats, auth, process limits, package smoke |
| Contract / inspection | Invariants examples cannot show | Forbidden SMTP verbs, dependency direction, reason-code/document sync, public field allowlists |

Add tests at the layer closest to an interface change, plus one composition-level regression test where safety depends on wiring. A test must fail on the unsafe behavior it guards; an assertion that only restates a mock's configured return value is not enough.

### Specification tests and structural tests

Contract and inspection tests read code or documents instead of running code, so a harmless refactor or rewording can fail them. Two registered pytest markers keep them apart from specification tests:

| Marker | Applies to | Typical failure after a harmless change |
| --- | --- | --- |
| `inspection` | Tests that read project source or its syntax tree | A function moved or was renamed; an import changed |
| `docs_contract` | Tests that read published documentation | A sentence or table in `docs/` or a README was reworded |

Everything else is a specification test, which exercises behavior through public functions, ports, fakes, or loopback fixtures.

```bash
make test-spec        # python -m pytest -m "not inspection and not docs_contract"
make test-structure   # python -m pytest -m "inspection or docs_contract"
make test             # both; CI runs the two groups as separate steps
```

Rules:

- Prefer a specification test. Write an inspection test only for a property no example can show: the absence of a code path (no `DATA`, no unverified TLS context), dependency direction, or a single construction point. Its docstring names the invariant it protects.
- Assert the property, not the spelling. Check imports, calls, or names in the syntax tree, not exact source lines.
- When a refactor fails a structural test, confirm that the invariant still holds and the specification tests pass, then update the inspection in the same change. Never delete or weaken a guard just to make the run green; a change that really removes the property is a real failure.
- Mark every new structural test. A module named `*_inspection.py` or `test_docs_*.py` carries the marker for the whole module; elsewhere, mark the individual test. `tests/test_test_taxonomy.py` fails when a test that reads source or documentation is unmarked, or when a per-test marker would move a specification test out of the specification run. Its `NOT_STRUCTURAL` list records, with reasons, the few tests the scan flags that are not structural, such as the SMTP-command scanner's own tests, which feed it synthetic source.

### Coverage by subsystem

#### Parsing, DNS, and classification

Cover valid, invalid, and unsupported address forms, IDNA domains, control-character injection, overlong input, and stable normalized identity. Unsupported syntax must never silently become `invalid`.

DNS fixtures cover:

- MX ordering, equal preference, multiple exchangers, and trailing-dot host names;
- Null MX, NXDOMAIN, missing MX with an eligible implicit A/AAAA route, and authoritative absence of a route;
- SERVFAIL, timeout, malformed or contradictory responses, and resolution failures of individual candidates;
- positive and negative TTLs, TTL zero, bounded cache entries, and coalescing of concurrent requests;
- mixed safe and unsafe resolved addresses, unexpected peers, and blocked fallback candidates.

Classification fixtures cover role-name normalization, disposable overrides, free-mail independence from MX providers, label-bounded provider matching, ambiguous providers, malformed metadata, missing datasets, and dataset fingerprint changes. Classification must never decide deliverability.

#### Evidence and verdicts

Check the published statuses, reason codes, confidence categories, and risk flags against the [status model](status-model.md), in particular:

- `invalid` requires target-specific, non-temporary hard-negative evidence;
- `likely_deliverable` requires a route and a qualifying acceptance with no stronger blocker;
- a bare SMTP `250` does not prove a mailbox exists, a bare `550` is not automatically recipient-not-found, and `252` is not an acceptance;
- evidence order and duplicates do not change the verdict;
- risk-only flags do not change the status, and a temporary condition does not become `invalid` when a retry budget runs out;
- errors in this service, its storage, or admission never appear as mailbox evidence;
- public output contains no raw SMTP text, secrets, internal exceptions, or uncalibrated probabilities.

A docs-contract test keeps the published reason-code table and the enum identical.

#### SMTP transport and dialogue

Use scripted SMTP peers and deliberately failing transports. Exercise `250`, `251`, `252`; temporary `450`–`452`; `550 5.1.1`; policy `550 5.7.1`; bare `550`; accept-all behavior; malformed multiline replies; oversized lines; slow banners; dropped connections; and interrupted writes.

Check the safety properties, not only the returned status:

1. Production code can build only the permitted encoded commands. No `DATA`, `AUTH`, `VRFY`, `EXPN`, or message body reaches the wire.
2. One ordinary verification touches at most one recipient in total, across fallback, retries, timeouts, and restarts. Inspect wire events, not only in-memory counters.
3. Fallback and retries happen only when recipient contact provably did not occur. A lost reply or partly written `RCPT TO` never leads to another recipient attempt.
4. STARTTLS and certificate and hostname verification follow the production policy. A TLS failure ends the session and never leads to plaintext or an `invalid` verdict.
5. Selected destinations and actually connected peers follow the same policy; unsafe, private, reserved, unapproved, or mismatched endpoints are refused.
6. Every connect, read, write, and whole probe is bounded, and cancellation releases connections and permits.
7. A cleanup error after the recipient reply does not overwrite the observation.

The exact recipient-contact rules are in the [SMTP state machine](smtp-state-machine.md) and [ADR 0019](adr/0019-operation-recipient-budget-and-atomic-job-identity.md).

#### Quotas, jobs, and caches

Test global admission, per-principal queue share, domain and MX pacing shared across accounts, per-account and per-key quotas, and cancellation. An exhausted budget refuses work before any network activity. Tokens and concurrency permits are released on failure, and exhausted destination state is never evicted to restore capacity.

Check idempotency under duplicate submissions and concurrent workers, including the gap between job creation and executor admission. A cache hit enqueues nothing and opens no SMTP connection. Cached verdicts are scoped by account, target, ruleset, sender identity, dataset fingerprint, and expiry, and DNS TTLs do not restart on a hit.

Retry tests use the recorded recipient-contact state, not status labels. Recovering interrupted work never replays a recipient that may have been touched.

#### Persistence, deletion, and privacy

Run several service instances against local stores to test races between replicas. Cover:

- account-owned writes and store fences checked within the same transaction;
- the durable account generation advanced before deletion, including a writer paused between admission and commit;
- mismatched store authorities, a missing account-state authority, and old schemas being refused;
- partial deletion failures reported and safely retried, never reported as complete;
- retention expiry, bounded scheduled sweeps, failure reporting, and removal of plaintext;
- no complete addresses, raw remote replies, credentials, or unstable exception text in routine output, logs, or metrics;
- addresses in local output only on explicit request, CSV formula escaping, and atomic output replacement on failure or cancellation.

Deletion tests show logical deletion only; they do not show forensic erasure of SQLite WAL files, backups, or snapshots ([privacy](privacy.md)).

#### CLI, local batch, and packaging

Test the legacy single-address form, `check` and `batch`, CSV and TXT parsing, row order, malformed rows, output formats, duplicate policies, `--start-row`, progress, exit codes, and input and quota limits. Confirm that the local path has no SMTP component and that `expand` uses neither DNS nor SMTP.

Candidate generation tests cover several wildcards, per-slot choices, deduplication, candidate-count overflow, Unicode restrictions, empty tokens, invalid later candidates, and unchanged output files after a failure. Installation smoke tests from source and wheel run outside the working tree ([releasing](releasing.md)).

## 3. Fixtures

Scripted SMTP scenarios cover `250`, `251`, `252`, `550 5.1.1`, policy `550 5.7.1`, bare `550`, temporary `450`/`451`/`452`, full mailboxes, accept-all behavior, delayed or malformed replies, disconnects mid-command, and STARTTLS success and failure. Each fixture records the commands sent and the number of connections, so safety tests can assert actual contact instead of inferring it from a status.

All fixtures are small, reproducible, and safe on a developer machine:

- DNS: table-driven fake answers with explicit TTLs and resolver failures.
- SMTP: a scripted reply sequence, recorded wire commands, and configurable partial writes, delays, and disconnects.
- Time: fake wall and monotonic clocks and a fake sleeper. Never assert retry or pacing behavior with real sleeps.
- Storage: isolated temporary SQLite files, and several instances when testing concurrency. No shared global state between tests.
- TLS: loopback test certificates and throwaway public fixture keys, never reused as deployment credentials.
- Classification: local, explicitly versioned test data; never fetch provider lists during a test.

No CI fixture sends a probe to someone else's mailbox.

## 4. Invariants

- An automated test that attempts third-party network access fails.
- Neither risk-only classification nor non-target evidence creates a decisive mailbox verdict.
- Evidence aggregation is deterministic and independent of input order and duplicates.
- A normal verification makes at most one recipient contact across all sessions and retries.
- Forbidden SMTP verbs never reach the wire, and every network operation and queue is bounded.
- Destination and peer checks run before probing, and pacing is acquired before connecting.
- No full address appears in routine logs or rate-limit keys, and stale writes cannot undo a deletion.
- Retry exhaustion, cancellation, or a service failure never creates an `invalid` verdict.

## 5. Evaluation beyond unit tests

In a separately authorized study, measure hard-invalid precision, unknown and temporary rates, consistency of recipient responses, policy blocks, and timeouts by evidence class, and track latency, outbound connections per request, cache reuse, and resource bounds. Do not advertise a calibrated deliverability probability or an accuracy guarantee without representative ground truth and a documented study.

## Review checklist

A change is ready for review when:

- [ ] The behavior and its failure cases have regression tests.
- [ ] `make check` passes, or each failure is documented with its cause.
- [ ] The offline network guard is still enabled.
- [ ] The SMTP recipient-touch, command, TLS, and destination restrictions are intact.
- [ ] Changed timeouts, admission, quotas, and cancellation have explicit tests.
- [ ] Public output and logs reveal no additional personal or secret data.
- [ ] Documentation and stable output vocabulary are updated when behavior changes.
- [ ] No real external probing stands in for deterministic tests.
