# Architecture

EmailAddressChecker keeps three things apart: interpreting an address, collecting mail-routing evidence, and optional SMTP probing. It reports only what the evidence supports. A working MX record or an SMTP acceptance does not prove that a mailbox exists.

This page describes the component boundaries and runtime behavior. The precise rules are in the documents listed under [Related documents](#related-documents).

## Runtime modes

| Mode | Entry point | Network activity | Availability |
| --- | --- | --- | --- |
| Passive single-address check | `emailcheck ADDRESS` or `emailcheck check ADDRESS...` | DNS only; no SMTP | Available |
| Passive file processing | `emailcheck batch FILE` | DNS only; no SMTP | Available |
| Candidate expansion | `emailcheck expand PATTERN` | None | Available |
| Active check | A separately configured service; the legacy CLI `--remote` client | Controlled SMTP | Operator-gated |

The active path requires authentication, explicit authorization, destination controls, TLS, pacing, and a deployment the operator has approved. The default local stack contains no SMTP component at all, so there is no flag that could turn one on. See [readiness](readiness-checklist.md) and [operations](operations.md).

### Component reachability

Much of the code is service infrastructure that the installed `emailcheck` command does not use. It is tested and composed only through the library, because each piece is a prerequisite for a public service that 0.1.0 does not ship. This table is the authoritative list.

| Component | Code | Installed `emailcheck` command | Library (`build_verification_stack`) |
| --- | --- | --- | --- |
| Passive verification: syntax, DNS, classification, aggregation | `domain/`, `application/verification.py`, `adapters/dns/` | Used by `check`, `batch`, legacy `ADDRESS` | Always composed |
| API-key authentication | `adapters/auth/api_keys.py` | Internal only: one random per-process key accounts local quota; no key management | Composed from `Deployment.api_keys` |
| Admission, pacing, quotas, abuse guard, admin switches | `application/admission.py`, `adapters/system/`, `application/abuse.py`, `application/admin.py` | In-process passive quota and budgets | Composed |
| Version and readiness reports | `application/readiness.py` | `--report-versions`, `--check-deployment` | Callable |
| Remote active-check client | `adapters/http/urllib_client.py` | Legacy `--remote` client; needs a server this project does not ship | — |
| HTTP request handler and schema | `apps/api.py`, `apps/schema.py` | Not reachable; no HTTP server is bundled | A plain function, `handle`, with no transport binding |
| Active SMTP | `application/smtp_*.py`, `adapters/smtp/` | Not reachable: the local stack contains no SMTP object | Only with `active_probing=True` and a sender identity, in the lab-active or service-active profile |
| Job service and executor | `application/jobs.py`, `adapters/execution/` | Not reachable: the local-passive profile accepts no job | Only in the lab-active or service-active profile |
| Persistent verdict cache, job and account-state stores | `adapters/storage/sqlite_store.py`, `adapters/storage/sqlite_job_store.py`, `adapters/storage/sqlite_account_state.py`, `application/verdict_cache.py` | Not reachable: the local stack persists nothing | Only when the corresponding store path is configured |
| Retention and account deletion | `application/retention.py`, `application/account_deletion.py` | Not reachable | Services always composed over whatever stores exist; the background retention scheduler only in the lab-active or service-active profile |
| Active batch | `application/batch.py`, `adapters/storage/sqlite_batch_store.py` | Not reachable | Not composed; an operator constructs `BatchService` (see [Active batch](#active-batch)) |
| Accept-all experiment | `application/accept_all.py` | Not reachable | Not composed; operator-run (see [Accept-all experiment](#accept-all-experiment)) |
| Limited-beta harness | `application/beta.py` | Not reachable | Not composed; operator-run measurement tooling |

No public service surface is scheduled for 0.1.0, and configuration alone never makes anything in this table reachable from the command line. The order and conditions for connecting these components are in [ROADMAP.md](../ROADMAP.md); until a step is done, its rows above stay "not reachable".

## 1. Dependency direction

```text
apps/ (CLI and transport-neutral API handlers)
  -> application/ (verification, jobs, scheduling, aggregation)
      -> domain/ (validated values and decisions)
      -> ports/ (interfaces for I/O and nondeterminism)
  -> composition.py (constructs the dependency graph)
      -> adapters/ (DNS, SMTP, HTTP, storage, clock, etc.)
```

- `domain/` and `ports/` do not import `application/`, `apps/`, `adapters/`, or `composition`.
- No component below `apps/` imports an HTTP framework.
- `composition.py` assembles the concrete dependencies once per deployment. It must not recreate limiters, quota stores, or administrative state for each request.
- Public wire formats shared across layers live in `ports/public_contract.py`; application modules project internal results into them.
- DNS, storage, cache, pacing, authentication, time, sleeping, and randomness are ports, so tests can replace them without changing any domain decision.

## 2. Core concepts

### Verification flow

```text
Input address
  -> parse and normalize
  -> syntax evidence, or rejection without network I/O
  -> DNS/MX route and passive classification
  -> evidence aggregation -> conservative result             (passive)
  -> optional authorized job -> SMTP observation -> aggregation (active)
```

### Addresses and DNS

`domain/address.py` validates raw input against the supported grammar and returns a `NormalizedAddress` or a structured rejection. Unsupported forms, such as SMTPUTF8 local parts, are kept distinct from invalid syntax. DNS and SMTP interfaces accept only validated address values, never arbitrary strings.

DNS produces a `MailRoute`, not a mailbox verdict:

| DNS finding | Effect on the final verdict |
| --- | --- |
| Authoritative NXDOMAIN, Null MX, or authoritative absence of any mail route | Can support `invalid` |
| DNS timeout, SERVFAIL, or another transient failure | Can support `temporary_unknown` |
| Malformed or inconsistent configuration, blocked destination, or internal failure | Never shows that the recipient is invalid |
| Usable MX, or an eligible implicit A/AAAA route | Shows a mail route, not a mailbox |

MX candidates keep their order and their individually validated addresses. Each resolved address is checked against the destination policy before use, and for active SMTP the selected destination and the connected peer are checked again. See the [threat model](threat-model.md).

### Passive classification

Classification produces risk signals and provider metadata, never deliverability statuses. Role-account detection looks at the local part, disposable and free-mail checks at the domain, and provider identification at MX hostnames with label-aware matching.

Datasets are versioned local resources and are never downloaded at startup. Only the authored role list has data. The disposable-domain, free-mail, and provider datasets stay empty until redistributable sources are approved, and missing data is not evidence that an address is safe or deliverable. See the [dataset policy](data-sources.md) and the [shipped datasets](../src/emailcheck/data/passive/README.md).

### Verdicts

`application/aggregate.py` is the only place that selects a final status. It applies a fixed precedence to structured, target-specific evidence; it does not add up scores or count observations.

- `invalid` requires a permitted hard-negative reason that is specific to the target and not temporary.
- `likely_deliverable` requires an eligible mail route, a qualifying recipient acceptance, and no stronger blocking evidence. It never means that the mailbox is proven to exist.
- Temporary and ambiguous evidence stays `temporary_unknown` or `unknown`. An operational refusal never becomes a deliverability verdict.
- Confidence is a category, not a calibrated probability. Risk flags do not affect the status.

The order of the input and repeated observations do not change the result. Public output uses an explicit field allowlist and never exposes raw diagnostics or protocol transcripts. `Verdict` requires its primary reason to lead the ordered reason-code list, so a mismatched primary reason cannot be constructed. See the [status model](status-model.md).

## 3. Package layout

The project is written in Python only. `composition.py` is the only module in `src/` that names a concrete adapter, and `build_verification_stack` takes no parameter for a clock, sleeper, limiter, transport, or TLS trust anchor. A local-passive deployment gets a stack with no SMTP service object at all.

| Package | Holds |
| --- | --- |
| `domain/` | Address types, SMTP commands and session transitions, evidence, verdicts, rate-limit values. No network or storage I/O. |
| `ports/` | Interfaces for DNS, transport, storage, scheduling, authentication, clocks, and randomness. |
| `adapters/` | Real system and network access, including DNS and SMTP. Adapters return bounded, typed outcomes instead of raw library exceptions. |
| `application/` | Orchestration and policy enforcement. No transport framework and no second verdict calculator. |
| `apps/` | CLI parsing, request validation, and serialization. `apps/api.py` is a transport-neutral handler, not a bundled HTTP server. |
| `classification/` | Passive datasets and provider metadata. |
| `security/` | Destination validation, identifiers, and redaction. |
| `settings.py` | Validated budget configuration. |
| `composition.py` | Wires the concrete implementations together. |

## 4. Active workflow

```text
Authorized request
  -> admission and caller quota
  -> bounded, ordered MX attempt plan
  -> destination pacing (recipient domain and MX host)
  -> approve resolved destination
  -> connect on port 25; verify actual peer
  -> SMTP greeting, EHLO, STARTTLS, EHLO, MAIL FROM, one RCPT TO
  -> bounded cleanup and normalized evidence
  -> final verdict or explicitly permitted job retry
```

The only SMTP commands are `EHLO`, `STARTTLS`, `MAIL FROM`, `RCPT TO`, `RSET`, and `QUIT`. There is no `DATA`, `AUTH`, `VRFY`, `EXPN`, message content, or provider-specific account enumeration. `domain/smtp_wire.py` builds bounded commands, `domain/smtp_session.py` limits state transitions, `application/smtp_dialogue.py` runs the protocol, and `adapters/smtp/asyncio_transport.py` does the I/O without deciding verdicts.

Safety rules for the session and the whole verification:

1. An ordinary verification touches at most one recipient, across all MX candidates, retries, and restarts. Reaching the `RCPT` stage ends MX fallback, even when the reply is lost or the write fails partway.
2. Only a failure that provably happened before recipient contact may allow another exchanger or a bounded job retry. A temporary result alone is not permission to retry.
3. Active production composition requires TLS with certificate and hostname verification. A STARTTLS or handshake failure never falls back to plaintext and never proves that a recipient is invalid.
4. The resolved destination, the approved selected IP, and the actual peer must all satisfy the policy. Unsafe, private, or reserved destinations, unexpected peers, and disallowed candidates are rejected.
5. Every connection, read, write, queue wait, and whole verification has a bound. Cancellation propagates and connections are closed.
6. Neither an address being checked nor an untrusted API request can supply the sender identity or trust settings; the operator configures them.

A reply such as a bare `250`, `252`, or `550` is read in the context of its stage and enhanced status code, and SMTP evidence mapping never assigns a final status directly. See the [SMTP state machine](smtp-state-machine.md), the [status model](status-model.md), and [ADR 0019](adr/0019-operation-recipient-budget-and-atomic-job-identity.md).

### Admission, quotas, and concurrency

| Control | Bounds |
| --- | --- |
| Admission | Running work, queue depth, and each principal's share |
| Destination pacing | Global, recipient-domain, and MX-host concurrency and token budgets |
| Abuse guard and quota | What an authenticated caller may request |

Destination pacing is shared across accounts within a worker, and its keys never contain full email addresses. Pacing uses global, per-domain, and per-MX concurrency limits and token buckets; a domain's settings apply to its MX hosts too. A probe starts only after every budget is acquired, within a single wait deadline on a monotonic clock, and a failed acquisition releases whatever it held. Spent bucket state is never evicted to restore capacity. Running out of wait raises `RateLimitTimeout`, which is not a `TimeoutError` and produces no SMTP evidence, because nothing was observed. Operational refusals produce no mailbox verdict, and a temporary reply defers later work for that destination without replaying the recipient that was already touched.

A verification's worst case is one rate-limit wait plus one session budget per MX candidate, because a deadline that runs out before the recipient stage is a pre-recipient failure and the next candidate gets a fresh budget and a fresh wait:

```text
configured upper bound = max_attempts × (wait_budget_seconds + session budget)

defaults : 3 × ( 10 s +  30 s) =  120 s
ceiling  : 8 × (120 s + 120 s) = 1920 s = 32 minutes
```

Each value is validated on its own, but their product has no separate bound, and the ceiling is a legal configuration. Local processing and cleanup run inside these budgets, so this is a configured bound, not a measurement.

The shipped limiter and quota stores belong to one process. Deployments run one worker process, and separate processes or replicas get no global pacing or quota guarantee. Distributed execution would need a shared atomic limiter, admission coordination, and consistent kill switches. See [operations](operations.md).

Limiter memory is bounded by the idle-entry cap plus the entries held by in-flight callers, and admission control must bound those callers. The limiter TTL applies to idle entries only and is not required to exceed the longest SMTP session.

### Requests and refusals

- A `Principal` comes only from the authenticator; no handler builds one from a request field, and there is no anonymous principal. Per-principal concurrency is a separate admission gate, so the destination buckets stay keyed by destination.
- The request schema is closed. An unknown key is refused, so no MX, sender, TLS, CA, retry, cache, or catch-all override can be passed.
- Admission bounds both running and waiting work; a request that finds the queue full is refused at once.
- A total deadline covers admission and verification. When it expires the request is refused; no partial verdict is returned, because a caller could not tell "the server was opaque" from "we ran out of time". `VerificationRefused` is neither a `TimeoutError` nor an `OSError`.
- Refusals use service-level response codes and carry no status.

### Jobs, caching, and persistence

Active checks run as asynchronous jobs: an API request is admitted and gets the job state back, so no API worker waits on an SMTP dialogue. Idempotency binds the caller, the normalized target, and the submitted key, and retries are limited by the recipient-contact history. A cache hit must not enqueue a new probe.

- Job states are `pending`, `running`, `retry_scheduled`, `completed`, `failed`, and `cancelled`. Transitions follow a closed table that is checked at run time, and the last three states are terminal.
- A job identifier is `secrets.token_urlsafe(32)`, carries no information, and can never contain `@`. Every job belongs to an authenticated principal, and another account's job answers exactly like an unknown one: `404`.
- `DELETE /v1/checks/{id}` cancels a job and is idempotent; cancellation reaches the SMTP dialogue and releases the permit, the lease, and the socket. A client disconnecting does not cancel an accepted job.
- The executor is a port. `InMemoryJobExecutor` has a fixed set of workers and a bounded queue that refuses when full, and it is not a service-active worker. An executor that refuses a job leaves no non-terminal job behind.

Verdict caches are scoped by account, normalized target, sender identity, ruleset, dataset fingerprint, and expiry; every key component is an HMAC under the operator's correlation key. Only an active verification's verdict is cached. It lives no longer than the shortest TTL among its decision-relevant reasons (all reason codes except the four risk-only ones), using the DNS TTL for DNS reasons and the `docs/requirements.md` section 13 table for SMTP reasons. Any other reason, `internal_error`, and a DNS TTL of zero make the verdict uncacheable. Expiry is part of the lookup, and there is no refresh field. A stored verdict holds digests and published vocabulary only. A cached result never overrides the conservative status rules.

The DNS cache is bounded separately by record type and TTL and does not share recipient observations across accounts. Concurrent lookups for the same key reach the resolver once; lookups for different keys never wait on each other.

Local `check` and `batch` reuse the passive verification service, keep the input order, and bound concurrent work and memory. Local batch has no job database or checkpoint, and `--start-row` begins a new passive run rather than resuming an old one. Offline expansion produces a bounded number of candidates and calls neither DNS nor SMTP.

### Active batch

Active batch is library-only and runs ordinary authorized jobs, never a second SMTP path.

- It runs only when the feature is enabled and an operator has approved the account; authentication alone is not approval. Both checks happen before the file is read.
- CSV input has byte and row limits checked before decoding and accepts one leading UTF-8 byte order mark. It follows the same reading rules as the local CLI: a strict CSV reader, exactly one `email` column and no repeated column names (`address_column_index`), blank lines skipped, a row whose field count differs from the header rejected, an empty address cell rejected as empty input, a NUL anywhere refusing the file, and surrounding ASCII whitespace trimmed exactly as the address parser trims it. Each cell goes through the ordinary address parser. A malformed or unparseable row is reported as `rejected`, never `invalid`, and the rest of the file proceeds.
- Duplicates are detected by HMAC. Bounded workers rotate fairly across exchangers and then domains, using exchangers learned from the ordinary pipeline.
- Every row ends in an explicit state, and the report balances against the file. Report cells are escaped against spreadsheet formulas, and no raw SMTP reply can appear in a row.
- Row state is persisted. A row is claimed before its job is submitted, so a restart presents the same idempotency handle and never starts a second verification.
- Results expire, belong to one principal, and are checked for ownership at three independent points.
- The submitted text is the only plaintext kept, and only so an unsubmitted row can still be submitted after a restart. It is cleared when the row reaches a terminal state and after `input_retention_seconds`, capped at 24 hours; a row whose input expired is recorded as refused.
- The owner can delete a batch, which removes its rows, retained plaintext, and result but no child job. Another account's delete removes nothing and does not reveal whether the batch exists.

### Accept-all experiment

The accept-all experiment is library-only operator tooling. It is a separate verification against a non-dictionary random local part, never a second `RCPT TO` in an ordinary verification. Five gates, all closed by default, must be opened; enabling it does not authorize it. It has its own domain budget, far below the ordinary one. Only decided answers are cached, for seven days, and the only thing published is the `accept_all_suspected` risk flag; aggregation is unchanged.

## 5. Failure isolation

The passive API must keep working when active probing is disabled, the active worker is down, port 25 is blocked, an exchanger stalls, or an optional service dependency fails. A failure of the active quota or store fails closed for active requests and is never reported as a fact about an address. Active workers may reach only DNS and approved SMTP destinations, not unrelated internal services; egress controls in the deployment are a second boundary behind the in-process destination checks.

## 6. Idempotency

An active request binds the authenticated account, the idempotency key, and the HMAC of the normalized target. Repeating it within the cache or idempotency window returns the existing job or result instead of scheduling another probe, and reusing a key with a different target is a conflict. An explicit, authorized refresh still goes through ordinary admission and quota. Where persistent storage is configured, the bound holds across concurrent submissions and worker restarts. See [ADR 0019](adr/0019-operation-recipient-budget-and-atomic-job-identity.md).

`JobService.submit` runs in this order:

```text
passive check -> idempotency -> cache -> enqueue
```

The passive check comes first because it produces the normalized target and the current evidence. Returning an existing job or a cached result therefore still costs passive work and caller quota; what it avoids is a new recipient contact.

## Privacy and account deletion

Normal logs, metrics, and public results never contain complete target addresses. HMAC identifiers allow correlation without keeping raw identifiers in routine logs. Local result files leave out addresses unless `--include-address` is given.

For persistent service state, deletion first advances a durable account generation and then deletes records. Every account-owned store binds to one account-state authority and checks each write against its copy of that generation inside the same transaction as the write. In-flight work, including work on another replica, therefore cannot recreate records after a deletion.

Deletion handles each composed store independently and reports a partial failure instead of marking it complete. There is no cross-store transaction, and logical deletion does not erase backups or old SQLite journal content. The active batch store takes part in deletion only if an operator composes it with the same authority. See [privacy](privacy.md).

## 7. Future scale

Adding replicas takes more than starting workers: globally shared, atomic destination pacing, quotas, queue ownership, kill switches, and crash fencing must replace the current per-process controls. Extra sender identities would need fixed, accountable partitions and shared destination limits, never rotation to get around remote restrictions. The semantic core, the recipient-contact bound, and conservative aggregation do not change with scale.

## Deployment boundary

Active probing is off by default. Approval is per deployment and requires an authorized target scope, a configured sender identity, destination controls, authentication, TLS, a tested kill switch and rate limits, suitable network egress, monitoring, and an incident owner. `emailcheck --check-deployment` only reports; it neither tests external connectivity nor grants approval. These application handlers provide no publicly writable administrative or account-deletion interface.

#### Stop conditions on the ASGI binding

These are requirements for a future transport binding; no HTTP server ships today. All seven must hold before these handlers are exposed:

- **trusted client IP provenance.** The reviewed transport binding is the only
  thing that may construct a `SourceIdentity` from an authenticated connection's
  network provenance; callers cannot submit their own trusted identity.
- **proxy header policy.** Trust `X-Forwarded-For` only from an operator-configured
  list of proxies. Untrusted forwarded headers must not select a source budget.
- **request body size.** Input needs a bound before it is parsed. The request body
  limit must be enforced while the body is read, not only after the complete
  upload has been buffered; this also applies to any future CSV upload.
- **request logging redaction.** Use `security/redaction.py` rather than a second
  implementation. Request bodies and authorization headers must not be logged.
- **one `Deployment` per process, built at startup**, not per request. Startup
  validation and shared controls must cover every request the process handles.
- **no request-local limiter, quota store, or admin state.** Counters and kill
  switches must be the same objects across requests.
- **the administrative interface is not mounted on the public application.**
  Deletion, suspension, and kill switches stay operator-only.

### Before an active deployment

Read the [readiness checklist](readiness-checklist.md), the [operations guide](operations.md), and the [runbooks](runbooks/).

## Related documents

| Document | Covers |
| --- | --- |
| [Requirements](requirements.md) | Scope and behavior |
| [Status model](status-model.md) | Evidence and verdict meanings |
| [SMTP state machine](smtp-state-machine.md) | Permitted protocol transitions |
| [Threat model](threat-model.md) | Abuse, destination, and privacy risks |
| [Privacy](privacy.md) | Retention and deletion guarantees |
| [Test strategy](test-strategy.md) | Regression tests and invariants |
| [ADRs](adr/) | Design decisions and trade-offs |
