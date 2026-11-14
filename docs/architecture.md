# Architecture

EmailAddressChecker separates address interpretation, mail-routing evidence, and optional SMTP probing. Its central rule is to **report only what the available evidence supports**: a working MX record or an SMTP acceptance does not prove that a mailbox exists.

This page describes the current component boundaries and runtime behavior. For the precise contracts, see [requirements](requirements.md), [status model](status-model.md), [SMTP state machine](smtp-state-machine.md), [threat model](threat-model.md), and [architecture decisions](adr/).

## Runtime modes

| Mode | Entry point | Network activity | Availability |
| --- | --- | --- | --- |
| Passive single-address check | `emailcheck ADDRESS` or `emailcheck check ADDRESS...` | DNS only; no SMTP | Available |
| Passive file processing | `emailcheck batch FILE` | DNS only; no SMTP | Available |
| Candidate expansion | `emailcheck expand PATTERN` | None | Available |
| Active check | Separately configured service; legacy CLI `--remote` client | Controlled SMTP | Operator-gated |
| Active batch service | Internal `BatchService` | Controlled SMTP through ordinary jobs | Implemented, not wired to public CLI/API |

The active path requires authentication, explicit authorization, destination controls, TLS, pacing, and an operator-approved deployment. The default local stack has **no SMTP component**, rather than a disabled SMTP component reachable through a flag. See [readiness](readiness-checklist.md) and [operations](operations.md).

## 1. Dependency direction

```text
apps/ (CLI and transport-neutral API handlers)
  -> application/ (verification, jobs, scheduling, aggregation)
      -> domain/ (validated values and decisions)
      -> ports/ (interfaces for I/O and nondeterminism)
  -> composition.py (constructs the dependency graph)
      -> adapters/ (DNS, SMTP, HTTP, storage, clock, etc.)

classification/   passive datasets and provider metadata
security/         destination validation, identifiers, redaction
settings.py       validated budget configuration
```

`domain/` and `ports/` must not import `application/`, `apps/`, `adapters/`, or `composition`. `composition.py` assembles concrete dependencies once per deployment; it must not recreate limiters, quota stores, or administrative state for each request. Public wire contracts shared across layers live in `ports/public_contract.py`, while application modules project internal results into those contracts.

The key design boundaries are:

- **Domain:** address types, SMTP commands and session transitions, evidence, verdicts, and rate-limit values. No network or storage I/O.
- **Ports:** DNS, transport, storage, scheduling, authentication, clocks, and randomness; these are replaceable in tests.
- **Adapters:** actual system and network access, including DNS and SMTP. They return bounded, typed outcomes rather than raw library exceptions.
- **Application:** orchestration and policy enforcement. No transport-specific API framework or alternate verdict calculator.
- **Apps:** CLI parsing, request validation, and serialization. `apps/api.py` is a transport-neutral handler, not a bundled public HTTP server.

## 2. Core concepts

Ports exist for DNS, storage, cache, pacing, authentication, time, sleeping, and randomness. Implementations can be replaced with test doubles without changing domain decisions. No component below `apps/` should import an HTTP framework.

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

`domain/address.py` accepts raw input, validates the supported grammar, and produces a `NormalizedAddress` or a structured rejection. Unsupported forms, including SMTPUTF8 local parts, are distinguished from invalid syntax. Downstream DNS and SMTP interfaces accept validated address values, not arbitrary input strings.

DNS produces a `MailRoute`, not a mailbox verdict. Its important distinctions are:

| DNS finding | Meaning for the final verdict |
| --- | --- |
| Authoritative NXDOMAIN, Null MX, or authoritative absence of any mail route | Can support `invalid` |
| DNS timeout, SERVFAIL, or transient failure | Can support `temporary_unknown` |
| Malformed or inconsistent configuration, blocked destination, or internal failure | Does not establish recipient invalidity |
| Usable MX, or eligible implicit A/AAAA route | Shows a mail route, not a mailbox |

MX candidates retain ordering and individually validated addresses. A candidate's resolved address is checked against the destination policy before use; the selected destination and the connected peer are checked again for active SMTP. See [threat model](threat-model.md).

### Passive classification

Classification produces risk signals or provider metadata, **not** deliverability statuses. Role-account detection uses the local part; disposable and free-mail checks use the destination domain; provider identification uses MX hostnames and label-aware matching.

Datasets are loaded from versioned local resources, never downloaded on startup. Only the authored role list is currently populated; disposable-domain, free-mail, and provider datasets are empty until redistributable sources are approved. Missing data is not evidence that an address is safe or deliverable. See [dataset policy](data-sources.md) and [shipped datasets](../src/emailcheck/data/passive/README.md).

### Verdicts

`application/aggregate.py` is the sole implementation of final status selection. It uses structured, target-specific evidence and deterministic precedence, not a sum of scores or a count of observations.

- `invalid` requires a permitted hard-negative reason that is target-specific and non-temporary.
- `likely_deliverable` requires an eligible mail route, qualifying recipient acceptance, and no stronger blocking evidence. It never means mailbox existence is proven.
- Temporary and ambiguous evidence remain `temporary_unknown` or `unknown`; operational refusal does not become a deliverability verdict.
- Confidence is categorical, not a calibrated probability. Risk flags are independent of status.

Input order and repeated observations must not alter the result. Public output uses an explicit field allowlist; raw diagnostics and protocol transcripts are not exposed. See [status model](status-model.md).

## 3. Package layout

The codebase follows the boundaries introduced in section 1: `domain/` contains validated value types, `ports/` defines external interfaces, `adapters/` implements I/O, `application/` coordinates decisions, and `apps/` exposes the CLI and request handlers. The `classification/` and `security/` packages own their respective policies. `composition.py` wires concrete implementations together. Interfaces for clocks, sleep, and randomness support deterministic testing.

## 4. Active workflow

The active workflow is deliberately narrow:

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

The exact allowed SMTP command vocabulary is `EHLO`, `STARTTLS`, `MAIL FROM`, `RCPT TO`, `RSET`, and `QUIT`. There is no `DATA`, `AUTH`, `VRFY`, `EXPN`, message content, or provider-specific account-enumeration method. `domain/smtp_wire.py` constructs bounded commands; `domain/smtp_session.py` limits state transitions; `application/smtp_dialogue.py` runs the protocol; and `adapters/smtp/asyncio_transport.py` handles I/O without deciding verdicts.

Safety constraints apply at both session and verification level:

1. **At most one recipient touch per ordinary verification operation**, including across multiple MX candidates, retries, and restarts. Reaching the RCPT stage ends MX fallback, even when the reply is lost or the write fails partway through.
2. Only failures **provably before** recipient contact may permit an alternative exchanger or a bounded job retry. A temporary result is not itself permission to retry.
3. Active production composition requires TLS and certificate/hostname verification. A STARTTLS or handshake failure does not fall back to plaintext and never proves recipient invalidity.
4. The resolved destination, approved selected IP, and actual peer must agree with policy. Unsafe/private/reserved destinations, unexpected peers, and disallowed candidates are rejected.
5. Every connection, read, write, queue wait, and whole verification has a bound. Cancellation propagates and connections are closed.
6. Operator-configured sender identity and trust settings cannot be supplied by an address being checked or an untrusted API request.

A reply such as bare `250`, `252`, or `550` is interpreted in context of its stage and enhanced code. SMTP evidence mapping does not directly assign final statuses. See [SMTP state machine](smtp-state-machine.md), [status model](status-model.md), and [ADR 0019](adr/0019-operation-recipient-budget-and-atomic-job-identity.md).

### Admission, quotas, and concurrency

Three controls serve different purposes:

| Control | Purpose |
| --- | --- |
| Admission | Bounds running work, queue depth, and per-principal share |
| Destination pacing | Bounds global, recipient-domain, and MX-host concurrency and token budgets |
| Abuse guard / quota | Bounds what an authenticated caller may request |

Destination pacing is shared across accounts within a worker. Keys must not contain full email addresses. Acquiring only some budgets is never sufficient to start a probe, and failed acquisition must release any held capacity. Operational refusals produce no mailbox verdict.

The shipped limiter and quota stores are **process-scoped**. Deployments use one worker process; independent processes or replicas are not covered by a global pacing/quota guarantee. Adding distributed execution requires a shared atomic limiter, admission coordination, and consistent kill switches. See [operations](operations.md) and [ADR 0020](adr/0020-local-batch-and-release.md).

### Jobs, caching, and persistence

Active checks use asynchronous jobs: an API request is admitted and receives job state without blocking an API worker for an SMTP dialogue. Idempotency binds a caller, normalized target, and submitted key; retry behavior is constrained by recipient-contact history. A cache hit must not enqueue a new probe.

Verdict caches are scoped by account, normalized target, sender identity, ruleset, dataset fingerprint, and expiry. DNS caching is separately bounded by record type and TTL; it does not make recipient observations public across accounts. Cached results never override the conservative status rules.

Local `check` and `batch` reuse the passive verification service, preserve input order, and bound concurrent work and memory. Local batch has no job database or persistent checkpoint. `--start-row` begins a **new** passive run; it does not resume a previous job. Offline expansion produces candidates under a bounded product and does not call DNS or SMTP.

The internal active batch subsystem builds on ordinary authorized jobs, rather than implementing a second SMTP pathway. Its durable state, ownership, fairness, and recovery mechanisms are described in [ADR 0018](adr/0018-controlled-batch-execution.md). **It is not currently composed into the public CLI or API.**

## 5. Failure isolation

The passive API must remain usable when active probing is disabled, the active worker is unavailable, SMTP port 25 is blocked, an individual exchanger stalls, or an optional service dependency fails. An active quota/store failure must fail closed for active requests without becoming a claim about an address. Active workers may reach only DNS and approved SMTP destinations, not unrelated internal services; deployment-level egress controls are a second boundary behind the in-process destination checks.

## 6. Idempotency

An active request binds the authenticated account, idempotency key, and HMAC of the normalized target. A repeated request within the applicable cache/idempotency window returns its existing job or result instead of scheduling another probe; reusing a key with a different target is a conflict. Explicit authorized refresh still requires ordinary admission and quota. The bound is enforced in persistent storage where configured, including concurrent submissions or worker restarts. See [ADR 0014](adr/0014-bounded-asynchronous-active-jobs.md) and [ADR 0019](adr/0019-operation-recipient-budget-and-atomic-job-identity.md).

## Privacy and account deletion

Normal logs, metrics, and public results do not expose complete target addresses. HMAC identifiers support correlation without retaining raw identifiers in routine log records. Local result files omit addresses by default; `--include-address` is an explicit opt-in.

For persistent service state, deletion advances a durable account generation before deleting records. Every account-owned store binds to one account-state authority and fences writes against its local copy of that generation **inside the same transaction as the write**. This prevents in-flight work, including work on another replica, from recreating records after deletion.

Deletion attempts each composed store independently; a partial failure is reported rather than falsely marked complete. There is no cross-store transaction, and logical deletion does not erase backups or historical SQLite journal content. The active batch store participates in deletion only if an operator explicitly composes it with the same authority. See [privacy](privacy.md).

## 7. Future scale

Adding replicas requires more than spawning workers: globally shared, atomic destination pacing, quotas, queue ownership, kill switches, and crash fencing must replace the current process-local controls. Any additional sender identities would require fixed, accountable partitions and shared destination limits, never identity rotation to bypass remote restrictions. The semantic core, recipient-contact bound, and conservative aggregation cannot change with scale.

## Deployment boundary

Active probing is **off by default**. Approval is per deployment and requires an authorized target scope, configured sender identity, destination controls, authentication, TLS, tested kill switch and rate limits, appropriate network egress, monitoring, and incident ownership. `emailcheck --check-deployment` is informational; it neither tests external connectivity nor grants approval.

A future web/ASGI binding must establish trustworthy client-IP provenance, enforce request-body size limits while reading input, apply an explicit proxy trust policy, and construct a single `Deployment` at startup. No publicly writable administrative or account-deletion interface is provided by these application handlers.

Refer to the [readiness checklist](readiness-checklist.md), [operations guide](operations.md), and [runbooks](runbooks/) before any approved active deployment.

## Related documents

- [Requirements](requirements.md) — scope and behavior.
- [Status model](status-model.md) — evidence and verdict semantics.
- [SMTP state machine](smtp-state-machine.md) — permitted protocol transitions.
- [Threat model](threat-model.md) — abuse, destination, and privacy risks.
- [Privacy](privacy.md) — retention and deletion guarantees.
- [Test strategy](test-strategy.md) — regression tests and invariants.
- [ADRs](adr/) — detailed design decisions and trade-offs.
