# ADR 0014: Bounded asynchronous active jobs

- Status: Accepted
- Date: 2026-08-10
- Phase: 6

## Context

`docs/requirements.md` section 5 lists "asynchronous active API" and "remote
active CLI" under MVP *Included*. Section 11 says `POST /v1/checks` "creates an
asynchronous job", supports idempotency, "returns passive evidence immediately
when available", and that `GET /v1/checks/{id}` "returns job state and result".
`prompts/06-api-cli.md` fixes the state enum, the idempotency key, a bounded
retry decision, cancellation, cache lookup before enqueue, and — explicitly —
**no synchronous waiting for active SMTP in API workers**.

The first Phase 6 build made `POST /v1/checks` await the SMTP pipeline and
return a verdict. That is the behaviour the prompt names and forbids.

## Decision: the state enum is the repository's, verbatim

`pending`, `running`, `retry_scheduled`, `completed`, `failed`, `cancelled`.

Not `queued`, not `succeeded`, not `in_progress`. `prompts/06-api-cli.md` wrote
these six, `retry_scheduled` exists because `docs/requirements.md` section 14
allows one automatic retry, and renaming a published state to a more familiar
word would be new API vocabulary invented to match a convention nobody asked
for.

## Decision: the transition table is closed and enforced at run time

| From | To |
|---|---|
| `pending` | `running`, `cancelled` |
| `running` | `completed`, `failed`, `retry_scheduled`, `cancelled` |
| `retry_scheduled` | `running`, `cancelled` |
| `completed`, `failed`, `cancelled` | — terminal |

`pending → completed` is refused: a job that never ran cannot have a result. A
terminal state has no exit, so `cancelled → completed` and `completed →
running` are unreachable rather than merely unused. The table is data, checked
by `CheckJob.transition_to`, and a forbidden move raises rather than being
silently ignored — the precedent `domain/smtp_session.py` set for its own state
table.

## Decision: job identifiers are unguessable, and carry nothing

`secrets.token_urlsafe(32)`. Not an incrementing integer, not a timestamp, not
a hash of the target, not UUID1 — each of those either enumerates other
callers' jobs or leaks what was asked about. `JobId` validates the shape at run
time: URL-safe characters only, a minimum length, and no `@`, so an identifier
can never be a mailbox even by construction accident.

Generation is a `RandomSource` port (`docs/architecture.md` already lists one),
so a test fixes the identifier without weakening production, and the production
adapter is `secrets`.

## Decision: every job is owned by an authenticated principal, and a foreign job is `404`

`prompts/06-api-cli.md` privacy: "job IDs are unguessable" **and** "cross-account
result access forbidden". Both, not either — an unguessable identifier is a
secret that can leak, and an ownership check is what makes the leak survivable.

Reads and cancellations compare `job.owner` against the requesting principal's
account. A mismatch answers exactly what an unknown identifier answers: `404
not_found`, same code, same body. The repository fixes no status code for this
case, so the choice is derived from the privacy requirement rather than
invented: `403` would confirm that the identifier names a real job belonging to
somebody else, which is the fact the ownership rule exists to withhold.

## Decision: cancellation is `DELETE` on the resource the repository already names

`docs/requirements.md` names three routes and no cancellation route;
`prompts/06-api-cli.md` requires cancellation without naming one. Rather than
invent a path, cancellation is `DELETE /v1/checks/{id}` — the resource is the
one section 11 already publishes, and no new path is added.

Cancellation is idempotent: cancelling an already-terminal job answers with the
job in its existing state and changes nothing. `pending` and `retry_scheduled`
jobs are cancelled without ever running; a `running` job has its worker
cancelled, which propagates into the SMTP step, so the admission permit, the
rate-limit lease, and the socket are all released by the `finally` blocks
Phases 4 and 6 already have.

## Decision: an HTTP request ending is not a job cancellation

Submitting a job and then disconnecting must not cancel the accepted job — that
is the whole point of an asynchronous API, and the earlier "no background work
outlives a request" instruction would have made the requirement unimplementable.
The job's lifetime belongs to the executor; the request task's lifetime ends
when the response is written.

The converse still holds and is tested: an **explicit** cancellation propagates
all the way into the SMTP dialogue, and a cancelled job leaves nothing running.

## Decision: the executor is a port with a bounded in-memory implementation

`JobExecutor` in `ports/job_executor.py`; `InMemoryJobExecutor` in
`adapters/execution/memory_executor.py`, which is `prompts/06-api-cli.md`'s
"memory executor for tests".

Everything about it is finite: a fixed number of worker tasks and one scheduler
task, all created at `start()`; a bounded queue that refuses rather than growing;
no `create_task` anywhere in the job path. A worker catches an exception from a
job and records `failed` rather than dying, and shutdown cancels the workers and
the in-flight job explicitly.

**It is not a service-active worker.** `docs/requirements.md` section 15
requires an isolated worker for that profile, and an in-process executor is not
one. The composition root refuses to build a service-active deployment on the
in-memory executor, so the fake cannot become the production default by
omission. A Redis-backed executor needs a package that is not installed and is
deferred with the rest of that extra.

## Decision: an idempotency key names one address

`docs/architecture.md` section 6: "An active request has an idempotency key
**and a derived target HMAC**." The first build keyed on `(account, key)` alone,
so a caller reusing a key with a different address received the *first*
address's job — a confident verdict about a mailbox nobody asked about, with
nothing in the response to reveal it. A final independent review measured it.

The identity is now `(account, key, HMAC(normalized target))`, taken under the
same operator secret the cache uses, so one address has one digest across both.
The raw address is never stored.

**A key reused for a different address is a conflict**, answered `409` with a
stable code. The alternative — quietly creating a second, unrelated operation
under one key — makes the key mean two things, and an idempotency key exists
precisely to mean one. The body names neither address, neither digest, nor the
earlier job: the caller learns the key is in use and nothing about what it was
used for.

**A submission whose address did not parse records no binding.** There is no
normalized target and so no digest, idempotency exists to avoid duplicating
expensive active work, and a syntax rejection costs zero lookups and zero
sockets. Inventing a second canonical form for unparseable text would be new
normalization vocabulary for no benefit.

The read and the write happen under one lock, so two concurrent submissions
carrying the same key cannot both miss and both register.

## Decision: an executor that refuses leaves nothing behind

`submit` registers the job and then hands it to the executor. If the executor
refuses, the registration is **rolled back**.

Without that, a `pending` job the executor never accepted stays in the registry
for ever: it can never run, and `_evict` only removes *terminal* jobs. A burst
of executor pressure therefore converted into a permanent `JobsFull`, surviving
the executor's recovery — measured at four refusals against a four-job registry.
The rollback catches `BaseException`, because a cancellation between registering
and enqueueing leaves the same wreckage, and it removes the idempotency binding
only when it still points at its own job, so it can never free a key another
submission has since taken.

Registration stays *first*, rather than enqueueing first and registering after:
a worker must never run a job the registry cannot answer for, and
`InMemoryJobExecutor.submit` reaches no `await` before it enqueues, so nothing
can start earlier. A test asserts that ordering at the seam.

## Decision: the remote job client follows no redirect

`adapters/http/urllib_client.py` carries the operator's API key in an
`Authorization` header. `urllib`'s default opener copies every header except
`content-length` and `content-type` onto a redirected request, so a `302` sent
the key to whatever host the answer named — cross-origin, over plaintext `http`
if the redirect said so, and the stdlib additionally permits `ftp:` as a
redirect target. `security/remote_url.py` validates only the *first* URL, so
after one hop nothing was checking anything.

The client builds its own opener with a `HTTPRedirectHandler` subclass that
**raises** rather than returning a request. Raising inside `redirect_request` —
the method that constructs the follow-up and copies the headers onto it — means
no redirected request object exists at all, which is a stronger statement than
stripping a header from one that was about to be sent.

Same-origin redirects are refused too. "Same origin" is a judgement about a URL
an attacker may have chosen, and an operator whose validator has moved can
change `--remote`. A refused redirect is an answer rather than a transient
failure, so it is not retried.

## Decision: retry eligibility is a closed set read out of section 14

`docs/requirements.md` section 14 gives three retryable conditions and one
prohibition. Mapped onto published reason codes, keyed on the verdict's
**primary reason**:

| Section 14 | Reason code | Retried? |
|---|---|---|
| explicit temporary SMTP response | `smtp_temporary_failure` | yes, ~20 min plus jitter |
| explicit temporary storage condition | `mailbox_full` | yes, ~20 min plus jitter |
| DNS SERVFAIL | `dns_temporary_failure` | yes, a few minutes |
| connection timeout, "only if service health is otherwise normal" | `smtp_connection_timeout` | **no** |
| syntax, NXDOMAIN, Null MX, permanent policy | — | no |
| everything else | — | no |

**The classification is the reason code's, never the reply's first digit.**
`mailbox_full` arises from `452 4.2.2` **and** from `552 5.2.2`, and
`docs/requirements.md` section 9 calls the latter a temporary mailbox or storage
condition — so section 14's "explicit temporary SMTP response" covers both. An
earlier build retried `450` and `451` but not `452`, a split section 14 does not
draw; branching on the basic code would have made that permanent. A `552 5.2.2`
is a 5xx that is retried and a `550 5.7.1` is a 5xx that is not, which is only
expressible semantically.

**There is no `if temporary: retry` shortcut.** A reason marked temporary is not
retryable by that fact alone: `rcpt_unverifiable` and a refused connection are
both non-permanent in ordinary language and neither is one of section 14's
conditions. A `ReasonCode` added to the vocabulary later is not retryable until
somebody puts it in the table on purpose, and an exhaustiveness test fails until
one side or the other is chosen for it.

The connection-timeout row is the one worth explaining. Section 14 permits that
retry only under a precondition — service health — that this project does not
model. Retrying anyway would be implementing half a rule and calling it the
rule, so it is not retried and the ADR records why rather than leaving a reader
to wonder whether it was forgotten.

The set is closed: a reason outside it is not retried, including
`rcpt_unverifiable` (`252`), `smtp_ambiguous_permanent_failure` (a bare `550`),
`rcpt_rejected_policy`, and every non-target failure. There is no
provider-specific rule and no rule derived from a reply's text.

**A retry is a whole new verification, not a second SMTP attempt.** It calls
`AddressVerificationService.verify` again, so it passes admission, DNS, the rate
limiter, the destination policy, the one-`RCPT TO` bound, and the total deadline
exactly as the first attempt did.

The distinction is worth stating plainly, because the two are easy to conflate
and only one of them is safe:

| | |
|---|---|
| **Forbidden** — Phase 4E | a second exchanger, or a second `RCPT TO`, for the same recipient *inside one verification*. `docs/threat-model.md` lists that pattern first, and gate 4E does not do it at all |
| **Permitted** — section 14 | one whole new verification, ~20 minutes later, capped at one, with jitter |

`smtp_temporary_failure` and `mailbox_full` are produced **only** at the
recipient stage, so section 14's first condition names nothing else — read any
other way, that bullet would implement nothing. `docs/architecture.md` section 4
places "schedule at most one retry if explicitly temporary" after the SMTP
transaction and the aggregation, which is exactly this.

## Decision: at most one retry, structurally

`CheckJob.retries_used` is `0` or `1`, validated on construction, and a job with
`retries_used == 1` is not eligible however its second attempt ended. The count
is on the job rather than in the scheduler, so a second retry cannot be arranged
by re-enqueueing.

## Decision: the delay is bounded, and is not a worker slot

The retry delay comes from the table above plus jitter from `RandomSource`, and
it is waited on by the `Sleeper` port — so a test measures twenty minutes
without waiting twenty minutes, exactly as the Phase 4 pacing tests do.

A delayed job does **not** hold a worker while it waits. The executor keeps a
bounded delayed set and one scheduler task that re-enqueues a job when its delay
expires; otherwise a handful of retrying jobs would occupy every worker for
twenty minutes.

## Decision: a job's public shape is the existing allowlist

`GET /v1/checks/{id}` returns the job identifier, the state, the creation and
update timestamps, and — for a `completed` job only — the result, built by
`application/public_result.py` and nothing else.

No `Evidence`, no `Evidence.details`, no attempt records, no transcript, no
exception text, no principal, no digest, and no cached-key material. A `failed`
job carries a stable categorical code and no message. A job that has not
completed carries **no status at all**: inventing one before a verdict exists
would be the exact re-derivation Phase 5 stop condition 1 forbids.

## Consequences

- `POST /v1/checks` returns in the time a passive check takes, and never waits
  for SMTP;
- a job worker is an entry point, so the Phase 4 stop condition 1 inspection now
  covers it: a worker reaching `SMTPProbeService`, `SMTPConnector`, or
  `SMTPTransport` is refused by test rather than by convention;
- no job state survives a process restart, and nothing claims it does.

## Alternatives rejected

- **`queued`/`succeeded` instead of the repository's enum.** Familiar, and not
  what is written down.
- **`403` for a foreign job.** It answers the question ownership exists to
  refuse.
- **Retrying a connection timeout anyway.** Half of section 14's rule is not
  section 14's rule.
- **A retry that re-probes only the SMTP step.** It would skip admission, the
  limiter, and the deadline — every bound Phase 6 added.
- **Durable jobs in SQLite.** No document asks for them, and a job table that
  outlives a process is retained personal data with no retention rule.
