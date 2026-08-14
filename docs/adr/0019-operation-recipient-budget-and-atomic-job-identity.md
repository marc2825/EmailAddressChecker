# ADR 0019: The operation recipient budget, atomic job identity, and crash semantics

- Status: Accepted
- Date: 2026-08-13
- Phase: post-Phase-10, final system audit Remediation A
- Supersedes parts of ADR 0014 (retry eligibility; the idempotency lock; "no job
  state survives a process restart")

## Context

The final system audit returned **B — Conditional Approval**. Its first
remediation group is three findings about active-operation correctness, and all
three are about the same gap: every safety bound in the job layer held *inside
one process, for one verification*, and nothing held across a second replica, a
second attempt, or a restart.

1. **Idempotency was not atomic across instances.** `JobService._claim` read and
   wrote its binding under an `asyncio.Lock`. Measured over one temporary SQLite
   file with two `JobService` instances, one owner, one key, and one address:
   two job identifiers, two executor admissions, two persistent bindings.
2. **Automatic retry could produce a second recipient touch.** A `450` at
   `RCPT TO` is an "explicit temporary SMTP response";
   `docs/requirements.md` section 14 retried those; a retry is a whole second
   verification. One submitted address, two `RCPT TO` commands on the wire.
3. **The store/executor handoff left states nothing could advance.** An initial
   save failure left an in-memory phantom with no work; an executor refusal
   could leave a persistent one; a failed `running` persist let SMTP proceed
   anyway; and a `retry_scheduled` job whose `schedule()` was refused stayed
   nonterminal for ever.

A fourth fact made the first and third academic in production and is fixed with
them: `composition.py` constructed no `SQLiteJobStore`, so `JobService.store`
was `None` in every deployment the composition root could build.

## Decision: one high-level operation may touch one recipient, in total

`docs/threat-model.md`'s bound is restated at the operation level rather than
the verification level. Everything one caller request causes — the first
verification, section 14's automatic retry, and anything a restart might re-run
— issues at most one `RCPT TO` between them.

This is the bound that was missing. Gate 4E's per-verification bound was never
violated and is untouched; what nobody had written down is that "at most one
automatic retry" caps the number of *verifications* and says nothing about how
many times one address is named to a mail server.

## Decision: an automatic retry requires proof that the recipient was not reached

`domain/recipient_touch.py` publishes `RecipientTouch`, with two members:
`not_touched` and `maybe_touched`. `maybe_touched` covers *touched* as well,
because the question asked of the value is only ever "may a replay contact this
recipient again?", and a `450` that arrived, a `RCPT TO` whose reply never came,
and a write that failed part way are one answer to it.

It is computed by `application/smtp_verification.py` from the transcript and the
stage reached — the same two barriers `touched_the_recipient` already used —
carried on `VerificationOutcome`, persisted on the job, and required as a
keyword by `retry_delay_seconds`.

**It is not derived from a status, and that is the whole point.**
`temporary_unknown` is produced by a DNS SERVFAIL that opened no socket *and* by
a `451` at `RCPT TO`. A retry rule that read the verdict could not tell those
apart, which is exactly how the defect arose. `NOT_TOUCHED` must be proven;
every producer that cannot answer says `MAYBE_TOUCHED`.

Section 14's delay table is unchanged. Membership became **necessary and not
sufficient**:

| Condition | Reason code | In the table? | Retried? | Why |
|---|---|---|---|---|
| DNS SERVFAIL | `dns_temporary_failure` | yes | **yes** | happens before any socket |
| pre-recipient temporary SMTP response | `smtp_temporary_failure` | yes | yes, if it could arise | eligible and untouched |
| `450` / `451` at `RCPT TO` | `smtp_temporary_failure` | yes | **no** | the recipient was reached |
| `452` / `552 5.2.2` at `RCPT TO` | `mailbox_full` | yes | **no** | the recipient was reached |
| `RCPT TO` written, reply lost | `smtp_*` / none | — | **no** | the command went out |
| `RCPT TO` write failed part way | — | — | **no** | delivery cannot be ruled out |
| connection timeout | `smtp_connection_timeout` | no | no | ADR 0014: service health is not modelled |
| every recipient answer, every permanent reason | — | no | no | not one of section 14's conditions |

In this build the two recipient-stage rows are eligible by reason and refused by
touch, so `dns_temporary_failure` is the only condition that schedules anything.
The delays stay keyed by reason rather than being deleted: a temporary SMTP
response observed before the recipient stage would be retryable under both
rules, and removing the row would be deciding here that such a thing can never
be observed.

**Alternative rejected: keep retrying recipient-stage temporaries and document
the second touch.** Section 14 is a defaults section; `docs/threat-model.md`'s
enumeration control is a safety invariant, and `AGENTS.md` resolves that
ordering. A second `RCPT TO` twenty minutes later is the slower version of the
harvesting pattern the invariant exists to refuse, and the fact that it is
scheduled rather than immediate makes it more deliberate, not less.

## Decision: the store decides idempotency, atomically

`JobStore.claim_idempotency(record) -> ClaimResult` replaces the read-then-write
under a lock. One transaction: `BEGIN IMMEDIATE`, an insert that does nothing on
conflict, and — when it wrote nothing — a read of the holder in the same
transaction. Three answers, no fourth: `NEW_CLAIM`, `EXISTING_SAME_TARGET`,
`CONFLICT_DIFFERENT_TARGET`.

The partial UNIQUE index is the structural identity barrier. The claim is
insert-first and keeps that write plus the winner lookup in one transaction, so
the first database action already contends on the constraint. `BEGIN IMMEDIATE`
is retained because taking the write lock before the insert simplifies
contention and snapshot semantics; it is not the uniqueness guarantee by
itself. A focused mutation to deferred `BEGIN` did not break the race because
the insert still takes the write lock before any lookup.

The barrier is `CREATE UNIQUE INDEX jobs_idempotency ON jobs (owner,
idempotency_digest) WHERE idempotency_digest IS NOT NULL`. Scoped to the owner,
because an idempotency key is caller-chosen text and a global constraint would
let one account's `order-1` answer another's. Partial, because SQLite treats
NULLs as distinct anyway and writing the predicate says so on purpose.

The in-process lock stays for the registry, which is genuinely process-local.

**`INSERT OR REPLACE` is removed.** SQLite's `REPLACE` resolves *every*
constraint by deleting conflicting rows, so once the index is unique, one job's
ordinary state write would silently have deleted whatever other job held its
binding — the winner of a claim, evicted by a loser's next transition. `save` is
now `ON CONFLICT (job_id) DO UPDATE`, and a write that would cross two job
identities raises `JobStoreConflictError` rather than resolving itself. The
ordinary update changes only mutable state columns. `job_id`, `owner`,
`created_at`, `idempotency_digest`, and `target_digest` are immutable, and a
`WHERE` equality guard turns a mismatch for the same JobId into the same closed
store error instead of rebinding it.

Version 2 introduced the unique index and recipient-touch checkpoint. The final
follow-up moves the schema to **3** for the executor-handoff fact. As before,
the version is read *before* the schema script runs, so an older file is refused
by version rather than failing part-way through schema creation.

## Decision: durable before irreversible, and a failed write stops the work

Two classes of persistence, and the difference is what the state authorizes:

- a state that **authorizes** something — `running` authorizes an SMTP dialogue,
  `retry_scheduled` authorizes a second one — must be on disk before that
  something happens. A failed write ends the job as an operational failure
  instead;
- a state that merely **records** an outcome — `completed`, `failed`,
  `cancelled` — is written best effort. Refusing to return a verdict because a
  disk was unavailable would be the worse answer.

The claim is durable before it is local. Once committed it is observable by a
second replica and is therefore never deleted as compensation for a later local
or executor refusal. Such a refusal preserves the same JobId and idempotency
binding as `failed` with an operational `JobFailure` and no mailbox status.

## Decision: commit one handoff opportunity before calling the executor

`JobAdmission` is persistent operational vocabulary separate from the six
public job states:

- `claimed`: the identity winner exists; no executor call is yet authorized;
- `handoff_committed`: this JobId irrevocably owns the one executor-call
  opportunity;
- `admission_failed`: the executor or local admission refused and the job is
  terminal;
- `not_required`: a cache hit completed without an executor;
- `interrupted`: stale nonterminal work was reconciled without replay.

The ordering is deliberately:

```text
claim(CLAIMED)
→ persist HANDOFF_COMMITTED
→ executor.submit
→ worker persists RUNNING / MAYBE_TOUCHED
→ active verification
```

There is no database-plus-executor transaction. A post-executor `ADMITTED`
acknowledgement would create the critical boundary "executor accepted, marker
write failed", where a second replica might mistake a missing ack for permission
to submit again. This design writes an irrevocable token first instead. A marker
write failure calls no executor; a crash after the token but before or after
acceptance loses work conservatively; neither case permits another admission.

The crash boundaries are therefore explicit:

| Boundary | Durable observation | May another replica enqueue? | Restart/recovery |
|---|---|---|---|
| A. claim persisted, executor not called | `pending` / `claimed` | no; the identity already has a winner | stale work becomes `failed` / `interrupted`, never replayed |
| marker persistence fails | the last durable row may remain `pending` / `claimed`; no executor was called | no; a missing handoff is not permission to reclaim | the same identity is reconciled as interrupted |
| B. executor definitely refuses | same JobId becomes `failed` / `admission_failed` | no | the terminal refusal survives restart |
| C. executor accepts and the process crashes before a later acknowledgement | no post-accept acknowledgement exists; `handoff_committed` was already durable | no | the committed handoff is reconciled without replay |
| D. handoff marker persisted | `pending` / `handoff_committed` | no; its one opportunity is spent before the call | no automatic resubmission |
| E. active work begins | `running` / `handoff_committed` with `maybe_touched` persisted first | no | interrupted, with recipient replay forbidden |

Thus the requested "accepted, marker missing" case is eliminated by ordering,
not guessed about after a failure. A missing pre-handoff marker means the
executor was never called; an accepted call necessarily follows an already
durable marker.

An executor refusal changes the same durable row to `failed` /
`admission_failed`, normally with `capacity_unavailable`, and never deletes the
identity winner. A replica that reconstructed but does not locally own a
nonterminal job re-reads the store before returning it again, so it observes
that terminalization rather than retaining a pending phantom.

## Decision: the recipient checkpoint is written on entry, not on exit

`running` is persisted carrying `maybe_touched` **before** the verification
starts. A checkpoint written when the verification returns is missing for
exactly the crash it exists to describe — between the command going out and the
reply coming back — so the record is conservative on entry and refined to what
was observed on exit.

The cost is accepted explicitly: a process that dies after arming and before
sending will refuse a replay that would in fact have been safe. One lost retry
against one duplicate recipient contact is not a close call.

## Decision: interrupted work is reconciled, never resumed

`JobService.recover_interrupted(before=…, limit=…)` ends every nonterminal row
it is given as `failed` / `interrupted` — a new `JobFailure` member, an
operational category carrying **no status**. `pending -> failed` and
`retry_scheduled -> failed` are added to the transition table to make that
reachable; `pending -> completed` is still refused, because a `JobFailure` is
not a result.

Even a `pending` row — provably safe to replay — is not re-enqueued. There is
nowhere to replay it to: `ports/job_executor.py`'s only implementation dies with
its process, and `docs/requirements.md` section 15 defers durable worker
infrastructure to the service-active profile. Inventing a durable queue out of
an in-memory one would be the overclaim ADR 0014's consequences section already
warned about.

Completed and cancelled rows are not returned by the store's predicate, so the
scan cannot resurrect a cancellation — structural, rather than a check that
could be edited away. The operation takes a cutoff and skips rows whose executor
handoff the calling process owns, because a store may be shared with a live
replica. Merely rehydrating another process's row does not make this process its
executor owner.

**No scheduler runs it.** It is an operator action, on the same footing as
`RetentionService`, and `docs/runbooks/queue-store-outage.md` describes when.

## Decision: the job store is wired by the composition root

`Deployment.job_store_path` builds a `SQLiteJobStore` for every profile that
builds a `JobService`, passes it to that service, and passes it to
`RetentionService` so persisted jobs are swept on the same window as the
registry. The local-passive profile **refuses** the setting: it accepts no job,
so the file would be one nothing writes and a retention obligation nothing
incurs.

A composition test asserts `stack.jobs.store is stack.job_store`. "A store was
created" and "the service has it" are different statements, and the audit found
a build where only the first was true.

## Consequences

- a recipient-stage temporary reply now settles the job on the first answer,
  with `retries_used == 0`: no retry was spent rather than one being spent and
  refused;
- `dns_temporary_failure` is the only condition that reaches
  `retry_scheduled` in this build. The state, the delay, and the budget are all
  still exercised;
- two replicas over one database agree about one key. A single-process
  deployment is unchanged;
- an executor refusal keeps that key bound to one terminal JobId across every
  replica and restart;
- a crash on either side of executor admission is never interpreted as
  permission for another admission;
- a job store file written by schema version 1 is refused at start;
- a restarted process publishes `failed` / `interrupted` for work the previous
  one left, where it previously published nothing and left the row unfinished;
- **nothing here implements durable execution.** Persistent job state and a
  durable execution queue are separate, and only the first exists.

## Alternatives rejected

- **A `retry_safe` boolean instead of a two-member enum.** A boolean's default
  is `False` in one direction and `True` in the other depending on how it is
  named, and the safe default has to be the one a forgotten argument produces.
- **Deriving retry safety from `Status` or `ReasonCode`.** The measured defect.
- **`SELECT` then `INSERT` outside one transaction.** The measured defect, with
  more steps.
- **Re-enqueueing recovered `pending` jobs.** Safe for that one state and
  indistinguishable, one edit later, from re-enqueueing `running` ones.
- **Running reconciliation automatically at startup.** A second replica starting
  up would declare the first one's running jobs interrupted.
