# ADR 0019: The operation recipient budget, atomic job identity, and crash semantics

- Status: Accepted
- Date: 2026-08-13

## Context

Every safety bound in the job layer once held only inside one process and one verification. A system audit found three consequences:

1. Idempotency was not atomic across instances: two `JobService` instances over one SQLite file produced two jobs, two executor admissions, and two bindings for one owner, key, and address.
2. An automatic retry could touch the recipient again. A `450` at `RCPT TO` counted as an explicit temporary SMTP response, which `docs/requirements.md` section 14 retried, so one submitted address received two `RCPT TO` commands.
3. Failures in the store/executor handoff left jobs that nothing could advance.

The composition root also built no persistent job store at all.

## Decision: one high-level operation touches one recipient, in total

Everything one caller request causes, the first verification, the automatic retry, and anything a restart might re-run, issues at most one `RCPT TO` between them. The per-verification bound still holds; "at most one automatic retry" limits verifications, not how often an address is named to a mail server.

## Decision: an automatic retry requires proof that the recipient was not reached

`domain/recipient_touch.py` defines `RecipientTouch` with two members, `not_touched` and `maybe_touched`. `maybe_touched` covers a reply that arrived, a `RCPT TO` whose reply never came, and a write that failed partway, because the only question asked is whether a replay could contact the recipient again. `application/smtp_verification.py` computes it from the transcript and the stage reached, it is carried on `VerificationOutcome` and persisted on the job, and `retry_delay_seconds` requires it as a keyword argument.

It is never derived from a status: `temporary_unknown` comes both from a DNS SERVFAIL that opened no socket and from a `451` at `RCPT TO`. `not_touched` must be proven; a producer that cannot prove it says `maybe_touched`.

Section 14's delay table is unchanged, but being in it is now necessary and not sufficient:

| Condition | Reason code | In the table? | Retried? | Why |
|---|---|---|---|---|
| DNS SERVFAIL | `dns_temporary_failure` | yes | yes | before any socket |
| pre-recipient temporary SMTP response | `smtp_temporary_failure` | yes | yes, if it occurs | eligible and untouched |
| `450` / `451` at `RCPT TO` | `smtp_temporary_failure` | yes | no | the recipient was reached |
| `452` / `552 5.2.2` at `RCPT TO` | `mailbox_full` | yes | no | the recipient was reached |
| `RCPT TO` written, reply lost | — | — | no | the command went out |
| `RCPT TO` write failed partway | — | — | no | delivery cannot be ruled out |
| connection timeout | `smtp_connection_timeout` | no | no | service health is not modelled |
| every recipient answer and permanent reason | — | no | no | not a section 14 condition |

In this build only `dns_temporary_failure` schedules a retry. The SMTP delay rows stay in case a temporary response is ever observed before the recipient stage.

Rejected alternative: keep retrying recipient-stage temporaries and document the second touch. Section 14 is a defaults section, while the enumeration control in `docs/threat-model.md` is a safety invariant, and a second `RCPT TO` twenty minutes later is a slower form of the harvesting pattern it forbids.

## Decision: the store decides idempotency atomically

`JobStore.claim_idempotency(record) -> ClaimResult` runs one transaction: `BEGIN IMMEDIATE`, an insert that does nothing on conflict, and, if nothing was written, a read of the current holder. It returns `NEW_CLAIM`, `EXISTING_SAME_TARGET`, or `CONFLICT_DIFFERENT_TARGET`.

The identity barrier is `CREATE UNIQUE INDEX jobs_idempotency ON jobs (owner, idempotency_digest) WHERE idempotency_digest IS NOT NULL`, scoped to the owner so one account's key never answers for another's. An in-process lock remains only for the process-local registry.

`INSERT OR REPLACE` is not used, because with a unique index it would delete the job holding a binding. `save` is `ON CONFLICT (job_id) DO UPDATE` and changes only mutable state columns; `job_id`, `owner`, `created_at`, `idempotency_digest`, and `target_digest` never change, and a write that would cross two identities raises `JobStoreConflictError`. The schema is version 3, and the version is read before the schema script runs, so an older file is refused cleanly.

## Decision: durable before irreversible

- A state that authorizes something must be on disk before it happens: `running` authorizes an SMTP dialogue and `retry_scheduled` a second one. If the write fails, the job ends as an operational failure.
- A state that only records an outcome (`completed`, `failed`, `cancelled`) is written best effort; refusing to return a verdict because a disk failed would be worse.
- A committed claim is visible to other replicas and is never deleted to compensate for a later refusal. The same job ID becomes `failed` with an operational `JobFailure` and no mailbox status.

## Decision: commit one handoff opportunity before calling the executor

`JobAdmission` is persistent operational vocabulary, separate from the six public job states: `claimed`, `handoff_committed` (this job irrevocably owns its one executor call), `admission_failed`, `not_required` (a cache hit), and `interrupted`.

```text
claim(CLAIMED)
→ persist HANDOFF_COMMITTED
→ executor.submit
→ worker persists RUNNING / MAYBE_TOUCHED
→ active verification
```

There is no transaction spanning the database and the executor. Writing an irrevocable token before the call removes the "executor accepted, acknowledgement missing" state in which another replica might resubmit. A failed marker write calls no executor; a crash around the call loses work conservatively; neither permits another admission.

| Boundary | Durable observation | May another replica enqueue? | Restart/recovery |
|---|---|---|---|
| A. claim persisted, executor not called | `pending` / `claimed` | no; the identity has a winner | stale work becomes `failed` / `interrupted`, never replayed |
| Marker write fails | the row may stay `pending` / `claimed`; no executor call | no | reconciled as interrupted |
| B. executor definitely refuses | same job becomes `failed` / `admission_failed` | no | the refusal survives restart |
| C. executor accepts, process crashes | `handoff_committed` was already durable | no | reconciled without replay |
| D. handoff marker persisted | `pending` / `handoff_committed` | no; the opportunity is spent | no automatic resubmission |
| E. active work begins | `running` / `handoff_committed`, `maybe_touched` persisted first | no | interrupted; recipient replay forbidden |

A replica that rebuilt a non-terminal job it does not own reads the store again before returning it, so it sees a later refusal.

## Decision: the recipient checkpoint is written on entry

`running` is persisted with `maybe_touched` before the verification starts, so the crash between sending `RCPT TO` and reading the reply is covered; the value is refined on exit. A process that dies after arming and before sending will refuse a replay that was actually safe, which is an acceptable cost.

## Decision: interrupted work is reconciled, never resumed

`JobService.recover_interrupted(before=…, limit=…)` ends every non-terminal row it is given as `failed` / `interrupted`, an operational category with no status. `pending -> failed` and `retry_scheduled -> failed` are allowed for this; `pending -> completed` is still refused. Even a `pending` row is not re-enqueued, because the only executor dies with its process and there is no durable queue. The store's predicate never returns completed or cancelled rows, and the operation skips rows whose handoff the calling process owns. It is an operator action, not scheduled; `docs/runbooks/queue-store-outage.md` says when to run it.

## Decision: the composition root wires the job store

`Deployment.job_store_path` builds a `SQLiteJobStore` for every profile that has a `JobService` and passes it to the service and to `RetentionService`. The local-passive profile refuses the setting. A composition test asserts `stack.jobs.store is stack.job_store`.

## Consequences

- A recipient-stage temporary reply settles the job on the first answer, with `retries_used == 0`.
- Only `dns_temporary_failure` reaches `retry_scheduled` in this build.
- Two replicas over one database agree about one key, and an executor refusal keeps the key bound to one terminal job across replicas and restarts.
- A crash on either side of executor admission never permits another admission.
- A restarted process reports `failed` / `interrupted` for work the previous one left.
- Job state is persistent; execution is not. There is no durable queue.

## Alternatives rejected

- A `retry_safe` boolean: its safe default depends on how it is named, and a forgotten argument must produce the safe value.
- Deriving retry safety from `Status` or `ReasonCode`: the original defect.
- `SELECT` then `INSERT` outside one transaction: the original defect with more steps.
- Re-enqueueing recovered `pending` jobs: safe for that state, and one edit away from re-enqueueing `running` ones.
- Reconciling automatically at startup: a second replica starting would mark the first one's running jobs interrupted.
