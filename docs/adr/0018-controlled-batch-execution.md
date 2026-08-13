# ADR 0018: Batch as orchestration, never as a second path

- Status: Accepted
- Date: 2026-08-12
- Phase: 10

## Context

`prompts/10-batch.md` asks to "process authorized CSV jobs fairly without
weakening single-check safety", and opens by saying batch is "an operational
permission, not merely a profile switch". `docs/requirements.md` section 15 says
the same of the `bulk` profile.

The danger is specific and it is not subtle. Every control this project has was
built for one address at a time, and the obvious way to make ten thousand
addresses fast is to do them differently. That would be a second SMTP path, a
second limiter, and a second set of decisions about what a reply means — three
things this repository has spent nine Phases refusing.

## Decision: every row is an ordinary Phase 6 submission

`BatchService` calls `JobService.submit`, and reaches nothing lower. Not the
verification service, not the probe, not a transport, not a resolver. An
inspection test refuses each of those names in the module.

That single choice is what makes the prompt's *reuse all existing budgets* and
*no increase in per-destination rate* true rather than promised: a batch row
inherits the kill switch, the Phase 7 caller and destination budgets, admission,
the verdict cache, the destination policy, TLS, the sender identity, the
one-`RCPT TO` bound, and section 14's single retry — because it is the same
submission a single check makes. Ten thousand rows are ten thousand ordinary
submissions, paced by the same limiter.

The corollary is measured rather than assumed: with the default registry of 512
jobs, a thousand-row batch **submits 512 and refuses 488**, every refusal
explicit. A batch may not assume the executor's refusal is harmless, and it does
not get a larger registry for being a batch.

## Decision: fairness is two rotations — exchangers, then domains

`prompts/10-batch.md`: *fair scheduling by target domain and MX*, and *one
domain cannot monopolize workers*. Those are two bounds, and an implementation
that keeps only the first satisfies the prompt by half.

`FairRotation` serves exchangers in turn and, within one, the domains sharing
it in turn. Ordering by row number would make one row at a quiet domain wait
behind nine thousand at a busy one; ordering by domain alone would let twenty
domains behind one provider take twenty of a rotation's slots while every
per-domain rule is satisfied. Behind both rotations are hard caps —
`max_in_flight_per_domain` and `max_in_flight_per_mx` — because a batch that is
*entirely* one domain, or one provider, has nothing to rotate to and the
property must still hold.

Neither changes any **rate**. Phase 4's per-domain pacing is untouched and is
still what decides how fast a destination is approached; this decides only which
row is offered to it next.

The rotation is pure and synchronous, so fairness is read off an ordering rather
than inferred from a scheduler's timing.

### Where the exchanger comes from, and exactly what it means

**Learned from the ordinary pipeline, never resolved here.**
`VerificationOutcome` gains `scheduling_key`, produced by `scheduled_exchanger`.
It decides nothing — no status, confidence, reason, or flag reads it — which is
the precedent `route_ttl_seconds` set for exactly this kind of carried metadata.

Its definition is **the exchanger this verification will approach first**: the
preferred connectable candidate, *after* the administrator's blocked-exchanger
switch. The filter is not decoration. A first revision read
`connectable_candidates[0]` unfiltered, and `application/verification.py`
removes blocked exchangers before Phase 4E plans — so with the preferred host
blocked the key named `mx-a` while every packet went to `mx-b`. A scheduler
using it would have accounted `mx-b`'s work against `mx-a` and spread load
across a destination nothing contacts. One function now answers the question for
the key and for the destination charge, so they cannot drift.

**The scope of the fairness claim, chosen rather than assumed.** Phase 4E falls
through to a later candidate when an attempt fails before the recipient stage,
and nothing computed before the verification runs can know whether that will
happen. Phase 10 therefore provides **fairness over first-approached
exchangers**, and a test asserts that the plan handed to Phase 4E holds a host
the key does not name — so the claim cannot quietly become per-attempt fairness.

Per-attempt fairness was considered and rejected as out of scope rather than
impossible: the seam would have to be inside `application/smtp_verification.py`,
which runs *after* the scheduling decision and below the layer that makes it.
Reaching it from a batch would mean either a second routing path or a scheduler
that re-orders work mid-verification, and both are larger changes than
`prompts/10-batch.md` asks for.

The alternative was for `BatchService` to call a resolver, and it was rejected:
that is a second routing path with none of Phase 2's ordering, caching, or
destination policy, and it opens a gap between the host the scheduler grouped by
and the host the probe actually reaches. An inspection test refuses `resolve(`,
`MailRoute`, `RouteCandidate`, and `connectable_candidates` in the scheduler.

A domain is its own provisional group until its first row answers. That is not a
special case; it is what "learned" means, and a new group joins at the back so
learning never lets a domain jump the queue.

### Why this could not be inherited: a rate bound is not fairness

`docs/architecture.md` records that `InProcessRateLimiter` partitions state by
the recipient **domain** alone — the MX host is carried, validated, and divides
no budget. So the existing stack imposes no MX bound of any kind, let alone a
fair one: two domains behind one provider hold two independent concurrency slots
and two independent token buckets. A test measures three concurrent leases on
one exchanger under a per-domain concurrency of one, so this is a measurement
rather than a reading of the code.

Even if an MX budget existed it would be a *ceiling*, not an ordering: rate
bounds say how fast, fairness says whose turn. The scheduler is the only place
the second question can be answered, which is why it is answered there.

## Decision: bounded workers, not one task per row

A fixed set of `max_in_flight` workers pulls from the rotation. Creating fifty
thousand coroutines and holding them behind a semaphore would move the growth
rather than stop it — the shape `application/admission.py` already refuses for
its queue, and the reason its bound is on the queue as well as on the pool.

## Decision: every row ends in an explicit state, and the report balances

Phase 8's lesson, applied: a run that started work and reported nothing about it
is a record with a hole in it. `BatchReport` refuses at construction to hold
fewer rows than the input carried, and `state_summary` sums to `input_rows`.

`BatchRowState` is **not** a second job-state machine. `domain/job.py` publishes
the six states a *verification* moves through; a row that became a job carries
its `JobId` and the job's state is the job's. These are states of a **row**,
which is a different thing — a row can be rejected before any job exists, and a
job cannot be "not an address".

`cancelled` is deliberately shared with `JobState` and means the same thing in
both. Nothing else overlaps, and a test pins it.

### `rejected`, not `invalid`

The first draft called an unparseable row `invalid`, which collided with
`Status.INVALID` — a much stronger claim, that a *mailbox* does not exist. A
report carrying a `row_state` column beside a `status` column, both reading
`invalid`, would invite exactly the confusion Phase 8 had to force apart for its
execution states, and `docs/requirements.md` section 6 sends unsupported syntax
to `unknown` rather than to `invalid` anyway. `AddressRejected` is Phase 1's own
word, and a test now refuses any row state that reuses a status's word.

## Decision: batch is enabled *and* approved, or it does not run

`BatchSettings.enabled` is `False` and `BatchApproval.accounts` is empty, and
both must be true. `prompts/10-batch.md`'s preconditions are *account
review/approval* and *domain ownership or documented lawful purpose*, neither of
which a program can establish and both of which a person records.

**An authenticated account is not an approved one.** Phase 6 authenticates a
caller; this says an operator separately reviewed them for bulk. The prompt's
non-goals begin with *public anonymous uploads*, and the shortest route to one
is treating authentication as approval.

## Decision: the CSV boundary refuses on the way in and escapes on the way out

*Documented UTF-8 CSV schema; file size and row limits; one address column;
duplicate detection by HMAC.*

Both limits, because either alone is bypassable: a million one-character rows is
a small file, and one row can be a megabyte. The byte bound is checked **before
decoding**, which is the first step that costs memory proportional to a caller's
input. The column is a fixed header rather than a caller-supplied index: a
column somebody points at the wrong field is somebody's data being probed.
Duplicates are detected on the Phase 7 correlation digest, and the duplicate row
keeps its own position so the report still lines up with the file.

Malformed rows do not fail the file — the prompt asks for *partial failure*, and
ten thousand rows refused for one bad address would be refused for ever.

On the way out, **every** cell is escaped, not the ones that look risky. A cell
beginning `=`, `+`, `-`, `@`, tab, or carriage return is executed by every major
spreadsheet, and this project's output is a file somebody opens in a spreadsheet
about addresses they were told were invalid: the payload arrives in the input
the submitter chose, survives as data, and runs on the reader's desk. The
character is prefixed rather than stripped, because an investigator needs to see
what was actually sent.

No raw SMTP reply can leave, and that is structural: a report row has a status,
published reason codes, risk flags, and counts, and no field a diagnostic could
occupy.

## Decision: resumability is persistence, and the crash boundary is idempotency

`prompts/10-batch.md`'s scheduler asks for *resumable job state* and its tests
ask for *restart/resume*. An in-process registry answers neither, because the
process is what a restart destroys. `ports/batch_store.py` holds row state, the
target digest, the child `JobId`, and a deterministic per-row idempotency
handle, with `adapters/storage/sqlite_batch_store.py` on the Phase 6 store's
conventions — module-constant SQL, an explicit schema version, ownership and
expiry as predicates, and a bounded purge.

Resume semantics are exact:

| Row state | On resume |
|---|---|
| `submitted`, with a `JobId` | reconnected to the existing job; never resubmitted |
| `duplicate`, `rejected`, `refused`, `cancelled` | terminal; never resubmitted |
| `queued` | submitted, if the batch is live and not cancelled |
| `claimed` | submitted **under its recorded handle** |
| expired, deleted, cancelled, or another account's | not resumable at all |

**The claim is written before the call**, and that ordering is the whole
crash-safety argument. A process that stops between handing a row to
`JobService.submit` and recording the result leaves a `claimed` row whose
handle is already persisted; the resume presents that handle and Phase 6's
idempotency answers with the existing job. Recording afterwards would leave a
row that looks untouched and a verification already running — the case
"probably unlikely" is not an answer to.

The handle is `HMAC(batch, row number, account, target digest)`, so the same row
of the same batch always presents the same one and no two rows, batches, or
accounts share one. It is a digest, so the binding `application/jobs.py` keeps
carries no address.

### The batch store alone was not enough

An earlier Phase 10 revision stopped here and recorded "a whole-process restart
loses the child jobs" as an accepted residual. That was wrong, and the reason is
that the residual was not a *reporting* gap but a **safety** one: with
`JobService`'s registry and idempotency bindings in memory, a fresh process
presented with a row's deterministic handle had no record of it and started a
**second verification** for a row whose verification had already run. A
duplicate `RCPT TO` for one address, arranged by restarting the service, is the
enumeration pattern `docs/threat-model.md` lists first. A deterministic handle
is only half a mechanism; the other half is a record of it that outlives the
process.

So `ports/job_store.py` and `adapters/storage/sqlite_job_store.py` were added,
on the same conventions. They persist job identity, owner, state, retry count,
the public result projection, the target digest, and a **digest** of the
`(owner, idempotency key)` pair — never the key itself, because
`IdempotencyKey` permits an `@` and Phase 7's privacy corpus found an address
used as one. `_resolve_binding` consults the store on a memory miss, **before**
the cache lookup: both avoid a probe, but only the store keeps
`docs/architecture.md` section 6's promise that a repeat returns the *existing*
job rather than a new one carrying a cached result.

This is not a second job-state machine. `domain/job.py` still owns the six
states and the transition table; the store records which one a job is in, and
nothing reads it to decide a transition. It is also not a batch-only shadow
copy: `JobService` is the only writer, and `BatchService` reads jobs through
`JobService.fetch`, so there is no second version of a job's state to disagree
with the first.

### What a restart recovers, and what it deliberately does not

It recovers **identity, state, retry budget, and result**. A completed child's
verdict is readable by a process that did not create it; a cancelled child stays
cancelled; a spent retry stays spent, so a restart cannot refill
`docs/requirements.md` section 14's one-retry budget.

It does **not re-execute** work that was in flight. A job that was `running`
when the process died stays `running`, is visible, and is reported by its batch
as not yet final. That is a decision, not an omission: this project cannot know
whether that verification's one `RCPT TO` was already issued, and re-running it
on the assumption that it was not is precisely the duplicate this store exists
to prevent. Re-executing interrupted work is a property of the durable queue and
isolated worker `docs/requirements.md` section 15 defers to the service-active
profile — PostgreSQL and Redis — and it is not something Phase 10 may invent on
top of a development executor that `composition.py` already refuses to ship in
that profile.

## Decision: the result is an expiring artifact behind a principal

*Expiring downloadable result.* A `BatchArtifact` carries the owner, the batch
identifier, creation and expiry, a media type, and the rendered CSV, and it is
retrieved through an application service that takes a `Principal`. **Not an
anonymous token**: a download handle that authorized by itself would be the
*public anonymous upload* the prompt's non-goals name, arrived at from the other
end. No HTTP route is added — "downloadable" is satisfied by a bounded artifact
an authenticated transport can serve later, and the transport's stop conditions
are still open.

**It is not a second `VerdictCache`**, and the distinction is load-bearing. A
cache answers "is this address still deliverable" and is consulted *before* work
is done; this answers "what did that batch report" and is written *after*. It is
keyed by a batch identifier rather than by a target, nothing reads it to decide
a verdict, and an inspection test refuses `VerdictCache` in every batch policy
module. The prompt's *one active result cache shared with single checks* is
satisfied by batch rows going through `JobService`, which consults the one
process-wide cache — measured by a single check filling it and a batch row then
enqueueing nothing.

### When a result is final

An artifact carries `complete`. A batch stops *submitting* long before its
verifications stop *running*, and exporting a `submitted` row with a status
column filled in from the passive half would present a partial answer as the
final one. So a row's status is published only from a job that reached
`completed`, a `job_state` column says where each row actually is, and reading
the report after the jobs finish rebuilds and replaces the artifact. A
non-final artifact is a submission report and says so.

## Decision: retained plaintext is bounded by the privacy policy, not by need

A row that has not been submitted must still be submittable after a restart, and
`JobService.submit` takes the submitted text — so the store holds it. That is
the one plaintext field, and it is bounded three ways: it is cleared the moment
a row reaches a terminal state; `RetentionService` calls `forget_inputs` with a
cutoff of `now - BatchSettings.input_retention_seconds`; and that setting is
capped at `MAX_INPUT_RETENTION`, 24 hours, so a deployment may shorten the
window and cannot lengthen it. A row whose input has expired can never be
submitted, so a resume records it as refused — the accounting outlives the
input, which is why clearing is an `UPDATE` and not a `DELETE`.

An earlier revision of this ADR claimed all three of those and only the first
was true: `input_retention_seconds` was read by nothing, `forget_inputs` had no
caller in `src/`, and `BatchStore` was not among `RetentionService`'s
collaborators. An independent review measured it — raising the ceiling to a year
changed no test — and the claim was closed by implementing it rather than by
softening the wording.

**Two operations, two windows, one sweep.** Clearing the plaintext a resume
needs is not the same act as removing a finished batch's accounting and its
downloadable result: the first is priced by `input_retention_seconds` and the
second by `result_retention_seconds`, and `RetentionService.run` calls both with
cutoffs derived separately. `DeletionReport` counts them separately for the same
reason.

**What is implemented is the retention *operation*, not a schedule.** Nothing
runs `RetentionService` periodically, because nothing constructs the batch
subsystem at all — composition is deferred. Wiring it is a composition
responsibility, listed below with the others.

## Decision: ownership has three independent barriers, each pinned

An account reaching another account's persisted job would need all three to
fail. They are deliberately of different kinds, because two implementations of
one idea fail together:

| Barrier | Where |
|---|---|
| the binding digest is `HMAC(…\|owner\|key…)` | `JobService._idempotency_digest` |
| `WHERE owner = ?` | `SQLiteJobStore._SELECT_BY_IDEMPOTENCY` |
| `stored.owner == account` after the lookup | `JobService._resolve_binding` |

The third was added after an independent review removed the second and the whole
suite passed — the digest alone was doing the work, and the SQL predicate was an
unpinned comment. Each now has a test that fails when only it is removed, and
the third is exercised with a store that deliberately answers a question it was
not asked.

A mismatch answers `None`, not an error: a distinct answer would tell the caller
that somebody else's job exists. The operator gets an event instead.

### `JobStore.load` takes no account, and that is deliberate

`BatchStore.load_batch` puts the account in the query and `JobStore.load` does
not, which is a real inconsistency between two ports of the same Phase. It is
kept, narrowly: `load` is reached only by `JobService.fetch`, which checks the
owner before returning and answers `None` for another account exactly as an
unknown identifier does — the Phase 6 rule the in-memory `get` already follows.
Adding an account parameter would make the *port* look like the barrier while
`fetch`'s check remained the thing that runs, so the check is pinned by its own
test instead. Reviewed as an accepted, documented divergence rather than treated
as query-level ownership.

## Decision: deletion is the owner's, and stops at the batch

Owner-authorized `delete` removes the batch record, its rows and their retained
plaintext, and the artifact. It removes **no child job**: a job is Phase 6's
record, is expired by Phase 7's retention, and may be shared with a single check
through the cache, so deleting one here would delete somebody else's answer.
Another account's delete removes nothing and reports nothing about whether the
batch exists.

## Decision: capacity is a refusal

The store is bounded in batches. Expired ones are cleared first; if it is still
full, `save_batch` raises `BatchStoreFull`. Evicting a live batch to admit a new
one would make submitting batches a way to erase somebody else's.

## Decision: composition stays deferred, as it did for Phase 9

No `Deployment` field, no `composition.py` wiring, and no API or CLI surface —
`prompts/10-batch.md` requires none, and an inspection test refuses the words
`batch`, `bulk`, and `csv` in every request-facing module. Wiring a subsystem
nobody may yet run only creates a path.

Before it is wired: the Phase 8 human deployment gate; an operator source for
the approved-account record; a scheduler that actually runs `RetentionService`
with the `batches` and `job_store` collaborators set, since the retention
operations exist and nothing invokes them periodically; and the Phase 7 ASGI
stop conditions, of which **request body size** becomes load-bearing the moment
an upload exists — a body limit must be enforced *while* the body is read, which
is middleware and not `parse_batch_csv`'s byte bound on a value already in
memory.

## Consequences

- A batch is exactly as safe as a single check, because it *is* single checks.
- One domain cannot take the workers, and no destination is approached faster.
- Every row is accounted for, including the ones nothing was spent on.
- Phase 9's accept-all experiment is untouched; a test refuses its name in every
  batch module, so a batch spends zero `ACCEPT_ALL_DOMAIN` budget.
- A batch resumes after its scheduler is destroyed, and a row handed over
  before the interruption is recovered rather than repeated.
- One exchanger cannot take every worker, and neither can one domain behind it.
- The submitted addresses expire on the operator's configured window through
  the central sweep, and expiry costs the rows that had not run — recorded as
  refused rather than hidden. The batch's accounting and its result outlive the
  plaintext, on their own longer window.
- The downloadable report has **no address column**. It had one, and it was
  always empty for exactly the reason above; the row number is the handle a
  submitter matches against the file they still have.
- A **whole-process** restart — both services rebuilt, only the files shared —
  recovers each row's job rather than starting a second verification, and a
  terminal child's result is readable by the new process.
- Work that was *in flight* at the moment of death is not re-executed. It is
  visible, accounted, and reported as not final; resuming it needs the durable
  queue `docs/requirements.md` section 15 defers to the service-active profile.
- Fairness is over **first-approached** exchangers, after the blocked-exchanger
  filter. A pre-recipient fallback reaches a host the scheduling decision could
  not have known about.
- No bulk execution has been performed and none is authorized.
