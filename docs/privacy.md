# Privacy and data handling

## 1. Data categories

- submitted address;
- normalized domain;
- target HMAC;
- account and API-key identifiers;
- DNS evidence;
- SMTP structured evidence;
- bounded raw diagnostic;
- timestamps and latency;
- abuse features.

## 2. Data minimization

Default behavior:

- process the plaintext address only for the active job;
- redact in ordinary logs;
- use HMAC for correlation;
- aggregate metrics by domain/MX and reason;
- do not keep raw protocol text unless debugging retention is explicitly enabled.

## 3. Retention defaults

- plaintext request: 24 hours;
- encrypted raw SMTP diagnostic: 24 hours. **Nothing is retained today**, so
  there is nothing to encrypt: Phase 4 keeps a bounded sanitized diagnostic and
  no raw reply, and section 2's default is not to keep raw protocol text unless
  debugging retention is explicitly enabled. Implementing the encryption needs a
  cryptographic dependency, its own ADR, and a Phase permitted to install one;
  ADR 0016 records it as a Phase 8 stop condition. The privacy-preserving half
  of this line holds by absence, which is the stronger form;
- result history: disabled by default or 30 days when explicitly enabled;
- HMAC and aggregate audit data: policy-defined, with deletion support;
- account and billing records: separate policy.

## 4. Redaction

Examples:

```text
alice@example.com → a***@example.com
a@example.com     → *@example.com
```

Do not rely on redaction as anonymization. Domain and local-part patterns can
remain identifying.

## 5. HMAC

Use a secret key distinct from encryption keys.

```text
HMAC-SHA-256(key, canonical_input_version || normalized_target)
```

Store the canonicalization version. A plain unsalted hash is not sufficient
because addresses are guessable.

`security/identifiers.py` implements this. The version is part of the HMAC
**input** rather than a column beside it, so two canonicalizations cannot
collide onto one digest. Adding it changed every digest this project produces,
once, and `adapters/storage/sqlite_store.py` moved its schema version in the
same change even though no column did: a store whose rows have all become
unreachable looks like a cache that never hits, which is a worse failure than
one that refuses to open. ADR 0016.

## 6. Access

- raw evidence administrator-only;
- account users see their safe normalized results;
- support access is logged;
- secret material is never returned;
- API errors do not contain raw remote replies.

## 7. Deletion

**Scheduled since Remediation B.** `RetentionScheduler` runs the sweep on
`RetentionSettings.interval_seconds` for every profile that owns persistent
service state, and `VerificationStack.run_retention` is the operator trigger for
the same operation. The effective deletion time is therefore the retention
cutoff **plus at most one scheduling interval**; the windows below are cutoffs,
not wall-clock guarantees.

**Account-requested deletion is implemented.**
`VerificationStack.delete_account_data(account)` runs
`AccountDeletionService`. Deletion is **by owner**, never by target: two
accounts checking one mailbox own two records.

**What the shipped stack erases**, because capability and composition are not
the same thing:

| Store | Implemented | Composed today |
|---|---|---|
| verdict store — every dataset fingerprint and ruleset | yes | yes |
| job store — jobs, idempotency bindings, result projections, retry and admission state | yes | yes |
| `JobService` registry, in this process | yes | yes |
| batch store — batches, rows, retained plaintext, artifacts | yes | **no** |

The batch row is the one to read carefully. `AccountDeletionService` accepts a
`BatchStore` and deletes from it, and that path has its own tests — but Phase 10
is deliberately not wired into `composition.py`, so the shipped
`VerificationStack` holds no batch store and `delete_account_data` has none to
erase. When the batch subsystem is composed its store must be passed to the same
deletion service; until then, a deployment that runs batches has wired them
itself and is responsible for the same.

It does not wait for the retention scheduler. Retention is a window; this is an
operator action, and it takes effect when it is invoked.

**No cross-store transaction exists and none is claimed.** Three SQLite files
and one registry cannot commit together, so each store is attempted
independently and `AccountDeletionReport.failed_stores` names any that held on.
`complete` is `False` in that case: an operator told "deleted" while one store
still has data is worse off than one told which store to retry. Re-running the
operation is safe and is the documented recovery.

**Work already running, including on another replica.** The authority is a
**durable account generation** in `AccountStateStore`, shared by every process:
work records the generation it was admitted under, deletion advances it before
a single row is removed, and every persistent write for that account is refused
unless its generation is still current.

That ordering is the point. Deleting first and raising the barrier afterwards
leaves a window for a late write to land between the two steps — and a barrier
held only in the deleting process's memory closes nothing at all across
replicas, which is how a second `JobService` came to recreate an account after
the operator had been told the deletion was complete.

**And the generation alone is a check, not a fence.** Reading it from
`accounts.db` and then writing `jobs.db` is two transactions, and a replica
paused between them recreated a job row, a cached verdict, and an idempotency
binding after this operation reported success. So the deletion also writes the
new generation **into each store it is about to empty**, and every
account-owned write is conditional on that value inside the same transaction as
the write. The two contend for one database's write lock, so a stale write
either lands before the fence and is deleted, or waits and is refused. A store
whose fence cannot be raised is not emptied at all — the report names it, and
the operator retries.

Two configuration rules follow, and both fail at start-up rather than during a
deletion:

- a deployment that configures `store_path` or `job_store_path` must configure
  `account_state_path`; a persistent service with no authority permitted every
  write, including the ones that put a deleted account back;
- each persistent store is bound to the `accounts.db` it was first opened under
  and refuses another, because two replicas sharing one store while trusting
  different authorities is a deletion neither can see.

The account suspension and `JobService`'s in-process tombstone remain and are
**local cleanup and latency, not the cross-replica authority**: each lives in
one process's memory. A deployment with no configured `account_state_path` no
longer starts at all.

A generation rather than a permanent tombstone, because this is
account-*requested* deletion: a later legitimate request reads the new
generation and works normally, with no operator step to remember. The
suspension this operation also sets is the operator's own switch and is
separately reversible.

**Operator-only.** There is no route. `docs/architecture.md` carries "no public
administrative interface" as a stop condition, and no request field names an
account other than the authenticated one.

**Logical deletion, not physical erasure.** A sweep deletes rows and sets
retained plaintext to `NULL`. It does not overwrite SQLite free pages, rewrite
the write-ahead log, or reach a backup taken before it ran. Anyone who needs
those guarantees needs storage-level or backup-level erasure, which this project
does not perform and does not claim.

`application/retention.py` implements this, and keeps **three retentions
separate**: a cached verdict expires on its own `expires_at` (ADR 0015, from
`docs/requirements.md` section 13), a finished job record lives
`job_retention_seconds` — this document's 24 hours — and an audit event lives
as long as the ring holds it. Section 13's TTLs price *evidence classes*, so
using one as a job or log retention would apply a deliverability-freshness rule
to a privacy question.

A sweep is bounded per run and reports whether more remain, so a backlog is
cleared over several runs rather than in one statement holding a write lock. A
failure is counted and audited rather than propagated: a sweep that raised into
a scheduler would stop the schedule.

Implement and test:

- scheduled expiry;
- account-requested deletion;
- API-key revocation;
- deletion of plaintext separate from aggregate metrics;
- deletion failure alerting.

Obtain legal review before commercial or cross-border production use.
