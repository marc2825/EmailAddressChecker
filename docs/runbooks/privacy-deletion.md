# Runbook: privacy deletion

Covers `docs/operations.md` section 4's *delete user data*, and the
`retention deletion tested` deployment gate in section 1.

Two situations bring you here: a scheduled sweep that failed, and a person or
account asking for their data to be deleted. The procedure is nearly the same,
because the deletion path is the same one.

## 1. When this fires

- A data subject or an account asks for deletion.
- `docs/operations.md` section 3's `deletion job failure` alert fires, or the
  `deletion_failure` metric is non-zero.
- The retention sweep has not run, or `DeletionReport` keeps reporting that more
  remain across many runs.
- You are testing the `retention deletion tested` gate before the beta.

## 2. Do this now

### If a sweep is failing

Deletion failure is the one failure this project deliberately does **not**
propagate: `application/retention.py` counts and audits it rather than raising,
because a sweep that raised into a scheduler would stop the schedule and turn
one failed run into an indefinite retention. So the alert is the only thing
telling you, and it needs acting on rather than acknowledging.

1. Read the audit trail for the deletion events and the `deletion_failure` and
   `deletion_removed` metrics. Establish whether *nothing* is being deleted or a
   *subset* is failing.
2. If the store is unavailable, this is the store outage:
   [queue-store-outage.md](queue-store-outage.md). Come back here afterwards.
3. Do not extend the retention window to make the backlog fit. The window is a
   commitment in `docs/privacy.md` section 3, not a capacity setting.

### If somebody asks for deletion

1. Confirm the request comes from the account that submitted the data, through
   an authenticated channel. A deletion request is also a plausible pretext for
   getting somebody else's records removed.
2. Run the account-requested deletion path and record the count removed.
3. Confirm the plaintext request records and the finished job records are gone
   for that account, and that the sweep reports nothing remaining for it.

## 3. Then diagnose

Three retentions are kept **separate** by `application/retention.py`, and
knowing which one you are looking at prevents most of the confusion here:

| What | Lifetime | Governed by |
| --- | --- | --- |
| A cached verdict | its own `expires_at` | ADR 0015 / `docs/requirements.md` section 13 |
| A finished job record | `job_retention_seconds` (24 hours by default) | `docs/privacy.md` section 3 |
| An audit event | as long as the ring holds it | `application/admin.py` |

The TTLs in section 13 price *evidence freshness*. Using one as a job or log
retention would apply a deliverability rule to a privacy question, which is why
they are three settings and not one.

Check also what is genuinely present. This deployment retains **no raw protocol
text** — `docs/privacy.md` sections 2 and 3 make that the default, and Phase 4
keeps a bounded sanitized diagnostic rather than a raw reply. If somebody asks
you to delete raw SMTP transcripts, the answer is that there are none, and that
is a stronger answer than deleting them would be.

Aggregate metrics are deliberately not deleted with the plaintext: they are
counted by domain, MX, and reason and contain no address. `docs/privacy.md`
section 7 lists the separation as a requirement.

## 4. Do not

- **Do not disable or lengthen retention to work around a deletion failure.**
  The failure is that data is being kept longer than promised; the fix is not to
  promise less.
- **Do not bypass the bounded sweep** by issuing an unbounded delete against the
  store. The batch limit exists so a sweep does not hold a write lock across the
  whole table; an unbounded delete during an incident is how a deletion becomes
  an outage.
- Do not copy records out of the store "to investigate later". A copy made
  during a deletion incident is data outside every retention this document
  describes.
- Do not write a complete address into the incident log, the ticket, or your
  own notes while handling a deletion request. `AGENTS.md` forbids logging one
  in normal application logs, and a deletion ticket is the worst possible place
  to create the first exception.
- Do not delete audit events to make a deletion look complete. The audit trail
  is what proves the deletion happened.
- Do not treat a deletion request as a reason to re-probe anything.

## 5. Record and escalate

Record:

- who asked, through which authenticated channel, and when (UTC);
- what was deleted, as counts by category;
- the audit event identifiers for the deletion;
- for a failure: what failed, for how long, and how many records were affected.

Escalate to the incident owner if data was retained beyond its stated lifetime,
if a deletion request could not be satisfied, or if you cannot establish what
was retained. `docs/privacy.md` closes by requiring legal review before
commercial or cross-border production use; a retention overrun is exactly the
kind of fact that review will need.

## 6. Testing this gate before the beta

The `retention deletion tested` gate is satisfied by performing this procedure,
not by reading it:

1. Create expired records in the deployment store — ordinary job records, aged
   past `job_retention_seconds`.
2. Run the sweep.
3. Confirm the records are gone, the audit event exists, and
   `deletion_removed` reflects the count.
4. Confirm a *failure* is also handled: make the store unavailable, run the
   sweep, and confirm it counts and audits the failure rather than raising.
5. Record who did this and when, in [../readiness-checklist.md](../readiness-checklist.md).

## Account-requested deletion, as an operation

Since Remediation C this is one call rather than a list of manual steps:

```python
report = await stack.delete_account_data(account_id)
assert report.complete
```

It advances the account's durable deletion generation, suspends the account
locally, clears this process's registry state, and empties the **verdict and job
stores** of everything that account owns — every dataset fingerprint and every
ruleset, not only the current ones.

**It does not erase batch data in the shipped stack**, because Phase 10 is not
composed and the stack holds no batch store. The capability exists: a deployment
that wires the batch subsystem must pass its `BatchStore` to the same deletion
service, and until it does, batch data is that deployment's own responsibility.

**A deployment with no `account_state_path` no longer starts.** Configuring a
persistent store without the deletion authority is refused at composition, so
the case where this operation had nothing to raise a barrier with cannot reach
production. If it is somehow reached anyway, the operation returns
`complete=False` with `failed_stores=("account_state",)` and deletes nothing.

**Workers on other replicas are already handled.** The generation is advanced
before any row is deleted, and is then written into each store as a fence that
every account-owned write is checked against inside its own transaction — so
work admitted anywhere before that moment is refused when it tries to write,
including work that had already passed its own check. You do not need to stop
the other replicas first, and the fence survives a restart of all of them.

**A busy store can make this fail, and that is deliberate.** Raising a fence is
a write, so a deletion contending with a long-running write on the same database
may time out. It then reports `complete=False` naming that store, having deleted
nothing from it. Retry; the account's data is still there and no stale replica
can add to it.

**All the stores must share one authority.** Each is bound to the `accounts.db`
it was first opened under and refuses to open under another. If start-up fails
naming a different account-state authority, a replica has been pointed at the
wrong file — fix the configuration rather than repointing the store, because a
deletion recorded by one authority is invisible to the other. A store file from
an older schema version is refused for the same reason and needs a deliberate
migration, not a new authority.

**Check `report.complete`.** There is no cross-store transaction. If a store was
unreachable, `failed_stores` names it, `complete` is `False`, and the account is
**not** fully deleted. Fix the store and run the operation again; it is safe to
repeat and the account stays suspended in the meantime.

**What it does not do.** It is logical deletion: rows are removed and retained
plaintext is set to `NULL`. SQLite free pages, the write-ahead log, and any
backup taken before the run are outside what this project touches. If a request
requires those, it requires storage-level or backup-level erasure, which is an
infrastructure procedure rather than an application one.

Record the returned counts and `failed_stores` in the incident notes. The report
carries no address, job identifier, idempotency key, or path, so it is safe to
paste as it stands.
