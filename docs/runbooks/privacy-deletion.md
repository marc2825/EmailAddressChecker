# Runbook: privacy deletion

Covers *delete user data* from `docs/operations.md` section 4, and the `retention deletion tested` deployment gate in section 1.

Two situations bring you here: a scheduled sweep that failed, or a request to delete someone's data. Both use the same deletion path.

## 1. When this fires

- A data subject or an account asks for deletion.
- The `deletion job failure` alert in `docs/operations.md` section 3 fires, or the `deletion_failure` metric is non-zero.
- The retention sweep has not run, or `DeletionReport` reports remaining rows across many runs.
- You are testing the `retention deletion tested` gate before the beta.

## 2. Do this now

### If a sweep is failing

`application/retention.py` counts and audits deletion failures instead of raising them, so that one failed run cannot stop the schedule and turn into indefinite retention. The alert is therefore the only signal; act on it.

1. Read the deletion events in the audit trail and the `deletion_failure` and `deletion_removed` metrics. Establish whether nothing is being deleted or only some records fail.
2. If the store is unavailable, follow [queue-store-outage.md](queue-store-outage.md), then come back.
3. Do not extend the retention window to fit the backlog. The window is a commitment in `docs/privacy.md` section 3, not a capacity setting.

### If someone asks for deletion

1. Confirm through an authenticated channel that the request comes from the account that submitted the data. A deletion request is also a plausible pretext for removing someone else's records.
2. Run the account deletion (see the last section) and record the counts.
3. Confirm that the account's plaintext request records and finished job records are gone and that the sweep reports nothing remaining for it.

## 3. Then diagnose

Three retentions are kept separate; knowing which one you are looking at avoids most confusion:

| What | Lifetime | Governed by |
| --- | --- | --- |
| A cached verdict | its own `expires_at` | `docs/requirements.md` section 13 (ADR 0015) |
| A finished job record | `job_retention_seconds` (24 hours by default) | `docs/privacy.md` section 3 |
| An audit event | as long as the ring holds it | `application/admin.py` |

The section 13 TTLs describe how fresh evidence is; they are never used as a job or log retention.

Check what is actually stored. No raw protocol text is kept (`docs/privacy.md` sections 2 and 3), only a bounded, sanitized diagnostic. If someone asks you to delete raw SMTP transcripts, the answer is that none exist.

Aggregate metrics are not deleted with the plaintext: they are counted by domain, MX, and reason and contain no address (`docs/privacy.md` section 7).

## 4. Do not

- Do not disable or lengthen retention to work around a deletion failure. The failure is that data is kept longer than promised; the fix is not to promise less.
- Do not bypass the bounded sweep with an unbounded delete against the store. The batch limit keeps a sweep from holding a write lock over the whole table; an unbounded delete during an incident turns a deletion into an outage.
- Do not copy records out of the store "to investigate later". A copy made during a deletion incident escapes every retention described here.
- Do not write a complete address into the incident log, a ticket, or your own notes while handling a deletion request.
- Do not delete audit events to make a deletion look complete; the audit trail proves the deletion happened.
- Do not treat a deletion request as a reason to probe anything again.

## 5. Record and escalate

Record:

- who asked, through which authenticated channel, and when (UTC);
- what was deleted, as counts by category;
- the audit event identifiers;
- for a failure: what failed, for how long, and how many records were affected.

Escalate to the incident owner if data was kept beyond its stated lifetime, a deletion request could not be met, or you cannot establish what was kept. `docs/privacy.md` requires legal review before production use, and a retention overrun is exactly what that review needs to know.

## 6. Testing this gate before the beta

The `retention deletion tested` gate is met by performing this procedure:

1. Create expired records in the deployment store: ordinary job records older than `job_retention_seconds`.
2. Run the sweep.
3. Confirm the records are gone, the audit event exists, and `deletion_removed` shows the count.
4. Make the store unavailable, run the sweep, and confirm it counts and audits the failure instead of raising.
5. Record who did this and when in [../readiness-checklist.md](../readiness-checklist.md).

## Account deletion

```python
report = await stack.delete_account_data(account_id)
assert report.complete
```

The call advances the account's durable deletion generation, suspends the account locally, clears this process's registry, and empties the verdict and job stores of everything the account owns, for every dataset fingerprint and ruleset.

- Batch data is not erased in the shipped stack, which has no batch store. A deployment that composes active batch must pass its `BatchStore` to the same deletion service; until it does, batch data is that deployment's responsibility.
- A deployment with a persistent store but no `account_state_path` refuses to start. If that state is reached anyway, the call returns `complete=False` with `failed_stores=("account_state",)` and deletes nothing.
- Other replicas need not be stopped. The generation is advanced before any row is deleted and written into each store as a fence that every account-owned write checks inside its own transaction, so work admitted anywhere earlier is refused when it tries to write. The fence survives restarts.
- A busy store can make the call fail. Raising a fence is a write, so it can time out against a long write on the same database; the call then reports `complete=False` for that store, having deleted nothing there. Retry; no stale replica can add data in the meantime.
- All stores must share one authority. Each is bound to the `accounts.db` it was first opened with and refuses another. If start-up fails naming a different authority, a replica points at the wrong file: fix the configuration, do not repoint the store, because a deletion recorded under one authority is invisible to the other. A store with an older schema is refused and needs a deliberate migration.
- Check `report.complete`. There is no cross-store transaction; if a store was unreachable, `failed_stores` names it and the account is not fully deleted. Fix the store and run the call again. It is safe to repeat, and the account stays suspended meanwhile.
- This is logical deletion: rows are removed and retained plaintext is set to `NULL`. SQLite free pages, the write-ahead log, and earlier backups are not touched; erasing those is an infrastructure procedure.

Record the returned counts and `failed_stores` in the incident notes. The report contains no address, job identifier, idempotency key, or path, so it can be pasted as it is.
