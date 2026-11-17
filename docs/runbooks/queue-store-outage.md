# Runbook: queue/store outage

Covers *restore queue/store* from `docs/operations.md` section 4, and the `rate-limit storage failure`, `queue growth`, and `deletion job failure` alerts from section 3.

The queue and the store hold active jobs, rate-limit counters, and retention state. When they are unavailable, the passive API must stay available (`docs/architecture.md` section 5), and every control that depends on the store fails closed, refusing work.

## 1. When this fires

- The store or queue is unreachable, slow, or returning errors.
- Queue depth grows without being drained.
- `QuotaStoreUnavailable` or rate-limit storage failures appear in the metrics.
- The retention sweep cannot run (see also [privacy-deletion.md](privacy-deletion.md)).
- Active submissions are refused and nobody threw a switch.

## 2. Do this now

1. Confirm the passive API still answers, for example with `emailcheck ADDRESS` against the deployment or a passive API request. Passive checks share no state with the queue. If passive checks are also down, this is a service outage, and the isolation property has failed; record it as a defect.
2. Stop feeding the queue: `AdminControl.set_active_probing(False)`. The global switch stops enqueueing and the worker together. Active submissions are refused, which is the intended and honest behavior.
3. Leave the fail-closed behavior alone. When the quota store is unavailable, admission refuses, because a rate limiter that cannot count is not a rate limiter.

## 3. Then diagnose

1. Find which component is failing: the queue, the job store, the quota store, or the cache. They fail and recover differently.
2. Decide whether it is capacity or availability. `QuotaStoreUnavailable` because the budget table is full is a sizing problem; a connection error is an availability problem.
3. Check the backlog size and the age of the oldest job. Jobs older than their retention window should expire, not run; nobody is still waiting for a two-day-old answer.
4. Confirm the retention sweep can run once the store is back. An outage extends every retention in `docs/privacy.md` section 3, and the overrun does not clear itself.
5. Restore the component through the ordinary operational path for whatever backs it. This project has no special recovery mode.

## 4. Do not

- Do not disable rate limiting to get work flowing while the quota store is down. This is the most likely wrong action here; the refusals are the safety property, not the symptom.
- Do not bypass admission, run the worker against the queue directly, or write jobs into the store by hand. Admission is where the kill switches, quotas, and abuse budgets are checked, and going around it skips all three.
- Do not drain the backlog faster than the configured pacing once the store returns. A recovered queue emptying at speed is a burst of connections to remote hosts that looks exactly like the threat in `docs/threat-model.md`. Resume at the normal rate.
- Do not raise per-domain or per-MX rates, or add workers expecting more throughput; more workers must not mean higher per-domain or per-MX rates (`docs/operations.md` section 5).
- Do not extend retention windows to fit the backlog.
- Do not retry queued verifications with more recipients per session or a second `RCPT TO` to save connections.
- Do not delete queued jobs to clear an alert without recording what was discarded; they are callers' submissions.

## 5. Record and escalate

Record:

- which component failed, when it started, and when it recovered (UTC);
- whether the passive API stayed available throughout, stated explicitly either way;
- how many submissions were refused and how many queued jobs were affected;
- whether any retention window was exceeded because the sweep could not run;
- whether any caller was told.

Escalate to the incident owner if the passive API went down, a retention window was exceeded, or the backlog was discarded.

## 6. Restoring

1. Bring the store back and confirm that quota counters can be read and written.
2. Run the retention sweep before resuming work, so expired records are cleared and the overrun is bounded.
3. Reconcile jobs the stopped process left behind (section 7).
4. Re-enable probing with `AdminControl.set_active_probing(True)`.
5. Watch queue depth, policy blocks, and timeouts for the first hour. If the queue fills again at once, the capacity problem is not fixed.

## 7. Jobs a stopped process left unfinished

A restarted process does not resume interrupted work, by design. The job store keeps job state but is not a durable execution queue, and the executor dies with its process. A `pending`, `running`, or `retry_scheduled` row found after a restart has nothing that will advance it, and it must never be re-run: a `running` row may already have issued its one `RCPT TO`, and this cannot be known (ADR 0019).

The admission field shows how a `pending` row got there. `claimed` means the job identity exists but no executor call was authorized. `handoff_committed` means the job irrevocably used its one handoff, whether the executor accepted it or the process vanished around the call. Neither is replayed. A definite executor refusal is already terminal (`failed` / `admission_failed`) and reconciliation does not return it.

`JobService.recover_interrupted(before=…, limit=…)` ends each such row as `failed` with the `interrupted` category, an operational state with no status, because "we do not know whether we contacted the recipient" is a fact about this service, not about a mailbox. Callers polling those jobs get a terminal answer.

Nothing runs it automatically. Run it deliberately, like the retention sweep, and only under two conditions:

- `before` is a real cutoff. Pass a time comfortably older than the longest verification this deployment allows; an hour is ample against a 30-second total deadline. Without a cutoff, a scan of a store shared with a live replica would declare that replica's running jobs dead. The call also skips rows whose handoff the calling service owns; a row merely loaded from another process's state is not owned.
- Run it once, from one place. Its effect is idempotent, but two operators running it on different replicas at once is what the cutoff makes safe, not something to rely on.

The report has four counts. Record `unsafe_to_replay`: the number of interrupted operations that may already have contacted a recipient, which tells you whether the incident touched anyone else's mail server.

Do not re-submit those addresses automatically to "finish the batch". A caller may re-submit with a new idempotency key if they choose; that is their decision and their budget, and it appears as a new job instead of a silent second probe.
