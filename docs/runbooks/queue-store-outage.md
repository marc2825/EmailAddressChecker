# Runbook: queue/store outage

Covers `docs/operations.md` section 4's *restore queue/store* and section 3's
`rate-limit storage failure`, `queue growth`, and `deletion job failure` alerts.

The queue and the store carry active jobs, rate-limit counters, and the retention
state. When they are unavailable the correct behaviour is already defined:
`docs/architecture.md` section 5 requires the **passive API to remain
available**, and every control that depends on the store fails **closed** —
refusing work — rather than open.

## 1. When this fires

- The store or queue is unreachable, slow, or returning errors.
- Queue depth grows without being drained.
- `QuotaStoreUnavailable`, or rate-limit storage failures, appear in the
  metrics.
- The retention sweep cannot run — see also
  [privacy-deletion.md](privacy-deletion.md).
- Active submissions are being refused and nobody threw a switch.

## 2. Do this now

1. **Confirm the passive API is still answering.** This is the first check, not
   the last: passive checks share no state with the queue and must keep working.
   `emailcheck ADDRESS` against the deployment, or a passive request to the API,
   answers it. If passive is *also* down, you have a service outage rather than a
   store outage, and the isolation property has failed — that is a defect to
   record.
2. **Stop feeding the queue.** `AdminControl.set_active_probing(False)`. A queue
   that cannot be drained does not need more work put into it, and the global
   switch stops the enqueue and the worker together. Active submissions will be
   refused; that is the intended behaviour and it is honest to callers.
3. **Leave the fail-closed behaviour alone.** When the quota store is
   unavailable, admission refuses. It is meant to: a rate limiter that cannot
   count is not a rate limiter, and continuing without one would remove the
   pacing that keeps this project distinguishable from a harvester.

## 3. Then diagnose

1. Establish which component is failing — the queue, the job store, the quota
   store, or the cache. They fail differently and they recover differently.
2. Check whether the failure is capacity or availability. `QuotaStoreUnavailable`
   raised because the budget table is full is a sizing problem; a connection
   error is an availability problem.
3. Check the size of the backlog and the age of the oldest job. Jobs older than
   their retention window should be expired rather than run: a verification
   answered from a two-day-old submission is answering a question nobody is
   still asking.
4. Confirm the retention sweep can run once the store is back. A store outage
   silently extends every retention in `docs/privacy.md` section 3, and that
   overrun does not clear itself.
5. Restore the component through the ordinary operational path for whatever
   backs it. There is nothing application-specific about bringing a store back
   up, and this project does not have a special recovery mode.

## 4. Do not

- **Do not disable rate limiting to get work flowing while the quota store is
  down.** This is the single most likely wrong action in this runbook. The
  refusals are the safety property, not the symptom.
- **Do not bypass admission**, run the worker against the queue directly, or
  submit jobs by writing to the store by hand. Admission is where the kill
  switches, the quotas, and the abuse budgets are checked, and a path around it
  is a path around all three at once.
- **Do not drain the backlog faster than the configured pacing** once the store
  returns. A recovered queue emptying at speed is a burst of connections to
  remote hosts that looks exactly like the thing `docs/threat-model.md` is
  about. Resume at the normal rate and let it take the time it takes.
- Do not increase per-domain or per-MX rates, or add workers expecting more
  throughput: `docs/operations.md` section 5 is explicit that increasing workers
  must not increase per-domain or per-MX rates.
- Do not extend retention windows to accommodate the backlog.
- Do not retry queued verifications with more recipients per session or a second
  `RCPT TO` to reduce the number of connections.
- Do not delete queued jobs to clear an alert without recording what was
  discarded — those are callers' submissions.

## 5. Record and escalate

Record:

- which component failed, when it started, and when it recovered (UTC);
- whether the passive API stayed available throughout — explicitly, either way;
- how many submissions were refused and how many queued jobs were affected;
- whether any retention window was exceeded because the sweep could not run;
- whether any caller was told.

Escalate to the incident owner if the passive API did not survive, if a
retention window was exceeded, or if the backlog was discarded.

## 6. Restoring

1. Bring the store back and confirm the quota counters read and write.
2. Run the retention sweep before resuming work, so the backlog of expired
   records is cleared and the overrun is bounded.
3. Re-enable probing with `AdminControl.set_active_probing(True)`.
4. Watch queue depth, policy blocks, and timeouts for the first hour. A recovery
   that immediately re-fills the queue is a capacity problem you have not fixed
   yet.
