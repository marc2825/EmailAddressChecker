# Operations

## 1. Deployment gates

Do not enable service-active until all are true:

- static public IP;
- outbound port 25 confirmed;
- PTR configured;
- EHLO forward DNS aligned;
- SPF configured;
- sender mailbox monitored;
- abuse and postmaster mailboxes monitored;
- hosting terms reviewed;
- global kill switch tested;
- rate limits tested;
- private-network egress blocked;
- retention deletion tested;
- incident owner assigned.

## 2. Kill switches

At minimum:

- global active checks;
- one sender identity;
- one account/API key;
- one target domain;
- one target MX.

`application/admin.py` implements every switch above. Each one goes through `AdminControl._record`, which appends an `AuditEvent` naming the operation, a digest of the subject, and whether the state changed.

- The global switch stops both new enqueues and the worker, so nothing keeps contacting remote hosts after an operator says stop.
- A blocked domain refuses the whole verification; no exchanger for that domain is approached. A blocked exchanger is removed from the plan, and another unblocked exchanger for the same domain may still be used. The domain check runs before the candidates are filtered. The exchanger block is exact: every candidate is checked, not only the preferred one.
- Domain and exchanger blocks are canonicalized like mail routes (case-folded, trailing dot removed, IDNA-encoded), so `EXAMPLE.TEST`, `example.test.`, and `bücher.test` are each one block. An unusable host name is refused instead of stored. Account and API-key subjects are opaque and not normalized.
- A lab-active deployment also lists what it may contact in `Deployment.lab_destination_allowlist`, canonicalized the same way. It only restricts: a block still wins, and an allowlisted host must still pass the destination policy, the peer check, and TLS verification.
- No public application route reaches these controls. `application/admin.py` has no transport, and mounting it publicly is forbidden by the stop conditions in `docs/architecture.md`.

Two things are not switches:

- Automatic retries are limited by design. `MAX_RETRIES` is 1, and the retry in `docs/requirements.md` section 14 is available only to an attempt that provably never reached the recipient stage (`RecipientTouch.replay_is_safe`, checked by `application/jobs.py`). A pre-recipient retry, such as after a DNS failure, can still happen; a recipient-stage replay never can. To stop retries along with everything else, use the global switch.
- Retention is configuration, not a runtime switch. `RetentionSettings` (`job_retention_seconds`, `interval_seconds`, `batch_limit`) is read when the stack is composed, and `application/retention.py` sweeps on that interval and audits each sweep through `AdminControl.record_deletion` under the `run_deletion` event kind. That event records a sweep; there is no `run_deletion` command. Deleting one account's data on request is `AccountDeletionService` (`docs/runbooks/privacy-deletion.md`). Changing what is kept means changing the settings and restarting.

### Sizing the layered budgets

Every limit in `QuotaSettings` counts verification budget units, not API requests:

| Operation | Caller layers | Destination layers |
|---|---|---|
| A submission's passive pass | 1 | — |
| The first active verification | 1 | 1 |
| The one automatic retry | 1 | 1 |
| A passive check | 1 | — |

`per_account = 5000` is therefore about 2,500 active submissions per window, not 5,000. Retries are rare, because one is allowed only for a first attempt that never reached the recipient stage (in this build, only DNS SERVFAIL), but size for the worst case. Cache hits are charged too.

The per-MX volume budget charges the preferred exchanger, so a verification that falls through to the next exchanger under-charges it by at most `max_attempts - 1`; the domain budget above it still covers the total. The per-MX block is exact (section 2).

Abuse indicators only report. Suspending a caller is an operator decision through `application/admin.py`, never automatic, because a blunt heuristic that suspended automatically could be triggered by someone else on a caller's behalf.

### Retention

`VerificationStack.start` starts a `RetentionScheduler` for every profile that keeps persistent service state; local-passive gets none, because it accepts no job and owns no batch. `aclose` stops it, and `VerificationStack.run_retention` runs the same sweep on demand.

`RetentionSettings.interval_seconds` defaults to fifteen minutes, must be between one minute and one day, and cannot be changed by any request, flag, or admin call. Data is deleted at most one interval after its retention cutoff.

A sweep deletes logically: rows are removed and retained plaintext is set to `NULL`. It does not securely erase SQLite free pages, the write-ahead log, or backups taken earlier; see [privacy.md](privacy.md). Each store is cleaned under its own handler, so one failure does not stop the others; `DeletionReport.failed_stores` names the failed categories, and a failed sweep does not stop the schedule. Each sweep removes a bounded number of rows and reports whether more remain.

### Restarts and interrupted jobs

Job state is persistent; the execution queue is not. A restarted process does not resume in-flight verifications, because a `running` job may already have issued its one `RCPT TO`, and running it again would contact the recipient twice. Reconciling those jobs is an operator action, `JobService.recover_interrupted`; [runbooks/queue-store-outage.md](runbooks/queue-store-outage.md) section 7 gives the procedure and its two conditions.

Before calling the executor, the service writes an irrevocable, durable handoff token. A definite refusal keeps the same job ID and records an operational failure. A crash on either side of the call is never taken as permission for another replica to submit the job again. This is conservative handoff safety, not a durable queue or exactly-once execution.

## 3. Alerting

Alert on:

- a sudden rise in policy blocks;
- more timeouts or tarpitting;
- attempts to bypass authentication;
- rate-limit storage failures;
- queue growth;
- deletion job failures;
- the sender IP appearing on a blocklist;
- a remote abuse complaint;
- an attempt to resolve an unsafe destination.

Metric labels are closed enumerations, so there are no per-domain metric series. Analyse per-domain rates from the redacted operator events instead.

## 4. Runbooks

The runbooks are in [runbooks/](runbooks/). Seven files cover nine topics; [runbooks/README.md](runbooks/README.md) maps them and states the rule that overrides all of them.

| Topic | Runbook |
| --- | --- |
| disable active probing | [stop-active-checks.md](runbooks/stop-active-checks.md) |
| rotate compromised API key | [stop-active-checks.md](runbooks/stop-active-checks.md) |
| disable sender identity | [sender-identity-incident.md](runbooks/sender-identity-incident.md) |
| respond to abuse complaint | [abuse-complaint.md](runbooks/abuse-complaint.md) |
| investigate false invalid | [false-invalid-investigation.md](runbooks/false-invalid-investigation.md) |
| roll back ruleset | [false-invalid-investigation.md](runbooks/false-invalid-investigation.md) |
| investigate destination SSRF alert | [destination-ssrf-alert.md](runbooks/destination-ssrf-alert.md) |
| delete user data | [privacy-deletion.md](runbooks/privacy-deletion.md) |
| restore queue/store | [queue-store-outage.md](runbooks/queue-store-outage.md) |

Revoking a key is the per-account form of the kill switch, and rolling back a ruleset is the response to a false `invalid` traced to a deployment, so those two topics are procedures inside neighbouring runbooks.

None of the runbooks has been executed yet. The gates "global kill switch tested" and "retention deletion tested" in section 1 are met by performing [stop-active-checks.md](runbooks/stop-active-checks.md) and [privacy-deletion.md](runbooks/privacy-deletion.md) once on the deployment before the beta.

## 5. Capacity

Being a polite remote client limits throughput more than anything else. Adding workers must not raise per-domain or per-MX rates, and fair scheduling keeps one domain from occupying every worker.

On the caller side, `application/admission.py` lets one principal hold at most `queue_share` of the waiting slots, so a caller sending requests faster than they are served cannot force every other account's request to be refused. When `queue_share` is not configured it is derived from the queue length, so a deployment that tunes nothing still has the property.
