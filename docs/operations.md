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

`application/admin.py` implements every switch above, with an audit trail
behind each one: each goes through `AdminControl._record`, which appends an
`AuditEvent` naming the operation, a digest of the subject, and whether the
state actually changed.

**Two things an earlier version of this section listed are not switches**, and
an operator reaching for them during an incident would not find them. They are
here as what they actually are, so the distinction is legible before it is
needed:

*Automatic retries are bounded structurally, not toggled.* `MAX_RETRIES` is 1,
and `docs/requirements.md` section 14's retry is available **only** to an
attempt that provably did not reach the recipient stage —
`RecipientTouch.replay_is_safe`, which `application/jobs.py` checks before
scheduling one. A safe pre-recipient retry (a DNS failure, a refused banner) can
still happen; a recipient-stage replay cannot, whatever an operator does. There
is nothing to disable, which is stronger than a switch somebody has to remember
to throw. To stop retries along with everything else, use the global
active-checks switch.

*Raw evidence retention is configuration and scheduling, not a runtime toggle.*
What is kept and for how long is `RetentionSettings` — `job_retention_seconds`,
`interval_seconds`, and `batch_limit` — read at composition, with
`application/retention.py` sweeping on that interval and calling
`AdminControl.record_deletion`, which audits the sweep under the `run_deletion`
event kind. That event kind is the audit record of a sweep having run; it is not
an operator command, and no method named `run_deletion` exists. Erasing one
account's data on request is `AccountDeletionService`
(`docs/runbooks/privacy-deletion.md`), which is a separate operation with its
own report and is not a retention setting. Changing what is retained means
changing the deployment's settings and restarting it.

**The administrative control surface publishes no public application route.**
`application/admin.py` holds no transport, and no request surface reaches it:
binding a control that can disable a security mechanism to the public
application is what "non-public interface" exists to prevent, and
`docs/architecture.md` carries that as a stop condition on the ASGI binding.

**A destination switch is canonicalized before it is stored.** A domain or
exchanger block goes through the same `HostName` identity the mail route uses —
case-folded, trailing dot removed, IDNA-encoded through Phase 1's UTS-46
encoder — so `EXAMPLE.TEST`, `example.test.`, and `bücher.test` are one block
rather than three that each match nothing. Before Remediation B they were stored
as typed and compared against a canonical route, so each of those three read as
thrown and blocked nothing. An unusable host name is refused at the boundary
rather than stored inert. Account and API-key subjects are **not** normalized:
those are opaque identifiers, and two spellings really are two accounts.

**A lab-active deployment additionally names what it may contact.**
`Deployment.lab_destination_allowlist` is the exchanger inventory
`docs/requirements.md` section 15 requires, canonicalized the same way. It
restricts and grants nothing: a block still beats it, and an allowlisted host
still passes the destination policy, the peer check, and TLS verification.

The global switch stops the enqueue **and** the worker. A switch that stopped
only new work would leave the queue connecting to remote hosts after an operator
said stop, which is the moment they most need it to have worked.

### Sizing the layered budgets

Every limit in `QuotaSettings` counts **verification budget units**, not API
requests. One submitted active check spends the caller's layers twice — once for
the submission's passive pass and once for the active verification — and a third
time if `docs/requirements.md` section 14's one retry runs. A passive check
spends one unit.

So `per_account = 5000` is roughly 2500 active submissions per window, not 5000.
Size these as spends. ADR 0016 decision 5c has the table.

The "third time" is now rarer than it reads: ADR 0019 permits an automatic retry
only for a first attempt that provably did not reach the recipient stage, and in
this build that is DNS SERVFAIL alone. Size for it anyway — the budget must
cover the worst case, and the retry that does run costs a full verification.

### Retention

`RetentionService` is now **scheduled**. `VerificationStack.start` starts a
`RetentionScheduler` for every profile that owns persistent service state —
local-passive gets none, because it accepts no job and owns no batch — and
`aclose` stops it. `VerificationStack.run_retention` is the operator trigger and
runs the same sweep, so a timer and an operator cannot get different policy.

`RetentionSettings.interval_seconds` is operator configuration: fifteen minutes
by default, refused below one minute or above one day, and reachable from no
request, flag, or admin call. **The effective deletion time is the retention
cutoff plus at most one interval**, not the cutoff exactly.

A sweep is logical deletion — rows removed, retained plaintext set to `NULL`.
Secure physical erasure of SQLite free pages, the write-ahead log, or any backup
taken before the sweep is outside what this project does; see
[privacy.md](privacy.md).

One failing store no longer suppresses the others: each cleanup runs under its
own handler and `DeletionReport.failed_stores` names the categories that failed,
in this project's vocabulary rather than an exception's text. A failed sweep
does not end the schedule.

### Restarts and interrupted jobs

Persistent job state and a durable execution queue are different things, and
only the first exists. A process that stops does not resume its in-flight
verifications when it comes back, because a `running` job may already have
issued its one `RCPT TO` and re-running it would contact one recipient twice.
Reconciling those rows is an operator action —
`JobService.recover_interrupted` — and
[runbooks/queue-store-outage.md](runbooks/queue-store-outage.md) section 7 has
the procedure and the two conditions on running it.

Executor admission uses an irrevocable durable token before the executor call.
A definite refusal preserves the same JobId as an operational failure; a crash
on either side of the call is never treated as permission for another replica
to submit the job again. This is conservative handoff safety, not a durable
queue or exactly-once execution claim.

## 3. Alerting

Alert on:

- sudden rise in policy blocks;
- timeout or tarpit increase;
- authentication bypass attempts;
- rate-limit storage failure;
- queue growth;
- deletion job failure;
- sender IP blocklist appearance;
- remote abuse complaint;
- unsafe destination resolution attempt.

## 4. Runbooks

They exist, in [runbooks/](runbooks/). Seven files cover these nine topics —
[runbooks/README.md](runbooks/README.md) carries the mapping and the rule that
outranks all of them:

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

Two topics share a runbook with a neighbour rather than getting a file of their
own: revoking a caller's key is the per-account form of the kill switch, and
rolling a ruleset back is what a false `invalid` traced to a deployment calls
for. Both are named procedures inside those files.

**None of these has been executed.** `global kill switch tested` and
`retention deletion tested` in section 1 are verified by *performing*
[stop-active-checks.md](runbooks/stop-active-checks.md) and
[privacy-deletion.md](runbooks/privacy-deletion.md) on the deployment, once,
before the beta.

## 5. Capacity

Remote etiquette dominates throughput. Increasing workers must not increase
per-domain or per-MX rates. Fair scheduling should prevent one domain from
occupying all worker capacity.

The caller-side half of that is `application/admission.py`'s queue share: one
principal may hold at most `queue_share` of the waiting slots, so a caller
issuing requests faster than they are served cannot make every other account's
request refuse while holding no capacity at all. The share is derived from the
queue length when it is not configured, so the property holds for a deployment
that tunes nothing.
