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
- one target MX;
- automatic retries;
- raw evidence retention.

`application/admin.py` implements every switch above, with an audit trail
behind each one. It publishes **no route**: binding an interface that can
disable a security control to the public application is what "non-public
interface" exists to prevent, and `docs/architecture.md` carries that as a stop
condition on the ASGI binding.

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
