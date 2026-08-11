# ADR 0016: Abuse controls, privacy enforcement, and observability

## Status

Accepted. Phase 7.

## Context

`prompts/07-hardening.md` makes the service-active profile suitable for a small
closed beta. It requires layered budgets across nine dimensions, conservative
sequence indicators, privacy enforcement, bounded observability, and a
non-public administrative interface.

Phases 4 and 6 already built two control layers, and `docs/architecture.md`
recorded what they left open: the admission queue is bounded globally, so one
account can occupy it and refuse another that holds no capacity at all. Phase
6's independent review carried that as F11 and deferred it here.

The constraints are the ones every Phase has had: Python 3.12, no new
dependency, no Redis and no PostgreSQL, and no ASGI binding — so everything
below is in-process, behind a port, and replaceable by a shared implementation
without anything above the port learning which one it has.

## Decision

### 1. Three control layers, and quota is a third

| Control | Phase | Question it answers |
|---|---|---|
| `application/admission.py` | 6 | how many verifications may run *at once* |
| `adapters/system/rate_limit.py` | 4 | how *fast* one destination may be approached |
| `application/abuse.py` | 7 | how *many* one caller may ask for in a window |

They are not merged and none is re-keyed. Re-keying Phase 4's per-domain token
bucket onto the account would give every account its own destination pacing,
which is the opposite of protecting a destination — `docs/architecture.md` says
so for Phase 6 and it is still true. `prompts/07-hardening.md` lists "global
concurrency" among the layered budgets and admission already enforces it; a
second implementation of a reviewed bound is two bounds that will disagree, so
Phase 7 does not add one.

### 2. Fixed windows, not sliding ones

A sliding window needs the timestamp of every event inside it: a per-caller
unbounded list with a remote trigger. A fixed window costs one integer per key.

The cost is stated rather than hidden: a caller may spend two windows'
allowance across one boundary. That is a factor of two on a bound, not an
unbounded one, and it is the right trade for a memory profile that cannot be
attacked.

### 3. A live counter is never evicted

Evicting a counter resets a budget, which is a bypass rather than tidiness —
the rule the Phase 4 limiter's per-domain table already follows. So the quota
store evicts only counters whose window has ended, and refuses when the table
is full of live ones.

That refusal is the honest failure mode, and the arithmetic that makes it
tolerable is the layering. A new counter is created only by a request that also
spends the caller's per-key, per-account, and daily counters, and those already
exist — so the table fills at the rate of the *narrowest* budget, not at request
rate. With the defaults, one account can create at most `daily_total` new
counters per day whatever its request rate.

### 4. Spending is all-or-nothing

A request refused by the eighth layer must not have spent the first seven, or a
caller near one limit is drained by requests that never ran. So the whole set is
presented to the store at once and the limit travels with the key: an
implementation cannot decide atomically about a rule it was not told.

**And the table's own capacity is part of that.** An independent review measured
the first build checking every limit, beginning to increment, and discovering on
a later layer that the table was full — raising with the earlier layers already
spent. The refusal was correct and the accounting was not: a request that never
ran had drained the caller's key, account, and daily budgets, which is the exact
failure this decision exists to prevent.

`consume` therefore runs three passes, and the order is the whole argument:

1. every layer's limit is checked;
2. every table slot the commit will need is **reserved**, counted as a set,
   before anything is written;
3. only then does anything increment.

Counting the missing slots as a set matters on its own: two layers needing new
counters need two free slots, and asking `len(table) < max` once per insertion
answers the wrong question when exactly one is left. Reserving first also means
there is nothing to roll back — a rollback across a partially committed set is
the design this avoids rather than the design it uses.

### 5. Every verification charges the caller's layers

One rule, no exceptions, and the consequences are what the prompt asks for
rather than special cases added to produce them:

- a **cache hit is not free**. It parses, resolves, and answers, so it charges.
  Free cache hits would leave a caller enumerating already-cached addresses
  entirely unbudgeted;
- a **retry is not free**. Section 14's one automatic retry is a whole new
  verification and charges what one costs;
- a **passive check** charges the caller's layers and no destination layer,
  because it opens no socket and spends nobody's reputation.

### 5c. The unit is a **verification**, not an API request

Stated because the numbers do not mean what an operator would assume. Every
limit in `QuotaSettings` counts *quota spends*, and one submitted active job
spends the caller's layers more than once:

| Operation | Caller layers | Destination layers |
|---|---|---|
| submission's passive pass | 1 | — |
| first active verification | 1 | 1 |
| section 14's one retry | 1 | 1 |

So one active job costs **two** caller spends, or three if it retries, and one
or two destination spends. `MAX_RETRIES` bounds it; nothing in Phase 7 does.

`per_account = 5000` therefore means five thousand **verification budget
units** per window — roughly 2500 active submissions, or fewer once retries are
counted — and not five thousand API requests. A passive check is one unit. An
operator sizing these must read them as spends, and the field names, the
document, and `docs/operations.md` all say "budget units" rather than
"requests" for that reason.

The direction is conservative: over-counting refuses earlier than an operator
expects, which is the safe way to be surprised.

### 5a. The volume budget approximates; the kill switch does not

These are two different things and an earlier revision of this ADR described
only the first, which let the second inherit an approximation it must not have.

**The per-MX volume budget is approximate.** The exchanger *charged* is the
preferred one among those a verification may reach — the candidate Phase 4E
approaches first and, unless it fails before the recipient stage, the only one.
A request that falls through under-charges the second exchanger by at most
`max_attempts - 1`; the domain budget above it covers the total either way.

**The per-MX administrative block is exact.** Every candidate Phase 4E may
approach is checked against `AdminState.blocked_mx_hosts` before the route
reaches `plan_attempts`, and a blocked host is removed from the plan. An
independent review measured the earlier build consulting the switch for the
preferred candidate alone: `mx2` was blocked, `mx1` was tried first, and Phase
4E fell through to `mx2` and connected. `docs/threat-model.md` section 4 lists
per-MX blocking among the **required** controls before service-active, and a
control that a remote host can evade by failing its own first exchanger is not
that control.

An operator throwing a switch is entitled to an exact answer. A budget may
approximate because its purpose is aggregate pressure; a kill switch may not,
because its purpose is a specific host and a specific incident.

### 5b. Domain and exchanger blocks mean different things

`docs/operations.md` section 2 lists "one target domain" and "one target MX" as
**separate** kill switches, so they are implemented as separate decisions:

| Switch | Effect |
|---|---|
| blocked domain | the whole verification is refused; no exchanger for that domain is approached |
| blocked exchanger | that host is removed from the plan; another unblocked exchanger for the same domain may still be used |

The domain check runs **before** the candidates are filtered. Otherwise the two
controls set together answer "nowhere to connect" and the caller receives a
passive verdict where the domain switch promises a refusal — a publicly visible
difference between throwing one switch and throwing two.

This changed one behaviour: blocking the *preferred* exchanger used to refuse
the whole verification, because it was the only one checked. It now skips to the
next, which is what "block one target MX" says.

### 6. No proxy header is trusted, and the type says so

`X-Forwarded-For` and `Forwarded` are written by whoever sent the request unless
a trusted-proxy list says which hops may set them. This project has no such list
because it has no ASGI binding, and a spoofable value in a budget key is worse
than no budget: it turns a per-source limit into a per-*claimed*-source limit
that an attacker resets by changing a string.

So `domain/source.py` reads nothing. A `SourceIdentity` is built by a transport
boundary from the connection's own peer address or it does not exist, the source
layer is simply not counted when it does not, and `ApiRequest.body` accepts
exactly one key so a body cannot carry one. Proxy trust is a **stop condition on
the binding Phase**, recorded in `docs/architecture.md`.

### 7. Metric labels are closed enumerations

The dangerous property of a metrics API is unbounded cardinality: a label taking
free text becomes one series per distinct value — a memory leak triggered by a
request, and a copy of user input in a monitoring system where none of this
project's redaction applies.

`MetricLabels` is a closed dataclass whose subject must be a value one of this
project's published enumerations already declares. There is no method taking a
free string.

This is **stricter than the prompt**, which permits "target-domain and MX rates
subject to cardinality controls". A bound enforced by a cap starts discarding
values exactly when an attack makes them interesting.
`docs/requirements.md` section 16 already gives domain-level analytics a home —
the operator event stream, which is redacted and retained under a policy. The
cost is real and is accepted: per-domain rates are queried from events rather
than scraped from a gauge.

### 8. The correlation digest gains a canonicalization version

`docs/privacy.md` section 5 specifies
`HMAC-SHA-256(key, canonical_input_version || normalized_target)` and asks that
the version be stored. Phase 6's digest had no version, so no stored digest
could be identified with the canonicalization that produced it — and the day
the canonical form changes, every digest silently stops matching with no way to
tell an old one from a new one.

The version is part of the HMAC **input** rather than a column beside it, so two
canonicalizations cannot collide onto one digest.

**This changed every digest this project produces, once.**
`adapters/storage/sqlite_store.py` moved from schema version 2 to 3 in the same
change even though no column changed: a store whose every row has become
unreachable looks like a cache that never hits, which is a worse failure than
one that refuses to open.

### 9. Indicators report; they never refuse

`prompts/07-hardening.md` says indicators "may suspend or require manual
review", and both are an operator's action through `application/admin.py`. An
automatic suspension driven by a blunt heuristic is a denial of service that
somebody else can trigger on a caller's behalf, and every threshold here is
deliberately blunt so that an operator can explain it to the person it flagged.

The indicator window holds *shapes* — a domain, a keyed digest, a stem with its
trailing number removed — never a local part and never an address.

### 10. Three retentions, kept separate

| What | Lifetime | Decided by |
|---|---|---|
| A cached verdict | its own `expires_at` | ADR 0015, from section 13 |
| A finished job record | `job_retention_seconds`, default 24 h | `docs/privacy.md` §3 |
| An audit event | the ring's capacity | `application/admin.py` |

Section 13's TTLs price *evidence classes*. Using one as a job or log retention
would apply a deliverability-freshness rule to a privacy question, which is how
a caching decision quietly becomes a retention policy.

Purging is bounded per run and reports whether more remain, so a backlog is
cleared over several runs rather than in one statement holding a write lock.

### 11. Raw diagnostics stay unretained rather than encrypted

`docs/privacy.md` section 3 prices an *encrypted* raw SMTP diagnostic at 24
hours. This project retains none: Phase 4 keeps a bounded sanitized diagnostic
and no raw reply, and section 2's default is not to keep raw protocol text
unless debugging retention is explicitly enabled.

Implementing encryption needs a cryptographic dependency, which needs its own
ADR and a Phase permitted to install one. The privacy-preserving half of the
requirement holds today, and it holds **by absence** — which is the stronger
form. Recorded as a Phase 8 stop condition rather than left to be inferred.

## Consequences

- One account can no longer starve another of the admission queue. F11 closed.
- Every layer `prompts/07-hardening.md` names is enforced, or is named here as
  belonging to an earlier Phase, and a test asserts the mapping is total.
- An operator can suspend a key without suspending its account, which needed one
  account to be able to hold several keys — so `Principal` gained an opaque
  `key_id` and the authenticator issues one per credential.
- Every stored digest changed once, and a version-2 store is refused.
- Per-domain metric series do not exist; that analysis moves to operator events.
- A quota-store failure refuses active checks and leaves passive ones working.

## Alternatives considered

**A sliding window.** Rejected: unbounded per-caller memory with a remote
trigger, to remove a factor-of-two edge effect on a bound.

**Evicting live counters under pressure.** Rejected: it resets budgets, which is
the bypass the Phase 4 limiter's own eviction rule exists to prevent.

**Trusting `X-Forwarded-For` behind a configuration flag.** Rejected: a flag
that makes a spoofable value authoritative is one that will be set by somebody
who has not read this file.

**A bounded-cardinality domain label.** Rejected: the bound sheds exactly the
values an incident needs. See decision 7.

**Automatic suspension on an indicator.** Rejected: see decision 9.

**Re-keying the Phase 4 token bucket per account.** Rejected: it would make each
account's destination pacing independent, which protects nobody.
