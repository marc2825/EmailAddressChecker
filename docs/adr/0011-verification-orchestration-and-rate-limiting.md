# ADR 0011: One verification, one recipient, and a limiter that can say no

- Status: Accepted; domain-only pacing superseded by ADR 0020
- Date: 2026-08-09
- Phase: 4E

## Context

Gates 4A–4D built a probe that can observe one recipient on one exchanger and
express the result as evidence. Two things were missing before Phase 4 could be
called finished, and they are connected.

**A mail route publishes more than one exchanger.** A domain whose primary MX
refuses the connection is not a domain this project can say anything about, so
something has to try the secondary. Nothing did: `SMTPProbeService.probe` takes
one candidate and one address.

**`RateLimiter` had no implementation.** `SMTPProbeService` has required one
since 4C, with no default, so the *ordering* — authorization before a socket —
has been structural for two gates. But an inspection test kept `src/` free of any
implementation, which means every probe this project could run was authorized by
a test double. ADR 0009 recorded the real budgets as 4E's.

They are connected because MX fallback multiplies outbound connections. Adding
the loop without adding the limiter would have turned one request into as many
connections as a DNS answer cared to name.

## Decision: one verification issues at most one `RCPT TO`, in total

Not one per session — 4A's state table and counter already guarantee that — but
one across every candidate a verification tries.

The moment a dialogue reaches the recipient stage, the verification stops. Not
when it gets an answer: **when it reaches the stage.** A `450`, a `550`, a `252`,
a connection reset after the command went out, and a write that failed part way
all end the verification identically.

The alternative is worse than it looks. Asking a second exchanger about the same
recipient produces a second `RCPT TO` for one address, from one identity, within
seconds — which is the pattern `docs/threat-model.md` lists first under address
enumeration and the one a receiving site fingerprints as harvesting. It would
also be a retry, and `docs/requirements.md` section 14 puts retries on a
schedule measured in minutes, not inside a probe.

It is tempting on a `450`, because temporary reads like "ask again". That is
exactly the case this rule exists for: a temporary answer is still an answer,
and the right response is one bounded retry much later, which this gate does not
implement.

### Two barriers decide it, and each is pinned

```text
SMTPCommand.RCPT_TO in report.commands_issued   the command was written
report.stage_reached at or past RCPT_TO         the dialogue got that far
```

Neither is redundant. A write that *fails* never reaches the transcript, and
this project cannot know how many of its bytes reached the peer — so the stage
catches that one. And `SessionReport` permits a transcript naming `RCPT TO` at an
earlier stage, which is the shape gate 4D's own barrier tests are built from — so
the transcript catches that one.

Both are conservative in the same direction: a false positive costs one
verification that reports `unknown`, and a false negative costs a second
recipient probe on another server.

## Decision: fallback is for pre-recipient failures, and it is capped

A refused connection, a bad banner, a refused `EHLO`, a TLS failure, a rejected
`MAIL FROM`, or a lost connection before the recipient stage: none is an answer
about the address, so the next exchanger asks the question for the first time
rather than asking it again.

Two things never fall through. A failure of this project's own stops the
verification, because falling back would hide our bug behind another server's
answer — the same rule Phase 2 and gate 4B already follow. And `CancelledError`,
`KeyboardInterrupt`, `SystemExit`, `GeneratorExit`, and `AssertionError` are not
caught at all: a worker told to stop must not be answered with the next MX.

**The plan is capped at three endpoints and de-duplicated before anything
connects.** `docs/requirements.md` section 9 asks for one bounded attempt per
candidate and forbids racing them; it fixes no number. Three covers a primary, a
secondary, and one more. The number matters less than its existence: without a
cap, how many sockets one request opens is whatever a hostile DNS answer says.

De-duplication is on `(MX host, address, port)` and deliberately **not** on the
address alone. Two exchanger names sharing an address are two TLS identities —
the certificate is verified against the host name — so collapsing them would
silently accept one host's certificate for the other's.

Ordering is Phase 2's and is never re-decided: MX preference order, with equal
preferences in the order the resolver served them, and each candidate's addresses
in the order Phase 2 recorded. Nothing is sorted again and nothing is randomized.
A randomized scan would make one verification unreproducible, and choosing a
different endpoint to get a different answer is the rotation `AGENTS.md` forbids.

## Decision: three budgets, one wait, and a monotonic clock

`adapters/system/rate_limit.py` implements the port with global concurrency,
per-domain concurrency, and a per-domain token bucket. A caller holds all three
or holds none.

**A token bucket rather than a fixed interval**, because a first probe to a
domain should not be paced for nothing while a burst of probes to one domain
should be. Capacity is the burst and the refill interval is the steady rate.
Refill is `min(capacity, tokens + elapsed / refill_seconds)` with the clamp
applied *after* the addition, so no amount of idling and no float rounding can
widen a burst — and `TokenBucket` refuses a token count outside `0..capacity` on
construction, so a bug in the arithmetic fails rather than accumulating.

**Time comes from `MonotonicClock` and waiting from a new `Sleeper` port.** The
clock was already a port for the reason ADR 0009 gives; waiting had to become one
too, or a pacing test could only be written by actually waiting, which measures
the machine rather than the pacing. Every delay in the limiter is computed from
the bucket and applied through the port, so the whole suite runs with no sleep at
all.

**The wait budget is separate from the session budget, on purpose.** ADR 0009 put
the rate-limit wait outside the SMTP session deadline so that queue depth is
never recorded as `deadline_exhausted` — a flag Phase 4D reads as a bound on a
*remote* conversation. That left the wait itself unbounded, which this closes:
one deadline covers all three acquisitions, so three steps cannot cost three
budgets, and pacing refuses *before* sleeping when the delay could not fit
anyway, rather than holding a global slot to wait out a budget it cannot meet.

Exceeding it raises `RateLimitTimeout`, which is deliberately not a
`TimeoutError`, not an `OSError`, and not an `SMTPContractError`: a handler
written for a remote timeout must not catch this project's own queueing. The
verification records it as an operational stop reason and **produces no SMTP
evidence**, because nothing was observed. Reporting it as `smtp_connection_timeout`
would attribute our scheduling to a mail server.

### The state table is bounded, and the bound is stated honestly

Per-domain state in a dictionary that only grows is a memory leak with a remote
trigger: a caller supplies a new domain every time. Two rules bound it — anything
idle beyond a TTL is dropped, and beyond a cap the least-recently-used idle
entries are dropped — and an entry with an active lease or a waiter is **never**
evicted, because evicting one in use would orphan the counter that releases it.

So the bound is `max_tracked_domains` plus whatever is in flight, and in-flight
entries are bounded by the concurrency of the calling code rather than by this
table. That is the honest statement, and ADR 0008 already established that a
document claiming more than the code does is worse than one claiming less. The
attack this defends against is the unbounded-history one, and it does.
`RateLimitSettings` requires the cap to be at least the global concurrency, so a
configuration where the cap cannot be honoured is unconstructible.

## Decision: the budget is per recipient domain, and the key carries no mailbox

**What is implemented, precisely.** `RateLimiter.acquire` takes an account, the
recipient's domain, and the MX host. All three are canonicalized and validated,
and the limiter then partitions global concurrency by nothing and both per-domain
budgets by the **domain alone**. The account and the MX host divide no budget.

The Phase 4 final review found three documents describing a three-part key, which
overclaimed what the code does — the failure ADR 0008 named and this project has
now made four times. The honest statement is the one above, and the reason it is
worth being exact about is the next paragraph.

`docs/requirements.md` section 15 requires per-account budgets in the
service-active profile, and **Phase 4 deliberately does not implement one.** An
account identifier is only meaningful once something has authenticated it, and
that is Phase 6. Partitioning on a caller-supplied `account` string now would
produce something that *looks* like per-account isolation and is defeated by
sending a different string — which is worse than an absent control, because it
would be reported as present. The gap is recorded as a Phase 6 stop condition in
`plans/phase-04-smtp.md` rather than closed with a partition that cannot hold.

`rate_limit_key` **refuses an `@` in any component** rather than stripping one.
`docs/requirements.md` section 16 forbids a complete address in metrics and keys,
and a limiter's state is both. That is a **shape** check and not a provenance
one: it constrains what the value may be, and says nothing about who chose it.

Refusing rather than stripping is deliberate. Stripping would keep the local part
in the caller's hand and put the domain in the key under a name that lied about
what it held; refusing makes the caller fix the call. The domain and the MX host
are case-folded and lose a trailing dot, so `Example.COM.` and `example.com` are
one budget rather than two — otherwise varying the spelling of a name buys a
fresh quota. The account is *not* folded: it is an opaque identifier this project
did not issue, and folding it would merge two accounts a deployment considers
distinct.

## Decision: the 4D mapper is wired here, and stays pure

`map_session_evidence` and `map_connect_failure` get their first production
caller. `observed_at` comes from the existing `Clock` port as an aware UTC
timestamp, supplied by this layer — the mapper takes a timestamp rather than a
clock precisely so that it remains a function of its input (ADR 0010), which
makes supplying one the caller's job.

Evidence provenance is carried by `AttemptRecord` rather than by a new field on
`Evidence`. Which attempt produced which evidence is a question the record that
holds it answers, and adding a detail key to a 4D value would have widened a type
whose privacy bound was reviewed one gate ago.

A refusal at `approve_destination` is recorded as an attempt and produces **no**
evidence, because ADR 0010 settled that Phase 2 already reported it as
`unsafe_destination` and a second weaker copy is double-counting.

## Consequences

- **Phase 4E produces no status, no confidence, and no verdict**, and
  `aggregate_evidence` still raises `NotImplementedError`. `VerificationStop` is
  operational vocabulary: `candidates_exhausted` means every exchanger failed
  before the recipient stage, which is a fact about the route and not about the
  address. Section 4 resolves the evidence, and evidence that says nothing
  resolves to `unknown`.
- **The two Phase 5 stop conditions from ADR 0010 are unchanged and now have an
  inspection covering the orchestration tree as well**: membership of
  `POSITIVE_RECIPIENT_REASONS` may not become a status, and
  `EvidenceStrength.STRONG` may not become `invalid`.
- **The limiter is single-process.** It bounds one worker, not a fleet, which is
  the right size for the MVP and is why the port exists. A shared limiter is part
  of the service-active profile in `docs/requirements.md` section 15, and
  replacing this one is implementing `acquire` elsewhere.
- **A verification's worst case is a rate-limit wait *plus* a session budget per
  candidate**, because a deadline exhausted before the recipient stage is a
  pre-recipient failure and the next candidate gets a fresh budget *and* a fresh
  wait. An earlier wording here said "three session budgets" and omitted the
  waits; the Phase 4 final review measured the arithmetic:

  ```text
  configured upper bound = max_attempts × (wait_budget_seconds + session budget)

  defaults : 3 × ( 10 s +  30 s) =  120 s
  ceiling  : 8 × (120 s + 120 s) = 1920 s = 32 minutes
  ```

  Both are finite and every value is validated on its own; what is **not**
  bounded is their product, and the ceiling is a legal configuration. Small local
  processing and the cleanup steps sit inside those budgets, so this is the
  configured upper bound rather than a measured one.

  **A verification-total deadline is a Phase 6 stop condition**, not a Phase 4
  omission: a second overlapping bound belongs with the queue that owns a
  request's latency, and adding one here would duplicate a deadline this gate
  cannot see the whole of.
- **A rate-limit refusal produces an empty evidence tuple**, so Phase 5 must read
  `stopped_because` to tell "nothing was observed because we were paced" from
  "no SMTP was attempted". That is recorded as a Phase 5 note rather than solved
  with a new reason code, because inventing published vocabulary for an
  operational condition is what `docs/status-model.md` section 5 requires an API
  version for.
- Adding an `AttemptOutcome` member requires deciding whether it stops the loop:
  `_STOPS` is a table and a member absent from it continues, which is the
  permissive answer, so a test asserts every member is accounted for.

## 0.1.0 amendment

ADR 0020 adds independent MX concurrency and token buckets shared across recipient
domains/accounts, inside one acquisition deadline. Domain settings apply to both.
Spent state cannot be evicted to replenish a bucket. Temporary replies defer later
operations; they never replay the touched recipient.
