# ADR 0012: Evidence aggregation and final status semantics

- Status: Accepted
- Date: 2026-08-09
- Phase: 5

## Context

Four layers produce `Evidence` and none of them produces a status. Phase 5 is
the code that decides, and it is the first place in this project where a wrong
answer is a wrong answer to the user rather than a wrong observation.

`docs/status-model.md` section 4 already fixes the precedence, and it was
written in Phase 0. What it does not fix is a set of details that only become
questions once something implements it: what confidence means when there is no
calibration study, what happens when the evidence contradicts itself, whether a
`250` on its own is enough, and what `aggregate_evidence(())` answers. Every one
of those has a plausible wrong answer, and this document records the choice
rather than leaving it in the code.

The failure mode this Phase must avoid is not a crash. It is a verdict that
looks reasonable: an accept-all server's `250` reported as `likely_deliverable`,
a policy rejection reported as `invalid`, a greylisting reported as a permanent
failure. None of those looks like a bug.

## Decision: six tiers, and the lowest non-empty one decides

`application/aggregate.py` implements `docs/status-model.md` section 4 literally:

| Tier | Contents | Status |
|---|---|---|
| 1 | supported hard invalid | `invalid` |
| 2 | unsupported input | `unknown` |
| 3 | explicit temporary condition | `temporary_unknown` |
| 4 | policy, opaque, non-target, and anything unrecognised | `unknown` |
| 5 | accepted recipient, with a usable route and no blocker | `likely_deliverable` |
| 6 | route and passive metadata only | `unknown` |

Each observation is assigned a tier; the lowest tier present decides. Nothing
counts observations, weights them, or reads `EvidenceStrength`.

**Tier 4 is the complement, not a list.** An observation that matches none of
tiers 1, 2, 3, 5, or the small explicit tier-6 set lands in tier 4, which is
`unknown` and which blocks a positive verdict. A reason code added in a later
Phase and forgotten here therefore resolves to `unknown` rather than being
ignored. The alternative — an explicit tier-4 list with tier 6 as the fallback —
fails open, and `AGENTS.md` requires ambiguity to resolve to `unknown`.

## Decision: two gates, each in exactly one place

`supports_invalid` and `supports_likely_deliverable` are the only functions that
can produce a decisive status, and an inspection test asserts that no function
in the module names `Status.INVALID` or `Status.LIKELY_DELIVERABLE` at all — the
tier table is the single place a tier becomes a status. Two `if`s producing the
same status are two conditions that will drift apart, and the drift is invisible
until one of them is wrong.

**`invalid` requires three conditions and none of them is strength:**

1. the reason must be one of the five `docs/status-model.md` section 2 lists;
2. the observation must be about the target;
3. it must not be temporary.

Each is pinned by a test in which the other two pass. `EvidenceStrength` is not
imported by the module at all, so section 7.6 stop condition B is closed by
absence rather than by discipline.

**`likely_deliverable` requires three conditions**, discussed below.

## Decision: targetness is read from the producer first, and a set second

`is_about_the_target` believes a producer that says an observation is *not*
about the target — gate 4D publishes `about_the_target` on every piece of SMTP
evidence, and it knows the stage the dialogue reached and how many recipients
were attempted, which this module does not. Absent that statement, membership of
`TARGET_SPECIFIC_REASONS` decides, and an unclassified reason is **not** target
evidence.

Both directions matter and each is pinned separately. A `550 5.1.1` carried by a
session that never reached the recipient stage is refused by the first barrier
alone; every non-target SMTP reason is refused by the second alone.

The positive form is deliberate, on the gate 4D precedent: `reason not in
NON_TARGET_SMTP_REASONS` fails *open*, and a reason forgotten from both published
sets would be promoted to target evidence.

## Decision: `likely_deliverable` requires a usable route as well as an acceptance

This is the one place where the implementation asks for more than
`docs/status-model.md` section 2 states, and it needs recording.

Section 2 says `likely_deliverable` means "positive delivery-stage evidence
exists and no stronger contradictory evidence exists". Read literally, a single
`rcpt_accepted` with nothing beside it satisfies it. Gate 4D's stop condition A
says membership of `POSITIVE_RECIPIENT_REASONS` must not map *directly* to a
status and that every aggregation must run the section 4 precedence first — it
does not, on its own, forbid a lone `250` from surviving that precedence.

So the two documents are consistent and the question is genuinely open. It is
resolved toward the conservative reading:

> `LIKELY_DELIVERABLE` requires a `mx_available` or `implicit_mx_available`
> observation **and** a qualifying recipient acceptance **and** no tier 1–4
> evidence.

Three reasons.

- **The pipeline cannot produce a lone acceptance.** An SMTP session that
  accepted a recipient is a session that resolved a route, approved a
  destination, and connected to an exchanger, so Phase 2 route evidence is
  always present in practice. Requiring it costs nothing real.
- **An aggregator must not assume its input is coherent.** That is a general
  rule here, and a lone `250` is exactly an incoherent set. Answering `unknown`
  is the conservative direction.
- **It makes the Phase 4 promise literally true of this function.**
  "A bare SMTP `250` is not automatically `likely_deliverable`" is otherwise
  true only because of how the caller happens to be wired.

The cost is that a hand-assembled evidence set can no longer reach
`likely_deliverable` without a route, which is a restriction in the safe
direction only.

## Decision: confidence is a table on the primary reason

`docs/requirements.md` section 17 permits a probability only after a controlled
labelled evaluation, and `docs/status-model.md` section 3 makes confidence
categorical with `calibrated` false and `score` null. ADR 0004 already decided
that. What was undecided is how the level is computed.

**It is a lookup on the primary reason, and nothing else.** No arithmetic
anywhere: no sum, no average, no product, no count. There is no calibration
study, so there is no evidence for *any* arithmetic — a number produced by
adding two categories is an invention with a decimal point on it. A table also
makes three properties structural rather than tested-and-hoped: duplicate
evidence cannot move confidence, input order cannot move it, and an unrelated
extra observation cannot move it.

`Confidence` now refuses a score while `calibrated` is false, so the number
cannot be added without the study being declared.

Where section 3 states a level, it is used verbatim. Where it gives a range, the
**lower** level is taken:

| Evidence | Section 3 | Chosen | Why |
|---|---|---|---|
| Syntax violates supported grammar | high | high | stated |
| NXDOMAIN, Null MX | high | high | stated |
| No mail route | — | high | the same observation: an authoritative absence on both families |
| Explicit RCPT `5.1.1` | medium **or** high | **medium** | the higher reading would claim more than section 7.3 allows about a `550 5.1.1` |
| RCPT `250` | medium | medium | stated, and section 7.3 forbids high |
| RCPT `251` | — | medium | the same answer, about a forwarding arrangement |
| Bare `550` | low | low | stated |
| Policy block | low | low | stated |
| Timeout | low **or** medium | **low** | our bound, not the remote side's statement |
| Explicit `4xx`, `mailbox_full`, DNS SERVFAIL | — | medium | the remote side stated the condition; one level above a timeout |
| Unsupported input | — | medium | certain about our limits, and the reason a caller reads is about us |
| `252`, TLS, banner, protocol, unsafe destination, internal | — | low | nothing was established |
| Passive risk list | not confidence evidence | low | the level records that nothing was established |

## Decision: duplicates collapse before anything reads the evidence

Distinct reasons are collected into a mapping before any rule runs, so nothing
downstream *can* count. Where two observations carry one reason and disagree —
one temporary and one not, which two attempts against two exchangers can
legitimately produce — the lower tier wins, so the more decisive reading is
kept.

This matters because gate 4E produces exactly this shape. Three pre-recipient
failures for one address are three attempts at one question, not three
independent answers to it, and `confidence += 0.1 * count` would be reading
this project's own retry loop as corroboration.

Evidence from different layers is not treated as independent either. Syntax,
DNS, SMTP, and passive observations of one address are correlated in ways nobody
has measured, so no Bayesian-looking arithmetic is implemented.

**Decision-time deduplication and audit-time retention are separate.** The
verdict keeps the whole input tuple, in the caller's order, unmodified.

## Decision: the primary reason comes from an explicit total order

`REASON_PRIORITY` ranks every published reason code. The primary reason is the
highest-ranked reason within the *deciding tier*; `reason_codes` is every
distinct reason sorted by tier and then by rank, so the primary reason is always
first and no information is lost.

Neither the enum's declaration order nor a set's iteration order is used.
Reordering `ReasonCode` for readability would otherwise silently change which
reason a verdict reports, and a test asserts `REASON_PRIORITY` is exactly the
enum so a new code cannot be added without ranking it.

**`internal_error` leads tier 4.** A failure of this project's own must not hide
behind a remote server's answer: the status is `unknown` either way, and naming
the remote rejection would send an operator to look at the wrong system. It does
not outrank a hard invalid or an explicit temporary condition, because those are
still true.

## Decision: `LINE_TOO_LONG` keeps its entry-point difference

Gate 4D left this open. Reached through `map_connect_failure` a bounded-read
failure is `smtp_protocol_error` and permanent; reached mid-dialogue it arrives
with no reply and becomes `smtp_connection_timeout` and temporary. The
difference reaches the verdict: `unknown` versus `temporary_unknown`.

**The difference is kept, as deliberate entry-point provenance.** Collapsing it
would need one of two things, and both are worse. Making the session path report
`smtp_protocol_error` is impossible without changing a reviewed 4C contract — a
`SessionReport` carries no `TransportFailure`, so that path genuinely cannot
know which bound was hit. Making the connect path report a timeout would discard
information the caller actually has.

It is safe because of what bounds it: **both readings are non-target, and
neither can ever produce `invalid`**. A test asserts exactly that, alongside the
two statuses, so the difference cannot quietly become a collapse or a widening.

## Decision: risk flags are derived after the status and never read by it

`_RISK_FLAG_BY_REASON` maps published reasons to published flags, is consulted
once the status is already decided, and no rule anywhere reads a flag. A test
asserts that adding every passive risk observation to a verdict of each status
changes the status, the confidence, and the primary reason not at all.

`internationalized_local_part` is derived from `unsupported_smtputf8`. It is the
one published flag with no producer, and that reason code is precisely "the local
part requires SMTPUTF8", so the flag is derivable from existing vocabulary
rather than needing a new signal. No flag is derived from an SMTP reply.

`mx_configuration_anomaly` both raises `domain_configuration_anomaly` and lands
in tier 4. Those are not in tension: `docs/architecture.md` maps a configuration
anomaly to `unknown`, and a route nobody can use is not a route.

## Decision: `aggregate_evidence(())` is `unknown` with no primary reason

`Verdict.primary_reason` becomes `ReasonCode | None`, and `None` is permitted
only when there are no reason codes at all. There is no published code meaning
"nothing was observed", and inventing one would be new API vocabulary for the
absence of an observation.

## Decision: two contradictions are unconstructible

`Verdict.__post_init__` enforces `PERMITTED_PRIMARY_REASONS`: an `invalid`
verdict may only name one of the five hard-invalid reasons, and a
`likely_deliverable` verdict may only name `rcpt_accepted` or `rcpt_forwarded`.
`unknown` and `temporary_unknown` accept any published reason.

The asymmetry is the point. Those two are the answers a caller acts on, so a
contradiction there must be impossible to build — including by a Phase 6 that
assembles a result some other way. The two unknown statuses stay open because
`docs/status-model.md` section 5 says one reason may appear under different
statuses, and an aggregator that raised on a contradictory evidence set would be
worse than one that answered `unknown`.

## Decision: a syntax evidence producer, written here

`application/syntax_evidence.py` turns an `AddressRejected` into `Evidence`.
Phase 1 was the only layer with no producer, which left the first row of the
precedence reachable only from evidence a test built by hand.

Writing it now rather than in Phase 6 is the argument gate 4C made for writing
the 4D mapping table early: a mapping authored alongside the API that consumes
it is shaped by whatever that API made easy, and the strength of a syntax
observation is exactly the decision that gets made carelessly in passing.

Strength follows `RejectionKind`, which Phase 1 already defined — `INVALID` is
strong, `UNSUPPORTED` is weak — so no second classification of the same fact is
introduced. **There is no evidence for an address that parsed**, and no reason
code meaning "the syntax was fine": such a code would be the first thing a later
aggregation mistook for delivery evidence.

## Decision: the primary reason leads `reason_codes`, enforced by the type

Added after the independent review. `reason_codes` was already documented as
"primary first" here, in `Verdict`'s own docstring, and in
`docs/status-model.md` section 4.6 — and the two orderings are produced by two
functions. The review mutated `_ranked_reasons` to sort by the enum's
declaration order: `primary_reason` stayed correct, a different reason led the
list, and the whole suite passed.

`Verdict.__post_init__` now refuses a verdict whose `reason_codes` do not lead
with its `primary_reason`. The alternative — a test asserting that both
functions call the same ranking helper — pins the current implementation rather
than the property, and would not constrain a Phase 6 that assembles a result
some other way. An inspection test adds the structural half anyway, because a
value-type check cannot say *which* ranking was used.

## Decision: a calibrated score is checked for shape and not for range

Also from the review. `Confidence` refused a score while `calibrated` was false
and checked nothing else, so `score="high"`, `score=42.0`, and `calibrated=True`
with no score at all were constructible.

It now requires a score to be a real, finite, non-boolean number, and requires
`calibrated=True` to carry one — the mirror of the existing rule, because the
flag asserts that a study happened and without its number the flag is a claim
with nothing behind it.

**It deliberately checks no range.** No document states what range a calibrated
score would live in, and `0..1` is a guess about the semantics the calibration
study exists to establish. Refusing `42.0` would therefore be this ADR
pre-empting a study it cannot run. The range is a pre-calibration stop
condition in `plans/phase-05-aggregation.md` instead, and the shape checks are
the same ones `TransportTimeouts` makes for the same reason.

`Verdict.ruleset` must be a non-empty string, because a cache is matched against
it and a ruleset that identifies nothing is not provenance.

`Verdict.checks` has its **keys** closed to strings and its **values** left
open. `docs/status-model.md` section 6 publishes a layer summary carrying
`"mx_hosts": [...]`, so closing the values to safe scalars — the bound
`Evidence.details` carries — would forbid the shape that document shows. What
may reach a public response is Phase 6's schema to name explicitly, which is
already a stop condition.

## Consequences

- `aggregate_evidence` is pure. No socket, resolver, limiter, clock, or storage,
  asserted by inspection because behaviour cannot show an absent import;
- `observed_at` decides nothing. No document defines a staleness policy, so
  none is implemented, and old evidence is not silently weakened;
- no new reason code and no new risk flag were added;
- a lone acceptance, a lone route, a lone risk flag, and an empty set all
  resolve to `unknown`;
- Phase 6 must not re-derive any of this. The verdict it serializes comes from
  `aggregate_evidence`, and the response shape is its own problem;
- tier 3 is the `Evidence.temporary` flag and not a second reason list, and it
  is fail-safe in both directions: neither a wrongly-set nor a wrongly-cleared
  flag can reach `likely_deliverable`;
- tier 6 holds route evidence as well as passive metadata. It was documented as
  "passive-only unknown", which was narrower than the code and behaviourally
  indistinguishable, so nothing caught it until the review reconstructed the
  table from the code.

## Alternatives rejected

- **A numeric score.** Forbidden by `docs/requirements.md` section 17 until a
  calibration study exists, and `0.87` beside a status is read as a probability
  whatever the field is called.
- **Corroboration counting.** Two `550 5.1.1` answers from two exchangers are
  not twice the evidence; with the one-`RCPT TO` rule this project could not
  collect them anyway, and the shape gate 4E *does* produce is repeated
  pre-recipient failures, which corroborate nothing.
- **Weighting by `EvidenceStrength`.** Section 7.6 stop condition B forbids
  mapping it to a status, and a weighted sum is that with extra steps.
- **Letting a hard invalid be overridden by a later positive answer.** Section 4
  closes with the opposite rule: a network probe that should never have happened
  does not erase the result that made it unnecessary.
- **Raising on contradictory evidence.** `unknown` is the required answer to
  ambiguity, and a verdict that crashed on odd input would fail a request rather
  than answer it conservatively.
- **Removing the redundant acceptance clause from `supports_likely_deliverable`.**
  The review showed it is unreachable as a decision — `_base_tier` routes only a
  qualifying acceptance to tier 5, so the gate is never consulted without one.
  It stays because the helper is exported and its docstring promises three
  conditions, and a caller invoking it directly on a route with no acceptance
  must get `False`. The answer was a test on the helper, not a smaller helper.

## Future caution, not a Phase 5 change

`internal_error` beside a hard invalid yields `invalid`, with the internal error
visible in `reason_codes` and `checks`. That is unchanged and reviewed.

The asymmetry worth remembering: `invalid_syntax` is computed locally from the
input, so a bug elsewhere cannot fabricate it, while `rcpt_rejected_address` is
derived from the network machinery that just reported it malfunctioned. The
combination is **not reachable from the current pipeline** — gate 4E stops on an
internal failure and never falls through to another exchanger, and a DNS
`internal_error` yields no connectable candidates — so there is nothing to fix.
If a later Phase makes it reachable, the rule to revisit is whether an
`internal_error` from the *same layer* should demote that layer's hard-invalid
evidence.
