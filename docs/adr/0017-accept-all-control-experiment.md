# ADR 0017: The accept-all experiment, kept apart from verification

- Status: Accepted
- Date: 2026-08-12
- Phase: 9

## Context

this ADR asks for an estimate of `accept_all_suspected` "under
strict domain budgets without claiming a mailbox result". The measurement is one
control recipient — an address nobody created — offered to a domain's exchanger
to see whether it is accepted.

Every part of that is close to something this project forbids. A second
recipient is the enumeration pattern `docs/threat-model.md` lists first. A
generated local part is an invented mailbox. An "accept-all" answer is one step
from a claim about the caller's target. So the decisions below are mostly about
what the experiment is *not* allowed to touch.

## Decision: the experiment is a separate verification, never a second `RCPT TO`

One verification issues at most one `RCPT TO`, in total. Gate 4A bounds a
session with a state table and a counter; gate 4E bounds the whole request with
a transcript check and a stage check. That invariant is `docs/threat-model.md`'s
first enumeration control and it is not negotiable.

A control recipient is a *different* recipient. Probing it inside the caller's
verification would make that verification issue two, and no amount of care about
which one is "real" changes what a receiving site sees: one identity asking
about two recipients, in one session, seconds apart.

So the experiment is its own high-level operation with its own one-`RCPT TO`
bound, and it goes through the same `SMTPVerificationService` an ordinary check
does. `application/verification.py` does not import it, `application/accept_all.py`
does not import `application/verification.py`, and an inspection test holds both
directions. An ordinary `verify()` is byte-for-byte the operation it was before
this Phase.

The alternative — a flag on `verify()` that added a control probe — was rejected
outright. It would have put the decision "is this one recipient or two" inside
the function whose whole guarantee is that it is one.

## Decision: five gates, every one closed by default

| Gate | Where |
|---|---|
| the operator enabled the feature | `AcceptAllSettings.enabled`, `False` |
| the operator authorized *this domain* | `AcceptAllAuthorization`, empty |
| the administrative controls permit it | Phase 7's `AbuseGuard`, including the global kill switch |
| the separate accept-all domain budget has room | `BudgetLayer.ACCEPT_ALL_DOMAIN` |
| no unexpired cached answer exists | `ports/accept_all_cache.py` |

this ADR's acceptance criterion is that no public caller can
enable the feature without authorization and budget. The shape of that here is
that a caller has **no parameter at all**: `run` takes a route, a domain, and a
principal, and every gate is read from operator configuration. No request body
key, no query parameter, and no CLI flag names the feature; an inspection test
asserts that the request-facing modules do not name it.

**Enabling is not authorizing**, on the precedent Phase 8's `BetaAuthorization`
set. A deployment may build this service and probe nothing. External accept-all
probing additionally inherits Phase 8's human deployment gate in
`docs/operations.md` section 1, which nothing in this Phase can satisfy.

The global kill switch reaches the experiment through `check_caller(active=True)`,
which is where `active_probing_enabled` is read. An earlier build consulted only
the destination switches, and a test measured the experiment continuing after an
operator threw the global switch — the one moment `docs/operations.md` section 2
says a switch most needs to have worked.

## Decision: a separate domain budget, sized far below the ordinary one

`BudgetLayer.ACCEPT_ALL_DOMAIN`, with `per_accept_all_domain = 5` against
`per_target_domain = 500`. Both this ADR and
`docs/requirements.md` section 10 require the budget to be *separate*, and the
reason is directional: an experiment is contact a caller did not ask for — they
asked about one mailbox — so it may not be paid for out of the budget that
bounds ordinary verification of that domain, and exhausting it must not stop
ordinary verification either. Both halves are measured.

The size follows from the cache: one decided answer per domain per week is the
intended traffic, so a limit that allowed hundreds would permit the shape it
exists to stop. Spending stays all-or-nothing, so "the experiment ran out" and
"the domain ran out" remain different facts.

## Decision: the control local part is non-dictionary by construction

Twenty characters drawn uniformly from thirty-six — lower-case ASCII letters and
digits — through the `RandomSource` port. About 103 bits.

**No word list.** this ADR forbids personal names, roles, and
sequential strings, and a blocklist is only as good as its vocabulary. A uniform
draw at this length is not a word in any language, is not a name, is not a role,
and is not sequential — and that holds for languages nobody thought of, which a
list cannot promise. An inspection test refuses a mailbox-name literal in any
Phase 9 module, so a generator rewritten around a list fails.

The alphabet carries no dot, `+`, hyphen, or underscore. Each would make a
generated address resemble a tagged or structured address somebody might own,
and none adds entropy worth the resemblance. Every character is a dot-atom
character Phase 1 already accepts, so a control address parses through the
ordinary grammar rather than through a second one.

Collision retries are finite — three draws, then a refusal. A generator that
kept drawing until something was acceptable is the first step of adaptive
probing, which this Phase forbids outright: no branch anywhere reads a reply to
decide what to ask next.

## Decision: seven days, and only for a decided answer

`docs/requirements.md` section 13 prices accept-all suspicion at seven days and
this ADR asks for a "seven-day or longer domain cache".
`AcceptAllSettings.cache_seconds` defaults to seven days and refuses less.

The key is `(domain HMAC, sender identity HMAC, experiment version)`.

- **A domain, never a mailbox.** Accept-all is a property of the domain's
  configuration. Keying on the caller's target would file one domain's answer
  under every address anybody asked about, and would put a target in a store
  that outlives the request by a week. The key type has no field a local part
  could occupy.
- **The sender identity**, because a destination may treat two identities
  differently, and section 13 requires it.
- **The experiment version**, because a cached answer is seven days old at the
  end of its life. If what the experiment asks or how the reply is read changes
  inside that window, the cached answers were produced by a different
  experiment; bumping `EXPERIMENT_VERSION` invalidates them by construction
  rather than by anybody remembering to clear a table.

**Only `suspected` and `not_suspected` are cached.** Temporary, inconclusive,
and refused outcomes are not, because freezing a timeout or an ambiguous reply
into a week-long answer would turn one bad minute into seven days of a claim
this project never established.

The alternative considered was caching `suspected` alone — section 13 prices
only that class, and ADR 0015 established that a class section 13 does not price
is not cached at all. It was rejected here because the precondition asks for a
*domain cache* rather than for a cached verdict, and because the common case is
`not_suspected`: never caching it would make every verification of an ordinary
domain re-probe, which is the amplification the separate budget exists to
prevent. The cost is recorded rather than hidden — this reading caches one more
class than section 13 prices, and both classes are statements about the domain's
configuration rather than about any mailbox.

## Decision: the only thing published is `accept_all_suspected`

this ADR's Result section says "only add" that flag, safe
control metadata, and the checked time and cache expiry.

So `SUSPECTED` produces one `Evidence` — layer `accept_all`, reason
`accept_all_suspected`, `WEAK`, non-temporary — and **every other outcome
produces none**. In particular `NOT_SUSPECTED` publishes nothing: this project
has no reason code meaning "not accept-all", and inventing one would be
inventing a claim nobody reviewed. It is the absence of suspicion, not evidence
that the caller's target exists.

Neither direction says anything about the caller's address, and the module's own
documentation states both halves:

- the control was accepted — the destination may accept every recipient. It does
  not follow that the caller's target does not exist;
- the control was rejected — nothing is published. It does not follow that the
  caller's target does exist.

## Decision: Phase 5 is not touched

this ADR requires that "an accepted target plus suspected
accept-all aggregates to `unknown`". That already holds:
`application/aggregate.py` placed `accept_all_suspected` in tier 4 in Phase 5,
tier 4 is `unknown`, and tier 4 blocks a positive verdict. Phase 5's own status
records it as "aggregated but never emitted — Phase 9 is what would produce it".

So Phase 9 adds a producer and changes no rule about what evidence means. No
tier moved, no gate gained a condition, and the published invariant that **a
risk flag alone never changes a deliverability status** is untouched: it is the
*evidence* that lands in tier 4, and the flag is derived after the status as it
always was. Nothing in any Phase 9 module names a `Status`, and an inspection
test asserts it.

## Consequences

- An ordinary verification is unchanged, and unreachable from the experiment.
- With the feature disabled — the default — one submitted check is at most one
  verification, exactly as before this Phase.
- With the feature enabled, the domain authorized, and no cached answer, one
  check may be accompanied by at most one separate experiment, itself at most
  one `RCPT TO`. A cache hit adds none.
- The experiment is **not wired into `composition.py`**, deliberately, and that
  is this Phase's recorded stop condition: wiring a subsystem nobody may yet run
  only creates a path. The wiring, the operator surface that would carry the
  authorized-domain record, and the beta-report field for the outcome are a
  later slice, after this one is independently reviewed.
- External accept-all probing has not been performed and is not authorized.
