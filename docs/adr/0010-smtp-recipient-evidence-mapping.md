# ADR 0010: SMTP observations become evidence, and only evidence

- Status: Accepted
- Date: 2026-08-08
- Phase: 4D

## Context

Gate 4C ends with a `SessionReport`: what stage the dialogue reached, what the
server replied, whether TLS was negotiated, whether this project's own budget ran
out. It deliberately concludes nothing. `250` produces `ACCEPTED` and `550`
produces `REJECTED`, and both are observations about a protocol exchange.

Something has to turn that into the published vocabulary, and the danger in doing
so is specific rather than general. Every mistake available here produces a
*plausible* answer: a refusal to verify that reads as an acceptance, a rejected
sender that reads as a rejected recipient, a certificate failure that reads as a
missing mailbox. None of them looks like a bug in a test run. All of them are
wrong in the direction `AGENTS.md` says this project must never be wrong in.

The mapping was therefore written into `docs/status-model.md` section 7 during
gate 4C, **before this code existed**, on the same reasoning that put the 4A
safety gate before the 4B transport: a mapping authored alongside its
implementation is a mapping shaped by whatever the implementation made easy.

## Decision: a pure function, with the timestamp as a parameter

`application/smtp_evidence.py` takes a `SessionReport` and returns
`tuple[Evidence, ...]`. It opens no socket, resolves no name, acquires no budget,
retries nothing, stores nothing, and reads no clock.

The clock is the interesting one. `Evidence.observed_at` is the single thing a
mapper would plausibly need one for, and both existing evidence producers —
`application/passive.py` and `application/mail_route.py` — take a `Clock` port.
This one takes `observed_at: datetime` instead, because a mapping whose output
depends on when it ran is not a mapping. The deviation from the local precedent
is deliberate, and it makes every test an equality assertion rather than a
comparison against a fake.

An inspection test enforces the rest: no `socket`, `asyncio`, `ssl`, `smtplib`,
`dns`, `time`, `random`, or `os` import; no `SMTPTransport`, `SMTPConnection`,
`RateLimiter`, `Clock`, or `ProviderFamily` named anywhere; no coroutine and no
`await`; no `environ`, `getenv`, or `now()`.

## Decision: `252` is separated before any generic handling of `ACCEPTED`

This is the entry condition `plans/phase-04-smtp.md` records, and it is the first
branch in the classifier.

```text
252 Cannot verify the user, but will accept the message and attempt delivery
```

The server is declining to answer. Gate 4C records it as
`RecipientStageOutcome.ACCEPTED` because at that layer `ACCEPTED` means only
"answered in the 2xx class" — the taxonomy describes the protocol, not the
meaning — and that is exactly the trap: `outcome` cannot tell `252` from `250`,
and neither can `is_about_the_target`, which is true for every 2xx.

So `252` becomes `rcpt_unverifiable`, weak, and never enters
`POSITIVE_RECIPIENT_REASONS`. That set holds `rcpt_accepted` and `rcpt_forwarded`
and nothing else; the two sets differing by exactly that member is section 7.4
expressed as code rather than as a warning.

## Decision: the branch order is part of the specification

Two rows of the table can match one reply, so the order in which they are read is
not an implementation detail:

1. `252`, before anything generic;
2. `X.2.2`, a mailbox or storage condition in class 4 **or** class 5;
3. the basic class;
4. the enhanced code, for a permanent rejection only.

Steps 1 and 2 are the only places where an enhanced code outranks the basic
class, and both move toward the conservative answer.

**`552 5.2.2` is temporary.** `docs/requirements.md` section 9 names `552` with
an explicit `X.2.2` as a temporary mailbox or storage condition, and section 7.3
of the status model had described `mailbox_full` for `4xx` only. The requirements
document wins — it is first in the precedence order in `docs/INDEX.md` — so the
status model was corrected rather than the code narrowed.

**A `4xx` is never converted into a rejection.** `450 4.1.1` reads like
`550 5.1.1` one component at a time. The class is read first, so it stays
`smtp_temporary_failure`; `docs/requirements.md` section 17 makes "temporary
failures are not converted to invalid" a quality target, and a mutation that
read the subject and detail before the class turned exactly this reply into the
strongest evidence this project produces.

## Decision: one piece of evidence per session, with everything else as detail

The TLS outcome, the deadline flag, and the cleanup status are **details on the
primary evidence**, not evidence of their own.

That answers two requirements structurally rather than by convention. A cleanup
failure cannot overwrite the recipient's answer, and cleanup cannot reach a
verdict on its own, because there is nothing for an aggregator to weigh it as.
`RCPT 250` followed by an `RSET` that times out is `rcpt_accepted` with
`cleanup = incomplete` recorded beside it — the server answered the only question
that was asked before the courtesy commands were issued.

The return type stays a tuple so the shape is stable for Phase 5 and for a later
gate that may add a second item. Ordering is fixed and nothing iterates a set, so
two equal reports produce two equal tuples with the same detail keys in the same
order.

## Decision: one new reason code, `smtp_protocol_error`

Section 7.3 as written in gate 4C left one row unresolved: a reply that could not
be parsed at all, at a stage past the greeting. It said the code "is added by 4D
with its own ADR entry". This is that entry.

The existing vocabulary genuinely could not express it. `smtp_banner_invalid` is
the greeting specifically, and widening a published code's meaning is what
`docs/status-model.md` section 5 requires an API version for. `internal_error` is
this project's own fault and this is not. `smtp_ambiguous_permanent_failure` is a
*rejection*, and an unreadable reply is not one.

So `smtp_protocol_error` covers an unparseable reply after the greeting and the
two reply-size bounds, `line_too_long` and `total_limit_exceeded`. It is a
non-target reason: a server this project cannot parse says nothing about the
recipient. Every other case was expressible with the codes that already existed,
and none was added.

## Decision: the destination policy keeps its DNS layer

Almost every reason this mapper produces carries `EvidenceLayer.SMTP`. Two do
not, and both are honest rather than tidy. A failure of this project's own is
`INTERNAL`, and `unsafe_destination` stays `DNS`.

The transport re-runs the destination policy immediately before it opens a socket
and again on the peer it reached, so an SMTP component is where the refusal is
*noticed*. But `docs/status-model.md` section 5 lists `unsafe_destination` under
`dns`, and reporting it under `smtp` would put one published reason code under
two layers depending on which component happened to catch it.

A refusal at `approve_destination` is not mapped here at all. It happens before
any transport failure exists, and Phase 2's route already reported it; producing
a second, weaker copy of evidence that already exists would double-count it.

## Decision: the target/non-target question is answered from the positive set

`about_the_target` is derived as `reason in RECIPIENT_STAGE_REASONS`, not as
`reason not in NON_TARGET_SMTP_REASONS`.

The two are equivalent while the published sets partition every reason this
mapper emits, which they do and which a test now fixes. They differ for a reason
that is in **neither** set — which is to say, for a reason someone adds later and
forgets to classify. The first form calls it non-target, the second calls it
evidence about the address, and `AGENTS.md` decides between them: unknown or
ambiguous evidence resolves to `unknown`, never to an optimistic verdict.

This is a case where no behavioural test could have chosen for us, because the
two forms agree on every input that exists. The reasoning has to carry it, so it
is written down here.

## Decision: the barriers before a recipient rejection are three, and each is pinned

`_recipient_reply` refuses to treat a reply as a recipient answer unless the
outcome is one a recipient answer produces, exactly one recipient was attempted,
and the session reached the recipient stage.

The independent review found that removing any single one of those left the whole
suite passing, and the diagnosis matters more than the fix. It was not missing
assertions: every test reached the mapper through one of two helper functions,
and neither helper can build a report where a single barrier is load-bearing. The
tests were therefore evidence about the helpers' shapes rather than about the
code's conditions.

Phase 4A recorded the rule — *two barriers are only two barriers if each is
pinned by its own test* — after the same discovery about the `RCPT TO` limit, and
Phase 4C found it again in the session deadline. This is the third time, which is
enough to say that a matrix built from convenient constructors will keep
producing it, and that the counter-measure is deliberately awkward inputs rather
than more rows.

## Decision: `Evidence` validates itself, including its timestamp

`Evidence` is a Phase 0 type and this is a cross-phase change, taken here because
it is small: all three producers already pass aware UTC timestamps and safe
scalar details, and the suite passed unchanged.

What it closes is narrow. A naive `datetime` cannot be compared with an aware
one — the comparison raises `TypeError` — so a single naive timestamp makes
ordering a mixed set of evidence fail at run time rather than at construction,
and Phase 5 orders evidence from four producers. Three of them take a `Clock`,
which always answers aware UTC. This mapper takes the timestamp as a parameter
precisely so that it stays a function of its input, which makes it the one
producer whose timestamp comes from an unvalidated caller, and `AGENTS.md`
already requires UTC internally with explicit offsets.

`map_connect_failure` checks its own primitives on top of that. It is the entry
point that takes raw integers rather than values `RecipientObservation` and
`SessionReport` have already validated, and two entry points into one module must
not answer to two contracts.

## Consequences

- Phase 5 receives evidence and two published sets to filter with,
  `NON_TARGET_SMTP_REASONS` and `RECIPIENT_STAGE_REASONS`, rather than having to
  re-derive from reason codes which ones concern the address.
- **Phase 4D produces no risk flag.** Risk is orthogonal to deliverability and
  none of the four flags is something an SMTP reply reports. An inspection test
  keeps `RiskFlag` out of every application SMTP module along with `Status`,
  `Verdict`, and `Confidence`.
- `rcpt_accepted` is `moderate` and never `strong`. Section 3 caps an accepted
  recipient at medium confidence, because an accept-all server says `250` to
  everyone, and the strength field is where that cap becomes machine-readable.
- A `SessionReport` carries no `TransportFailure`, so a connection lost
  mid-dialogue cannot be told from one that timed out; both are
  `smtp_connection_timeout`. Section 7.2 fixes that answer, and both are
  temporary and non-target, so the imprecision changes no decision. Carrying the
  failure through the report would be a 4C contract change.
- Adding a seventh SMTP reason code needs a status-model row, an enum member, and
  a mapping test, and the synchronization test fails until all three exist. It
  also needs a place in exactly one of the two published sets, because the
  partition is now asserted: a reason in neither, or in both, fails.
- **Two Phase 5 stop conditions come out of this gate.**
  `POSITIVE_RECIPIENT_REASONS` is a semantic category and not an aggregation
  rule, so membership may not be mapped directly to `likely_deliverable`; and
  `EvidenceStrength.STRONG` means strong evidence and never final truth, so
  strength may not be mapped directly to `invalid`. Both are the shortest
  correct-looking code an aggregator author could write, which is why they are
  written down rather than left to review attention.
  `docs/status-model.md` section 7.6 and `plans/phase-04-smtp.md` carry them.
