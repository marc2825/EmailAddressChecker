# ADR 0013: Production composition and the public boundary

- Status: Accepted
- Date: 2026-08-10
- Phase: 6

## Context

Phases 1 to 5 published components and deliberately no wiring. Nothing called
`aggregate_evidence`, nothing built a `Verdict`, and `plans/phase-04-smtp.md`
and `plans/phase-05-aggregation.md` between them recorded twelve stop
conditions — every one of which is a way the wiring can be wrong.

Phase 6 is the wiring. It adds no deliverability rule, and its risk is not a
wrong answer but a *shortcut*: a serializer that reads a reason code and picks a
status, a handler that builds a `Principal` from a request field, an entry point
that reaches past the high-level service. Each is short, plausible code.

## Decision: one composition root, and the four graph-shaped stop conditions

`composition.py` is the only module in `src/` that names a concrete adapter. It
builds one limiter, one admission gate, one clock, one sleeper, and hands the
same instances to every request — because a limiter constructed per request has
counters that start at zero every time, which permits everything.

`build_verification_stack` takes a `Deployment` and one seam, `operator`. There
is deliberately **no parameter** for a clock, a sleeper, a limiter, a transport,
or a TLS trust anchor: those are four of the seven Phase 4 stop conditions, and
a keyword argument for any of them would be the hole each one names. A test
asserts the signature.

## Decision: the passive profile is an absent object, not a flag

`docs/requirements.md` section 15's local-passive profile is "no active
probes". `build_verification_stack` returns a service whose `smtp` is `None`
for such a deployment, rather than one holding an SMTP service behind a boolean.
A flag can be flipped by a later edit; an absent object cannot be called.

## Decision: `Principal` is shape, and the authenticator is provenance

Phase 4 carried an `account` string that divided no budget, because a
caller-supplied account is isolation in appearance only. `Principal` closes
that — but the type cannot carry the guarantee, because nothing stops a handler
writing `Principal(account_id=body["account"])`.

So the split is the one `PeerEndpoint` and `confirm_peer` already use: the value
guarantees the shape, `ports/authentication.py` grants the identity, and an
inspection test refuses the constructor everywhere except the authenticator
adapter. The limiter is handed `principal.rate_limit_account` — a named
property, so a call site reading it is visibly reading an authenticated identity
and a call site reading a request body is visibly not.

**There is no anonymous principal.** `authenticate` answers `None` for an
absent, malformed, or unknown credential, and both endpoints refuse. A default
account would satisfy every type and defeat section 15.

## Decision: per-account isolation is a new layer, not a re-keyed bucket

`docs/requirements.md` section 15 requires per-account budgets. The obvious
implementation is to key the Phase 4 token bucket on `(account, domain, mx)` —
and that would change what a reviewed gate measures. That bucket exists to pace
*a recipient domain*, and mixing an account into its key makes each account's
pacing independent, which is the opposite of protecting a destination.

So per-principal concurrency is a separate gate in admission control, and the
Phase 4 bucket is untouched.

## Decision: admission bounds both in-flight and waiting

A queue in front of a bounded worker pool is unbounded memory unless the queue
is bounded too: ten thousand waiters are ten thousand coroutines, ten thousand
upstream sockets, and — because Phase 4 claims a `_DomainState` *before* global
admission — ten thousand limiter entries if each names a different domain. That
is the memory bound `plans/phase-04-smtp.md` said Phase 6 owns.

A request arriving to a full queue is refused immediately rather than admitted
to an unbounded wait.

## Decision: the total deadline refuses rather than returning a partial verdict

Phase 4 bounds a rate-limit wait and an SMTP session *per candidate*; three
candidates is three of each, plus DNS, plus the wait for an admission permit.
Phase 6 bounds the sum.

**The ordering is part of the decision and was got wrong once.**
`asyncio.timeout` wraps `admission.admit`, not the other way round. With the two
reversed the queue was bounded in depth and not in time — a caller could wait
behind a full gate indefinitely — while this ADR and the module's own docstring
both claimed the deadline covered admission. An independent review measured it.
A test now fails if the ordering is put back, and it carries its own outer bound
so the reversal fails rather than hanging.

When it expires, the request is **refused**. The alternative — aggregate
whatever evidence arrived and return it — is tempting because `aggregate_evidence`
resolves missing evidence to `unknown`, so a partial verdict cannot overclaim.
It is rejected anyway, for two reasons:

- **it presents our limits as a statement about the address.** A caller cannot
  distinguish "the server was opaque" from "we ran out of time", and the two
  call for different actions;
- **`unknown` is the status a caller retries.** Answering it when the real
  problem is our own capacity adds load at exactly the moment there is none to
  spare.

This is the treatment `RateLimitTimeout` already gets: our own scheduling
produces no `Evidence`, because nothing was observed. `VerificationRefused`
derives from neither `TimeoutError` nor `OSError`, so a handler written for a
remote failure cannot catch it.

## Decision: HTTP status codes

`docs/requirements.md` fixes none, so:

| Condition | Code | Why |
|---|---|---|
| no or unknown credential | `401` | authentication, not authorization |
| body is not exactly `{"email": …}` | `400` | including every rejected knob |
| a new job was accepted | `202` | the work has not happened yet |
| an existing job or a cached result | `200` | nothing new was accepted |
| unknown, malformed, or foreign job | `404` | ADR 0014; `403` would confirm it exists |
| wrong method on a published path | `405` | the path exists; the verb does not |
| capacity or queue full | `503` | transient; the request may be repeated |
| verification-total deadline | `504` | work was started and abandoned |
| anything unexpected | `500` | a stable code and no internals |

The `401` body is **identical** for an absent, empty, malformed, unknown, and
wrong credential. A message that distinguished them would be an oracle for
"this key exists", which is the fact the constant-time comparison below it
exists to withhold; the error object carries exactly two keys, asserted, so it
cannot grow a `detail` that leaks one either.

## Decision: a closed request schema rather than a deny list

A request body may carry exactly one key. An MX override, an IP, a sender, an
EHLO name, a CA file, a TLS policy, a retry count, and an accept-all flag are
all refused by the same rule that refuses a typo — so a knob nobody thought of
is refused too. A deny list needs updating once per hazard; this does not.

## Decision: the public response is an allowlist, built from the `Verdict`

`application/public_result.py` names every field it emits. It reads
`verdict.status.value` and never a `Status` member, branches on no `ReasonCode`,
and imports none of the aggregation sets — so Phase 5 stop condition 1 is closed
by absence rather than by discipline.

`Evidence.details` reaches nothing. `Verdict.checks` carries `reason_count` and
`evidence_count` internally and the public projection drops both: how many
observations a layer made is a fact about this project's attempt loop, and a
caller counting them is reading our fan-out. `internal` is not a public layer —
an operator is told which component failed; a caller is told `unknown`.

**No number anywhere.** Section 17 permits a probability only after a
calibration study, and Phase 5 leaves even the *range* of a calibrated score
undefined — so a response could not carry one meaningfully even if the study
existed. `as_json_object` builds no float, and a test asserts it.

## Decision: the HTTP layer imports no framework

`pyproject.toml` declares `fastapi` in a `phase6` extra, and it is not
installed; installing it means network access, which this Phase forbids. Rather
than write untested framework code, `apps/api.py` maps a validated request to a
status code and a body with no framework import at all.

That is what `docs/architecture.md` section 1 asks for regardless — a framework
belongs in `apps/` and nothing below may know it — and it means the routing,
validation, error mapping, and response schema are all tested. **The binding
from an ASGI route to `handle` is the one remaining piece**, it holds no policy,
and it is named here rather than pretended into existence.

The CLI uses `argparse` for the same reason: `typer` is in the same uninstalled
extra.

## Decision: what a stored verdict may hold

Digests and published vocabulary. `StoredVerdict` refuses an `@` in any digest
field and refuses a naive timestamp; there is no column for an address, an
account identifier, an evidence detail, a transcript, a certificate, or a sender
identity.

The **aggregation ruleset is part of the lookup**, not a column beside it.
Phase 5 stop condition 4 says a cached verdict served after the rules changed is
a result nothing produced; filtering afterwards leaves such a row reachable, and
putting it in the `WHERE` clause does not.

## Consequences

- `aggregate_evidence` has its first production caller, and nothing recomputes
  a status afterwards;
- a rejected address costs zero DNS lookups and zero sockets;
- Phase 2 decides whether there is anywhere to connect, and Phase 6 reads
  `connectable_candidates` rather than re-reading a DNS answer;
- an `internal_error` reaches the operator sink while the caller sees `unknown`,
  and so does an *unexpected exception*: the first build answered `500` and told
  nobody, which an independent review measured;
- this project's own pacing reaches the operator from a production-reachable
  fact — the `AttemptRecord`s the Phase 4E loop produces — rather than from a
  `RateLimitTimeout` that layer never sees. The first build had a handler only a
  fake could exercise;
- an explicit cancellation releases every permit, every lease, and every socket,
  and stops the SMTP dialogue rather than detaching it. A *job* accepted by
  `POST /v1/checks` deliberately outlives its request; ADR 0014 separates the
  two lifetimes.

## Deferred, and named rather than implied

- the ASGI binding, for the reason above. The `prompts/06-api-cli.md` privacy
  requirement "request logging middleware must redact" belongs with it and is
  recorded as a stop condition on that work;
- Redis and PostgreSQL adapters, in the uninstalled `service` extra.

**Update (0.1.0 public release).** The `phase6` and `service` extras, and the
PostgreSQL/Redis `docker-compose.yml` that accompanied them, were removed before
publication: no module imported any of their packages, so they only widened the
dependency and audit surface. The deferrals above stand. Whoever implements the
ASGI binding or a Redis/PostgreSQL adapter adds the dependency it actually
imports, with an ADR, at that time.

**Not deferred.** An earlier revision of this ADR recorded the asynchronous job
subsystem and the result cache as deferred, on the authority of a conversational
instruction forbidding work that outlives a request. That instruction was not a
repository requirement, and recording it here made a transient brief look like
durable design rationale.

`docs/requirements.md` sections 5 and 11 and `prompts/06-api-cli.md` require
authenticated asynchronous active checks in Phase 6, so bounded background job
execution is part of Phase 6. ADR 0014 records the job subsystem; ADR 0015
records the result cache and the verdict TTL that this ADR previously described
as an undecided question.

## Alternatives rejected

- **Re-keying the Phase 4 token bucket on the account.** It would make each
  account's destination pacing independent, which is the opposite of protecting
  a destination, and it would change what a reviewed gate measures.
- **Returning a partial verdict on the total deadline.** See above.
- **A deny list of forbidden request fields.** It is one hazard behind, always.
- **Serializing the `Verdict` directly.** One `Evidence` field away from
  publishing a remote server's prose.
