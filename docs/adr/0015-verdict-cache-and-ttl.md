# ADR 0015: The result cache, its key, and the verdict TTL

- Status: Accepted
- Date: 2026-08-10
- Phase: 6

## Context

`prompts/06-api-cli.md` requires "cache lookup before enqueue" and a test that a
cache hit skips the enqueue. `docs/architecture.md` section 6 fixes the rule:
"Repeated requests within the address cache window return the existing result
unless an authorized caller explicitly requests a refresh and has budget."

`docs/requirements.md` section 13 gives cache defaults **per evidence class**
and fixes the key: "Cache keys include relevant ruleset, sender identity, and
normalized target HMAC." It defines no lifetime for an aggregated `Verdict`,
which is a composition of evidence from several classes at once. The first
Phase 6 build left this undecided and left the store off the request path.

## Decision: a verdict lives no longer than the shortest-lived evidence that decided it

```text
verdict TTL = min(TTL of each decision-relevant reason)
```

and a verdict whose decision-relevant evidence includes a class section 13 does
not price is **not cached at all**.

The alternatives were weighed as follows.

| Candidate | Rejected because |
|---|---|
| Primary reason only | A `likely_deliverable` from `rcpt_accepted` would cache for six hours even when the MX record it depended on had a five-minute TTL. The acceptance is only as current as the route it was obtained through. |
| Status-specific TTL | A second table keyed on something section 13 never mentions, which would drift from section 13 the first time either changed. |
| Maximum, or any average | Serves a stale positive answer, which is the one error this project's status model exists to avoid. |
| All evidence, including risk | Passive datasets are versioned rather than timed (section 13), so every routed verdict would be uncacheable and the cache would not exist. |
| Tier-decisive evidence only | The most precise answer, and it would require Phase 6 to import the aggregation internals that the Phase 5 stop-condition inspection refuses. Correctness of the cache is not worth a hole in the re-derivation barrier. |

**Decision-relevant** means: every reason in `Verdict.reason_codes`, minus the
four risk-only reasons. That set is published vocabulary, needs no aggregation
internals, and includes both the reason that decided the status and the route
reason it rests on.

Risk-only reasons — `disposable_domain`, `role_account`, `free_mail`,
`provider_opaque` — are excluded because section 13 governs passive datasets by
**data version** rather than by duration. They also decide nothing: a risk flag
never changes a status, so letting one shorten a verdict's life would be a
timing rule derived from an observation with no bearing on the answer.

`internal_error` is never cacheable, at any position. A failure of this
project's own is not an observation about the address, and storing one would
serve our outage back to the next caller.

## Decision: DNS-layer reasons are priced by the DNS TTL, which Phase 2 already computed

Section 13 prices DNS by the record's own TTL under a cap — 24 hours positive, 3
hours negative — and `domain/dns.py`'s `apply_ttl_policy` already implements
exactly that, including honouring a served TTL of zero as zero. `MailRoute.ttl`
carries the result.

So the policy reads `route.ttl.applied_seconds` for a DNS-layer reason rather
than re-deriving a cap, and a served TTL of `0` makes the verdict uncacheable —
the server asked for no caching, and that request survives aggregation.

`VerificationOutcome` gained one field to carry it. That is additive: it decides
nothing, and no status reads it.

## Decision: the SMTP classes are section 13's table, and nothing else is priced

| Reason code | Section 13 class | TTL |
|---|---|---|
| `rcpt_accepted`, `rcpt_forwarded` | SMTP accepted | 6 h |
| `rcpt_rejected_address` | explicit recipient-not-found | 1 h |
| `smtp_temporary_failure`, `mailbox_full` | temporary SMTP failure | 10 min |
| `rcpt_rejected_policy`, `smtp_policy_blocked` | policy block | 30 min |
| `smtp_connection_timeout` | connection timeout | 5 min |
| `accept_all_suspected` | accept-all suspected | 7 d (Phase 9; not produced today) |

**Everything else is uncacheable**, and the list of what that covers is worth
stating because it is not small: `rcpt_unverifiable` (`252`),
`smtp_ambiguous_permanent_failure` (a bare `550`), `smtp_connection_refused`,
`smtp_banner_invalid`, `smtp_protocol_error`, `smtp_tls_failure`,
`mail_from_rejected`, `unsafe_destination`, and every syntax reason.

Two of those are common answers, so this costs real repeat probing. The
alternative is to invent a duration section 13 did not write, which is how a
cache policy becomes a deliverability rule nobody reviewed. **Recorded as a gap
for a section 13 amendment rather than closed by guessing.** Syntax reasons
being uncacheable costs nothing: a rejected address already reaches its status
with zero DNS lookups and zero sockets.

## Decision: the key is section 13's, plus the account boundary already in the store

```text
(target HMAC, sender identity HMAC, aggregation ruleset, account HMAC)
```

Section 13 requires the first three. The fourth is retained from the existing
store rather than dropped: `prompts/06-api-cli.md` forbids cross-account result
access, and a shared cache row is the quietest way to hand one account another
account's answer. Section 13's list is a minimum, and narrowing isolation to
meet it exactly would trade a privacy property for a hit rate.

The **sender identity is a key component, not a column beside one.** A verdict
obtained from one envelope sender is not evidence about another: reputation,
SPF alignment, and policy responses are all properties of the sender that asked.
It appears in the `WHERE` clause, and a mutation removing it fails a test.

Every component is an HMAC under the operator's correlation key —
`security/identifiers.py`, which until now had no production caller. The raw
address, the raw account identifier, and the raw sender never reach the
database.

## Decision: expiry is a lookup predicate, not a filter afterwards

`expires_at` is stored and compared in the `WHERE` clause, next to the ruleset.
A row filtered after selection is a row an implementation can still answer with;
one excluded by the query is not. This is the same argument Phase 5 stop
condition 4 made for the ruleset, and it gets the same treatment.

The schema version moves from 1 to 2. `prompts/06-api-cli.md` says not to
overbuild migrations, and no document requires an existing development database
to survive, so a version-1 database is refused at start rather than migrated.

## Decision: only an active verification's verdict is cached

A passive verdict and an active one for the same address are different evidence,
and serving the first for an active request would answer without probing while
reporting a status derived from a probe that never happened. Only a completed
active job writes a cache row, and only an active submission reads one.

## Decision: there is no refresh field, because the repository defines no way to authorize one

Section 6 of `docs/architecture.md` permits an existing result to be bypassed
"unless an authorized caller explicitly requests a refresh **and has budget**".
Both conditions are structural: an authorization model that distinguishes a
refresh-capable caller, and a budget to spend. This build has neither — every
authenticated principal is equal, and there is no separate refresh budget.

So no refresh parameter is accepted. Adding one now would be a
request-controlled cache bypass with the authorization half missing, which is
the shape `prompts/06-api-cli.md`'s closed request schema exists to refuse. The
request body still carries exactly one key.

## Consequences

- a cache hit returns a completed job and enqueues nothing, which is measured
  rather than assumed;
- `security/identifiers.py` has a production caller;
- a verdict is never served after the shortest-lived evidence behind it expired;
- two common SMTP answers are not cached, and section 13 needs amending before
  they can be.

## Alternatives rejected

- **Inventing TTLs for `252` and bare `550`.** They would be deliverability
  policy written in a caching ADR.
- **Dropping the account from the key** to match section 13's list exactly.
- **Filtering expiry in Python after the query.**
- **Caching passive verdicts for active requests.**
