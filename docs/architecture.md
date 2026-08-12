# Architecture

## 1. Dependency direction

```text
apps/api, apps/cli
        ↓
application use cases
        ↓
domain models and policies
        ↑
ports
        ↑
adapters
```

Domain and application policy must not depend on concrete web frameworks,
databases, DNS libraries, SMTP sockets, or Redis clients.

## 2. Core concepts

### Address

Untrusted text becomes a usable value through one path only:

```text
RawAddressInput
  → parse_address
  → AddressAccepted | AddressRejected
  → NormalizedAddress
```

`RawAddressInput` holds the submitted text and a redacted display form. It has
no SMTP target and no parsed parts, so raw input cannot be handed to an external
I/O port. `parse_address` returns a result rather than raising: user mistakes
are data, and only a programmer error raises. A rejection carries a specific
issue, whether the input broke the supported grammar or is merely unsupported,
and a public reason code, so aggregation never re-parses text.

`NormalizedAddress` is the only address type the DNS and SMTP ports accept. Its
parts validate themselves on construction, so it cannot exist in a state where
its target would carry CR, LF, NUL, or a domain that differs from the one it
displays.

`application/syntax_evidence.py` turns a rejection into `Evidence`, and there is
deliberately **no** evidence for an address that parsed: no published reason code
means "the syntax was fine", and one would be the first thing an aggregation
mistook for delivery evidence. Strength follows `RejectionKind`, which already
separates a broken grammar from a form this MVP declines to judge.

Parsing is pure domain logic, not a port. It performs no I/O and depends on no
clock or randomness, and a replaceable implementation would weaken the guarantee
that one construction path validates every target. A future syntax policy
change, such as SMTPUTF8 support, is added as a domain policy rather than behind
an I/O port. See ADR 0005.

### Mail route

DNS answers become a `MailRoute`, never a verdict. The distinctions it keeps are
the ones later aggregation cannot recover:

| Observation | Outcome | Later status |
|---|---|---|
| Authoritative NXDOMAIN | `domain_not_found` | hard invalid |
| RFC 7505 Null MX alone | `null_mx` | hard invalid |
| No MX and no A/AAAA | `no_mail_route` | hard invalid |
| SERVFAIL, timeout, refused | `temporary_failure` | temporary |
| MX records exist, none usable | `configuration_anomaly` | unknown |
| A malformed answer anywhere | `configuration_anomaly` | unknown |
| Every candidate address refused | `unsafe_destination` | unknown |
| This project failed | `internal_error` | unknown, never about the domain |
| Usable MX host | `mx_route` | a route, not a mailbox |
| No MX, usable A/AAAA | `implicit_mx_route` | a route, not a mailbox |

Only an authoritative absence on both address families reaches `no_mail_route`.
A malformed answer, a refusal, a timeout, or a failure of this project's own
proves nothing about the domain and never becomes a hard-invalid result.

A route carries ordered candidates, each with its own status, so an exchanger
that will not resolve is reported separately from a domain that cannot receive
mail. `connectable_candidates` is empty for every outcome except the two route
outcomes, so a Null MX cannot yield a destination later, and every candidate it
does return carries at least one allowed address for Phase 4 to connect to.
`MailRoute.reason` is derived from the outcome, so a route cannot report the
reason code of a different outcome.

Each resolved address passes the destination policy in `security/` before it
becomes a candidate. That policy is a pure function and runs again in Phase 4
against the address a socket actually connected to.

### Passive classification

Four signals that need no network, kept independent because they are wrong in
different ways:

| Signal | Input | Result |
|---|---|---|
| Role account | local part, compared exactly on a lower-cased tag-stripped form | risk flag |
| Disposable | destination domain, with local overrides | risk flag |
| Free-mail | destination domain only | risk flag |
| Provider family | MX host names, label-bounded suffix match | metadata |

`PassiveClassification` has no status field, so this layer cannot express a
deliverability judgment. Its three reason codes are risk-only, its evidence is
weak and non-temporary, and provider family is metadata that may select a reply
parser later but never a verdict.

Free-mail is membership of the destination domain, never an inference from who
hosts its mail: a company domain behind a large provider is not free-mail.
Provider inference reads only MX-sourced hosts, abstains with `unknown` when two
families match, and never attributes `google.com.evil.example` to anyone.

A classification holds a validated `HostName` and, when a role matched, a
canonical `RoleName` taken from the dataset. Neither can hold a complete
address or a submitted local part, so what reaches evidence is bounded by the
types rather than by the caller's care.

Datasets are versioned files loaded explicitly, never at import and never
downloaded. Each answer carries the dataset version that produced it. The
document schema is closed: an entries array is mandatory even when empty, an
unknown top-level field is refused, and metadata values are bounded and free of
control characters because they become `Evidence.source_version`.

Overrides correct one list. `not_disposable` and `disposable` describe
membership of the disposable list and never a delivery decision — the allow/deny
vocabulary belongs to `security/destination.py` alone. An override file declares
the `target` it corrects, and an unimplemented target is refused. See ADR 0007
and `src/emailcheck/data/passive/README.md`.

### SMTP probe

The command set is closed, and what keeps it closed is the encoder's shape:
`domain/smtp_command.py` has six functions, one per allowed command, each taking
typed values, and no function that takes a command name. A caller cannot ask for
a command the enum does not have, because there is no parameter through which to
ask. `scripts/check_forbidden_smtp.py` refuses fourteen commands in every
production SMTP path, reading the first SMTP verb of each string literal rather
than matching text.

A session is an immutable value in `domain/smtp_session.py`. Two of its refusals
are product promises rather than protocol details:

| Promise | How it is kept |
|---|---|
| At most one `RCPT TO` | The state table gives `RCPT_RESULT_RECEIVED` no way to issue one, **and** a counter refuses one from any state |
| No plaintext after a TLS failure | Failure moves to `FAILED`, which permits only `QUIT` and has no transition back |

The destination policy runs three times, and each run is a type rather than a
step:

```text
RouteCandidate            Phase 2, on the DNS answer
  → approve_destination()   the address must be one the candidate offered
  → ApprovedDestination     the policy runs again, before connect
  → confirm_peer()          the address and port the socket actually reached
  → ConfirmedPeer           the policy runs a third time
  → SMTPSession             checks it is a ConfirmedPeer at run time
```

`approve_destination` is the only path in. The policy answers "is this address
safe to reach"; it does not answer "did the domain publish it", so the factory
asks the second question by requiring the address to be one the candidate
resolved to, and takes the host from the candidate rather than from a parameter.

`SMTPSession` verifies the peer's type in `__post_init__` rather than trusting
the annotation, and `SMTPTransport.connect` verifies its destination the same
way before it evaluates the policy or creates a socket: mypy checks `src` only,
`Any` launders a wrong value, and an object that merely has an address, a port,
and a version has passed none of the checks the type stands for.

`PeerEndpoint` validates its own shape — a numeric address with no CR, LF, NUL,
or scope identifier, and a port within 1..65535 — and stops there. **The value
guarantees the shape; `confirm_peer` grants the permission.** A value type that
judged policy would let a caller acquire the permission by constructing the
value, so the two stay independent and both are tested refusing on their own.

`application/smtp_connect.py` is the only production code that walks that chain,
and `adapters/smtp/asyncio_transport.py` is the only module that opens a socket.
The transport is an I/O component and nothing more: it connects, reports the
peer, reads bounded lines, and closes. It makes no protocol decision and knows
nothing about `EHLO`, reply codes, or the recipient stage.

`application/smtp_dialogue.py` is the protocol on top of it — banner, `EHLO`,
capability parsing, optional `STARTTLS` with a re-`EHLO`, `MAIL FROM`, one
`RCPT TO`, then best-effort `RSET` and `QUIT`. It decides *when*, and everything
it is allowed to say existed before it did.
`application/smtp_probe.py` owns the order the whole probe happens in:

```text
rate-limit authorization → start the session deadline → approve destination
  → connect → confirm peer → session → dialogue → close
```

Three properties of that split matter more than the code:

- **the only thing that can be written is an encoded command**, and three
  separate layers are what make that true. Stating them separately matters,
  because the type alone is weaker than it looks:

  | Layer | What it guarantees |
  |---|---|
  | `WireCommand` | one CRLF-terminated line, within the 512-octet limit, carrying no other CR, LF, or NUL, and beginning with the verb the value names |
  | The six factories in `domain/smtp_wire.py` | the only argument forms production approves — each calls the matching encoder on typed values |
  | An inspection test | production code builds a `WireCommand` **only** through those factories |

  The type constrains the verb, not the argument, so `RCPT TO:<a@b>,<c@d>` and
  `MAIL FROM:<x@y> AUTH=<victim>` are refused by the second and third layers
  rather than by the first. Saying the type alone fixes the reachable wire lines
  would claim more than the code does, which ADR 0008 already established is
  worse than claiming less. There is no method taking `bytes`, a string, or a
  command name; `_write_line` stays private inside the adapter (ADR 0009);
- **no socket, stream, reader, or file descriptor crosses the port.** The
  application sees a `PeerEndpoint`, typed read outcomes, and a close;
- **every path that does not return a session closes the connection**, in a
  `finally`, so an exception between connecting and confirming leaks nothing.

The transport connects with `AF_INET` for an IPv4 destination and `AF_INET6` for
an IPv6 one and never relies on `AI_V4MAPPED`, because a dual-stack socket
reports an IPv4 peer as `::ffff:…`, which the policy refuses on purpose. A
mapped or 6to4 peer is refused as `PEER_UNEXPECTED_FAMILY` rather than unwrapped:
the family is normalized by the transport, and the policy is never taught to
trust a mapped address. Only port 25 is reachable, and the peer port is
confirmed against it.

Every read, write, and connect has its own deadline, and a reply is bounded per
line and per connection. `TransportFailure` is this project's vocabulary for
what went wrong; a library's exception text never reaches a caller, and no
transport failure is ever evidence about the address. Cancellation,
interruption, and this project's own invariant failures are the exception: they
are re-raised rather than named, because a worker that was told to stop must not
be answered with a fact about the network. `close` needs no deadline of its own,
because it performs no `await` — which also means it offers no point at which a
cancellation could leave the descriptor open.

Sender provenance is a port, not a value. `EnvelopeSender` fixes the shape;
`SenderIdentityProvider` in `ports/smtp_sender_identity.py` supplies one from
operator configuration, never from the probe target or from user input, and
`adapters/smtp/sender_identity.py` implements it from a mapping the caller loaded
deliberately. It reads no environment variable, refuses an unknown key, refuses
the null reverse path, and refuses an EHLO name unrelated to the sender's domain.

TLS is `adapters/smtp/tls.py` and `adapters/smtp/asyncio_transport.py`, and
nothing else imports `ssl` — a value type or an orchestration step that knew
about `SSLContext` would be one that could be handed an insecure one.
Verification is not configurable: `check_hostname` and `CERT_REQUIRED` are always
set and there is no parameter that changes either. The name verified against
comes from the `ConfirmedPeer`, so the destination chain reaches all the way into
the handshake, and `start_tls` compares the peer that request carries against the
endpoint the connection actually reached before anything is negotiated. A failed
handshake is terminal and is never mailbox evidence.

`TLSTrust` is the one seam and it may only widen trust. **It is operator
configuration only**: request, user, and API input may never supply a CA file, a
PEM body, a trust anchor, or a verification override, and that is a stop
condition on Phase 6 rather than a convention (ADR 0009).

Two deadlines bound a probe and the total dominates: per-operation timeouts in
`TransportTimeouts`, and a `SessionBudget` in `domain/smtp_deadline.py` measured
against a `MonotonicClock`. The total starts in `application/smtp_probe.py`
*before* the connect, so one probe costs one budget rather than
`connect_seconds + budget`, and the effective connect bound is the smaller of the
two. Waiting for a rate-limit lease sits outside it, so queueing is never
recorded as a remote timeout. See ADR 0009.

A reply becomes `SMTPReply`: a basic code, a valid enhanced code when there is
one, and a bounded diagnostic. The remote text is not kept. The sanitizer's
guarantee is narrow and stated exactly: a token containing a literal ASCII `@`
is removed and no `@` survives, control and format characters are removed, and
the result is bounded — it is **not** an RFC mailbox parser or a general PII
scrubber, and a raw reply must never reach an ordinary log.
`RecipientObservation` records what was observed and carries no status: `250`
does not become `likely_deliverable` and `550` does not become `invalid`,
because an accept-all server says the first to everyone and policy rejections
share the second. `SessionReport` in `domain/smtp_protocol.py` wraps it with the
stage reached, the TLS detail, the capability set, the cleanup status, and the
command transcript — all context for Phase 4D, none of it a verdict. See ADR 0008
and ADR 0009.

`application/smtp_evidence.py` is where an SMTP observation becomes published
vocabulary, and it is a **pure function**: a `SessionReport` and a timestamp in,
`Evidence` out. No socket, no clock, no resolver, no limiter, no storage, no
retry. `observed_at` is a parameter rather than a `Clock` port — unlike the
passive and DNS producers — because a mapping whose output depends on when it ran
is not a mapping, and an inspection test enforces the rest.

It reads the whole report rather than one field. `stage_reached` is what
separates a rejected sender from a refused greeting, since both are
`CONNECTION_ERROR`; `basic_code` is what separates `252` from `250`, since both
are `ACCEPTED`. **`252` is branched on before any generic handling of a 2xx
reply**, because a mapping written against `outcome` alone turns a server's
refusal to verify into an acceptance (ADR 0010).

Three independent barriers stand between a `MAIL FROM 550` and a recipient
rejection — the outcome must be one a recipient answer produces, exactly one
recipient must have been attempted, and the session must have reached the
recipient stage — **and each is pinned by a test that fails when that barrier
alone is removed**. The stage set is derived from `STAGE_ORDER` rather than
listed, so a stage added after `RCPT_TO` is included instead of being silently
treated as pre-recipient. Every real recipient answer reports `cleanup` rather
than `rcpt_to`, because `rcpt_to` is the stage a dialogue is *in* while the
command is outstanding; `docs/status-model.md` section 7.3 says so, and a Phase 5
filter written the other way would discard all of it.

One piece of evidence per session. The TLS outcome, the deadline flag, and the
cleanup status are details on it rather than evidence of their own, which is what
makes "a cleanup failure never overwrites the recipient's answer" structural
instead of remembered. `NON_TARGET_SMTP_REASONS` and `RECIPIENT_STAGE_REASONS`
are published beside the mapping so Phase 5 filters rather than re-derives, and
they **partition** every reason the mapper emits — a tested property, because
`about_the_target` is derived from the recipient-stage set so that an
unclassified reason is non-target rather than target evidence. Phase 4D produces
no status, no confidence, and no risk flag.

### Verification orchestration

`application/smtp_verification.py` is the last gate of Phase 4 and the only code
that runs more than one probe. It takes a `NormalizedAddress` and a Phase 2
`MailRoute` and returns a `VerificationReport`: attempt records, the `Evidence`
each attempt produced, and an operational stop reason. No status, no confidence,
no verdict.

```text
MailRoute → plan_attempts()  ordered, de-duplicated, capped
  → for each: rate-limit lease → probe → SessionReport | ProbeRefused
  → gate 4D mapper → Evidence
  → stop, or try the next candidate
```

**One verification issues at most one `RCPT TO`, in total.** Gate 4A's state
table and counter bound one *session*; this bounds the whole request. Reaching
the recipient stage ends the verification — not receiving an answer, reaching the
stage — so a `450`, a `550`, a `252`, a reset after the command went out, and a
write that failed part way all stop it identically. A second exchanger asked
about the same recipient is the enumeration pattern `docs/threat-model.md` lists
first, and it would be a retry, which this gate does not do at all.

Two barriers decide it and each is pinned by its own test: the transcript naming
`RCPT TO`, and the stage being at or past `RCPT_TO`. A failed write reaches the
stage without reaching the transcript; a `SessionReport` may carry the transcript
at an earlier stage. Neither alone is enough.

**Fallback is only for failures before the recipient stage**, and never for a
failure of this project's own — hiding our bug behind another server's answer is
what Phase 2 and gate 4B already refuse. Cancellation and interruption propagate
rather than becoming a fallback.

**The plan is bounded before anything connects.** Candidates come in Phase 2's
preference order, are expanded in the address order Phase 2 recorded, are
de-duplicated on `(MX host, address, port)`, and are capped. Nothing is sorted
again and nothing is randomized. The de-duplication key includes the host name
because the certificate is verified against it: two exchangers sharing an address
are two TLS identities, and collapsing them would accept one host's certificate
for the other's name. See ADR 0011.

### Rate limiting

`adapters/system/rate_limit.py` implements the `RateLimiter` port that
`SMTPProbeService` has required since gate 4C. Three budgets, acquired in order
and released in reverse, inside one wait deadline: global concurrency, per-domain
concurrency, and a per-domain token bucket for pacing. A caller holds all three
or holds none — a refusal, an exception, and a cancellation all unwind what was
taken, because a concurrency slot that is not given back removes capacity from
the process permanently.

All the arithmetic and every bound is in `domain/rate_limit.py` and is pure:
refill is clamped after the addition so no amount of idling widens a burst, and
`TokenBucket` refuses a token count outside `0..capacity`. Time comes from
`MonotonicClock` and waiting from `Sleeper`, so pacing is measurable in a test
without waiting for it.

**The budget Phase 4 enforces is per recipient domain, and only that.**
`RateLimiter.acquire` takes an account, the recipient's domain, and the MX host;
`rate_limit_key` canonicalizes and validates all three, and the limiter then
partitions its state by the **domain alone**. The account and the MX host are
carried and checked but do not divide any budget today.

Saying so precisely matters. `docs/requirements.md` section 15 requires
per-account budgets for the service-active profile, and Phase 4 does **not**
implement one — because an account identifier only becomes meaningful when
Phase 6 authenticates it. A caller-supplied `account` string used as a budget
partition would look like per-account isolation and be bypassable by sending a
different string, which is worse than not having one. `plans/phase-04-smtp.md`
carries it as a Phase 6 stop condition.

`rate_limit_key` refuses an `@` in any component rather than stripping one, so
no component can be a mailbox. That is a **shape** check: it says what the value
is not, and says nothing about where it came from.

**Per-domain state is bounded** by an idle TTL and a least-recently-used cap, and
an entry in use — holding a lease *or* waiting for one — is never evicted, in
either sweep. That guard is a safety barrier rather than tidiness: evicting a
held entry replaces a spent bucket with a full one, which is a pacing bypass, so
each sweep's guard has a test that fails when only it is removed. The TTL applies
to idle entries only and is **not** required to exceed the longest SMTP session.

The bound is `max_tracked_domains` **plus whatever is in flight**. A caller
registers interest in a domain before it is admitted globally, so in-flight
entries are bounded by the concurrency of the calling code rather than by this
table — bounding *that* is Phase 6 admission control, recorded as a stop
condition. The attack this table closes is the other one: a caller supplying an
unbounded number of different domains over time.

**The wait is bounded and is not the session budget.** ADR 0009 put the
rate-limit wait outside the SMTP deadline so queue depth is never recorded as a
remote timeout; the wait has its own budget, and exceeding it raises
`RateLimitTimeout` — deliberately not a `TimeoutError` and not an `OSError`, so
a handler written for a remote timeout cannot catch this project's own queueing.
A refused verification opens no socket and produces no SMTP evidence.

The limiter is single-process. It bounds one worker rather than a fleet, which is
what the MVP needs and why the port exists: a shared limiter implements the same
`acquire`, and nothing above the port learns which one it has.

### Evidence

An immutable observation produced by one layer. Evidence records:

- layer;
- kind;
- normalized reason;
- strength;
- permanence;
- safe structured details;
- observed time;
- source version.

It validates itself, because an annotation is not a runtime check and this is a
value assembled from a caller's parameters rather than from values that have
already validated themselves. **`observed_at` must be timezone-aware**: a naive
datetime cannot be compared with an aware one without raising, and aggregation
orders evidence from four producers. Three of them take a `Clock`, which always
answers aware UTC; `application/smtp_evidence.py` takes the timestamp as a
parameter so that it stays a function of its input, which makes it the one
producer whose timestamp arrives unvalidated. Every detail value is a string, an
integer, a boolean, or null — the bound `docs/status-model.md` section 7.5 puts
on what may reach a public response, enforced where the value is built.

**`strength` is evidence weight, never a verdict.** `STRONG` may not be mapped to
`invalid` by aggregation: that needs target-specific, non-temporary evidence with
the right reason semantics, and a non-target SMTP reason never supports it
whatever its strength.

### Verdict

A deterministic aggregation of evidence: status, confidence level, primary
reason, ordered reason codes, risk flags, check summaries, the retained evidence,
and a ruleset version.

`application/aggregate.py` is the only thing that builds one. It implements
`docs/status-model.md` section 4 as six tiers, and **the lowest non-empty tier
decides**. Nothing counts observations, weights them by strength, or reads the
order they arrived in.

**Two gates, and each is in exactly one place.** `invalid` needs an approved
hard-invalid reason *and* target-specific evidence *and* non-temporary evidence;
`likely_deliverable` needs no tier 1–4 blocker *and* a usable route *and* a
qualifying recipient acceptance. An inspection test asserts that no function in
the module names either status at all — a tier becomes a status in one table —
because two `if`s producing one status are two conditions that will drift apart.

**Strength is not an input to either gate.** The module does not import
`EvidenceStrength`, so `if strength is STRONG: return INVALID` is unreachable
rather than merely absent. Membership of `POSITIVE_RECIPIENT_REASONS` is a
condition of three, never an answer: an accept-all server says `250` to everyone.

**The route requirement is the one condition section 2 does not state.** A lone
`rcpt_accepted` is an evidence set the pipeline cannot produce — an acceptance
implies a route was resolved and connected to — and an aggregator must not assume
its input is coherent, so a bare acceptance is `unknown`. ADR 0012 records it.

**Confidence is a table on the primary reason**, with no arithmetic anywhere.
`docs/requirements.md` section 17 permits a probability only after a calibration
study, and `Confidence` now refuses a score while `calibrated` is false. A table
also makes duplicate evidence, input order, and unrelated observations
structurally unable to move the level.

**Duplicates collapse before any rule runs.** Gate 4E can produce three
pre-recipient failures for one address, and those are three attempts at one
question rather than three answers to it. Decision-time deduplication and
audit-time retention are separate: the verdict keeps the whole input tuple in
the caller's order, unmodified.

**Two contradictions are unconstructible.** `PERMITTED_PRIMARY_REASONS` in
`domain/verdict.py` refuses an `invalid` verdict naming an accepted recipient and
a `likely_deliverable` one naming a rejection — including from a Phase 6 that
assembles a result some other way. The two unknown statuses stay open, because
section 5 says one reason may appear under different statuses and an aggregator
that raised on contradictory evidence would be worse than one answering
`unknown`.

Tier 3 membership is the `Evidence.temporary` flag and nothing else — there is no
second list of temporary reason codes to keep in step — and it is fail-safe in
both directions, because neither a wrongly-set nor a wrongly-cleared flag can
reach `likely_deliverable`. Tier 6 holds route evidence as well as passive
metadata: residual observations that block nothing and answer nothing.

**The primary reason always leads `reason_codes`, and `Verdict` refuses a result
where it does not.** The two orderings are computed separately, so the type is
what keeps them in step.

Risk flags are derived after the status and read by nothing: a disposable
address may be likely deliverable, and a role address may be invalid.

Pure. No socket, resolver, limiter, storage, retry, or clock —
`Evidence.observed_at` is input metadata, no document defines a staleness policy,
and inventing one would silently weaken the evidence a rate-limited SMTP session
was spent collecting.

### Composition, and the public boundary

`composition.py` is the only module in `src/` that names a concrete adapter, and
it is where four Phase 4 stop conditions are closed — because each is a property
of the object graph rather than of any class in it. It builds **one** limiter,
**one** admission gate, one `SystemClock`, one `SystemMonotonicClock`, and one
`SystemSleeper`, and hands the same instances to every request: a limiter
constructed per request has counters that start at zero, which permits
everything. `build_verification_stack` exposes no parameter for a clock, a
sleeper, a limiter, a transport, or a `TLSTrust`, and a test asserts the
signature.

A deployment with no active probing gets a service whose `smtp` is `None` rather
than one holding an SMTP service behind a boolean. `docs/requirements.md`
section 15's local-passive profile is "no active probes", and an absent object
cannot be called by a later edit that forgets a flag.

`application/verification.py` is the high-level service and the only door. A
rejected address stops before DNS, so an invalid or unsupported input costs zero
lookups and zero sockets; the SMTP step runs only when
`MailRoute.connectable_candidates` is non-empty, so Phase 2's decision about
whether there is anywhere to connect is *read* rather than re-derived. The
account the limiter partitions by is `principal.rate_limit_account` and nothing
else.

`Principal` is the value that closes Phase 4 stop condition 2, and the split is
the one `PeerEndpoint` uses: **the value guarantees the shape,
`ports/authentication.py` grants the identity**, and an inspection test refuses
the constructor outside the authenticator adapter. There is no anonymous
principal and no default account.

**Two bounds Phase 6 owns.** `application/admission.py` caps concurrent
verifications *and* the queue in front of them — a bounded pool behind an
unbounded queue moves the growth rather than stopping it — plus a per-principal
cap. Re-keying the Phase 4 token bucket on the account would have made each
account's destination pacing independent, which is the opposite of protecting a
destination.

**What that per-principal cap is and is not.** It bounds *concurrency* per
account, which is the part of `docs/requirements.md` section 15's per-account
isolation Phase 6 implements.

Phase 6 bounded the waiting queue **globally** and this document recorded what
that left open: one account filling it could crowd another out. Phase 7 closed
it. A principal may hold at most `AdmissionSettings.queue_share` of the waiting
slots, so a caller issuing requests faster than they are served can no longer
make every other account answer `AdmissionRefused` while holding no capacity at
all. The share is *derived* from the queue length when it is not set, because a
fixed default larger than a short queue would bound nothing — and the only other
honest option was to refuse configurations that already existed.

That is the smallest thing that closes the property: not a fair queue, not
round-robin, not a reservation per known account. `docs/operations.md` section 5
asks that fair scheduling stop one *domain* occupying all worker capacity, which
is Phase 4's pacing; this is the caller-side half.

And a **verification-total deadline** bounds the sum of every per-candidate
bound. `asyncio.timeout` sits *outside* `admission.admit`, so the wait for a
permit is inside the same clock: a queue bounded only in depth leaves that wait
unbounded in time, and an independent review found this module's own
documentation claiming otherwise.

Capacity, pacing, and the total deadline are **local operational refusals**.
None produces `Evidence`, none becomes a `Verdict`, and `VerificationRefused`
derives from neither `TimeoutError` nor `OSError` — the treatment
`RateLimitTimeout` already gets, for the same reason. ADR 0013 records why a
partial verdict is not returned instead.

`application/public_result.py` is an allowlist. It reads `verdict.status.value`,
names no `Status` member, branches on no `ReasonCode`, and imports none of the
aggregation sets, so Phase 5 stop condition 1 is closed by absence. No
`Evidence.details` reaches it, the internal layer is not public, and
`as_json_object` builds no float — Phase 5 leaves the range of a calibrated
score undefined, so there is nothing a response could carry meaningfully.

`apps/api.py` maps a request to a status code and a body and **imports no web
framework**: section 1 of this document puts frameworks in `apps/`, and the
binding from an ASGI route to `handle` holds no policy. A request body may carry
exactly one key, so every low-level knob is refused by the rule that refuses a
typo. `apps/cli.py` runs the local-passive profile through the same service and
the same allowlist, and `--remote` submits to another instance through a
`RemoteCheckClient` port whose stdlib adapter converts every library failure
into this project's own vocabulary. **That adapter follows no redirect at all**:
it carries the operator's API key, and `urllib`'s default opener copies every
header except `content-length` and `content-type` onto a redirected request — so
a `302` sent the key cross-origin, and over plaintext `http` if the redirect
said so, while `security/remote_url.py` validated only the first URL. ADR 0014.
The key itself is read from a file under a hard size bound, with exactly one
conventional line ending removed and interior whitespace left alone. `apps/schema.py` publishes the contract, and
it is **generated**: every example body comes out of the same `public_result`
and `public_job` a real response does, so there is no second hand-written copy
to drift.

### Asynchronous active checks

`docs/requirements.md` section 11 makes `POST /v1/checks` create a job, and
`prompts/06-api-cli.md` states the requirement from the other side: **no
synchronous waiting for active SMTP in an API worker**. ADR 0014 records the
decisions.

```text
POST /v1/checks
  → authenticate
  → validate (one key, closed schema)
  → passive check           parse + DNS; returned immediately, section 11
  → idempotency lookup      in memory, keyed by (account, key, target HMAC)
  → cache lookup            one indexed row, ADR 0015
  → enqueue                 the SMTP half, later
```

**The passive step comes first**, because both lookups below it are keyed by the
normalized target and that target does not exist until the address has been
parsed. So a cache hit and an idempotent repeat both still cost the passive DNS
work; what they avoid is the enqueue and the SMTP probe — measured on an
executor that counts, rather than assumed from a fast response. That is the
property `prompts/06-api-cli.md` requires, and it is the expensive half by
orders of magnitude.

Saying it that way round matters: an earlier revision of this section put the
cache above the passive step and claimed a hit cost nothing, and a final
independent review measured three DNS lookups on one. A document that claims
more than the code does is worse than one that claims less.

**An idempotency key names one address.** The identity is `(account, key, HMAC
of the normalized target)` — `docs/architecture.md` section 6's "idempotency key
and a derived target HMAC", taken under the same operator secret the cache uses.
Reusing a key for a different address is a `409` conflict rather than a second
meaning for the key, because answering with the first address's job would be a
confident verdict about a mailbox nobody asked about. ADR 0014.

**An executor that refuses leaves nothing behind.** A registration is rolled
back when the work cannot be handed over: a `pending` job the executor never
accepted can never run, and eviction only removes terminal jobs, so one left
behind would occupy a registry slot for ever.

`domain/job.py` holds the six states `prompts/06-api-cli.md` publishes —
`pending`, `running`, `retry_scheduled`, `completed`, `failed`, `cancelled` —
and the closed transition table between them. A terminal state has no exit, so
`cancelled → completed` is unreachable rather than merely unused, and a
forbidden move raises rather than being ignored. **A job that has not completed
carries no status at all**: `unknown` is a real published status and a pending
job is genuinely unknown, which makes inventing one there the most tempting and
most misleading form of the re-derivation Phase 5 stop condition 1 forbids.

Job identifiers come from a `RandomSource` and carry nothing: not a counter, not
a timestamp, not a digest of the target. **Ownership is checked anyway** — an
unguessable identifier is a secret that can leak, and the second barrier is what
makes the leak survivable. A job belonging to another account answers exactly
what an unknown one does, because `403` would confirm the identifier is real.

`ports/job_executor.py` is the seam to a worker. `InMemoryJobExecutor` is the
development implementation `prompts/06-api-cli.md` asks for, and it is bounded
in every dimension: a fixed worker set, a bounded queue that refuses, a bounded
delay set, and no `create_task` on the job path. It answers `is_isolated` as
`False`, and the composition root **refuses** to build a service-active
deployment on it — section 15 requires an isolated worker for that profile, and
a development fake must not become the production default by omission.

**One retry, and only for what section 14 names.** `application/retry.py` maps
section 14's conditions onto reason codes and is a closed, explicit set:
`smtp_temporary_failure`, `mailbox_full`, and `dns_temporary_failure` are
retried, and `smtp_connection_timeout` is not — section 14 permits that one only
"if service health is otherwise normal", and this project does not model service
health, so retrying anyway would be implementing half a rule and calling it the
rule.

**The classification is the reason code's, never the reply's first digit.**
`mailbox_full` arises from `452 4.2.2` and from `552 5.2.2`, and section 9 calls
the latter a temporary storage condition — so a `552 5.2.2` is a 5xx that is
retried while a `550 5.7.1` is a 5xx that is not. There is no `if temporary:
retry` shortcut either: a reason added to the vocabulary later is not retryable
until somebody puts it in the table on purpose, and an exhaustiveness test fails
until one side or the other is chosen for it.

A retry is a whole new verification through `AddressVerificationService`, so
admission, DNS, the limiter, the destination policy, the one-`RCPT TO` bound,
and the total deadline all apply again. Phase 4E's rule is untouched and the
distinction is worth keeping sharp: a second exchanger or a second `RCPT TO`
*inside one verification* is the enumeration pattern `docs/threat-model.md`
lists first and gate 4E refuses; one whole new verification twenty minutes
later, capped at one, is what section 14 authorizes. The budget lives on the
job, so a second retry cannot be arranged by re-enqueueing.

### The result cache

`application/verdict_cache.py` and `domain/cache_policy.py`, decided in ADR
0015. The key is every input that could change the answer — the normalized
target, the sender identity the answer was obtained through, the aggregation
ruleset, and the account — as HMACs under the operator's correlation key, all of
them in the `WHERE` clause along with the expiry.

The lifetime is **the shortest among the evidence that decided the verdict**,
composed from `docs/requirements.md` section 13's per-class defaults. Section 13
prices evidence classes and not aggregated verdicts, so the composition is the
decision: a positive answer is only as current as the route it was obtained
through, and a verdict whose decisive evidence includes a class section 13 does
not price is **not cached at all**. That last part has a cost worth naming —
`252` and a bare `550` are common answers and are re-probed — and the
alternative was to invent a duration nobody wrote down, which is how a caching
rule becomes an unreviewed deliverability rule.

### Abuse controls, privacy, and observability

Phase 7. `prompts/07-hardening.md` is the scope and ADR 0016 records the
decisions. Three things are worth stating here because they are properties of
the graph rather than of any module in it.

**There are three control layers and they answer different questions.**
`application/admission.py` bounds how many verifications run at once,
`adapters/system/rate_limit.py` bounds how fast one destination is approached,
and `application/abuse.py` bounds how many a caller may ask for in a window.
None is re-keyed onto another's dimension: re-keying the Phase 4 token bucket
per account would give every account its own destination pacing, which protects
nobody. The prompt's "global concurrency" layer is admission's and is
deliberately not re-implemented — a reviewed bound with a second implementation
is two bounds that will disagree.

**Every budget key, metric label, and audit field is an opaque digest, a
canonical host, or a closed enumeration value.** `MetricLabels` is a closed
dataclass whose subject must be a value one of this project's enums already
declares, so a target, a local part, a job identifier, an API key, and a source
address are *unrepresentable* as labels rather than merely absent. Domain-level
analytics live in the operator event stream, which is redacted and retained
under a policy, rather than in a monitoring label that is kept for ever.

**A budget unit is a verification, not a request.** One submitted active check
spends the caller's layers twice — the submission's passive pass and the active
verification — and three times with section 14's retry. `per_account = 5000` is
therefore about 2500 active submissions per window. ADR 0016 decision 5c.

**Source identity stops at a type.** No header is read and none is trusted:
without a trusted-proxy list, `X-Forwarded-For` is written by whoever sent the
request, and a spoofable value in a budget key turns a per-source limit into a
per-claimed-source limit. A `SourceIdentity` comes from a transport boundary's
own peer address or it does not exist, and the source layer is simply not
counted when it does not. `ApiRequest.body` accepts exactly one key, so a body
cannot carry one.

**The administrative interface has no route.** `application/admin.py` publishes
the six controls `prompts/07-hardening.md` requires and binds to nothing:
putting an interface that can disable a security control behind whatever
authenticates the public API is what the phrase "non-public interface" exists to
prevent.

#### Stop conditions on the ASGI binding

Recorded here rather than left to be discovered by whoever writes it:

- **trusted client IP provenance.** The binding is the only thing that knows the
  peer address, and it is the only thing that may construct a `SourceIdentity`;
- **proxy header policy.** No `X-Forwarded-For` or `Forwarded` hop may be
  trusted without an operator-configured list of proxies that may set it. Until
  that list exists, the source layer stays uncounted;
- **request body size.** `VerificationLimits.max_submitted_length` bounds the
  address; the *body* needs a bound before it is parsed, which is middleware;
- **request logging redaction.** `prompts/06-api-cli.md`'s middleware, using
  `security/redaction.py` rather than a second implementation;
- **one `Deployment` per process, built at startup.** Not per request: a guard,
  a limiter, and an admission gate rebuilt per request permit everything;
- **no request-local limiter, quota store, or admin state**, for the same
  reason;
- **the administrative interface is not mounted on the public application.**

### Ports

Ports exist for external I/O, storage, and non-determinism: network, database,
cache, rate limiting, time, and randomness.

- `DNSResolver`
- `DomainClassifier`
- `SMTPProber`
- `Cache`
- `Store`
- `Executor`
- `RateLimiter`
- `SenderIdentityProvider`
- `Clock`
- `MonotonicClock`
- `Sleeper`
- `RandomSource`
- `Authenticator`
- `OperatorSink`
- `VerdictStore`
- `JobExecutor`
- `RandomSource`
- `RemoteCheckClient`
- `QuotaStore`
- `MetricsSink`

`MonotonicClock` and `Sleeper` are the two halves of the same problem: a
component that reads `time.monotonic()` can only be tested against the machine's
clock, and one that calls `asyncio.sleep` can only be tested by waiting. Both are
ports so that a deadline test measures the deadline and a pacing test measures
the pacing.

## 3. Suggested packages

```text
domain/
  immutable values and enums
application/
  orchestration and aggregation
ports/
  protocols owned by the application
adapters/
  concrete DNS, SMTP, storage, cache, queue, and HTTP boundaries
classification/
  passive datasets and provider metadata
security/
  destination policy, redaction, HMAC, and abuse features
config/
  profile validation
```

## 4. Active workflow

```text
request
  → parse and sanitize
  → passive DNS/classification
  → return hard passive result, or enqueue active job
  → acquire account/address/domain/MX budgets
  → resolve and validate destination
  → select stable sender identity
  → perform one bounded SMTP recipient transaction
  → normalize evidence
  → aggregate verdict
  → store redacted result
  → schedule at most one retry if explicitly temporary
```

## 5. Failure isolation

The API must continue to serve passive checks when:

- Redis is unavailable;
- active worker is disabled;
- port 25 is blocked;
- one provider tarpits;
- sender identity is suspended.

Active worker processes or containers must not have direct access to unrelated
internal services. Egress is limited to DNS and allowed SMTP destinations.

## 6. Idempotency

An active request has an idempotency key and a derived target HMAC. Repeated
requests within the address cache window return the existing result unless an
authorized caller explicitly requests a refresh and has budget.

## 7. Future scale

Scale by adding workers behind a shared fair scheduler. Do not change the
semantic core. Multiple static identities, if ever needed, are fixed shards
with shared destination limits, not a rotation mechanism.
