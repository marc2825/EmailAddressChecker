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
and `data/passive/README.md`.

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

A deterministic aggregation of evidence:

- status;
- confidence level;
- primary reason;
- ordered reason codes;
- risk flags;
- check summaries;
- ruleset version.

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
- `RandomSource`

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
