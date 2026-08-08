# SMTP probe state machine

## 1. Purpose

This client is a recipient-stage observer, not a mail-sending client.

The implementation must expose no operation that can submit message content.

## 2. Allowed states

```text
DISCONNECTED
  → CONNECTING
  → BANNER_RECEIVED
  → EHLO_COMPLETED
  → TLS_NEGOTIATED          optional
  → EHLO_COMPLETED_AFTER_TLS
  → MAIL_FROM_ACCEPTED
  → RCPT_RESULT_RECEIVED
  → RESET_COMPLETED         best effort
  → CLOSED
```

Error or timeout from any state transitions to a terminal failed state and then
best-effort close. `FAILED` permits only `QUIT`, and there is no transition from
it back to a state that can issue `MAIL FROM`, so a failed STARTTLS cannot
continue in plaintext.

`src/emailcheck/domain/smtp_contract.py` holds the per-state table of permitted
commands, and `smtp_session.py` holds the transitions as an immutable value.
Three rules are visible in the table:

- `TLS_NEGOTIATED` permits `EHLO` and `QUIT`, and nothing else. `EHLO` is the
  only way forward, so the session is re-introduced after TLS before anything
  else happens; `QUIT` exists so an upgraded session can still be ended politely
  rather than by dropping the socket. **`QUIT` leads nowhere**: it is a cleanup
  and abort path, it cannot reach `MAIL FROM`, and no state reachable from it
  can. So the property that matters — nothing but a re-introduction may follow a
  handshake — holds with both commands permitted;
- `RCPT_RESULT_RECEIVED` does not permit `RCPT TO`, so a second recipient has no
  state to be issued from;
- `RESET_COMPLETED` permits only `QUIT`. `RSET` clears a transaction in SMTP,
  but this product observes one recipient per session, so it does not buy a
  second one.

A session also requires a `ConfirmedPeer`, and checks the type at run time
rather than trusting the annotation, so the destination policy has run three
times before any command is permitted. See ADR 0008.

## 3. Allowed commands

- `EHLO`
- `STARTTLS`
- `MAIL FROM`
- `RCPT TO`
- `RSET`
- `QUIT`

The set is closed by `SMTPCommand`, and by the encoder in
`domain/smtp_command.py`: six functions, one per command, none of which takes a
command name. There is no parameter through which to ask for another.

Forbidden, and refused by `scripts/check_forbidden_smtp.py` in every production
SMTP path:

- message content: `DATA`, `BDAT`, `SEND`, `SOML`, `SAML`;
- recipient enumeration: `VRFY`, `EXPN`;
- authentication: `AUTH`;
- relay and queue control: `TURN`, `ATRN`, `ETRN`, `BURL`;
- trusted-peer impersonation: `XCLIENT`, `XFORWARD`;
- provider login or account endpoints;
- more than one requested target recipient in one MVP transaction.

The recipient limit has two independent barriers: the state table, and a counter
on the session that refuses a second `RCPT TO` from any state at all.

The envelope sender is supplied by `SenderIdentityProvider`
(`ports/smtp_sender_identity.py`) from operator configuration. It is never
derived from the probe target, and `EnvelopeSender` alone does not enforce that:
the value type fixes the shape, the port owns the provenance.
`adapters/smtp/sender_identity.py` implements it, reads a mapping the caller
loaded deliberately, reads no environment variable, and refuses the null reverse
path for a probing identity — `docs/requirements.md` section 9 wants SPF, a PTR,
and monitored `postmaster` and `abuse` channels, and `<>` has none of them.

**There is no `HELO` fallback and there will not be one.** `HELO` is not a member
of `SMTPCommand`, so no encoder produces it, no `WireCommand` can carry it, and
no state permits it. A server too old for `EHLO` is one this project does not
probe; that is a narrower capability than a second greeting.

**A command reaches the wire only as a `WireCommand`.** The connection port takes
no `bytes`, no string, and no command name: `write_command` accepts a value that
names one of the six enum members and carries the bytes the matching encoder
produced, checked at construction to begin with that verb.

That check fixes the *verb*, not the argument. What fixes the argument is the six
factories in `domain/smtp_wire.py`, and what fixes that production uses only
those is an inspection test over `src/`. Three layers; the property "no wire line
exists that an encoder did not produce" is their conjunction, not the type's
alone. See ADR 0009.

## 4. STARTTLS

STARTTLS is optional in the first SMTP sub-Phase.

When enabled:

- parse the EHLO capability safely. `domain/smtp_capabilities.py` reads keyword
  names on exact token boundaries, case-insensitively, ignores an unknown
  extension, and **never branches on one**: an `X-` keyword is a better
  fingerprint than an MX name, and `docs/architecture.md` keeps provider identity
  as metadata that decides nothing;
- apply the configured TLS policy. `TLSPolicy.REQUIRED` is the default: a server
  that advertises no `STARTTLS` ends the probe as `TLS_ERROR`, which is a
  non-target outcome. `TLSPolicy.OPPORTUNISTIC` continues in plaintext when the
  extension is absent, and **neither policy tolerates a failed handshake** — that
  is not a fallback, and there is no transition back to plaintext;
- send STARTTLS only once, which the session refuses by count;
- verify the certificate and the host name, always. The name comes from the
  `ConfirmedPeer`, so it is the MX host the destination chain validated and never
  the recipient's domain. Verification has no off switch (ADR 0009);
- refuse the upgrade when anything is already buffered, because those bytes are
  plaintext an attacker could have injected before it (CVE-2011-0411). That
  refusal is reported as `tls_handshake_failed`, the same as a genuine handshake
  failure, and the collapse is deliberate: both are non-target TLS failures with
  no plaintext fallback and both resolve to `unknown`. The difference is a
  diagnostic — the smuggling refusal moves zero bytes — not a decision, so no
  enum member is spent on it. `docs/status-model.md` section 7.2 records this so
  a Phase 4D author does not have to discover it;
- re-read `getpeername()` before and after the upgrade, so a connection cannot
  become a different peer's by being wrapped;
- connect with `AF_INET` for an IPv4 destination and `AF_INET6` for an IPv6 one,
  and do not rely on `AI_V4MAPPED`: a dual-stack socket reports an IPv4 peer as
  `::ffff:…`, which the destination policy refuses, so the transport normalizes
  the family rather than the policy unwrapping a mapped address;
- apply handshake timeout;
- verify the peer according to the explicit TLS policy;
- issue EHLO again after TLS;
- never infer mailbox invalidity from TLS failure.

## 5. Reply parser

Requirements:

- support multiline replies;
- cap line bytes and line count;
- require syntactically consistent reply codes where practical;
- extract the basic code;
- extract an enhanced status code only when valid;
- retain a bounded redacted diagnostic. The guarantee is exactly this, and no
  more: a whitespace-delimited token containing a literal ASCII `@` is replaced,
  no literal `@` survives, control and format characters are removed, and the
  result is capped. It is **not** an RFC mailbox parser and not a general PII
  scrubber — a local part alone, a percent-encoded form, and a fullwidth at sign
  all survive — so a raw SMTP reply must never be written to an ordinary log;
- bound the sanitizer's work, not only its output. Only a fixed prefix of the
  reply is examined, because a legal 80 KB reply must not cost more than a short
  one to reduce to 120 characters;
- drop an enhanced code whose class contradicts the basic code. `250 5.1.1`
  describes nothing real, and taking the enhanced half would turn an acceptance
  into a rejection;
- treat a code that changes mid-reply as malformed rather than preferring one:
  a `250-` prelude with a `550` conclusion is two replies, and guessing is how a
  rejection gets attributed to the wrong command;
- never use raw text alone when a structured code is available.

## 6. Timeout budget

Separate configuration:

- DNS resolution;
- TCP connect;
- banner;
- individual command;
- TLS handshake;
- total session.

The total session deadline dominates all others, and it is implemented rather
than intended: `domain/smtp_deadline.py` holds a validated `SessionBudget` and a
`SessionDeadline` that recomputes what is left from a `MonotonicClock`, and every
awaited step of the dialogue runs inside the remaining budget.

**It covers the TCP connect as well.** `application/smtp_probe.py` starts the
deadline before it connects, so one budget spans the first SYN to the final
close, and the effective connect bound is
`min(TransportTimeouts.connect_seconds, remaining session budget)`. The
per-operation timeout is kept, not replaced; the smaller of the two applies, as
everywhere else. A budget already spent opens no socket at all.

**Waiting for a rate-limit lease is outside it**, deliberately. The deadline
starts once the lease is held, because a budget spanning the wait would record
this project's own queueing as `deadline_exhausted`, which Phase 4D reads as a
bound on a *remote* conversation. Bounding the wait for a budget belongs to the
limiter (ADR 0009).

Each awaited step is pinned individually rather than collectively:
`tests/unit/application/test_smtp_deadline_stages.py` gives the dialogue a peer
that goes silent at one named stage and requires the session to end anyway, and
reads the source to check that every `self.connection.…` call sits inside the
deadline wrapper. Removing the wrapper from the read step, the write step, or
the handshake used to leave the whole suite passing.

Monotonic, not wall clock: a deadline computed from `datetime.now()` moves when
the machine's clock is adjusted. Recomputed, not decremented: a stage that
overran cannot leave the budget looking healthy.

Both halves are needed. A per-read deadline of 30 seconds bounds one read; a
dialogue of eight steps bounds nothing useful, because a peer answering each
stage just inside its deadline holds a worker for four minutes without ever
timing out.

## 7. Transcript

Tests record every command. Production records only safe structured events by
default: `SessionReport.commands_issued` is a tuple of enum members, never the
bytes that carried them, and the report refuses to be built if the transcript
and the observation disagree about the recipient.

A test must fail if the command sequence contains a forbidden command or more
than one `RCPT TO`. The two shapes are asserted exactly:

```text
plain   EHLO, MAIL FROM, RCPT TO, RSET, QUIT
TLS     EHLO, STARTTLS, EHLO, MAIL FROM, RCPT TO, RSET, QUIT
```

**Cleanup never changes the answer.** By the time `RSET` and `QUIT` are issued,
the recipient result is in hand; a server that drops the connection first has
already answered the only question that was asked. A cleanup failure is recorded
as `CleanupStatus` and changes nothing about the observation, and cleanup is not
attempted at all after a terminal failure — no command is ever written once the
connection has failed.

## 8. MX handling

- use MX priority order;
- do not race all MX hosts;
- make a bounded number of attempts;
- destination limits apply to domain and concrete MX;
- revalidate each resolved and connected IP;
- do not use an alternate MX to reinterpret an explicit target-specific
  recipient rejection without a documented policy.
