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

- `TLS_NEGOTIATED` permits only `EHLO`, so the session is re-introduced after
  TLS before anything else happens;
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

## 4. STARTTLS

STARTTLS is optional in the first SMTP sub-Phase.

When enabled:

- parse the EHLO capability safely;
- send STARTTLS only once, which the session refuses by count;
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

The total session deadline dominates all others.

## 7. Transcript

Tests record every command. Production records only safe structured events by
default.

A test must fail if the command sequence contains a forbidden command or more
than one `RCPT TO`.

## 8. MX handling

- use MX priority order;
- do not race all MX hosts;
- make a bounded number of attempts;
- destination limits apply to domain and concrete MX;
- revalidate each resolved and connected IP;
- do not use an alternate MX to reinterpret an explicit target-specific
  recipient rejection without a documented policy.
