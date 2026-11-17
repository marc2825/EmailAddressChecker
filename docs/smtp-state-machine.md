# SMTP probe state machine

## 1. Purpose

The client observes the recipient stage; it is not a mail-sending client. It exposes no operation that can submit message content.

## 2. States

```text
DISCONNECTED
  → CONNECTING
  → BANNER_RECEIVED
  → EHLO_COMPLETED
  → TLS_NEGOTIATED          required by the dialogue
  → EHLO_COMPLETED_AFTER_TLS
  → MAIL_FROM_ACCEPTED
  → RCPT_RESULT_RECEIVED
  → RESET_COMPLETED         best effort
  → CLOSED
```

An error or timeout in any state moves to a terminal failed state, followed by a best-effort close. `FAILED` permits only `QUIT` and has no route back to a state that can issue `MAIL FROM`, so a failed STARTTLS cannot continue in plaintext.

`src/emailcheck/domain/smtp_contract.py` holds the table of permitted commands per state, and `smtp_session.py` holds the transitions as an immutable value. The table enforces three rules:

- `TLS_NEGOTIATED` permits `EHLO` and `QUIT` and nothing else. `EHLO` is the only way forward, so the session introduces itself again after TLS; `QUIT` lets an upgraded session end politely. `QUIT` leads only to closing and cannot reach `MAIL FROM`.
- `RCPT_RESULT_RECEIVED` does not permit `RCPT TO`, so a second recipient has no state to come from.
- `RESET_COMPLETED` permits only `QUIT`. `RSET` clears a transaction, but this product observes one recipient per session, so it does not allow a second one.

A session requires a `ConfirmedPeer` and checks the type at run time, so the destination policy has run three times before any command is allowed (ADR 0008).

## 3. Commands

Allowed: `EHLO`, `STARTTLS`, `MAIL FROM`, `RCPT TO`, `RSET`, `QUIT`.

The set is closed by `SMTPCommand` and by `domain/smtp_command.py`, which has one encoder per command and none that takes a command name.

Forbidden, and refused by `scripts/check_forbidden_smtp.py` in every production SMTP path:

- message content: `DATA`, `BDAT`, `SEND`, `SOML`, `SAML`;
- recipient enumeration: `VRFY`, `EXPN`;
- authentication: `AUTH`;
- relay and queue control: `TURN`, `ATRN`, `ETRN`, `BURL`;
- trusted-peer impersonation: `XCLIENT`, `XFORWARD`;
- provider login or account endpoints;
- more than one requested recipient in one transaction.

Two independent barriers stop a second recipient: the state table, and a session counter that refuses a second `RCPT TO` from any state.

There is no `HELO` fallback. `HELO` is not in `SMTPCommand`, so no encoder, `WireCommand`, or state can produce it, and a server too old for `EHLO` is not probed.

A command reaches the wire only as a `WireCommand`. `write_command` takes no bytes, string, or command name, only a value naming one of the six commands and carrying the bytes its encoder produced, checked at construction to start with that verb. The verb check, the six factories in `domain/smtp_wire.py`, and an inspection test that production uses only those factories together ensure that no wire line exists that an encoder did not produce (ADR 0009).

The envelope sender comes from `SenderIdentityProvider` (`ports/smtp_sender_identity.py`), backed by operator configuration, and is never derived from the target. `adapters/smtp/sender_identity.py` reads a mapping the caller loaded deliberately, reads no environment variable, and refuses the null reverse path for a probing identity, because `<>` has no SPF, PTR, or monitored mailboxes (`docs/requirements.md` section 9).

## 4. STARTTLS

STARTTLS is required in every dialogue, including library use; `TLSPolicy.REQUIRED` is the only policy (ADR 0021).

- Capabilities are parsed safely. `domain/smtp_capabilities.py` matches keyword names on exact token boundaries, case-insensitively, ignores unknown extensions, and never branches on one, since provider identity decides nothing.
- A server that advertises no `STARTTLS` ends the probe as `TLS_ERROR`, a non-target outcome. No sender or recipient command follows a missing upgrade or a failed handshake.
- STARTTLS is sent once; the session refuses a second by count.
- The certificate and host name are always verified, with no off switch. The name comes from the `ConfirmedPeer`, so it is the validated MX host, never the recipient's domain.
- The upgrade is refused if any bytes are already buffered, because they could be injected plaintext (CVE-2011-0411). The refusal is reported as `tls_handshake_failed`, the same as a real handshake failure: both are non-target TLS failures with no fallback and resolve to `unknown`, and the smuggling refusal differs only in moving zero bytes. `docs/status-model.md` section 7.2 records the same.
- `getpeername()` is read before and after the upgrade, so wrapping cannot turn the connection into another peer's.
- The transport connects with `AF_INET` for IPv4 and `AF_INET6` for IPv6 and does not rely on `AI_V4MAPPED`, because a dual-stack socket would report an IPv4 peer as `::ffff:…`, which the destination policy refuses.
- The handshake has its own timeout.
- `EHLO` is issued again after TLS.
- A TLS failure never implies mailbox invalidity.

## 5. Reply parser

- Supports multiline replies, with caps on line bytes and line count.
- Extracts the basic code, and an enhanced status code only when it is valid.
- Drops an enhanced code whose class contradicts the basic code: `250 5.1.1` describes nothing real, and using the enhanced half would turn an acceptance into a rejection.
- Treats a code that changes mid-reply as malformed: a `250-` prelude with a `550` conclusion is two replies, and guessing attributes a rejection to the wrong command.
- Never relies on raw text when a structured code is available.
- Keeps a bounded, redacted diagnostic. It guarantees only that a whitespace-delimited token containing an ASCII `@` is replaced, that no `@` remains, that control and format characters are removed, and that the result is capped. It is not a mailbox parser or a general PII scrubber (a local part alone, a percent-encoded form, and a fullwidth at sign survive), so a raw SMTP reply must never be written to an ordinary log.
- Bounds the sanitizer's work as well as its output: only a fixed prefix is examined, so an 80 KB reply costs no more than a short one.

## 6. Timeout budget

Separate timeouts cover DNS resolution, TCP connect, banner, each command, the TLS handshake, and the total session.

The total session deadline dominates the others. `domain/smtp_deadline.py` holds a validated `SessionBudget` and a `SessionDeadline` that recomputes the remaining time from a `MonotonicClock`, so clock adjustments cannot move it and an overrunning stage cannot hide. Every awaited dialogue step runs inside the remaining budget. A per-read deadline alone bounds one read, not a dialogue: a peer answering each of eight steps just inside 30 seconds would hold a worker for four minutes.

The budget covers the TCP connect too. `application/smtp_probe.py` starts the deadline before connecting, so the connect bound is `min(TransportTimeouts.connect_seconds, remaining session budget)`, and a spent budget opens no socket.

Waiting for a rate-limit lease is outside the budget, so this project's own queueing is never recorded as `deadline_exhausted`, which means a bound on the remote conversation. The limiter bounds that wait separately.

`tests/unit/application/test_smtp_deadline_stages.py` checks each step individually: a peer that goes silent at a named stage must still end the session, and every `self.connection.…` call must sit inside the deadline wrapper.

## 7. Transcript

Tests record every command. Production records only safe structured events: `SessionReport.commands_issued` is a tuple of enum members, never bytes, and the report cannot be built if the transcript and the observation disagree about the recipient.

A test fails if the command sequence contains a forbidden command or more than one `RCPT TO`. The two shapes are asserted exactly:

```text
plain   EHLO, MAIL FROM, RCPT TO, RSET, QUIT
TLS     EHLO, STARTTLS, EHLO, MAIL FROM, RCPT TO, RSET, QUIT
```

Cleanup never changes the answer. By the time `RSET` and `QUIT` are sent, the recipient result is already known. A cleanup failure is recorded as `CleanupStatus` and leaves the observation unchanged, and after a terminal failure no command is written at all.

## 8. MX handling

- Use MX preference order.
- Do not race all MX hosts.
- Make a bounded number of attempts.
- Apply destination limits to both the domain and the concrete MX host.
- Check every resolved and connected IP again.
- Do not use another MX to reinterpret an explicit, target-specific recipient rejection unless a documented policy says so.
