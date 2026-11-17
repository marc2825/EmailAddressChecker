# ADR 0009: The write capability is a type, and TLS is required

- Status: Accepted
- Date: 2026-08-08; plaintext option removed by [ADR 0021](0021-required-encryption-at-network-boundaries.md) on 2026-11-15

## Context

The dialogue has to write to the connection. The usual signature, `write(payload: bytes)`, would let any holder of a connection put any verb on the wire and reduce the closed enum, the encoders, the state machine, and the scanner (ADR 0008) to conventions. The dialogue also has to decide what happens when a server does not offer STARTTLS, since the recipient address travels in `RCPT TO`.

## Decision: the capability is `WireCommand`, not `bytes`

`SMTPConnection.write_command` takes a `WireCommand`:

```text
six factories in domain/smtp_wire.py
  → each calls the matching encoder in domain/smtp_command.py
  → WireCommand(command: SMTPCommand, payload: bytes)
  → connection.write_command(command)
```

`WireCommand` refuses to construct unless the verb in the bytes is the verb it names (`WireCommand(EHLO, b"DATA\r\n")` fails), using the scanner's rule: the first token up to a space or colon.

The type constrains the verb, not the argument; `WireCommand(RCPT_TO, b"RCPT TO:<a@b>,<c@d>\r\n")` constructs. No such line is reachable in production because of three layers, each tested:

| Layer | What it enforces |
|---|---|
| `WireCommand` | one CRLF-terminated line within 512 octets, no other CR, LF, or NUL, and the declared verb first |
| The six factories in `domain/smtp_wire.py` | the only approved argument forms, each built from typed values by its encoder |
| An inspection test over `src/` | production builds a `WireCommand` only through those factories |

A per-command argument parser inside the type is not added; it would add little and be a new place for bugs. The adapter's private `_write_line(bytes)` is not on the port and is reached only through `write_command`. An inspection test fails if a `write(bytes)` method is added to the port.

## Decision: TLS is required, and its absence never means the mailbox is invalid

`TLSPolicy.REQUIRED` is the only policy (ADR 0021). A server that advertises no `STARTTLS` ends the probe as `TLS_ERROR`, which is in `NON_TARGET_OUTCOMES` and can never support a target-specific verdict. A failed handshake is always fatal, and the state machine has no route back to plaintext (`FAILED` permits only `QUIT`).

The deciding argument is downgrade resistance, not exposure. DNS and the TCP connection already reveal the recipient's domain; TLS protects the local part. More importantly, an on-path attacker who can read plaintext SMTP can strip the `STARTTLS` line from the `EHLO` reply at no cost. With opportunistic TLS the probe would then continue in plaintext and send `RCPT TO` with nothing reporting the downgrade. With required TLS the same manipulation yields `TLS_ERROR` with `tls_reason = not_offered`, and no address is sent. Opportunistic TLS protects only against a passive observer, and the threat model assumes an active one.

The cost is that a server that really offers no STARTTLS yields `unknown`. The report carries `starttls_advertised` and `tls_reason`, so the rate can be measured under authorized, representative operation; no measurement is claimed here.

## Decision: verification cannot be turned off, and the one seam only widens trust

`build_client_context` always sets `check_hostname = True` and `verify_mode = CERT_REQUIRED`, with no parameter, flag, environment variable, or lab mode to change either.

The only seam is `TLSTrust`, which can add one certificate authority and nothing else; it cannot disable verification, override a host name, or supply a context. The TLS integration tests use it to run real handshakes. A trust anchor may come only from operator configuration: request, user, and API input must never supply a CA file, PEM body, trust anchor, or verification override. An inspection test fails if `TLSTrust` is constructed in `src/` outside the module with the system-trust default, or if a production module reads the environment.

`TLSUpgradeRequest` takes a `ConfirmedPeer`, so SNI and hostname verification use the MX host the destination chain validated, never the recipient's domain or a caller's string. Before any handshake byte:

- `getpeername()` is read again, resolving nothing, and compared with the reported peer; it is checked again after the upgrade.
- The read buffer must be empty. Buffered bytes could be plaintext injected before the upgrade (CVE-2011-0411), so the upgrade is refused and reported as `TLS_HANDSHAKE_FAILED`, the same category as a rejected certificate: both are non-target failures with no fallback and map to `smtp_tls_failure` (`docs/status-model.md` section 7.2). A test shows the refusal moves zero bytes.
- A second upgrade is refused by the transport and, independently, by the session's STARTTLS counter.

TLS runs over `ssl.SSLObject` with two `MemoryBIO`s instead of `wrap_socket`, so every byte still passes through `loop.sock_recv` and `loop.sock_sendall`, where the test suite's network guard and call counter can see it.

## Decision: two deadlines, and the total dominates

Each read, write, and connect has its own timeout, and `SessionBudget` bounds the whole dialogue. It is validated like `TransportTimeouts` (positive, finite, not boolean, below a maximum), and `SessionDeadline` recomputes the remaining time from a `MonotonicClock`, so clock adjustments cannot move it. Every awaited dialogue step runs inside the remaining budget, and the connect does too: its effective bound is `min(TransportTimeouts.connect_seconds, remaining session budget)`, and a spent budget opens no socket.

The wait for a rate-limit lease is outside the budget. Otherwise queue depth would be recorded as `deadline_exhausted`, which means this project's own bound on a remote conversation. The limiter bounds that wait separately.

`deadline_exhausted` is recorded beside the outcome, because a deadline and a reset produce the same outcome at the same stage. `SessionReport` refuses `cleanup = skipped_deadline` with the flag false. A budget spent mid-dialogue sets the flag with cleanup `not_attempted`; one spent during `RSET` sets it with cleanup `incomplete`.

## Decision: the configured envelope sender may not be the null reverse path

`EnvelopeSender.null()` is a legal value, but `load_sender_identity` refuses to build a probing identity from it: `<>` has no SPF or monitored mailboxes, and `MAIL FROM:<>` followed by one `RCPT TO` looks like harvesting. The loader also refuses an EHLO name and sender domain where neither equals or is a subdomain of the other; this catches a misconfiguration, not ownership. There is no default identity, so an unconfigured deployment does not probe.

## Decision: authorization precedes the socket

`SMTPProbeService` takes a `RateLimiter` with no default, so no code path can build an unmetered probe, and an inspection test keeps permissive limiter implementations out of `src/`. The budget key holds the account, the recipient's domain, and the MX host, never the local part.

## Consequences

- A seventh SMTP command needs an enum member, an encoder, a factory, and an ADR.
- A server without STARTTLS gives `unknown`, visible as `tls_reason = not_offered`. Changing this without a security review is not one of the options; ADR 0021 requires TLS regardless of the measured rate.
- The TLS test fixtures are committed certificates, because generating them needs `cryptography` or the `openssl` binary. `tests/fixtures/tls/README.md` explains how to regenerate them.
- `close` sends no TLS `close_notify`, because sending it would add an `await` and with it the cancellation point ADR 0008 removed. The peer sees a truncated session after a `QUIT` it has already answered.
