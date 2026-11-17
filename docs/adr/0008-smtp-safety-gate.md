# ADR 0008: The SMTP safety gate comes before the SMTP code

- Status: Accepted
- Date: 2026-08-07

## Context

ADR 0003 chose a purpose-built recipient-stage client so that the no-message-content rule could be tested. The original `scripts/check_forbidden_smtp.py` knew three commands, scanned two paths that would not exist, and compared whole string literals to command tokens, so `"AUTH PLAIN {credentials}"` or `"BDAT 42"` passed. The gate was therefore built and fixed before any network code, so that the fence would not be shaped by the code it fences.

## Decision: the scanner reads a string the way a server does

The scanner extracts the first SMTP token of each string (the verb, up to the first space or colon) and compares that; identifiers are compared exactly.

| Text | Verb | Result |
|---|---|---|
| `"DATA\r\n"` | `DATA` | refused |
| `"AUTH PLAIN {token}"` | `AUTH` | refused |
| `"BDAT 42"` | `BDAT` | refused |
| `"authentication"`, `"send_timeout"`, `"metadata"` | not a command | ordinary |

- A literal with several lines is split on CRLF (not a bare newline), so `"EHLO {host}\r\nDATA\r\n"` is caught and wrapped prose is not.
- Bytes literals, f-strings, and `+` concatenations are folded.
- A wire line whose first token is computed at run time is refused: an f-string, `%` formatting, or `str.format` that starts with a placeholder, or a concatenation that starts with a name. `f"EHLO {host}\r\n"` names its verb and is fine.
- Docstrings are exempt from the verb rule unless they contain CRLF, so code can say "this module never issues DATA".
- An exact identifier such as `send`, `data`, `auth`, or `turn` is refused; compounds such as `send_timeout` are not. The full list is in `docs/smtp-state-machine.md`.

The scanner protects against accidental introduction and ordinary drift, not against a committer deliberately obfuscating a command (`"".join(["DA", "TA"])`, `bytes([68, 65, 84, 65])`). Safety rests on structure: the closed command enum, six encoders with no name parameter, the state machine, and a transport port with no arbitrary-bytes method.

## Decision: fourteen refused commands, with a coverage check

`DATA`, `BDAT`, `SEND`, `SOML`, `SAML` (message content); `VRFY`, `EXPN` (enumeration); `AUTH` (the managed identity has no credentials to offer); `TURN`, `ATRN`, `ETRN`, `BURL` (relay and queue control); `XCLIENT`, `XFORWARD` (impersonating a trusted peer).

The scan roots are globs over every production path that could serialize a command, so a new module is covered by default, and the scanner exits non-zero if a path it must cover matches nothing. Tests and documentation are outside the scan so they can name the commands they refuse. Adding a member to `SMTPCommand` requires an ADR.

## Decision: structure closes the command set and the recipient limit

- `SMTPCommand` has six members, and `smtp_command.py` has one typed function per member and none that takes a command name. The CRLF is appended in one place, which checks the whole line for control characters again.
- A second `RCPT TO` is refused by two independent barriers, each with its own test: the state table gives `RCPT_RESULT_RECEIVED` no way to issue one, and a session counter refuses one from any state. `RSET` does not buy a second recipient; `RESET_COMPLETED` permits only `QUIT`.

## Decision: a session cannot exist without a confirmed peer

The destination policy runs on the DNS answer, again before connecting, and again on the address the socket reached. These are types, not steps:

```text
RouteCandidate
  → approve_destination()   the address must be one the candidate offered
  → ApprovedDestination     the policy runs again
  → confirm_peer()          the address and port the socket reached
  → ConfirmedPeer           the policy runs a third time
  → SMTPSession             checks the type at run time
```

`approve_destination` is the only way in: the candidate must be usable, the address must be among its allowed addresses, and the host comes from the candidate. An inspection test keeps `src/` from calling the raw constructor, which still validates as a second barrier. `SMTPSession` and `AsyncioSMTPTransport.connect` check their argument types at run time, before any policy evaluation or socket. The transport takes only an `ApprovedDestination` and returns a `PeerEndpoint`, which validates its own shape; the value guarantees the shape and the policy grants the permission, and each refuses on its own. Only port 25 is reachable, and the peer port is confirmed.

## Decision: SMTP domain code decides no status

`250` at `RCPT` does not prove a mailbox exists and a bare `550` does not prove it is missing. An inspection test keeps `Status`, `Verdict`, `Confidence`, `likely_deliverable`, and `temporary_unknown`, and also `socket`, `ssl`, `asyncio`, and `smtplib`, out of every `domain/smtp*` module. Aggregation decides the status (`docs/status-model.md` section 4).

## Decision: the diagnostic sanitizer promises something narrow

`sanitize_diagnostic` guarantees that a whitespace-delimited token containing an ASCII `@` is replaced, that no ASCII `@` remains, that control and format characters are removed, and that the result is at most 120 characters. It is not a mailbox parser: a local part alone, a domain alone, `user @ example.com`, `user%40example.com`, and a fullwidth at sign survive. That meets the rule that ordinary logs carry no complete address, but a raw SMTP reply must never be written to an ordinary log.

Its work is bounded as well as its output. The pattern `[^\s@]*@[^\s@]*` cannot backtrack, and only the first 512 characters are examined; tests assert `sanitize(text) == sanitize(text[:512])`.

## Decision: sender provenance belongs to a port

`EnvelopeSender` accepts any address, so the value alone cannot stop `MAIL FROM` from carrying the target. `ports/smtp_sender_identity.py` supplies a `SenderIdentity` (EHLO name and envelope sender, which must agree) from operator configuration only, and `current_identity()` takes no argument so it cannot depend on the target.

## Decision: cleanup cannot be interrupted, and process control is never a result

`AsyncioSMTPConnection.close` contains no `await`, so no cancellation can arrive half-way, and the release runs from a `finally`. A test drives the coroutine by hand and asserts it never yields.

`CancelledError`, `KeyboardInterrupt`, `SystemExit`, `GeneratorExit`, and `AssertionError` (`_NEVER_A_TRANSPORT_FAILURE`) propagate after the socket is closed. A bug in this project still becomes a typed `INTERNAL_ERROR` outcome; an interrupted process does not.

## Decision: the loopback guard is proven by inspection, not by dialling

The guard's decision functions, `is_loopback` and `is_permitted_bind_host`, are pure, and tests assert on them, on the permitted set being exactly `{127.0.0.1, ::1}`, and on the marker every installed guard carries. No test connects to a public address to prove that it is refused.

## Consequences

- The forbidden-command rule is enforced, and its own regression tests fail if it stops.
- The loopback fixture cannot pass the destination policy, because `127.0.0.1` is denied. Tests use an explicit, narrow, test-only construction path; production code has no trusted-address list.
- A production SMTP module containing the bare string `"data"` is refused. Renaming is cheap, and allowing it is what let `AUTH PLAIN` through before.
