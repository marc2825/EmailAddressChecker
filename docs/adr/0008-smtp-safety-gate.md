# ADR 0008: The SMTP safety gate comes before the SMTP code

- Status: Accepted
- Date: 2026-08-07
- Phase: 4A

## Context

ADR 0003 decided to build a purpose-built recipient-stage client rather than use
a mail library, so that the no-message-content invariant would be testable. It
did not say what makes it testable, and by the end of Phase 3 the only mechanism
was `scripts/check_forbidden_smtp.py`, which:

- knew three commands, and not `AUTH`, `BDAT`, `SEND`, `SOML`, or `SAML`;
- scanned two fixed paths, neither of which would exist in the eventual layout;
- compared each string literal to a command token **exactly**.

That last point is the one that matters. `"DATA\r\n"` happens to strip to
`DATA`, so the check appeared to work. But `"AUTH PLAIN {credentials}"`,
`"BDAT 42"`, `"VRFY x"`, and `"SEND FROM:<a>"` are not equal to any token, so
every forbidden command that carries an argument passed. The check would have
been satisfied by the exact code it existed to prevent.

Writing the transport first and the fence afterwards would produce a fence
shaped like the code. So Phase 4 was split, and 4A adds no network capability at
all.

## Decision: the scanner reads a string the way a server reads it

A string is not compared to a command. Its first SMTP token is extracted — the
verb, up to the first space or colon — and that is compared. Identifiers are
compared exactly.

This is the rule that makes both failure modes go away at once:

| Text | Verb | Result |
|---|---|---|
| `"DATA\r\n"` | `DATA` | refused |
| `"AUTH PLAIN {token}"` | `AUTH` | refused |
| `"BDAT 42"` | `BDAT` | refused |
| `"SEND FROM:<a@b>"` | `SEND` | refused |
| `"authentication"` | `AUTHENTICATION` | ordinary |
| `"send_timeout"` | `SEND_TIMEOUT` | ordinary |
| `"metadata"` | `METADATA` | ordinary |

A literal holding several commands is read line by line, split on CRLF, because
`"EHLO {host}\r\nDATA\r\n"` would otherwise be reported as an `EHLO`. The split
is on CRLF and not on a bare newline, so prose that wraps mid-sentence stays one
line and `"connection lost\ndata was discarded"` is not a finding.

Bytes literals, f-strings, and `+` concatenations are all folded, because each
of them builds a command line.

A wire line whose **first token comes from a run-time value** is refused
outright: a verb assembled at run time is a raw-command API by another route,
and it would make the closed enum meaningless. Four ordinary Python
constructions do that, and a review found that only the first was covered:

```text
f"{verb} {arg}\r\n"            an f-string starting with a placeholder
"%s %s\r\n" % (verb, arg)      percent formatting starting with a spec
"{} {}\r\n".format(verb, arg)  str.format starting with a field
verb + " " + arg + "\r\n"      concatenation starting with a name
```

All four are refused now. A literal that merely *contains* a placeholder later
in the line is fine — `f"EHLO {host}\r\n"` names its verb, and that is the
shape the real encoder uses.

Docstrings are excluded from the verb rule unless they contain CRLF. Production
code has to be able to write "this module never issues DATA" without failing
its own gate.

### The threat model this scanner has

> **The scanner protects against accidental introduction and ordinary code
> drift. It is not intended to defend against a malicious committer
> intentionally obfuscating SMTP commands.**

Stating that matters, because the alternative is a check whose limits nobody
knows. `"".join(["DA", "TA"])`, `bytes([68, 65, 84, 65])`, and
`base64.b64decode(...)` are not caught, and no static scan of Python catches a
computed string. Chasing them would trade real coverage for the appearance of
it.

Safety does not rest on the scanner. It rests on the closed command enum, the
six explicit encoders with no name parameter, the state machine, and a transport
port with no arbitrary-bytes method. The scanner is the layer that catches the
ordinary mistake early; the structure is what makes the mistake unreachable.

### What is deliberately not exempt

`send` is an ordinary name for writing bytes and it is also the SMTP `SEND`
command. The scanner flags the exact identifier and ignores every compound, so
`send_timeout` and `sendable` are fine and a method named `send` is not.

The same applies to thirteen other words, and `data`, `auth`, and `turn` are
common enough as local names that a 4B author would hit them. The complete list,
and every syntactic position it covers, is in
`src/emailcheck/adapters/smtp/AGENTS.md`, so the constraint is found before the
code is written rather than after the gate rejects it.

## Decision: fourteen commands, and a coverage self-check

The refused set is `DATA`, `BDAT`, `SEND`, `SOML`, `SAML` (message content),
`VRFY`, `EXPN` (recipient enumeration), `AUTH` (this project probes from a
managed identity and has no credentials to offer), `TURN`, `ATRN`, `ETRN`,
`BURL` (relay and queue control), and `XCLIENT`, `XFORWARD` (trusted-peer
impersonation).

The scan roots are globs over every production path that could serialize a
command, so a new module lands inside the fence by default. Globs fail quietly
when they stop matching — a scan of nothing finds nothing — so the scanner also
asserts that the paths it must cover are covered, and exits non-zero when one is
missing.

Tests and documentation are outside the fence on purpose. A test has to be able
to say `DATA` in order to prove that `DATA` is refused.

## Decision: the command set is closed by the encoder's shape

`SMTPCommand` has six members. What keeps it closed is not the enum but
`smtp_command.py`: six functions, one per member, each taking typed values, and
no function anywhere that takes a command name. There is no parameter through
which to ask for a seventh command.

The CRLF is appended in one place, which also re-checks the assembled line for
control characters even though every input type already refuses them. The check
is cheap and the failure it guards against is the one this project must never
have.

## Decision: the recipient limit has two independent barriers

`RCPT TO` is refused a second time by the state table, which gives
`RCPT_RESULT_RECEIVED` no way to issue one, and by a counter on the session,
which refuses one from any state at all.

A mutation check found that removing the state-table barrier changed no test
result, because the counter caught it. Two barriers are only two barriers if
each is pinned by its own test, so the table is now asserted directly.

`RSET` does not buy a second recipient. It clears a transaction in SMTP, but
this product observes one recipient per session, so `RESET_COMPLETED` permits
only `QUIT`.

## Decision: a session cannot exist without a confirmed peer

`docs/threat-model.md` requires the destination policy to run against the DNS
answer, again immediately before connecting, and again against the address the
socket actually reached. Written as three steps, the third is the one that gets
forgotten, and it is the one that catches a connection landing somewhere other
than the address that was approved.

So they are types, not steps:

```text
RouteCandidate
  → approve_destination()   the address must be one the candidate offered
  → ApprovedDestination     the policy runs again
  → confirm_peer()          the address *and port* the socket reached
  → ConfirmedPeer           the policy runs a third time
  → SMTPSession             checks the type at run time
```

A review found two gaps in the first version of this chain, and both are closed.

**The chain had no beginning.** `ApprovedDestination` was constructible from any
public IP with any host name, with no link to DNS at all. The policy answers "is
this address safe to reach"; it does not answer "did the domain publish it".
Both questions have to be asked, and only `approve_destination` asks the second:
the candidate must be `USABLE`, the address must be in its `allowed_addresses`,
the host comes from the candidate rather than from a parameter, and the policy
runs again. The raw constructor stays validating as a second barrier — Python
has no honest private constructor — and an inspection test fixes that nothing in
`src/` calls it.

**The chain had no end.** `SMTPSession(peer=...)` was checked by mypy and by
nothing else, so `peer=None`, `peer=<a bare tuple>`, and worst of all
`peer=<an ApprovedDestination>` all constructed successfully. The last skips the
post-connect check entirely, and it is the value a transport already holds.
mypy rejects all three, but mypy checks `src` only and `Any` launders any of
them, so `__post_init__` checks the type as well. Every other value in this
project validates itself; this was the one where forgetting to meant talking to
an unchecked peer.

The transport port takes an `ApprovedDestination` and nothing else, and returns
a `PeerEndpoint` rather than a bare address, so an implementation cannot report
the address and forget the port. There is no arbitrary-bytes write method.

Only port 25 is reachable, and the peer port is confirmed against it.

## Decision: no reply code becomes a status in this Phase

`250` at RCPT does not mean the mailbox exists — an accept-all server says it to
everyone — and a bare `550` does not mean it does not, because policy rejections
share the code. The recipient-stage taxonomy records what was observed and stops
there; `docs/status-model.md` section 4 gives Phase 5 the job of weighing it
against the syntax, DNS, and passive evidence.

An inspection test keeps `Status`, `Verdict`, `Confidence`, `likely_deliverable`,
and `temporary_unknown` out of every `domain/smtp*` module, and keeps `socket`,
`ssl`, `asyncio`, and `smtplib` out of them too, so the stop condition in
`plans/phase-04-smtp.md` is enforced rather than remembered.

## Consequences

- The forbidden-command set is now enforceable, and its regression tests fail if
  it stops enforcing. Adding a command to `SMTPCommand` requires an ADR.
- Gate 4B writes a transport against a fence that already exists and that it did
  not shape.
- **The loopback fixture cannot pass the destination policy.** `127.0.0.1` is
  denied, and `ApprovedDestination` re-runs that check, so 4B's scripted server
  is unreachable through the production path. That is the policy working. 4B
  must add an explicit, narrow, test-only construction path with its own review,
  and must not relax the policy or introduce a trusted-address list in
  production code.
- A metadata-style false positive is possible in principle: a production SMTP
  module containing the bare string `"data"` would be refused. In this tree that
  is a one-word rename, and the alternative rule — allowing it — is what let
  `AUTH PLAIN` through before.

## Decision: the diagnostic sanitizer promises something narrow, and says so

`sanitize_diagnostic` was described as removing "anything resembling an
address". It does not, and a document that claims more than the code does is
worse than one that claims less: Phase 6 will put this text in an API response
and a log line, and an author reading that sentence would treat it as a PII
scrubber.

**What it guarantees:**

- a whitespace-delimited token containing a literal ASCII `@` is replaced, so
  `user@example.com` and `<user@example.com>` do not survive;
- a literal ASCII `@` never appears in the result;
- control and format characters are removed;
- the result is at most 120 characters.

**What it does not guarantee.** It is not an RFC mailbox parser. A local part on
its own (`Support+Secret`), a domain on its own, a spaced form
(`user @ example.com`, which loses the `@` but keeps both halves), a
percent-encoded form (`user%40example.com`), and a fullwidth at sign all
survive. `docs/requirements.md` section 16 requires that ordinary logs carry no
*complete* address, which this meets. It does not make remote text safe in
general, and **a raw SMTP reply must never be written to an ordinary log.**

Tests pin both halves, so the guarantee and the behavior cannot drift apart.

### The work is bounded, not only the output

The address pattern was `\S*@\S*`, which is quadratic in the length of a run
without an `@`, because `\S*` can consume the `@` and then give it back: 8000
characters took 58 ms, and doubling the length quadrupled it. A reply may legally
be 40 lines of 2048 bytes, and sanitizing all 80 KB to produce 120 characters
cost 153 ms of CPU — a tarpit could spend a second of this project's CPU per
session while `docs/threat-model.md` believed the read caps bounded the work.

Two changes, either of which would have been enough, and both are cheap. The
pattern is `[^\s@]*@[^\s@]*`, which matches the same tokens with no
backtracking. And only the first 512 characters are examined at all, because
nothing past them could reach a 120-character result. The bound is what the
tests assert — `sanitize(text) == sanitize(text[:512])` — so the property is
deterministic and no wall-clock threshold flakes in CI.

## Decision: sender provenance belongs to a port, not to the value type

`EnvelopeSender` accepts any `NormalizedAddress`, so
`EnvelopeSender(address=target)` builds fine and `MAIL FROM` would carry the
address being probed. Answering that inside the value would mean giving it a
reference to the target, which is the wrong shape: a sender is not a function of
the address being checked.

So provenance is `ports/smtp_sender_identity.py`. A `SenderIdentityProvider`
supplies a `SenderIdentity` — an EHLO name and an envelope sender that must
agree — from operator-controlled configuration only. `current_identity()` takes
no argument, deliberately: a provider that received the target could return a
sender derived from it.

`EnvelopeSender` stays a shape, the provider owns the provenance, and gate 4C
cannot issue `MAIL FROM` until the provider exists.
