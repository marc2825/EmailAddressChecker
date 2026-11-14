# ADR 0009: The write capability is a type, and TLS is required by default

- Status: Accepted
- Date: 2026-08-08
- Phase: 4C

**Security update (2026-11-15):** [ADR 0021](0021-required-encryption-at-network-boundaries.md)
supersedes the former availability of `OPPORTUNISTIC`. Required TLS is now the
only supported policy, including internal dialogue use. The downgrade argument
below explains the historical trade-off; it grants no plaintext configuration.

## Context

Gate 4B deliberately published no way to write a byte. `SMTPConnection` had
`peer`, `read_line`, and `close`, and "nothing is written before the peer is
confirmed" was a property of the type rather than of the caller's care.

Gate 4C has to write. The obvious signature is the one every SMTP client has:

```python
async def write(self, payload: bytes) -> None: ...
```

Adding that would undo the gate. Once it exists, any holder of a connection can
put any verb on the wire, and the closed enum, the six encoders, the state
machine, and the scanner all become advisory — a convention the next author may
or may not notice. ADR 0008 says structure carries the load and the scanner is
only the early warning; a `write(bytes)` moves the load back onto the scanner,
which explicitly does not defend against a computed string.

## Decision: the capability is `WireCommand`, not `bytes`

`SMTPConnection.write_command` takes one argument, and its type is the whole
mechanism:

```text
six factories in domain/smtp_wire.py
  → each calls the matching encoder in domain/smtp_command.py
  → WireCommand(command: SMTPCommand, payload: bytes)
  → connection.write_command(command)
```

`WireCommand` validates itself, and one of the checks is the point of the type:
**the verb in the bytes must be the verb the value names.**
`WireCommand(EHLO, b"DATA\r\n")` does not construct. Without that check the
value is a label attached to arbitrary content, and a port accepting "only a
`WireCommand`" would accept any verb — the same hole with more ceremony.

The verb is read the way `scripts/check_forbidden_smtp.py` reads one: the first
token, up to a space or a colon. Two places reading a command line by the same
rule is deliberate. The scanner refuses fourteen verbs statically; the value
refuses everything the six-member enum does not name, at run time.

A mutation adding `write(payload: bytes)` to the port is caught by an inspection
test, and one that removes the verb check is caught by six.

### Three layers, and the type is only the first

An earlier version of this ADR said the type made the reachable wire lines "the
image of six pure functions". The independent review of 4C was right that this
claims more than the code does, and ADR 0008 already settled that a document
overclaiming is worse than one claiming less — it was the sanitizer's "removes
anything resembling an address" all over again.

**`WireCommand` constrains the verb, not the argument.** These all construct:

```text
WireCommand(RCPT_TO,   b"RCPT TO:<a@b>,<c@d>\r\n")            two recipients, one line
WireCommand(MAIL_FROM, b"MAIL FROM:<x@y> AUTH=<victim>\r\n")  an unapproved parameter
WireCommand(RCPT_TO,   b"RCPT TO:<a@b> NOTIFY=SUCCESS\r\n")   a delivery-status request
```

None is reachable in production, and the reason is three layers rather than one:

| Layer | What it enforces |
|---|---|
| `WireCommand` | exactly one CRLF-terminated line, within the 512-octet limit, no other CR, LF, or NUL, and the declared SMTP verb at the head |
| The six factories in `domain/smtp_wire.py` | the only argument forms production approves, each produced by the matching encoder from typed values |
| An inspection test over `src/` | production constructs a `WireCommand` only through those factories, so the raw constructor has no production caller |

The first is a value invariant, the second is a small closed API, and the third
is a gate. All three are tested, and the property everyone cares about — that no
wire line exists which an encoder did not produce — is the conjunction.

Closing the argument grammar inside the type as well would need a parser per
command. It is not done, because the marginal safety is small next to the three
layers already in place and a per-command parser is a new place for a bug to
live. What is done instead is stating the boundary exactly, here and in
`domain/smtp_wire.py`, so a later author does not read the type as more than it
is.

`_write_line(bytes)` still exists inside the adapter, one level below. It is
private, it is not on the port, and everything that reaches it has come through
`write_command`.

## Decision: TLS is required by default, and never means the mailbox is invalid

Two facts pull in opposite directions and both are true.

**The recipient address travels in `RCPT TO`.** `docs/threat-model.md` lists
submitted addresses as an asset. A plaintext SMTP session puts one in front of
every device on the path, to a host chosen by a DNS answer.

**Plenty of real mail servers still do not offer STARTTLS.** Refusing to probe
them yields `unknown`, which is a statement about this project's configuration
rather than about the address.

`TLSPolicy.REQUIRED` is the default. A server that advertises no `STARTTLS` ends
the probe as `TLS_ERROR`, which is in `NON_TARGET_OUTCOMES`, so it can never
contribute to a target-specific verdict. Historically `TLSPolicy.OPPORTUNISTIC`
allowed plaintext when STARTTLS was absent. ADR 0021 removes that option.
A handshake that is attempted and fails is always fatal.
There is no plaintext fallback here and no transition to one in the state
machine — `docs/smtp-state-machine.md` has `FAILED` permit only `QUIT`.

Choosing the default silently would have hidden the trade-off, which is why it is
a named value with this paragraph attached to it.

### The decisive argument is downgrade resistance, not exposure

The exposure argument above is true and it is the weaker half. DNS and the TCP
connection already reveal the recipient's *domain* to an observer; what TLS
protects is the local part. That is worth protecting and it is not, on its own,
enough to settle a default.

What settles it is that **opportunistic TLS is trivially removable by exactly
the attacker STARTTLS exists to stop.** An on-path attacker who can read
plaintext SMTP can also modify it, and stripping the `STARTTLS` line out of the
`EHLO` reply costs nothing:

- under `OPPORTUNISTIC`, the probe sees a server that offers no TLS, continues
  in plaintext, and puts the `RCPT TO` on the wire. Nothing anywhere reports
  that an upgrade was available;
- under `REQUIRED`, the same manipulation produces `TLS_ERROR` with
  `tls_reason = not_offered`, the probe ends, and no address is transmitted.

So `REQUIRED` is not merely the more private default; it is the only one of the
two that resists stripping at all. `OPPORTUNISTIC` protects against a passive
observer and against nobody else, and an active attacker is the threat model
`docs/threat-model.md` is written against.

The cost is real and is stated in the consequences below: a server that
genuinely offers no STARTTLS yields `unknown`. That is measurable — the report
carries `starttls_advertised` and `tls_reason` — and
the public beta report template requests representative operational evidence.
No such measurement is claimed by this ADR or by passing tests.

## Decision: verification cannot be turned off, and the seam only widens trust

`build_client_context` always sets `check_hostname = True` and
`verify_mode = CERT_REQUIRED`, and there is **no parameter through which either
can be changed** — no flag, no environment variable, no "insecure" mode for the
lab profile. A context that skips verification turns STARTTLS into decoration:
an active attacker on the path completes the handshake with any certificate and
reads the `RCPT TO` the upgrade existed to protect.

The one seam is `TLSTrust`, and its shape is the argument. A caller may supply an
**extra certificate authority** and nothing else. The worst a misuse can do is
trust one more CA; it cannot disable verification, override a host name, or
supply a context. That is what the TLS integration tests use, and it is why they
can exercise a real handshake without production code ever learning what a test
is. `docs/test-strategy.md` forbids the `if testing:` shape, not dependency
injection whose default is the secure one — and the difference is that this seam
has no unsafe setting to reach.

The name verified against comes from a `ConfirmedPeer`: `TLSUpgradeRequest` takes
a peer rather than a host name, so the SNI value is the MX host the destination
chain already validated. The recipient's domain and a caller-supplied string are
unrepresentable.

**A trust anchor may come only from operator configuration.** `TLSTrust` cannot
disable verification, but it can widen it, and a Phase 6 request field reaching
it would let a caller choose who signs the certificate this project trusts —
which is `CERT_NONE` with extra steps. So the provenance rule is the same one
`SenderIdentityProvider` has: request, user, and API input may never supply a CA
file, a PEM body, a trust anchor, or any verification override. There is no such
field today and this ADR records it as a stop condition for
Phase 6; an inspection test already fails if a `TLSTrust` is constructed
anywhere in `src/` outside the module that defines the system-trust default, or
if any production module reads the environment.

Three further refusals happen before a handshake byte moves:

- **the peer must still be the one this connection reported.** `getpeername()` is
  read again and compared, and nothing is resolved: a name lookup here would
  reach somewhere the policy never saw. It is checked again after the upgrade,
  so a connection cannot become a different peer's by being wrapped;
- **the read buffer must be empty.** Anything already received is plaintext an
  active attacker could have injected before the upgrade, and reading it
  afterwards would treat it as though it had arrived inside TLS — CVE-2011-0411.
  RFC 3207 says discard it; refusing the upgrade leaves no path where injected
  bytes are used at all. That refusal is reported as `TLS_HANDSHAKE_FAILED`, the
  same failure a rejected certificate chain produces, and **it is deliberate
  that they share a category**: both are non-target TLS failures with no
  plaintext fallback, and Phase 4D maps both to `smtp_tls_failure` and thence to
  `unknown`. The two are distinguishable to an operator only by the fact that
  the smuggling refusal moves zero bytes — a test measures that. Splitting them
  into two enum members would buy a diagnostic and change no decision, so it is
  not done; `docs/status-model.md` section 7.2 records the collapse so a 4D
  author does not discover it by surprise;
- **a second upgrade is refused**, by the transport and, independently, by the
  session's STARTTLS counter.

### TLS runs over a memory BIO, not a wrapped socket

`ssl.SSLObject` with two `MemoryBIO`s, rather than `wrap_socket`. Encryption
becomes a transformation in memory and every byte still moves through
`loop.sock_recv` and `loop.sock_sendall`.

That is a testability decision as much as a design one: the suite's network guard
and its outbound-call counter observe an encrypted session exactly as they
observe a plaintext one. A wrapped socket would have moved the I/O onto methods
the guards do not see, and "external calls = 0" would have stopped meaning what
it says.

## Decision: two deadlines, and the total dominates

Gate 4B bounded every read, write, and connect. That bounds one operation, and a
dialogue of eight steps bounds nothing useful: a peer answering each stage just
inside its 30-second deadline holds a worker for four minutes without ever timing
out.

`SessionBudget` is validated the way `TransportTimeouts` is — positive, finite,
not a boolean, within a maximum — and `SessionDeadline` recomputes what is left
from a `MonotonicClock` rather than decrementing a counter, so a stage that
overran cannot leave the budget looking healthy.

The clock is monotonic and not the wall clock. A deadline computed from
`datetime.now()` moves when the machine's clock is adjusted, and "the session
ended early because NTP stepped" is a failure nobody debugs twice.

Every awaited step in the dialogue runs inside the remaining budget, so the total
dominates the per-operation timeouts as `docs/smtp-state-machine.md` section 6
requires. The handshake timeout is deliberately *not* required to be smaller
than the budget: the budget bounds it anyway, and requiring the two to agree by
hand is a configuration chore that a small budget would fail on.

A deadline is recorded as `deadline_exhausted` beside the outcome, because a
deadline and a reset produce the same non-target outcome at the same stage, and
Phase 4D needs to tell this project's own bound apart from the network's.
`SessionReport` refuses to be built with `cleanup = skipped_deadline` and that
flag false: two fields describing one fact must agree, or a reader picks the one
that suits them. The implication is one-directional — a budget spent mid-dialogue
sets the flag with cleanup `not_attempted`, and one spent during `RSET` sets it
with cleanup `incomplete`.

### The connect is inside the budget, and the rate-limit wait is not

The independent review of 4C found the deadline starting *after* the connection
existed, so the worst case for one probe was `connect_seconds + budget` — ten
seconds plus thirty — while this ADR and `docs/smtp-state-machine.md` both said
the total dominates everything. The claim was the correct one and the code was
made to match it: `SMTPProbeService` starts the deadline before it connects and
runs the connect inside whatever is left, so the effective bound is

```text
min(TransportTimeouts.connect_seconds, remaining session budget)
```

The per-operation timeout is kept rather than replaced. The smaller of the two
wins, which is the same rule every step of the dialogue already followed, and a
connect is not a special case of anything. A budget already spent opens no socket
at all: a connection with no time left to speak on it is a connection the remote
host sees for nothing.

**Waiting for a rate-limit lease is deliberately outside that budget.** The
deadline starts once the lease is held. A budget spanning the wait would turn
queue depth into `deadline_exhausted`, and Phase 4D reads that flag as *this
project's own bound on a remote conversation*; attributing our own scheduling to
the network is the exact confusion the flag exists to prevent. Bounding how long
a caller may wait for a budget is a real requirement and it belongs to the
limiter, in gate 4E, with its own vocabulary.

## Decision: the configured envelope sender may not be the null reverse path

`EnvelopeSender.null()` stays a legal value — RFC 5321 has uses for `<>` — but
`load_sender_identity` refuses to build a probing identity from one.

`docs/requirements.md` section 9 requires a managed envelope sender with SPF
authorizing the IP and monitored `postmaster` and `abuse` channels. None of that
exists for `<>`, and `MAIL FROM:<>` followed by a single `RCPT TO` is the exact
shape a receiving site fingerprints as harvesting. The alternative — deciding at
run time — means a deployment discovers which branch it took from a remote
server's behaviour.

The loader also refuses an EHLO name and a sender domain that are unrelated: one
must be the other or a subdomain of it. It is an alignment check, not an
ownership proof; only DNS can show that the PTR, the forward record, and the SPF
record line up, and section 9 makes that a deployment requirement. What this
catches is the configuration mistake that turns a probe into apparent forgery.

There is no default identity and no fallback. An unconfigured deployment does not
probe, because inventing a plausible EHLO name would put an unowned host name on
the wire.

## Decision: authorization precedes the socket, as an application contract

`SMTPProbeService` takes a `RateLimiter` with **no default**. A caller that has
not supplied one cannot construct the service, so there is no path from a future
API to an unmetered probe, and an inspection test fixes that no permissive
implementation ships in `src/`.

The real budgets, the kill switch, and per-destination pacing are gate 4E and
Phase 6. What 4C owes is the ordering, so that adding them is wiring rather than
restructuring. The budget key is the account, the recipient's *domain*, and the
MX host — never the local part, so a budget key cannot carry one.

## Consequences

- A seventh SMTP command needs a new enum member, a new encoder, a new factory,
  and an ADR. `write_command` gives it nowhere else to come from.
- Requiring TLS by default means a server without STARTTLS returns `unknown`.
  That is the conservative answer and it is visible in the report as
  `tls_reason = not_offered`. **How often it happens is not guessed at here.**
  Measure the `not_offered` rate under authorized representative operation
  before a limited beta. Measurements describe compatibility; ADR 0021 requires
  TLS regardless of that rate. Changing the default without a security review
  is not one of the options.
- The TLS test fixtures are committed certificates. Generating one needs
  `cryptography`, which this project does not depend on, or the `openssl` binary,
  which a CI image need not have. `tests/fixtures/tls/README.md` records what
  each is and how to regenerate them.
- `close` still sends no TLS `close_notify`. Sending one means writing, which
  means awaiting, which would put back the cancellation point ADR 0008's cleanup
  decision removed. The peer sees a truncated session after a `QUIT` it has
  already answered.
