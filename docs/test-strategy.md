# Test strategy

## 1. Principles

- no third-party SMTP connections in CI;
- deterministic DNS and SMTP fixtures;
- every network dependency mockable;
- protocol invariants tested mechanically;
- controlled owned domains only for manual integration;
- correctness measured by evidence class, not only one aggregate accuracy.

## 2. Test layers

### Unit

- address parsing;
- normalization;
- DNS mapping;
- enhanced status parsing;
- reason normalization;
- verdict aggregation;
- redaction;
- cache keys;
- retry decisions.

### Property and fuzz

- arbitrary input never injects CR/LF;
- parser never crashes on bounded strings;
- command encoder cannot produce an extra SMTP line;
- aggregation is deterministic;
- adding a risk flag alone does not change deliverability.

### DNS fixtures

A fake resolver answers from a table. Required scenarios:

- one MX; several preferences; equal preferences kept;
- exchange with a trailing dot;
- Null MX alone, and Null MX beside a real MX;
- malformed, empty, and root exchanges;
- no MX with A, with AAAA, and with both;
- no MX and no addresses;
- NXDOMAIN, SERVFAIL, timeout;
- positive and negative TTL caps, TTL zero, and a missing TTL;
- an MX host that fails while a sibling succeeds;
- safe and unsafe addresses on one host;
- a CNAME chain whose final address is forbidden.

### Passive classification fixtures

Dataset text is built in the test, never fetched. Required scenarios:

- role: case differences, `+tag`, dots, hyphens, prefix and suffix near misses,
  a one-character difference, and a Unicode local part that Phase 1 already
  refuses;
- disposable: hit, miss, case and trailing-dot normalization, IDN and punycode
  agreement, an override in both directions, a duplicate, a malformed entry;
- free-mail: hit, miss, independence from disposable, and a company domain
  hosted by a large provider that must not be flagged;
- provider: suffix match, several MX hosts, preference order irrelevance, an
  attacker-controlled lookalike suffix, label boundaries, unknown, ambiguous,
  and every non-MX route outcome contributing nothing;
- loader: unknown schema version, missing or unknown metadata field, duplicate,
  Unicode-normalization duplicate, IP literal, wildcard, wrong kind, oversized
  input, contradictory override, and a missing file;
- schema: a missing entries array, a misspelled entries key, an explicitly
  empty array that must stay valid, an entries array of the wrong type, an
  unknown top-level field, and one kind's array appearing in another's file. A
  missing array and an empty array must be distinguishable;
- metadata: CR, LF, NUL, tab, an escape sequence, a bidirectional override, a
  zero-width space, a line or paragraph separator, and an over-long value are
  all refused; an ordinary semantic version, commit hash, URL, SPDX identifier,
  and timestamp are all accepted;
- overrides: the `not_disposable` and `disposable` names load, a file using the
  legacy `allow` or `deny` names is refused by name, a missing or unsupported
  `target` is refused, both arrays are mandatory, and an override changes
  disposable membership and nothing else;
- values: a classification domain cannot be built from a complete address or
  from text carrying CR, LF, or NUL; a role name cannot be built from the
  submitted local part, a tagged form, or non-ASCII text; and no string reaching
  evidence carries a control character, an `@`, or the submitted local part.

### Integration

- scripted SMTP server;
- fake DNS resolver;
- cache/store adapters;
- API with fake executor;
- queue cancellation and retry.

### Manual controlled network

- owned mailbox;
- owned nonexistent recipient;
- owned alias;
- owned forwarding;
- owned accept-all;
- owned Null MX;
- explicitly authorized external tenant.

### SMTP safety gate

Tested without any transport, in Phase 4A:

- the scanner refuses each of `DATA`, `BDAT`, `AUTH`, `VRFY`, `EXPN`, `SEND`,
  `SOML`, `SAML`, `TURN`, `ATRN`, `ETRN`, `BURL`, `XCLIENT`, and `XFORWARD`,
  written as a bare literal, a bytes literal, an f-string, a concatenation, an
  encoded call, and with an argument;
- the scanner does not flag `authentication`, `author`, `send_timeout`,
  `database`, `metadata`, a docstring naming a command, or a comment;
- a command hidden after the first wire line of a multi-line literal is refused;
- a command line whose verb is interpolated is refused;
- the scanner covers every production SMTP path, and reports rather than passes
  when a glob matches nothing;
- the command enum holds exactly six members and no forbidden one;
- no encoder accepts a command name, a `str`, or a `bytes`;
- every encoded command is exactly one line, ends with one CRLF, carries no NUL,
  and is within the 512-octet limit;
- the local part is not rewritten by the encoder;
- a second `RCPT TO` is refused by the state table and, independently, by the
  session counter. Each barrier is pinned by its own test;
- `RSET` does not permit a second recipient;
- STARTTLS is issued at most once, only after EHLO, and only EHLO may follow it;
- a failure permits only `QUIT` and has no transition back to plaintext;
- an address the candidate never resolved to is refused by
  `approve_destination`, as are a non-usable candidate, a denied address, and
  any port but 25; production code reaches `ApprovedDestination` only through
  the factory, fixed by an inspection test;
- a forbidden or mismatched peer, and a peer on the wrong port, cannot become a
  `ConfirmedPeer`; an IPv4-mapped IPv6 peer is refused rather than unwrapped;
- a session cannot be built from `None`, an `ApprovedDestination`, a
  `RouteCandidate`, a tuple, or an arbitrary object, at run time and not only
  under mypy, including through `dataclasses.replace`;
- the sanitizer examines only a bounded prefix, asserted as
  `sanitize(text) == sanitize(text[:bound])` at 1 KB, 2 KB, 4 KB, 8 KB, and the
  parser's maximum, so the algorithmic bound is pinned without a wall clock;
- the sanitizer's documented non-guarantees are pinned too, so the guarantee and
  the behavior cannot drift apart;
- a wire line whose verb comes from an f-string placeholder, percent
  formatting, `str.format`, or a leading name is refused; the same forms with a
  literal verb are not;
- the transport picks `AF_INET` for an IPv4 destination and `AF_INET6` for an
  IPv6 one, and an IPv4-mapped, 6to4, cross-family, or scoped peer is refused
  rather than unwrapped;
- a destination the policy refuses at connect time creates no socket at all;
- the transport exposes `connect` and nothing else, `connect` takes an
  `ApprovedDestination` and nothing else, and neither the port nor the adapter
  publishes a write method;
- a refused peer closes the connection, exactly once, with zero writes recorded;
- an exception between connecting and confirming still closes;
- a timeout must be positive, finite, non-boolean, and within a maximum; a limit
  must be a positive whole number and a total may not be smaller than one line;
- a `PeerEndpoint` must be a numeric address with no CR, LF, NUL, scope
  identifier, whitespace, brackets, or port glued on, and a port within
  1..65535; a boolean port is refused because `True` would mean port one. The
  value guarantees the shape and nothing else — `confirm_peer` still re-runs the
  destination policy, and a test hands it an endpoint built with its own
  validation bypassed to prove the two barriers are independent;
- an `AsyncioSMTPConnection` cannot be built with a peer that is not a
  `PeerEndpoint`, with unvalidated limits or timeouts, with a negative or
  over-limit byte count, or reporting itself closed while holding an open
  socket;
- `read_line` never raises. Both an over-long line arriving complete and one
  arriving in pieces end in a typed bounded-read failure that abandons the
  connection; **which** failure it is, `line_too_long` or
  `total_limit_exceeded`, is whichever configured bound is reached first, so it
  is asserted as one of the two rather than pinned to one;
- once the total cap is exceeded, a further `read_line` returns the same typed
  failure immediately and performs no socket read, so a spent connection cannot
  cost a read deadline per call. Gate 4C treats any `ReadFailed` as terminal and
  closes;
- a reply's enhanced code is dropped when its class contradicts the basic code,
  an echoed address never survives into a diagnostic, and a malformed reply is a
  typed defect rather than an exception;
- no `domain/smtp*` module imports `socket`, `ssl`, `asyncio`, or `smtplib`, or
  names a status.

### SMTP transport testing, from gate 4B

**The default is a fake `SMTPTransport` under `tests/`.** `tests/fake_smtp_transport.py`
implements the port with a scripted sequence and opens no socket, so every
protocol test in section 3 runs deterministically, with no timing flake and no
address at all — the destination policy is simply not in the path. It scripts a
connect success, each connect failure, a malformed peer, a mismatched peer, a
denied peer, a wrong peer port, scripted reads, EOF, and close, and it records
what was asked of it.

The fake carries a `write_line_calls` counter and a private `_write_line` it
never needs, so "nothing was written before the peer was confirmed" is a
measurement rather than an assumption. Structurally it cannot happen either:
`SMTPConnection` declares no write method.

**The loopback suite is separate, and so is its guard.** `tests/integration/`
replaces the suite-wide `block_network` fixture with a narrower one that permits
`127.0.0.1` and `::1` and refuses everything else, including all name
resolution. Both are measured: the normal suite reports zero calls of every kind,
and the loopback suite reports zero external calls beside its loopback ones.

Those tests hand `AsyncioSMTPConnection._over_socket` an **already-connected
socket**, so they never build an `ApprovedDestination`, never call
`approve_destination` or `confirm_peer`, and never touch the production policy
chain. That primitive is named privately and is used by `connect` itself, which
is the honest description of it: an internal I/O primitive rather than a
test-only door. It is not an authorization bypass — it takes no destination, so
it grants no reachability a caller did not already have by holding a connected
socket, and it returns a connection with no write method rather than a session.
An inspection test fixes that nothing in `src/` outside the transport module
calls it, and that `connect` is its only production caller.

The fixture binds `127.0.0.1` on an ephemeral port and closes from a `finally`
so a failing test still releases it. Which host it may bind is a pure function,
`is_permitted_bind_host`, permitting `127.0.0.1` and `::1` only; it runs in the
constructor and again in `start`, so `0.0.0.0` is refused before a descriptor
exists and a test can assert that without binding anything.

They cover only what a fake cannot show: a real partial read, a real EOF, a real
reset, a real read deadline, the line and total caps against a real peer, that
close runs on the way out of the block and when an exception passes through, and
what happens when a read, a close, or the body of the block is cancelled.

**The guard is tested by inspection, never by dialling.** The earlier version
proved it by connecting to a public address and asserting the refusal, which
means that on the day the guard breaks, its own negative test is the thing that
reaches the internet — a mutation check confirmed exactly that. So
`tests/integration/test_loopback_guard.py` asserts on the pure classifier, on
the pure bind rule, and on the fact that every outbound entry point carries the
marker the fixture stamps on what it installs. No test in this repository
performs the act it exists to prove impossible.

The reason this needs saying: `127.0.0.1` is denied by `evaluate_destination`,
and `ApprovedDestination` re-runs that check, so a loopback fixture cannot reach
the production path. **That is the policy working, and it is not to be worked
around.** None of the following may be added:

- any relaxation of `evaluate_destination`, including a "test mode" parameter;
- a localhost or trusted-address allowlist in production code;
- an environment variable, config key, or profile flag that softens the policy;
- `if testing:` or `if DEBUG:` on a production path;
- `bypass_policy`, `skip_validation`, `unsafe_for_tests`, or a constructor that
  approves an arbitrary denied address;
- `# type: ignore` or `Any` used to get a wrong value past a runtime check.

Helpers and fixtures under `tests/` are fine. A test-only capability that
production code can import is not: the property that makes this safe is that the
escape lives in a package production code cannot reach.

### SMTP dialogue and STARTTLS, from gate 4C

**The default is `tests/fake_smtp_server.py`**, a scripted peer that opens no
socket and behaves like a server rather than like a tape: replies are queued when
a command arrives, so the transcript is the real sequence the dialogue produced
and a reply that was never triggered is never read.

Required scenarios, all against that peer:

- the plain path and the TLS path, with the transcript asserted exactly —
  `EHLO, MAIL FROM, RCPT TO, RSET, QUIT` and
  `EHLO, STARTTLS, EHLO, MAIL FROM, RCPT TO, RSET, QUIT` — and, in both, exactly
  one `RCPT TO`, at most one `STARTTLS`, at most one `MAIL FROM`, and no
  forbidden verb anywhere in the bytes;
- a banner that is `220`, multiline `220`, `4xx`, `5xx`, malformed, absent,
  oversized, over-long, or too many lines. **No command may be written after any
  of them**;
- an `EHLO` that is refused temporarily or permanently, malformed, unterminated,
  or lost. There is no `HELO` fallback and a test asserts the wire never carries
  one;
- capability parsing: case differences, a duplicate, a keyword with parameters, a
  malformed line, an unknown extension, an over-long keyword, and every lookalike
  of `STARTTLS` — `STARTTLSX`, `XSTARTTLS`, `START`, `TLS`, `NOSTARTTLS` — none
  of which is `STARTTLS`;
- `STARTTLS` absent under both policies, refused by the server, and every
  handshake failure: certificate, host name, timeout, peer changed, and a generic
  failure. None of them may be about the target, and none may continue in
  plaintext;
- a post-TLS `EHLO` failure, which must stop before `MAIL FROM`;
- a `MAIL FROM` refused temporarily, refused permanently, or disconnected on.
  **None produces a recipient observation at all**;
- every recipient class: `250`, `251`, `252`, `450`, `451`, `452`, `550 5.1.1`,
  a bare `550`, `550 5.7.1`, `552`, a malformed reply, and a reply that echoes
  the recipient;
- a write that fails at each stage, an EOF and a reset at each stage, and a
  cleanup command that fails — which must not change the observation;
- the session budget exhausted before anything is written and part way through,
  driven by a fake clock rather than by sleeping;
- cancellation at the dialogue boundary: re-raised, never converted, and the
  connection closed.

**Every awaited step is bounded, and each is pinned on its own.** A test that
reaches a deadline through some *other* step is not evidence that this one is
bounded: removing the wrapper from the read step, from the write step, and from
the TLS handshake each left the entire suite passing, because the clock those
tests drove advanced on every reading and whichever step ran next tripped the
budget. So `tests/unit/application/test_smtp_deadline_stages.py` uses a peer that
**goes silent** at one named point — banner read, `EHLO` write, `EHLO` read,
`STARTTLS` write, its reply, the handshake, the post-TLS `EHLO` write and read,
`MAIL FROM` write and read, `RCPT TO` write and read, and each of the four
cleanup steps — with a clock that never advances, so the only thing that can end
the await is the wrapper around it. Each test carries its own outer bound, so a
missing wrapper fails rather than hangs. An inspection test reads the four
`self.connection.…` call sites out of the source and requires each to sit inside
`self._bounded(...)`, because behaviour cannot cover a step no scenario reaches.

**The connect is inside the same budget**, and `tests/unit/application/test_smtp_probe.py`
fixes both directions: a connect that never answers ends on the session budget, a
connect timeout smaller than the budget stays the transport's own and is named as
such, time spent connecting comes out of what the dialogue gets, a budget already
spent opens no socket, and a cancelled connect still releases the lease.

**Sender provenance is tested as provenance**, not only as a type: the wire bytes
must carry the configured envelope sender and EHLO name, the target must appear
exactly once and only in `RCPT TO`, and changing the target must not change the
sender.

**Provider neutrality is tested two ways**, because neither alone is enough. The
same scripted server must produce an identical transcript and outcome for a
target at a large provider and at a domain nobody has heard of; and an inspection
asserts that no production SMTP module names a provider at all, because a test
cannot enumerate the providers it has not thought of.

**The TLS integration tests are real handshakes over loopback.**
`tests/fixtures/tls/` holds a throwaway CA, a certificate for `mx.test.example`,
a certificate for another host signed by the same CA, and a self-signed one. The
trusted certificate must succeed and then carry commands and replies; the
untrusted one must fail as `tls_certificate_invalid`; the wrong-name one must
fail as `tls_hostname_mismatch`. The last two are the tests a client with
verification quietly off would fail, which is why they exist — and one more test
asserts that the fixture CA is *not* trusted by the production default, so the
success cases prove something.

Production trust and test trust are separated by shape rather than by a flag:
`build_client_context` always sets `check_hostname` and `CERT_REQUIRED`, and the
only seam adds one certificate authority. There is no setting a test could reach
that a deployment could reach by accident. An inspection test adds the other
half — no `TLSTrust` is constructed anywhere in `src/` outside the module that
defines the system-trust default, and no production module reads the environment
— so a Phase 6 request field cannot quietly become a trust anchor.

**The upgrade request is bound to its own connection**, and that is tested
separately from the `getpeername()` re-read. A request carrying another
connection's `ConfirmedPeer`, one naming a different port, and one whose address
is written another way are all refused as `tls_peer_changed`; a matching one
reaches a different, named refusal, which is what shows the comparison let it
through rather than that everything ends the same way. Removing the comparison
broke no test before this existed.

### SMTP recipient evidence mapping, from gate 4D

The mapper is pure, so its tests need no fixture server at all: a `SessionReport`
is built directly and the evidence is compared. Replies are built **through the
Phase 4A parser** rather than by constructing `SMTPReply` by hand, so a test
cannot assert on an enhanced code the parser would have dropped.

The matrix is the specification in `docs/status-model.md` section 7, row by row:

- every recipient class — `250`, `251`, `252`, `450`, `451`, `452`, `550`, `551`,
  `552`, `553`, `554` — with its reason, strength, and temporary flag;
- every enhanced code that changes an answer: none, `2.x.x`, `2.1.5` on a `252`,
  `4.7.1`, `4.2.2`, `5.1.1`, `5.1.0`, `5.1.6`, `5.2.2`, `5.7.1`, and a
  contradictory `250 5.1.1` that the parser has already dropped;
- **a `4xx` carrying an address-shaped enhanced code**, `450 4.1.1`, which must
  stay temporary. It reads like `550 5.1.1` one component at a time, and a
  mutation that read the subject and detail before the class turned it into the
  strongest evidence this project produces. No row noticed until this one existed;
- every pre-recipient failure at every stage: a `4xx` and a `5xx` banner, a
  malformed banner, a refused `EHLO` before and after TLS, an unreadable reply
  after the greeting, a refused `MAIL FROM` in both classes, a lost connection,
  and an internal failure;
- all seven TLS reasons, which collapse to one non-target reason while the reason
  itself survives as metadata;
- the deadline, mid-dialogue and at the cleanup boundary, distinguished from a
  transport timeout by the flag rather than by the reason;
- all four cleanup categories, asserted to change **nothing but the cleanup
  detail** — comparing only the reason let a mutation that flipped
  `about_the_target` on a failed cleanup escape;
- every `TransportFailure` member, so a new one fails rather than defaulting.

**The invariants are tested as invariants**, not inferred from the rows: no
pre-recipient failure at any stage with any reply ever produces a recipient-stage
reason; a `MAIL FROM 550 5.1.1` and a `RCPT 550 5.1.1` carry the same enhanced
code and different evidence; `252` is never in the positive set; a `550 5.1.1` is
strong evidence and still not a status.

**Each of the three barriers before a recipient rejection is pinned on its own**,
and this needed deliberately awkward inputs rather than more rows. Removing any
one of the outcome check, the recipient-count check, or the stage check left the
entire suite passing, because every test built its report through one of two
helpers and neither helper can produce a report where a single barrier is
load-bearing. So three tests construct a `SessionReport` directly:

| Shape | The one barrier that refuses it |
|---|---|
| `connection_error` at `cleanup`, carrying `550 5.1.1`, one recipient attempted | the outcome check |
| `rejected` at `cleanup`, carrying `550 5.1.1`, **none** attempted | the recipient-count check |
| `rejected` at `mail_from`, carrying `550 5.1.1`, one attempted | the stage check |

All three are legal values, and each test fails when its own barrier alone is
deleted and passes when either of the others is.

**The published sets are tested as a partition**, because `about_the_target` is
derived from `RECIPIENT_STAGE_REASONS` and a reason in neither set would
otherwise be silently non-target: nothing the mapper emits may be missing from
both sets or present in both, every declared member must actually be emitted, and
the derivation is asserted directly to be fail-closed on a reason belonging to
neither. The positive set is checked to exclude `rcpt_unverifiable`,
`rcpt_rejected_address`, `rcpt_rejected_policy`,
`smtp_ambiguous_permanent_failure`, `mailbox_full`, and `smtp_temporary_failure`
by name rather than only by subset.

**`_CONNECT_REASONS` is pinned by mechanism, not only by coverage.** The keys must
be exactly `TransportFailure`, *and* an unmapped failure must raise rather than
default — the second is what fails when the subscript becomes a defaulting
`.get`, which the earlier test could not distinguish because it asserted only
that the result was a reason code.

**Both entry points are tested against the same input contract.**
`map_connect_failure` must refuse a negative, boolean, floating-point, or string
`elapsed_milliseconds`, a non-boolean deadline flag, a failure that is not a
`TransportFailure`, and an `observed_at` that is naive, `None`, or not a
datetime. `Evidence` refuses the same timestamps and a detail value that is not a
safe scalar, so the guarantee holds for every producer rather than only for this
one, and both layers are tested so neither is load-bearing alone.

**Privacy is measured on the surfaces Phase 6 will publish.** A reply that echoes
the recipient must not leave it in `repr`, `str`, the details mapping, or the
diagnostic, and no `@` may survive anywhere. No raw reply, no wire command or
transcript **this project issued**, no certificate, and no peer address reaches
the details, and every detail value is a string, an integer, a boolean, or
`None`.

The distinction in that sentence is deliberate and is asserted from both sides. A
server's own diagnostic may contain SMTP command words — `550 RCPT TO is not
allowed here` sanitizes to `RCPT TO is not allowed here` — and that is remote
prose, bounded and `@`-free, not a wire command. A test that forbade the string
outright would have been asserting something untrue while passing by accident on
its fixture's wording.

**Determinism is asserted directly**: the same report twice, two equal reports,
and a fixed detail key order. Nothing iterates a set.

**Purity is asserted by inspection**, because behaviour cannot show the absence
of an import: no network, clock, or storage module; no transport, connection,
limiter, clock, or provider named; no coroutine and no `await`; no environment
read.

### Verification orchestration and rate limiting, from gate 4E

**No test in this gate sleeps, and none opens a socket.** Waiting is a `Sleeper`
port, so a fake advances a fake `MonotonicClock` and yields: "wait five seconds
for a token" is a measurement rather than five seconds of CI. Every scenario also
carries its own outer bound, so a loop that waits when it should stop fails
rather than hangs.

`tests/fake_smtp_server.py` gains `RoutedSMTPTransport`, which hands out a
different scripted peer per destination address. The gate 4C fake gives every
destination the same script, so it cannot express the scenarios that matter here
— the first candidate refusing and the second accepting. Its `recipient_commands`
counts `RCPT TO` across every connection it handed out, so the central invariant
is measured **on the wire** rather than on the report, which is derived from the
code under test.

Required scenarios:

- a recipient answer on the first candidate: the second is never connected to;
- a connect failure, a TLS failure, a refused banner, and a rejected `MAIL FROM`
  each fall through to the next candidate, which then answers;
- **every recipient answer stops the verification** — `250`, `450`, `451`, `252`,
  and `550 5.1.1` alike. The `450` and the `252` are the rows that matter: both
  read like "ask someone else", and both are answers;
- a `RCPT TO` written and then lost before its reply stops the verification;
- a `RCPT TO` whose *write* failed stops it too, because this project cannot know
  what reached the peer;
- an internal failure stops it and never falls through to another exchanger;
- twenty candidates and a cap of three: exactly three connections;
- every candidate failing before the recipient stage produces evidence that is
  entirely non-target, and no status;
- a routeless `MailRoute` opens no socket and acquires no budget at all.

**Planning is tested as a pure function**: preference order preserved, addresses
expanded in Phase 2's order, one endpoint never planned twice, and the same
address behind two exchanger names planned as two attempts — because the
certificate is verified against the host name.

**The recipient-touched rule has two barriers and each is pinned**, on the
precedent gate 4D set. A `SessionReport` whose transcript names `RCPT TO` at an
earlier stage is caught by the transcript check alone; one that reached the stage
with an empty transcript is caught by the stage check alone.

**The limiter is tested against its own arithmetic first.** `domain/rate_limit.py`
is pure, so refill, clamping, key canonicalization, and every bound are asserted
with no clock and no loop — including that idling for `1e15` seconds still leaves
a bucket holding exactly its capacity, and that a key refuses an `@` in any
component.

The adapter is then tested for what it refuses and what it never leaks: global
and per-domain concurrency, pacing after the burst, a wait budget that bounds the
whole acquisition, a released slot letting a waiter through, double release,
re-entry, eviction under pressure, and an entry in use surviving a flood.

**Cancellation is tested against a caller that is actually holding something.**
This needed a second fake: `FakeSleeper` returns immediately, which is what makes
pacing measurable and is exactly wrong here, because the wait is over before
there is anything to cancel. `BlockingSleeper` never returns, so a test can park
a caller mid-wait and cancel it. Every cancellation test in the gate passed
before it existed — and a mutation from `except BaseException` to
`except Exception` passed the whole suite, because each of them was cancelling a
caller that had not yet acquired a slot.

**Inspection covers what behaviour cannot enumerate**, over the three modules
this gate added: no retry, backoff, or jitter; no `random`, `uuid`, or
accept-all recipient generation; no `Status`, `Verdict`, `Confidence`, or
`RiskFlag`; no transport, connection, or `ApprovedDestination` reachable from the
loop; no provider named in the limiter; and no wall clock in the pacing
arithmetic. Those scans read the **syntax tree with docstrings excluded**,
because both were written against the raw text first and both failed on their own
prose — the third time this repository has made that mistake.

### Evidence aggregation, from Phase 5

The aggregator is pure, so its tests need no fixture at all: `Evidence` is built
directly and the verdict is compared. Evidence is **not** driven through a
producer, deliberately — the contract is *evidence in, verdict out*, and several
rows are sets no pipeline can produce. The point of those rows is that the
aggregator answers them conservatively rather than assuming they cannot happen.

The matrix is `docs/status-model.md` section 4, row by row:

- syntax and route: invalid syntax, each unsupported form, NXDOMAIN, Null MX,
  authoritative no-mail-route, MX-only, implicit-MX-only, DNS temporary, unsafe
  destination, and a configuration anomaly;
- passive: role, disposable, free-mail, several flags at once, and the
  internationalized local part — each raising its flag and deciding nothing;
- SMTP recipient: `250`, `251`, `252`, `4xx`, `mailbox_full`, `550 5.1.1`,
  `550 5.7.1`, and a bare `550`, each with its status, primary reason, **and**
  confidence level;
- SMTP non-target: banner, EHLO, TLS, `MAIL FROM`, protocol error, timeout,
  refused connection, unsafe destination, and internal error, none of which
  reaches `invalid`;
- conflicts: hard invalid with `250` and with `251`, temporary DNS with `250`,
  unsupported with `250`, policy with `250`, `250` with `550 5.1.1`, `250` with
  `252`, a strong non-target beside a positive recipient, and an internal error
  beside one.

**Several invariants are asserted exhaustively over the vocabulary** rather than
inferred from the rows, because the rows can only cover what someone thought of:
exactly five reason codes can ever reach `invalid`, at any strength and in
either permanence state; no non-target reason ever can; no temporary observation
ever becomes permanently invalid; and every reason outside the target-specific
set is non-target.

**Each condition of each gate is pinned where the others pass.** A
`rcpt_rejected_address` marked temporary is refused by the permanence check
alone; one whose producer denied targetness is refused by the targetness check
alone; a policy rejection and a bare `550` are refused by the reason check
alone. That is the same discipline gates 4A, 4D, and 4E used, and it is the only
way a mutation of one condition fails.

**Order independence is tested by full permutation**, not by one reversal: every
conflicting set is aggregated in every order, with the status, confidence,
primary reason, reason codes, and risk flags all compared. Anything that
depended on arrival order — a first-match loop, a `dict` in input order, a set
iterated — passes the row and fails here.

**Duplicates are tested at 1, 2, 3, and 10 copies**, of seven different
observations, asserting that nothing changes. Separately, the *retained* evidence
is asserted to keep every copy in the caller's order, because decision-time
deduplication and audit-time retention are different things.

**Risk separation is tested over every status**: adding every passive risk
observation to a `likely_deliverable`, an `invalid`, a `temporary_unknown`, and
an `unknown` verdict changes the status, the confidence, and the primary reason
not at all, and only adds flags.

**Inspection covers what behaviour cannot.** No forbidden import in any of the
three modules; no collaborator named that could be asked for more information,
not even a `Clock`; no coroutine and no `await`; no multiplication, division, or
exponentiation anywhere; no function naming a decisive status; `.strength` read
nowhere; and no provider named in any of them, because a behavioural test cannot
enumerate the providers nobody thought of. Every scan reads the **syntax tree
with docstrings excluded** — these modules explain at length why they contain no
retry and no probe, and a text scan fails on its own prose, which this
repository has now done four times.

**The two Phase 4 stop conditions have their own file.** The exhaustiveness
guard is tested for what it admits, for failing loudly rather than defaulting,
for using `assert_never` rather than a `.get`, and for *not* being the dispatch —
because turning it into one would delete a reviewed 4D barrier and leave that
barrier's test passing. The `LINE_TOO_LONG` entry-point difference is pinned
from both entry points, in reason, in permanence, in resulting status, and in
the bound that makes it safe: neither reading is about the target and neither
can produce `invalid`.

**Five properties were added after the independent review**, each because a
mutation of the code changed an answer and nothing failed.

- **The primary reason leads `reason_codes`.** Pinned on a set whose
  `REASON_PRIORITY` order is the *reverse* of the enum's — `internal_error` is
  declared last and ranks first — because a fixture where both mechanisms agree
  proves nothing about which one is used, and most fixtures agree. `Verdict`
  refuses the inconsistent shape as well, so the property holds however the list
  was assembled;
- **unsupported input outranks an explicit temporary condition.** The only
  combination that can distinguish tier 2 from tier 4, since both produce
  `unknown` and the unsupported codes already outrank every tier-4 reason. Four
  rows, in both orders;
- **the confidence table is pinned by mechanism as well as by coverage**, on the
  `_CONNECT_REASONS` precedent: it must cover `REASON_PRIORITY`, and no decision
  table in the module may be read with a defaulting `.get`;
- **`internal_error` leads tier 4 by position**, not by one pairing. The earlier
  test compared it only against `smtp_policy_blocked`, so swapping it with the
  adjacent entry escaped;
- **the exported `supports_likely_deliverable` is tested on its own.** Its
  acceptance clause is redundant *inside* the aggregator — tier routing has
  already established it — so a caller invoking the helper directly is the only
  thing that can hold that condition.

**Privacy is tested on the `Verdict` surfaces, not only on `Evidence`.** Phase 5
added `Verdict.evidence`, so `repr(Verdict)` reaches every retained detail — a
carrier that did not exist when gate 4D wrote its privacy tests. The evidence is
driven through the real Phase 4D mapper from a session whose reply echoes the
recipient, so the Phase 4A sanitizer is exercised rather than bypassed, and the
invariant asserted is the narrow true one: **aggregation reintroduces nothing the
producers removed**. One test states the limit explicitly — a `Verdict` is
exactly as private as its input — so the others cannot be read as a promise that
arbitrary evidence becomes safe by being aggregated.

**The five Phase 6 stop conditions have a docs test**, in the style Phase 4
established for its seven: on substance rather than on wording, so the prose may
be rewritten and deleting any one condition fails its own row.

### Production composition, from Phase 6

Phase 6 computes no status, so its tests are about **wiring**. Two measurements
recur because they are only checkable here: the fake resolver counts what it was
asked, and the scripted SMTP service counts whether it was called at all.

- syntax: every rejection kind reaches its documented status with **zero** DNS
  calls and zero SMTP calls;
- the DNS boundary: Null MX, an authoritative no-mail-route, and a SERVFAIL each
  reach their status without the SMTP step running — read from
  `connectable_candidates` rather than from a rule written in Phase 6;
- every recipient class through the whole pipeline, with the evidence built by
  the real Phase 4D mapper from a real parsed reply;
- the account handed to the SMTP layer is `principal.rate_limit_account`, and is
  neither the target's domain nor anything a caller supplied;
- an `internal_error` reaches the operator sink while the caller sees `unknown`,
  and an ordinary verdict reports nothing — a sink that fires every time is one
  nobody reads.

**The graph is asserted as a graph.** One limiter and one admission gate shared
by identity, two stacks independent, the real clock and sleeper bound with no
parameter to replace them, `smtp is None` for a passive deployment, and
`build_verification_stack`'s signature carrying no seam for a clock, a sleeper,
a limiter, a transport, or a trust anchor.

**Neither bound is tested by waiting.** Admission is measured by counting who is
inside the gate; the total deadline is driven by a scripted delay against the
event loop's own clock. Every scenario carries its own outer bound, so a gate
that waits when it should refuse fails rather than hangs. Permits are asserted
returned after an exception, after a cancellation, and after a deadline.

**The twelve stop conditions are inspection tests.** Phase 6's risk is a
shortcut — a serializer that picks a status, a handler that builds a `Principal`
from a request field, an entry point reaching past the high-level service — and
every one of those is short, plausible code that no behavioural test catches
until the day it is wrong. So the aggregation sets, `EvidenceStrength`, every
`Status` member, `asdict`, `.details`, `TLSTrust`, `EnvelopeSender`,
`SMTPProbeService`, `os.environ`, `create_task`, and a numeric confidence are
each asserted absent from every Phase 6 module.

**The suite-wide network guard gained one exemption**, and every side of it is
pinned in `tests/test_no_network.py`. Asyncio's event loop wakes itself from a
worker thread by calling `send` on an `AF_UNIX` socketpair, so refusing it
deadlocked every test using `asyncio.to_thread` rather than stopping a packet. A
Unix socket has nowhere to send to except a path on this machine.

The first version pinned only the two halves that motivated it — `AF_INET`
refused, `AF_UNIX` permitted — and a mutation widening the test from "is
`AF_UNIX`" to "is not `AF_INET`", which permits IPv6 and **every unknown
family**, left the whole suite passing. That is the case the guard's own
docstring says matters most: a DNS query needs neither `getaddrinfo` nor
`connect`, so an IPv6 `sendto` was the half a widened exemption would have let
through. The classifier is now exercised directly on stand-in objects — IPv4,
IPv6, packet, netlink, an unknown number, `None`, a string, and an object whose
family cannot be read at all — so a future address family can be tested without
this file being the thing that creates one.

### Asynchronous jobs, the cache, and the remote CLI, from the Phase 6 follow-up

The independent review found that the Phase 6 build implemented composition and
left the job subsystem `docs/requirements.md` sections 5 and 11 require. These
are its tests.

**Two counters carry most of the weight.** A `RecordingExecutor` counts what was
enqueued without running it, and the scripted SMTP service counts whether it was
called at all — so `prompts/06-api-cli.md`'s "cache hit skips enqueue" is a
count of zero rather than an observation that the response was fast. The
executor runs **one pass** over what is pending rather than draining, because a
retry re-enters it and a draining loop would run the whole chain in one call,
which is exactly the step "at most one retry" needs taken separately.

Required scenarios:

- submission returns a `pending` job with the SMTP fake uncalled, and the
  passive result alongside it;
- every state reachable through `GET`, and a `completed` job carrying the
  aggregator's verdict through the existing allowlist;
- the same idempotency key from the same principal returns the same job and
  enqueues nothing; the same key from another principal is a different job;
- a cache hit enqueues nothing and probes nothing, and the lookup happens
  before the executor is touched — asserted as an ordering, because a build that
  enqueued first would still answer from the cache while having spent the slot;
- another account neither reads nor cancels the job, and gets the answer an
  unknown identifier gets;
- one retry for a temporary condition, none for any recipient answer, and a
  second retry structurally impossible;
- a cancellation landing *inside* a running verification does not become
  `completed`, `failed`, or `retry_scheduled` afterwards. An earlier version of
  this test cancelled a job that was still queued, so the fake executor simply
  removed the work and the settling code was never reached — a mutation of its
  guard escaped the entire suite;
- the registry evicts finished jobs, never a live one, and forgets their
  idempotency keys with them.

**The executor is tested as a set of refusals.** Bounds on workers, queue, and
delay set; a full queue and a full delay set refusing rather than growing; a
cancelled running job whose coroutine actually sees the cancellation; a pool
that keeps serving afterwards; a job that raises not stopping the pool; and
shutdown cancelling what is running. A delayed job is shown holding no worker,
which needed a **second sleeper**: `AdvancingSleeper` makes a twenty-minute
delay measurable and is exactly wrong for asserting something is still waiting,
so `HoldingSleeper` parks the scheduler while the pool is shown serving somebody
else. Gate 4E needed the same second fake for the same reason.

**The TTL policy is a table test against section 13**, row by row, and the rows
that matter most are the ones section 13 does *not* price — where the answer
must be "do not cache" rather than a default. Boundary cases are asserted just
before, at, and after expiry, against the real SQL rather than a fake, because
an independent review found the sender-identity and expiry predicates unpinned:
removing either from the `WHERE` clause left the suite passing.

**The remote CLI is tested against a fake client**, so the polling policy is
measured rather than waited out: a bounded number of attempts at a bounded
interval, pending and failed and cancelled each rendered as themselves, and no
verdict printed before one exists. Every polling test carries its own outer
bound — a mutation removing the attempt cap **hung** the suite instead of
failing it, which is the failure mode gate 4C's deadline tests were built to
avoid. The endpoint policy is a pure function: two permitted schemes by
allowlist, and `file:`, `data:`, credentials, queries, fragments, and control
characters all refused.

**The published schema is tested as the acceptance criterion it is.**
`prompts/06-api-cli.md` requires API examples that state explicitly that no
existence or delivery guarantee is made; a docs test fails if that sentence
disappears, if a job state loses its example, or if a published route is
missing from the document.

## 3. SMTP fixtures

Required scenarios:

- valid recipient `250`;
- forward `251`;
- unverifiable `252`;
- temporary `450`, `451`, `452`;
- recipient missing `550 5.1.1`;
- policy block `550 5.7.1`;
- storage full with enhanced code;
- bare ambiguous `550`;
- all-recipient `250`;
- slow banner;
- slow RCPT;
- malformed multiline response;
- oversized response;
- disconnect after MAIL FROM;
- STARTTLS success;
- STARTTLS failure.

## 4. Invariants

- no test reaches the network. `tests/conftest.py` makes name resolution,
  stream connections, datagram sends, and the asyncio transports fail for the
  whole suite, and `tests/test_no_network.py` fails if any of that stops
  working. Datagram sends matter most: a DNS query needs neither `getaddrinfo`
  nor `connect`, so blocking only the stream calls once let a real UDP query
  through. The guard raises an `AssertionError` subclass and the DNS adapter
  re-raises it rather than converting it into a failure value, so a blocked
  call fails the test instead of being reported as a DNS result;
- passive classification never produces a status, a hard-invalid result, or a
  risk flag outside its own four;
- **aggregation is deterministic on the multiset**: the same evidence in any
  order produces the same status, confidence, primary reason, and risk flags;
- **a risk flag alone never changes a deliverability status**;
- **only five reason codes can ever produce `invalid`**, and no non-target or
  temporary observation is one of them, whatever its strength;
- no forbidden SMTP command;
- no more than one target RCPT;
- no connection to unsafe IP;
- every operation bounded;
- no plaintext address in normal logs;
- rate budget acquired before connect;
- **at most one `RCPT TO` per verification**, not merely per session, measured on
  the wire across every connection one request opened;
- **a bounded number of outbound connections per request**, whatever the DNS
  answer's length;
- no rate-limit key carries a complete address, and no limiter state grows
  without a bound;
- a temporary result never becomes invalid only due to retry exhaustion.

## 5. Metrics

Track by evidence class:

- hard-invalid precision;
- accepted-recipient stability;
- temporary-result stability;
- provider-family unknown rate;
- policy block rate;
- timeout rate;
- mean and percentile session time;
- external connections per request;
- duplicate requests served from cache.
