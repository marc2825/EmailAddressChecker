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
- no forbidden SMTP command;
- no more than one target RCPT;
- no connection to unsafe IP;
- every operation bounded;
- no plaintext address in normal logs;
- rate budget acquired before connect;
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
