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
