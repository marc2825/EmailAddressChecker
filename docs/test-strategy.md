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
