# ADR 0006: dnspython as the resolver, and an explicit destination policy

- Status: Accepted
- Date: 2026-08-07
- Phase: 2

## Security update — 2026-11-15

Require `dnspython>=2.9.2,<3`. The previous range admitted vulnerable versions:
[CVE-2026-114605](https://github.com/rthalley/dnspython/security/advisories/GHSA-45c3-73f7-pv4m)
affects untrusted wire-name decompression and is relevant to DNS responses;
[CVE-2026-128089](https://github.com/rthalley/dnspython/security/advisories/GHSA-vvf4-9x63-8xvv)
affects WKS zone-text parsing, which the checker does not expose. Upgrading avoids
shipping either known vulnerable implementation without adding a dependency.
The DNS port, timeout, absolute-query policy and conservative failure mapping
remain unchanged. A bounded upstream WKS example is a regression test; malicious
large allocations and external DNS are not used in tests.

## Context

Phase 2 needs MX, A, and AAAA answers, the difference between an authoritative
absence and a temporary failure, and record TTLs. It also needs to decide which
resolved addresses may ever be connected to.

The standard library offers `socket.getaddrinfo`, which cannot ask for MX at
all, gives no TTL, and collapses every failure into one `OSError`. That is not
enough to tell NXDOMAIN from SERVFAIL, and that distinction decides whether a
result is `invalid` or `temporary_unknown`.

## Decision: dnspython as a production dependency

Depend on `dnspython>=2.7,<3` and place it in `dependencies`, not in an extra.
Resolving a mail route is core service behavior; a deployment without it cannot
answer a single check.

`src/emailcheck/adapters/dns/dnspython_resolver.py` is the only module allowed
to import it. Domain and application code import the port and the typed values.

### Exception mapping

Five outcomes are kept apart: an authoritative absence, a retryable resolver
failure, a refusal, an unusable answer, and a failure of this project's own.

| Raised | `DNSFailure` | Meaning |
|---|---|---|
| `NXDOMAIN` | `nxdomain` | The name authoritatively does not exist |
| `NoAnswer` | `no_records` | The name exists with no record of that type |
| `NoNameservers`, all servers REFUSED | `refused` | Unanimous refusal, read from the rcode |
| `NoNameservers`, anything else | `servfail` | No server could answer; temporary |
| `LifetimeTimeout`, `Timeout` | `timeout` | Deadline expired; temporary |
| `YXDOMAIN`, `NoRootSOA`, `FormError`, `SyntaxError` | `malformed` | Unusable answer |
| any other `DNSException` | `malformed` | An answer this project cannot use |
| `AssertionError` | *re-raised* | An internal assertion or a test's network guard |
| any other `Exception` | `internal_error` | This project failed, not the domain |

`internal_error` exists because the alternative is worse than useless. A
`TypeError` in this adapter reported as `malformed` becomes
`mx_configuration_anomaly`, which publishes our defect as the customer domain's
misconfiguration. `internal_error` maps to `ReasonCode.INTERNAL_ERROR`, which
`docs/status-model.md` already defines as never target invalidity.

`AssertionError` is deliberately not converted. The test suite's network guard
raises one, and an adapter that swallowed it could send real packets while the
test still passed. That is exactly what happened before this decision was
recorded.

`KeyboardInterrupt`, `SystemExit`, and `GeneratorExit` derive from
`BaseException` and are therefore never caught either.

No library message text is retained. A caller receives a closed enum, so a
change in dnspython's wording cannot alter a public result or leak into an API
response. `docs/requirements.md` section 11 forbids full exception text in
responses, and this is where that is enforced.

`no_records` is deliberately not temporary: the server answered, and the answer
was that there is no such record. Whether that makes the address invalid is the
route algorithm's decision, not the adapter's.

### REFUSED is read from the rcode, never from text

dnspython folds every non-NOERROR rcode into `NoNameservers`. Each entry it
records is a tuple whose last element is the response message, so the rcode is
read by calling `response.rcode()`. The same tuple contains a human-readable
rendering of the rcode; that string is never parsed, because it is not a
contract and is free to change between releases.

Only a unanimous refusal is reported as `refused`. A mixed answer, or any entry
without a structured response, falls back to `servfail`, which is retryable and
therefore the conservative reading.

### The search list is disabled on every query

Every `resolve()` call passes `search=False` and an absolute query name.
Without it the answer would depend on the injected resolver's
`use_search_by_default` and on the host's `/etc/resolv.conf`, so a lookup for
`example.com` could become `example.com.corp.internal` and a probe could reach
an internal domain. dnspython's current default happens to be safe; relying on
a library default for a security property is not.

## Decision: the destination policy lists ranges explicitly

`src/emailcheck/security/destination.py` names every forbidden range instead of
relying on the `ipaddress` convenience properties. Measured on CPython 3.12:

```python
ipaddress.ip_address("100.64.0.1").is_private  # False  carrier-grade NAT
ipaddress.ip_address("ff02::1").is_global  # True   IPv6 multicast
ipaddress.ip_address("64:ff9b::7f00:1").is_global  # True   NAT64 of 127.0.0.1
```

A filter written as `if not ip.is_global: deny` would allow IPv6 multicast and a
NAT64 address that reaches loopback. A filter written as `if ip.is_private: deny`
would allow carrier-grade NAT. Both readings are wrong in the direction that
matters, so each range is listed, ordered most specific first, and tested by
itself. `tests/unit/security/test_destination_policy.py` pins the three
properties above, so if CPython changes them the justification is re-examined
rather than silently invalidated.

An IPv6 address that carries an IPv4 address inside it (IPv4-mapped, NAT64,
6to4) is judged by the address it would actually reach, and then refused for its
form regardless. A mail exchanger has no reason to publish one.

Inside `fe00::/9` the more specific blocks are listed first, so the report names
what was actually hit: `fe80::/10` as link-local, `fec0::/10` as the deprecated
site-local range, and the remainder of `fe00::/9` as reserved. Site-local was
deprecated in RFC 3879 but is still an internal-network destination, which is
the class this policy exists to refuse.

The policy returns a typed decision with the normalized address, the IP version,
and a deny reason, not a bare boolean. Phase 4 applies the same function twice:
to each candidate before connecting, and to the peer address a socket actually
reached.

## Decision: anomalous MX configurations are never hard-invalid

Only the RFC 7505 form, preference `0` with the root as exchange, stops routing.
Every other odd configuration drops the unusable record, records a
`RouteAnomaly`, and resolves to `unknown` through the new reason code
`mx_configuration_anomaly`:

| Configuration | Result |
|---|---|
| `0 .` alone | `null_mx`, hard invalid |
| `0 .` beside a usable MX | anomaly recorded, the usable MX still routes |
| `10 .` | anomaly, record dropped |
| empty or malformed exchange | anomaly, record dropped |
| negative preference | anomaly, record dropped |
| MX records exist, none usable | `mx_configuration_anomaly`, `unknown` |

Reusing `no_mail_route` for the last row would turn a misconfiguration into a
false hard-invalid, and `docs/requirements.md` section 17 requires hard-invalid
classes to keep very high precision.

An MX host that does not resolve marks that candidate unusable. The domain keeps
its route while any candidate remains usable, because one broken exchanger is
not the domain refusing mail.

## Consequences

- Tests never need a resolver: the port is faked, and `tests/conftest.py`
  removes name resolution, stream connections, datagram sends, and the asyncio
  transports for the whole suite. Blocking only the stream calls was not
  enough, because a DNS query needs neither `getaddrinfo` nor `connect`.
- A new forbidden range is a one-line addition plus a test.
- DNSSEC is not validated and this project does not claim otherwise. Adding it
  would be a new decision, not a configuration change.
- Caching is in-memory for now. The TTL caps live in the domain, so a shared
  cache added later inherits them rather than restating them. Keys are
  `DNSCacheKey(host, record_type)` values, so MX, A, and AAAA answers for one
  host cannot overwrite each other and no key can carry an address.

### Negative TTLs are a conservative default, not an authoritative value

Every failure currently receives the fixed 60 second default. The SOA MINIMUM
that RFC 2308 defines as the negative caching TTL is **not** extracted, and
NXDOMAIN and NODATA are not cached separately. The 3 hour cap from
`docs/requirements.md` section 13 is implemented, but the authoritative source
it caps is not yet read.

This is safe in the direction that matters: 60 seconds is far shorter than the
cap, so nothing is retained longer than policy allows. It is recorded here
because the requirement says "authoritative negative TTL", and today's behavior
does not meet that word. Extracting `ChainingResult.minimum_ttl` is the obvious
follow-up.
