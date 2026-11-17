# ADR 0006: dnspython as the resolver, and an explicit destination policy

- Status: Accepted
- Date: 2026-08-07; dependency minimum raised 2026-11-15

## Context

Routing mail needs MX, A, and AAAA answers, their TTLs, and the difference between an authoritative absence and a temporary failure, which decides between `invalid` and `temporary_unknown`. `socket.getaddrinfo` cannot ask for MX, gives no TTL, and turns every failure into one `OSError`. The project also has to decide which resolved addresses may ever be connected to.

## Decision: dnspython as a production dependency

Depend on `dnspython>=2.9.2,<3` in `dependencies`. Versions before 2.9.2 are affected by [CVE-2026-114605](https://github.com/rthalley/dnspython/security/advisories/GHSA-45c3-73f7-pv4m) (wire-name decompression of untrusted responses) and [CVE-2026-128089](https://github.com/rthalley/dnspython/security/advisories/GHSA-vvf4-9x63-8xvv) (WKS zone-text parsing, not exposed here). Only `src/emailcheck/adapters/dns/dnspython_resolver.py` imports it.

Failures map to a closed enum, and no library message text is kept:

| Raised | `DNSFailure` | Meaning |
|---|---|---|
| `NXDOMAIN` | `nxdomain` | The name authoritatively does not exist |
| `NoAnswer` | `no_records` | The name exists with no record of that type; not temporary |
| `NoNameservers`, all servers REFUSED | `refused` | Unanimous refusal, read from the rcode |
| `NoNameservers`, anything else | `servfail` | No server could answer; temporary |
| `LifetimeTimeout`, `Timeout` | `timeout` | Deadline expired; temporary |
| `YXDOMAIN`, `NoRootSOA`, `FormError`, `SyntaxError` | `malformed` | Unusable answer |
| any other `DNSException` | `malformed` | An answer this project cannot use |
| `AssertionError` | re-raised | An internal assertion or a test's network guard |
| any other `Exception` | `internal_error` | This project failed, not the domain |

- `internal_error` keeps our own defects from being published as the domain's misconfiguration.
- `AssertionError` is never converted, because the test network guard raises one; swallowing it once let real packets out while a test passed. `BaseException` subclasses are never caught.
- REFUSED is read from `response.rcode()`, never from the text rendering. A mixed or unstructured answer is `servfail`, the retryable and conservative reading.
- Every query uses `search=False` and an absolute name, so neither the resolver default nor `/etc/resolv.conf` can turn `example.com` into an internal name.

## Decision: the destination policy lists ranges explicitly

`src/emailcheck/security/destination.py` names every forbidden range instead of using the `ipaddress` convenience properties, which are wrong in the dangerous direction (CPython 3.12):

```python
ipaddress.ip_address("100.64.0.1").is_private  # False  carrier-grade NAT
ipaddress.ip_address("ff02::1").is_global  # True   IPv6 multicast
ipaddress.ip_address("64:ff9b::7f00:1").is_global  # True   NAT64 of 127.0.0.1
```

Ranges are ordered most specific first and each is tested; `tests/unit/security/test_destination_policy.py` also pins the three properties above. An IPv6 address that embeds IPv4 (mapped, NAT64, 6to4) is judged by the address it would reach and then refused for its form anyway. The policy returns a typed decision (normalized address, IP version, deny reason) and is applied both to each candidate and to the peer actually reached.

## Decision: anomalous MX configurations are never hard-invalid

Only the RFC 7505 form, preference `0` with the root as exchange, stops routing. Any other odd record is dropped and recorded as a `RouteAnomaly`:

| Configuration | Result |
|---|---|
| `0 .` alone | `null_mx`, hard invalid |
| `0 .` beside a usable MX | anomaly recorded; the usable MX still routes |
| `10 .`, empty or malformed exchange, negative preference | anomaly; record dropped |
| MX records exist, none usable | `mx_configuration_anomaly`, `unknown` |

An MX host that does not resolve makes only that candidate unusable. Reusing `no_mail_route` for a misconfiguration would create false hard-invalid results.

## Consequences

- Tests never need a resolver: the port is faked, and `tests/conftest.py` blocks name resolution, stream connections, datagram sends, and asyncio transports for the whole suite.
- A new forbidden range is a one-line change plus a test.
- DNSSEC is not validated.
- TTL caps live in the domain, so any shared cache inherits them. Cache keys are `DNSCacheKey(host, record_type)`.
- Negative answers currently get a fixed 60-second TTL; the SOA MINIMUM of RFC 2308 is not read. This is shorter than the 3-hour cap and therefore safe, but it does not yet meet "authoritative negative TTL" in `docs/requirements.md` section 13.
