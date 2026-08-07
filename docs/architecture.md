# Architecture

## 1. Dependency direction

```text
apps/api, apps/cli
        ↓
application use cases
        ↓
domain models and policies
        ↑
ports
        ↑
adapters
```

Domain and application policy must not depend on concrete web frameworks,
databases, DNS libraries, SMTP sockets, or Redis clients.

## 2. Core concepts

### Address

Untrusted text becomes a usable value through one path only:

```text
RawAddressInput
  → parse_address
  → AddressAccepted | AddressRejected
  → NormalizedAddress
```

`RawAddressInput` holds the submitted text and a redacted display form. It has
no SMTP target and no parsed parts, so raw input cannot be handed to an external
I/O port. `parse_address` returns a result rather than raising: user mistakes
are data, and only a programmer error raises. A rejection carries a specific
issue, whether the input broke the supported grammar or is merely unsupported,
and a public reason code, so aggregation never re-parses text.

`NormalizedAddress` is the only address type the DNS and SMTP ports accept. Its
parts validate themselves on construction, so it cannot exist in a state where
its target would carry CR, LF, NUL, or a domain that differs from the one it
displays.

Parsing is pure domain logic, not a port. It performs no I/O and depends on no
clock or randomness, and a replaceable implementation would weaken the guarantee
that one construction path validates every target. A future syntax policy
change, such as SMTPUTF8 support, is added as a domain policy rather than behind
an I/O port. See ADR 0005.

### Mail route

DNS answers become a `MailRoute`, never a verdict. The distinctions it keeps are
the ones later aggregation cannot recover:

| Observation | Outcome | Later status |
|---|---|---|
| Authoritative NXDOMAIN | `domain_not_found` | hard invalid |
| RFC 7505 Null MX alone | `null_mx` | hard invalid |
| No MX and no A/AAAA | `no_mail_route` | hard invalid |
| SERVFAIL, timeout, refused | `temporary_failure` | temporary |
| MX records exist, none usable | `configuration_anomaly` | unknown |
| A malformed answer anywhere | `configuration_anomaly` | unknown |
| Every candidate address refused | `unsafe_destination` | unknown |
| This project failed | `internal_error` | unknown, never about the domain |
| Usable MX host | `mx_route` | a route, not a mailbox |
| No MX, usable A/AAAA | `implicit_mx_route` | a route, not a mailbox |

Only an authoritative absence on both address families reaches `no_mail_route`.
A malformed answer, a refusal, a timeout, or a failure of this project's own
proves nothing about the domain and never becomes a hard-invalid result.

A route carries ordered candidates, each with its own status, so an exchanger
that will not resolve is reported separately from a domain that cannot receive
mail. `connectable_candidates` is empty for every outcome except the two route
outcomes, so a Null MX cannot yield a destination later, and every candidate it
does return carries at least one allowed address for Phase 4 to connect to.
`MailRoute.reason` is derived from the outcome, so a route cannot report the
reason code of a different outcome.

Each resolved address passes the destination policy in `security/` before it
becomes a candidate. That policy is a pure function and runs again in Phase 4
against the address a socket actually connected to.

### Passive classification

Four signals that need no network, kept independent because they are wrong in
different ways:

| Signal | Input | Result |
|---|---|---|
| Role account | local part, compared exactly on a lower-cased tag-stripped form | risk flag |
| Disposable | destination domain, with local overrides | risk flag |
| Free-mail | destination domain only | risk flag |
| Provider family | MX host names, label-bounded suffix match | metadata |

`PassiveClassification` has no status field, so this layer cannot express a
deliverability judgment. Its three reason codes are risk-only, its evidence is
weak and non-temporary, and provider family is metadata that may select a reply
parser later but never a verdict.

Free-mail is membership of the destination domain, never an inference from who
hosts its mail: a company domain behind a large provider is not free-mail.
Provider inference reads only MX-sourced hosts, abstains with `unknown` when two
families match, and never attributes `google.com.evil.example` to anyone.

A classification holds a validated `HostName` and, when a role matched, a
canonical `RoleName` taken from the dataset. Neither can hold a complete
address or a submitted local part, so what reaches evidence is bounded by the
types rather than by the caller's care.

Datasets are versioned files loaded explicitly, never at import and never
downloaded. Each answer carries the dataset version that produced it. The
document schema is closed: an entries array is mandatory even when empty, an
unknown top-level field is refused, and metadata values are bounded and free of
control characters because they become `Evidence.source_version`.

Overrides correct one list. `not_disposable` and `disposable` describe
membership of the disposable list and never a delivery decision — the allow/deny
vocabulary belongs to `security/destination.py` alone. An override file declares
the `target` it corrects, and an unimplemented target is refused. See ADR 0007
and `data/passive/README.md`.

### Evidence

An immutable observation produced by one layer. Evidence records:

- layer;
- kind;
- normalized reason;
- strength;
- permanence;
- safe structured details;
- observed time;
- source version.

### Verdict

A deterministic aggregation of evidence:

- status;
- confidence level;
- primary reason;
- ordered reason codes;
- risk flags;
- check summaries;
- ruleset version.

### Ports

Ports exist for external I/O, storage, and non-determinism: network, database,
cache, rate limiting, time, and randomness.

- `DNSResolver`
- `DomainClassifier`
- `SMTPProber`
- `Cache`
- `Store`
- `Executor`
- `RateLimiter`
- `SenderIdentityProvider`
- `Clock`
- `RandomSource`

## 3. Suggested packages

```text
domain/
  immutable values and enums
application/
  orchestration and aggregation
ports/
  protocols owned by the application
adapters/
  concrete DNS, SMTP, storage, cache, queue, and HTTP boundaries
classification/
  passive datasets and provider metadata
security/
  destination policy, redaction, HMAC, and abuse features
config/
  profile validation
```

## 4. Active workflow

```text
request
  → parse and sanitize
  → passive DNS/classification
  → return hard passive result, or enqueue active job
  → acquire account/address/domain/MX budgets
  → resolve and validate destination
  → select stable sender identity
  → perform one bounded SMTP recipient transaction
  → normalize evidence
  → aggregate verdict
  → store redacted result
  → schedule at most one retry if explicitly temporary
```

## 5. Failure isolation

The API must continue to serve passive checks when:

- Redis is unavailable;
- active worker is disabled;
- port 25 is blocked;
- one provider tarpits;
- sender identity is suspended.

Active worker processes or containers must not have direct access to unrelated
internal services. Egress is limited to DNS and allowed SMTP destinations.

## 6. Idempotency

An active request has an idempotency key and a derived target HMAC. Repeated
requests within the address cache window return the existing result unless an
authorized caller explicitly requests a refresh and has budget.

## 7. Future scale

Scale by adding workers behind a shared fair scheduler. Do not change the
semantic core. Multiple static identities, if ever needed, are fixed shards
with shared destination limits, not a rotation mechanism.
