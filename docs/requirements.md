# Requirements

## 1. Product statement

Given one email address, estimate whether it is currently deliverable without
transmitting message content. Return the observed evidence, normalized reasons,
a conservative status, a confidence level, and independent risk flags.

The system does not prove:

- mailbox existence;
- ownership;
- active use;
- identity;
- final delivery;
- inbox placement.

## 2. Meaning of “no email is sent”

An active check may establish an SMTP session and issue only:

- `EHLO`;
- optional `STARTTLS`, followed by `EHLO`;
- `MAIL FROM`;
- one `RCPT TO` for the requested address;
- `RSET`;
- `QUIT`.

The system must never implement or issue `DATA`, message headers, bodies,
attachments, `VRFY`, or `EXPN`.

The public UI and API documentation must say that a remote mail server may be
contacted even though no message content is transmitted.

## 3. Deliverability status

The public status is exactly one of:

- `likely_deliverable`;
- `invalid`;
- `temporary_unknown`;
- `unknown`.

There is no `valid`, `exists`, `used`, `owner_verified`, or
`guaranteed_deliverable` field.

## 4. Risk flags

Risk is orthogonal to deliverability. Initial flags:

- `disposable`;
- `role_account`;
- `free_mail`;
- `accept_all_suspected`;
- `provider_opaque`;
- `internationalized_local_part`;
- `domain_configuration_anomaly`.

A disposable address may be likely deliverable. A role address may be invalid.
Risk flags must never overwrite status without independent evidence.

## 5. MVP scope

### Included

- safe single-address input;
- conservative ASCII mailbox syntax;
- IDNA domain conversion;
- MX lookup;
- Null MX;
- implicit MX through A/AAAA when no MX is present;
- passive domain classifications;
- active SMTP probing from a fixed managed identity;
- evidence normalization and aggregation;
- synchronous passive API;
- asynchronous active API;
- passive local CLI;
- remote active CLI;
- cache, retries, authentication, rate limits, audit events;
- isolated deterministic SMTP test server.

### Excluded

- anonymous active checks;
- CSV or bulk execution before Phase 10;
- arbitrary active accept-all checks before Phase 9;
- provider login, registration, password reset, OAuth, contact, or account APIs;
- `VRFY` and `EXPN`;
- IP rotation or identity rotation;
- machine-learned probability in the MVP;
- complete SMTPUTF8 support;
- Web UI before Phase 7;
- commercial SLA.

## 6. Address handling

### Accepted in MVP

- exactly one mailbox;
- ASCII dot-atom local part;
- IDNA-convertible DNS domain;
- total and component lengths enforced.

### Unsupported, not automatically invalid

- quoted local part;
- comments;
- domain literals;
- obsolete syntax;
- Unicode local part requiring SMTPUTF8.

Unsupported syntax produces `unknown` with a specific reason.

### Normalization

- trim surrounding user-interface whitespace before parsing;
- reject CR, LF, NUL, and control characters;
- lowercase the ASCII domain;
- do not lowercase or otherwise rewrite the local part;
- do not remove dots;
- do not remove plus tags;
- keep a separate display-safe redacted form.

## 7. DNS behavior

- distinguish NXDOMAIN, NOERROR/no route, SERVFAIL, timeout, and malformed data;
- detect Null MX and stop before SMTP;
- if no MX exists, evaluate A/AAAA as an implicit MX route;
- respect positive and negative TTLs with configured caps;
- retain ordered MX candidates;
- resolve candidate addresses through a security policy before connecting;
- reject private, loopback, link-local, multicast, documentation, reserved, and
  metadata destinations;
- revalidate the actual peer address.

## 8. Passive classification

Initial classifiers:

- disposable domain dataset;
- role local-part dataset;
- free-mail domain dataset;
- provider family inferred from MX patterns.

Provider family is metadata, not proof. A provider adapter may normalize known
reply patterns, but it must not return a verdict solely from provider identity.

Every external dataset requires:

- source;
- license;
- version;
- retrieval date;
- update process;
- regression tests;
- removal process for false positives.

## 9. SMTP probing

### Sender identity

Active checks require:

- a static IP;
- a stable EHLO FQDN;
- PTR aligned with the host;
- forward DNS that resolves the host back to the IP;
- a managed envelope sender;
- SPF authorizing the IP;
- monitored `postmaster` and `abuse` channels;
- a provider and host policy that permits the use.

### Session

- one requested recipient per session in the MVP;
- one bounded attempt per MX candidate;
- no parallel race against every MX;
- all reads, writes, handshakes, and sessions bounded;
- optional STARTTLS only when implemented safely;
- TLS failure is not mailbox invalidity;
- record a redacted transcript model, not arbitrary unbounded text.

### Classification

A basic SMTP code is insufficient by itself.

Examples:

- `250`: recipient accepted at that stage, normally
  `likely_deliverable / medium`;
- `251`: accepted for forwarding, record `rcpt_forwarded`;
- `252`: unverifiable, `unknown`;
- `4xx`: `temporary_unknown`;
- `550 5.1.1` at RCPT: strong recipient-not-found evidence;
- bare `550`: ambiguous unless normalized evidence disambiguates;
- `5.7.x`: policy/security, usually `unknown`;
- `552` with explicit `X.2.2`: temporary mailbox/storage condition;
- connection, sender, reputation, and policy failures are not target-address
  invalidity.

## 10. Catch-all

Active accept-all detection is not part of the MVP.

When Phase 9 is enabled:

- return only `accept_all_suspected`;
- require a separate domain budget;
- prefer verified domains;
- use a non-dictionary random local part;
- cache for at least seven days;
- do not declare catch-all from one ambiguous response;
- do not change IP or sender identity to get a different answer.

## 11. APIs

### Passive

`POST /v1/checks/passive`

- synchronous;
- no SMTP;
- may be available under a low anonymous quota, but authentication is preferred.

### Active

`POST /v1/checks`

- authentication required;
- creates an asynchronous job;
- idempotency supported;
- returns passive evidence immediately when available.

`GET /v1/checks/{id}` returns job state and result.

Public responses must not include:

- raw remote banner;
- unredacted SMTP reply;
- internal peer IP;
- full exception text;
- secrets or sender credentials.

## 12. CLI

Default:

```bash
emailcheck user@example.com
```

Runs passive checks locally.

Remote active mode:

```bash
emailcheck user@example.com --remote https://validator.example
```

Direct active mode exists only for the lab profile with an explicit destination
allowlist. It must not be a convenient unrestricted flag.

## 13. Cache defaults

Defaults are starting policy, not protocol truth:

- positive DNS: DNS TTL capped at 24 hours;
- negative DNS: authoritative negative TTL capped at 3 hours;
- passive datasets: data version;
- SMTP accepted: 6 hours;
- explicit recipient-not-found: 1 hour;
- temporary SMTP failure: 10 minutes;
- policy block: 30 minutes;
- connection timeout: 5 minutes;
- accept-all suspected: 7 days.

Cache keys include relevant ruleset, sender identity, and normalized target HMAC.

## 14. Retry defaults

At most one automatic retry in the MVP.

- explicit temporary SMTP response: approximately 20 minutes plus jitter;
- DNS SERVFAIL: one retry after a few minutes;
- connection timeout: one retry only if service health is otherwise normal;
- no retry for syntax, NXDOMAIN, Null MX, or permanent policy response.

Retry with the same target, sender, and stable identity. Do not rotate identity.

## 15. Profiles

### local-passive

- no active probes;
- memory or SQLite cache;
- no service authentication requirement;
- safe for a developer laptop.

### lab-active

- destination allowlist;
- controlled SMTP server or owned domain;
- active probing feature flag;
- low concurrency;
- no public exposure.

### service-active

- authentication;
- asynchronous queue;
- isolated worker;
- PostgreSQL and Redis;
- global, account, address, domain, MX, and identity budgets;
- static sender identities;
- global kill switch.

### bulk

Deferred until Phase 10. It is an operational permission, not merely a
configuration toggle.

## 16. Retention and privacy

- ordinary logs never contain a full address;
- HMAC for correlation and duplicate detection;
- plaintext retained only for an explicit short-lived job or history feature;
- default plaintext and raw-evidence retention: 24 hours;
- optional account history: 30 days;
- deletion jobs are tested;
- raw replies encrypted and administrator-only when retained;
- analytics aggregate by domain/MX and reason where possible.

## 17. Quality targets

Before broad use:

- hard-invalid classes have very high precision;
- bare-code ambiguity is never collapsed into false certainty;
- temporary failures are not converted to invalid;
- tests cover every protocol branch;
- active checks can be globally disabled immediately;
- unknown rate is measured by provider family and reason;
- external probes are minimal and rate limited.

Probability scores may be added only after a controlled labeled evaluation and
calibration. Until then, `confidence.level` is categorical and
`confidence.score` is null.
