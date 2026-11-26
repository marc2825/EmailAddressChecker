# Requirements

## 1. Product statement

Given one email address, estimate whether it is currently deliverable without sending message content. Return the observed evidence, normalized reasons, a conservative status, a confidence level, and independent risk flags.

The system does not prove:

- mailbox existence;
- ownership;
- active use;
- identity;
- final delivery;
- inbox placement.

## 2. Meaning of “no email is sent”

An active check may open an SMTP session and issue only:

- `EHLO`;
- the required `STARTTLS`, followed by `EHLO`, before any sender or recipient command;
- `MAIL FROM`;
- one `RCPT TO` for the requested address;
- `RSET`;
- `QUIT`.

The system must never implement or issue `DATA`, message headers, bodies, attachments, `VRFY`, or `EXPN`.

Public UI and API documentation must say that a remote mail server may be contacted even though no message content is sent.

The `no_message_data_sent` field publishes this promise:

- For a result this build produced, it is an invariant of the SMTP state machine.
- For a result received over `--remote`, it is a claim made by another instance, and this project must not invent it on that instance's behalf. The field is therefore required at the remote boundary and must be a real JSON boolean. A missing field makes the body malformed instead of defaulting to a safe value, and `"false"`, `0`, `1`, and `null` are refused instead of converted.
- A `false` value survives parsing, the job projection, persistence, reload, the API body, and the CLI. The CLI prints the affirmative statement only when the result makes it, and prints an explicit warning when it does not.

## 3. Deliverability status

The public status is exactly one of:

- `likely_deliverable`;
- `invalid`;
- `temporary_unknown`;
- `unknown`.

There is no `valid`, `exists`, `used`, `owner_verified`, or `guaranteed_deliverable` field.

## 4. Risk flags

Risk is independent of deliverability. Initial flags:

- `disposable`;
- `role_account`;
- `free_mail`;
- `accept_all_suspected`;
- `provider_opaque`;
- `internationalized_local_part`;
- `domain_configuration_anomaly`.

A disposable address may be likely deliverable, and a role address may be invalid. A risk flag must never change the status without independent evidence.

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
- an isolated, deterministic SMTP test server.

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

A single-label domain (`user@localhost`) and an unbracketed numeric domain (`user@192.0.2.1`) are syntactically accepted as DNS names. DNS and the destination policy decide their outcome, not the parser: a numeric top-level label has no delegation (NXDOMAIN), and loopback or private answers are refused as destinations. Neither is read as a domain literal or used directly as a connection target. See ADR 0005, judgments 4 and 11.

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
- keep a separate redacted form that is safe to display.

## 7. DNS behavior

- distinguish NXDOMAIN, NOERROR without a route, SERVFAIL, timeout, and malformed data;
- detect Null MX and stop before SMTP, treating only the RFC 7505 form (preference `0`, exchange `.`) as a refusal;
- treat any other unusable MX configuration as a configuration anomaly that resolves to `unknown`, never as proof that the domain refuses mail;
- report an MX host that cannot be resolved separately from a domain that has no mail route;
- if no MX exists, evaluate A/AAAA as an implicit MX route;
- respect positive and negative TTLs, within configured caps;
- keep MX candidates in order;
- check candidate addresses against a security policy before connecting;
- reject private, loopback, link-local, multicast, documentation, reserved, and metadata destinations;
- check the actual peer address again.

## 8. Passive classification

Initial classifiers:

- disposable domain dataset;
- role local-part dataset;
- free-mail domain dataset;
- provider family inferred from MX patterns.

Provider family is metadata, not proof. A provider adapter may normalize known reply patterns, but must not return a verdict from provider identity alone.

Every external dataset requires:

- source;
- license;
- version;
- retrieval date;
- update process;
- regression tests;
- a removal process for false positives.

## 9. SMTP probing

### Sender identity

Active checks require:

- a static IP;
- a stable EHLO FQDN;
- a PTR record matching the host;
- forward DNS that resolves the host back to the IP;
- a managed envelope sender;
- SPF authorizing the IP;
- monitored `postmaster` and `abuse` mailboxes;
- a provider and host policy that permits this use.

### Session

- one requested recipient per session in the MVP;
- one bounded attempt per MX candidate;
- no parallel race against every MX;
- a bound on every read, write, handshake, and session;
- required STARTTLS with certificate and exchanger hostname verification;
- a TLS failure is not mailbox invalidity;
- record a redacted transcript model, not arbitrary unbounded text.

### Classification

A basic SMTP code is not enough on its own. Examples:

- `250`: recipient accepted at that stage, normally `likely_deliverable / medium`;
- `251`: accepted for forwarding; record `rcpt_forwarded`;
- `252`: cannot be verified; `unknown`;
- `4xx`: `temporary_unknown`;
- `550 5.1.1` at `RCPT`: strong evidence that the recipient does not exist;
- bare `550`: ambiguous unless normalized evidence settles it;
- `5.7.x`: policy or security, usually `unknown`;
- `552` with an explicit `X.2.2`: temporary mailbox or storage condition;
- connection, sender, reputation, and policy failures do not make the target address invalid.

## 10. Catch-all

Active accept-all detection is not part of the MVP. When Phase 9 is enabled:

- return only `accept_all_suspected`;
- require a separate domain budget;
- prefer verified domains;
- use a random local part that is not a dictionary word;
- cache for at least seven days;
- never declare catch-all from one ambiguous response;
- never change IP or sender identity to get a different answer.

## 11. APIs

### Passive

`POST /v1/checks/passive`

- synchronous;
- no SMTP;
- may be offered under a low anonymous quota, but authentication is preferred.

### Active

`POST /v1/checks`

- authentication required;
- creates an asynchronous job;
- supports idempotency;
- returns passive evidence immediately when available.

`GET /v1/checks/{id}` returns the job state and result.

Public responses must not include:

- the raw remote banner;
- an unredacted SMTP reply;
- the internal peer IP;
- full exception text;
- secrets or sender credentials.

## 12. CLI

By default the CLI runs passive checks locally:

```bash
emailcheck user@example.com
```

Remote active mode:

```bash
emailcheck user@example.com --remote https://validator.example
```

Remote validators require HTTPS. For local development HTTP is allowed only for the exact IP literals `127.0.0.1` and `::1`; `localhost`, DNS-derived exceptions, and other spellings of an IP are refused. Redirects are not followed, and proxy environment variables do not route these credential-bearing requests. See ADR 0021.

Local Active Mode (ADR 0022):

```bash
emailcheck check user@example.com --mode active --config emailcheck.toml
```

It checks exactly one address, from the user's own machine, through the `local-active` profile. It needs an `[smtp]` section with the sender identity and `acknowledged = true`; until then the CLI prints what a probe reveals and stops before any network use. It is not an unrestricted flag: `batch` and `expand` cannot reach it, and every SMTP rule in sections 2, 7, 9, and 14 applies unchanged. Its quotas and pacing are per process and can be bypassed by whoever runs it, which the documentation states.

## 13. Cache defaults

These defaults are a starting policy, not protocol facts:

- positive DNS: the DNS TTL, capped at 24 hours;
- negative DNS: the authoritative negative TTL, capped at 3 hours;
- passive datasets: the data version;
- SMTP accepted: 6 hours;
- explicit recipient-not-found: 1 hour;
- temporary SMTP failure: 10 minutes;
- policy block: 30 minutes;
- connection timeout: 5 minutes;
- accept-all suspected: 7 days.

Cache keys include the relevant ruleset, sender identity, and the HMAC of the normalized target.

## 14. Retry defaults

The MVP allows at most one automatic retry, and only for a first attempt that provably did not reach the recipient stage.

This precondition comes first. One high-level active verification may contact a recipient at most once in total (section 9 and `docs/threat-model.md`), and an automatic retry is a second whole verification. Once `RCPT TO` may have been issued, the operation is settled, whatever the reply was. A case below that also reached the recipient stage is not retried.

- explicit temporary SMTP response observed before the recipient stage: about 20 minutes plus jitter;
- DNS SERVFAIL: one retry after a few minutes;
- connection timeout: one retry, only if the service is otherwise healthy;
- no retry for syntax, NXDOMAIN, Null MX, or a permanent policy response;
- no retry once the recipient stage was reached, including a `450`, `451`, `452`, or `552 5.2.2`, a `RCPT TO` whose reply never arrived, and a write of that command that failed partway.

In this build the first rule schedules nothing in practice: its reason codes, `smtp_temporary_failure` and `mailbox_full`, come only from the reply to `RCPT TO`. The delay stays documented for a response observed earlier in a dialogue, and because reading the rule any other way once put a second `RCPT TO` on the wire for one submitted address.

A process restart is not a retry and does not resume interrupted work; see section 15 and `docs/architecture.md`. A retry uses the same target, sender, and stable identity. Never rotate identity.

## 15. Profiles

### local-passive

- no active probes;
- memory or SQLite cache;
- no service authentication requirement;
- safe for a developer laptop.

### local-active

- one explicitly requested address from `check --mode active`;
- a sender identity and acknowledgement in the user's configuration file;
- the destination policy, required TLS, pacing, and in-process quotas;
- no jobs, stores, worker, retention daemon, or service component;
- for addresses the user owns or may check (ADR 0022).

### lab-active

- an enforced destination allowlist (see below);
- a controlled SMTP server or an owned domain;
- an active-probing feature flag;
- low concurrency;
- no public exposure.

`Deployment.lab_destination_allowlist` names the exchanger host names this deployment may contact, canonicalized to the same `HostName` identity that routes and operator blocks use. A probing lab deployment with an empty allowlist does not start, and an empty allowlist permits nothing. The allowlist only restricts: an allowlisted host must still pass the destination policy, the operator's blocks, the peer check, and TLS verification, and every MX candidate is checked, not only the preferred one.

### service-active

- authentication;
- asynchronous queue;
- isolated worker;
- PostgreSQL and Redis;
- global, account, address, domain, MX, and identity budgets;
- static sender identities;
- global kill switch.

### bulk

Deferred until Phase 10. Bulk is an operational permission, not just a configuration switch.

## 16. Retention and privacy

- ordinary logs never contain a full address;
- HMAC for correlation and duplicate detection;
- plaintext kept only for an explicit, short-lived job or history feature;
- default retention of plaintext and raw evidence: 24 hours;
- optional account history: 30 days;
- deletion jobs are tested;
- raw replies, when kept, are encrypted and visible only to administrators;
- analytics aggregate by domain or MX and by reason where possible.

## 17. Quality targets

Before broad use:

- hard-invalid classes have very high precision;
- ambiguity from a bare code is never turned into false certainty;
- temporary failures are not converted to invalid;
- tests cover every protocol branch;
- active checks can be disabled globally and immediately;
- the unknown rate is measured by provider family and reason;
- external probes are minimal and rate limited.

Probability scores may be added only after a controlled, labeled evaluation and calibration. Until then `confidence.level` is categorical and `confidence.score` is null.
