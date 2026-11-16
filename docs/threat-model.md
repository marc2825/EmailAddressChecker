# Threat model

## 1. Assets

- remote sender IP reputation;
- managed sender domain reputation;
- API credentials;
- submitted email addresses;
- SMTP transcripts and evidence;
- destination infrastructure;
- service availability;
- classification integrity.

## 2. Trust boundaries

- public client to API;
- API to queue;
- worker to DNS;
- worker to remote SMTP;
- service to datasets;
- service to persistence;
- administrator access.

## 3. Threats and controls

### Address enumeration

Threat: an authenticated or anonymous user discovers addresses that are probably live.

Controls:

- One high-level operation issues at most one `RCPT TO` in total, including the automatic retry of `docs/requirements.md` section 14 and anything a restart might re-run. Reaching the recipient stage ends the verification, whether or not an answer arrives: a `450`, `550`, or `252`, a reset after the command went out, and a partial write all stop it. Asking a second exchanger, or asking again later, about one recipient from one identity is the pattern receiving sites fingerprint as harvesting. Two independent barriers, the transcript and the stage, each pinned by its own test, enforce the per-verification bound, and the count is asserted on the wire across retries (ADR 0019).
- MX fallback is allowed only for failures before the recipient stage, so the next exchanger is asked for the first time, not again.
- An automatic retry requires proof that the first attempt never reached the recipient stage, carried as a protocol fact (`RecipientTouch`), not inferred from the status. `temporary_unknown` covers both a SERVFAIL that opened no socket and a `451` at `RCPT TO`, so the status cannot decide.
- Interrupted work is not replayed. A durable checkpoint written before the dialogue records that the recipient may be contacted, and a later process ends such a job as an operational failure instead of running it again.
- No anonymous active checks.
- Layered budgets per API key, account, source IP, target address HMAC, target domain, target MX, sender identity, and daily total, plus global concurrency (section 5).
- New-account quotas, sequence and dictionary-pattern detection, and domain ownership verification for elevated use.
- Suspension and audit.
- No provider account APIs, no `VRFY` or `EXPN`, and no bulk before abuse controls exist.

### Sender reputation damage

Threat: repeated `RCPT`-only sessions look like harvesting.

Controls: a stable, transparent sender identity; low concurrency; destination pacing; short retries; no rotation to get around limits; an abuse mailbox; metrics on remote failures; global and per-identity kill switches; a limited beta.

### SSRF and network pivoting

Threat: malicious DNS sends the worker to internal services.

Controls:

- Connect only to port 25, and confirm the peer was reached on it.
- Reject private, loopback, link-local, multicast, reserved, documentation, benchmark, carrier-grade NAT, and metadata ranges, and any IPv6 address that embeds a forbidden IPv4 address. The ranges are listed explicitly; `ipaddress.is_private` and `is_global` would allow carrier-grade NAT, IPv6 multicast, and a NAT64 address that reaches loopback (ADR 0006).
- Validate every A/AAAA answer and CNAME hop, and approve only an address the DNS candidate actually resolved to (`approve_destination`). The policy decides whether an address is safe; the route decides whether the domain published it; both are required.
- Make each check a type that is verified at run time: `ApprovedDestination` before connecting and `ConfirmedPeer` for the peer address and port actually reached. A session requires a `ConfirmedPeer`, and `SMTPTransport.connect` checks that it received an `ApprovedDestination` before it creates a socket, so an object that merely has an address and port cannot slip past (ADR 0008).
- Re-apply the policy in the transport just before creating the socket, and resolve no name there. Connect with the destination's own address family and never rely on `AI_V4MAPPED`; a mapped or 6to4 peer is refused as an unexpected family.
- Allow no way to write arbitrary bytes. `SMTPConnection.write_command` takes a `WireCommand` built only by the six command factories, so no caller can name a seventh command (ADR 0009).
- Bind TLS to the validated destination: `TLSUpgradeRequest` takes a `ConfirmedPeer`, so SNI and hostname verification use the approved MX host, never the recipient's domain or a caller's string. `getpeername()` is read again before and after STARTTLS.
- Acquire a rate-limit budget before a socket exists. `SMTPProbeService` has no default `RateLimiter`. `acquire` gets an account, the recipient's domain, and the MX host, never the local part, and `rate_limit_key` refuses an `@` in any component. The pacing budgets partition separately on domain and MX, across accounts; account-specific volume comes from the authenticated principal in the abuse guard, and a caller-supplied account string grants no extra capacity.
- Cap the number of endpoints one request may reach: `plan_attempts` limits and de-duplicates the plan on `(MX host, address, port)` before anything connects. MX preference order is kept and never randomized.
- Isolate worker egress and credentials, and cap reads and time.

### Tarpit and resource exhaustion

Controls:

- Global and per-destination concurrency, and bounded, fair queueing.
- Validated deadlines (positive, finite, not boolean, below a maximum) for connect, banner, each command, TLS, and the whole session.
- A total session deadline that dominates the per-operation ones, on a monotonic clock. The connect is inside it, every awaited dialogue step runs inside it and is pinned individually, and a spent budget opens no socket. The rate-limit wait is outside it, so queue depth is never recorded as a remote timeout, and has its own single deadline across all acquisitions; exceeding it raises `RateLimitTimeout`, which is neither a `TimeoutError` nor an `OSError`.
- Bounded reads: a per-line cap, a per-connection total, and a per-read deadline. An over-long line ends in a typed bounded-read failure that abandons the connection, and a spent total makes no further reads.
- Bounded work, not only bounded input: the reply sanitizer examines a fixed prefix with a linear pattern (ADR 0008).
- Bounded capability parsing: EHLO keywords have a length cap and a count cap, and nothing branches on them.
- Cleanup that cannot leak. The connection is an async context manager whose close is idempotent, never raises, and contains no `await`, so cancellation cannot interrupt it. Every path that does not return a session closes first.
- Process control is never a transport failure: `CancelledError`, `KeyboardInterrupt`, `SystemExit`, `GeneratorExit`, and `AssertionError` propagate after the socket is closed.
- Concurrency slots are always returned on refusal, exception, or cancellation (`except BaseException` is deliberate).
- Bounded limiter state: idle per-domain buckets are evicted by TTL and an LRU cap, never while in use.
- Bounded retries.

### SMTP command injection

Controls:

- A structured address object; CR, LF, NUL, and control characters are rejected before any network use, and the local part is never interpolated without validation.
- Six encoder functions, one per allowed command, none of which takes a command name. The CRLF is appended in one place, which checks the whole line again.
- `scripts/check_forbidden_smtp.py` refuses fourteen commands in every production SMTP path. It reads the first SMTP verb of each string literal, so `AUTH PLAIN ...` and `BDAT 42` are caught while `authentication` and `send_timeout` are not, and it refuses a wire line whose verb is computed at run time by f-string, `%`, `str.format`, or concatenation (ADR 0008).
- The scanner guards against accidents and drift, not against a committer who deliberately hides a command. The structure carries that: the closed enum, the encoders without a name parameter, the state machine, and a transport port with no arbitrary-bytes method.

### Sender identity misuse

Threat: the envelope sender comes from the address being probed or from request input, so a probe presents a forged or attacker-chosen return path.

Controls:

- `SenderIdentityProvider` supplies the identity from operator configuration only; `current_identity()` takes no argument, so it cannot depend on the target. `EnvelopeSender` and `EhloIdentity` fix the shape.
- The configuration is a mapping the caller loads deliberately: no environment variable, no default, no unknown key. An unconfigured deployment does not probe.
- The sender may not be the null reverse path; `MAIL FROM:<>` followed by one `RCPT TO` is a harvesting fingerprint (ADR 0009).
- The EHLO name and the sender's domain must be equal or one a subdomain of the other. This catches a configuration mistake; it does not prove ownership.
- A test checks the wire bytes, not only the types.
- One stable identity per deployment, never rotated to change an answer.

### Plaintext exposure of the recipient

Threat: the checked address travels in `RCPT TO` to a host chosen by a DNS answer.

Controls:

- `TLSPolicy.REQUIRED` is the only policy. A server that advertises no `STARTTLS` ends the probe as a non-target `TLS_ERROR`.
- Certificate and hostname verification are always on and cannot be switched off. The one seam can add a trust anchor, never remove one.
- A trust anchor comes from operator configuration only. `TLSTrust` can widen what is trusted, so request, user, or API input must never supply a CA file, PEM body, trust anchor, or verification override. An inspection test refuses a `TLSTrust` built anywhere in `src/` except next to the system-trust default, and refuses production modules that read the environment.
- A `TLSUpgradeRequest` is valid for one connection: its peer is compared with the endpoint actually reached before any handshake byte is sent. This check and the `getpeername()` re-read each have their own test.
- No plaintext fallback after a failed handshake, and no state-machine transition back to plaintext.
- The upgrade is refused if any bytes are already buffered, because they could be injected plaintext (CVE-2011-0411).
- A server without TLS is never an invalid mailbox: `TLS_ERROR` is in `NON_TARGET_OUTCOMES`.

### Message content submission

Threat: a change adds a way to send a message, breaking the central promise.

Controls: no message-content command, state, method, or enum member exists; the scanner refuses `DATA`, `BDAT`, `SEND`, `SOML`, `SAML`, and `BURL` and has its own regression tests; the state machine has no message-body state; `RecipientObservation.no_message_data_sent` is derived, always true, and published so tests can check it; two independent barriers allow at most one `RCPT TO` per session.

### False verdicts

Controls: evidence kept separate from the verdict; conservative handling of bare ambiguous codes; ruleset versioning; controlled fixtures; provider metadata never decides a verdict alone; categorical confidence until calibration.

### Privacy leakage

Controls: redaction; HMAC correlation; minimal retention, with raw replies not retained at all; role-based administrative access; deletion tests; no full addresses in metrics.

### Dataset compromise or licensing failure

Controls: pinned data artifacts; checksums; source, licence, and version metadata; dataset updates reviewed like code; regression tests; no downloads at run time.

## 4. Abuse response

Required controls before service-active:

- suspend an API key;
- suspend an account;
- block a destination domain or MX;
- disable active probing globally;
- disable a sender identity;
- keep an incident audit trail;
- delete submitted data that is no longer needed;
- investigate remote complaints.

## 5. Control checklist

Each control, where it lives, and the test that fails when it stops working. Section 3 explains why each exists.

### Layered budgets

Three controls answer different questions and are never merged or re-keyed onto each other: admission (`application/admission.py`) limits how many verifications run at once, destination pacing (`adapters/system/rate_limit.py`) limits how fast one destination is approached, and the abuse guard (`application/abuse.py`) limits how many verifications one caller may request in a window. Keying destination pacing by account would give each account its own pacing for a destination, which protects nobody.

| Layer | Code | Test |
|---|---|---|
| API key | `application/abuse.py`, `BudgetLayer.API_KEY` | `test_abuse_budgets.py` |
| Account | `application/abuse.py`, `BudgetLayer.ACCOUNT` | `test_abuse_budgets.py` |
| Source IP | `application/abuse.py` + `domain/source.py` | `test_abuse_budgets.py`, `test_source_identity.py` |
| Target address HMAC | `application/abuse.py`, `BudgetLayer.TARGET` | `test_abuse_budgets.py` |
| Target domain | `application/abuse.py` and destination pacing | `test_abuse_budgets.py` |
| Target MX | `application/abuse.py`, preferred exchanger | `test_abuse_budgets.py` |
| Sender identity | `application/abuse.py` | `test_abuse_budgets.py` |
| Global concurrency | `application/admission.py` | `test_admission_and_deadline.py` |
| Daily total | `application/abuse.py`, a day-long window | `test_abuse_budgets.py` |

The accept-all experiment has a separate domain budget, so an ordinary verification's target-domain budget is never spent on a control probe.

- Windows are fixed, not sliding: one integer per key instead of a per-caller event list. A caller can spend at most two windows' allowance across one boundary.
- A live counter is never evicted, because eviction resets a budget. When the table is full of live counters, the request is refused.
- Spending is all-or-nothing. `consume` checks every limit, then reserves every table slot the commit needs, and only then increments, so a refused request spends nothing.
- Every verification charges the caller's layers, including cache hits and the automatic retry. A verification that will probe also charges the destination layers; a passive check does not.
- No proxy header is trusted. `domain/source.py` reads nothing from headers; a `SourceIdentity` exists only when a transport builds it from the connection's peer address, and the source layer is skipped when it does not exist. Proxy trust is a stop condition on the HTTP binding (`docs/architecture.md`).

### Queue fairness

One principal may hold at most `queue_share` of the waiting slots, so a fast caller cannot make every other account's request answer `AdmissionRefused`. `application/admission.py`; `tests/unit/application/test_queue_fairness.py`.

### Administrative controls

| Control | Code | Test |
|---|---|---|
| Disable active globally | `AdminControl.set_active_probing` | `test_admin_controls.py` |
| Suspend key / account | `suspend_key`, `suspend_account` | `test_admin_controls.py` |
| Block domain / MX | `block_domain`, `block_exchanger` | `test_admin_controls.py` |
| Disable sender identity | `disable_sender` | `test_admin_controls.py` |
| Inspect safe audit events | `audit_events` | `test_admin_controls.py` |
| Trigger deletion | `application/retention.py` | `test_retention.py` |

The kill switch stops both new enqueues and the worker. Suspension takes effect immediately, because the state is read on every decision and replaced whole.

### Privacy

| Control | Code | Test |
|---|---|---|
| Versioned HMAC correlation | `security/identifiers.py` | `test_identifiers.py` |
| Ordinary log redaction | `security/redaction.py` | `test_redaction.py` |
| No address in logs, events, metrics, audit | every surface | `test_privacy_corpus.py` |
| Scheduled deletion | `application/retention.py` | `test_retention.py` |
| Deletion failure alerting | `MetricName.DELETION_FAILURE` | `test_retention.py` |
| Admin access audit | `application/admin.py` | `test_admin_controls.py` |

Raw SMTP diagnostics are not retained at all, so there is nothing to encrypt (`docs/privacy.md` section 3).

### Observability

Metric labels are closed enumerations, so a target, local part, job identifier, API key, idempotency key, or source address cannot be represented as a label. `ports/metrics.py`; `tests/unit/test_metrics_cardinality.py`.

### Abuse indicators

Five pure, report-only indicators: numeric sequences, dictionary-style attempts when configured, concentrated enumeration of one domain, multiple keys from one source, and exploration after a positive result. They store shapes, not addresses, and an admin summary shows a count and a name. `domain/indicators.py`; `tests/unit/domain/test_indicators.py`.

### Failure behaviour

| Failure | Behaviour | Test |
|---|---|---|
| Quota store unavailable | active refused, passive still served | `test_abuse_budgets.py` |
| Quota table full of live counters | refused; a live budget is never evicted | `test_quota_store.py` |
| Operator sink raises | never changes a verdict | `test_failure_injection.py` |
| Metrics sink raises | never changes a verdict | `test_failure_injection.py` |
| Retention run fails | counted and audited, never propagated | `test_retention.py` |

### Provider neutrality

No abuse threshold, budget, indicator, or administrative default depends on a provider's identity. An inspection test refuses provider names in these modules, because a behavioral test cannot list the providers nobody thought of.

## 6. Residual risk

Even a carefully limited service may be treated as a harvesting source by remote operators. Active probing must stay optional, rate limited, monitored, and easy to disable.
