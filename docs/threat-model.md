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

Threat: an authenticated or anonymous user discovers likely live addresses.

Controls:

- **one verification issues at most one `RCPT TO`, in total.** Gate 4A bounds one
  session; `application/smtp_verification.py` bounds the whole request. Reaching
  the recipient stage ends the verification — not receiving an answer, *reaching
  the stage* — so a `450`, a `550`, a `252`, a reset after the command went out,
  and a write that failed part way all stop it. Asking a second exchanger about
  one recipient, from one identity, within seconds, is the pattern a receiving
  site fingerprints as harvesting, and the temptation is real: a `450` reads like
  "ask again". Two independent barriers decide it — the transcript and the stage
  — and each is pinned by its own test (ADR 0011);
- **MX fallback is only for failures before the recipient stage**, so the next
  exchanger asks the question for the first time rather than asking it again;
- **one high-level operation issues at most one `RCPT TO`, in total.** The bound
  above is per *verification*; this one covers everything a caller's single
  request causes, including `docs/requirements.md` section 14's automatic retry
  and anything a restart might re-run. The gap between the two was real: a `450`
  at `RCPT TO` is an "explicit temporary SMTP response", section 14 retried
  those, and the retry was a whole second verification — so one submitted
  address reached one mail server twice, twenty minutes apart, which is the
  slower and more deliberate version of the pattern this section is about. An
  automatic retry now requires a first attempt that provably did not reach the
  recipient stage, carried as a protocol fact rather than inferred from a status:
  `temporary_unknown` arises from a DNS SERVFAIL that opened no socket *and*
  from a `451` at `RCPT TO`, and a rule that could not tell those apart is the
  rule that broke. The count is asserted on the wire, across retries;
- **an interrupted operation is not replayed.** A process that stops between
  writing `RCPT TO` and reading the reply leaves a durable checkpoint written
  *before* the dialogue began, saying the recipient may have been contacted; a
  later process ends such a job as an operational failure rather than re-running
  it. A duplicate `RCPT TO` arranged by restarting is the same duplicate;
- no anonymous active checks;
- per-account, IP, address, domain, and MX budgets;
- new-account quotas;
- sequence and dictionary-pattern detection;
- domain ownership verification for elevated use;
- suspension and audit;
- no provider account APIs;
- no VRFY/EXPN;
- no bulk before abuse controls.

### Sender reputation damage

Threat: repeated RCPT-only sessions resemble harvesting.

Controls:

- stable transparent sender identity;
- low concurrency;
- destination pacing;
- short retries;
- no rotation to bypass limits;
- abuse mailbox;
- remote failure metrics;
- global and identity kill switches;
- limited beta.

### SSRF and network pivoting

Threat: malicious DNS directs the worker to internal services.

Controls:

- allow only the configured SMTP port;
- reject private, loopback, link-local, multicast, reserved, documentation,
  benchmark, carrier-grade NAT, and metadata ranges, plus any IPv6 address that
  carries a forbidden IPv4 address inside it;
- list the ranges explicitly rather than relying on `ipaddress.is_private` or
  `is_global`, which would allow carrier-grade NAT, IPv6 multicast, and a NAT64
  address reaching loopback (ADR 0006);
- validate all A/AAAA answers and CNAME hops;
- approve only an address the DNS candidate actually resolved to, through
  `approve_destination`. The policy answers whether an address is safe to reach,
  not whether the domain published it, and both questions must be asked;
- validate immediately before connect, as `ApprovedDestination`;
- validate the actual peer address *and port*, as `ConfirmedPeer`, and refuse a
  peer that is permitted but is not the endpoint that was approved;
- make each of those a type rather than a step, and check the type at run time:
  a session requires a `ConfirmedPeer` and verifies it in `__post_init__`, and
  `SMTPTransport.connect` verifies that what it was given is an
  `ApprovedDestination` before it evaluates anything or creates a socket. An
  object that merely *has* an address, a port, and a version has passed neither
  `approve_destination` nor the policy, and duck typing would otherwise walk it
  straight past both (ADR 0008);
- connect with the family the destination belongs to and never rely on
  `AI_V4MAPPED`, so a dual-stack socket does not report an IPv4 peer in a mapped
  form the policy must refuse. The transport normalizes; the policy never
  unwraps a mapped address into a trusted public IPv4, and a mapped or 6to4 peer
  is refused as an unexpected family;
- re-apply the policy in the transport immediately before creating the socket,
  and create no socket when it refuses;
- resolve no name in the transport: the address is already numeric and
  validated, so a connect that resolved anything would be reaching somewhere the
  policy never saw;
- allow only port 25, and confirm the peer reached it;
- publish no way to write arbitrary bytes at all. `SMTPConnection.write_command`
  takes a `WireCommand` — one of six enum members plus bytes checked to begin
  with that verb — so no caller can name a seventh command. The *argument* forms
  are constrained by the six factories rather than by the type, and an
  inspection test fixes that production builds a `WireCommand` only through
  them: three layers, and the reachable set of wire lines is the image of the
  six only while all three hold (ADR 0009);
- bind the TLS host name to the destination chain. `TLSUpgradeRequest` takes a
  `ConfirmedPeer` rather than a host name, so SNI and hostname verification use
  the MX host the policy already validated, never the recipient's domain and
  never a caller-supplied string;
- re-read `getpeername()` before and after a STARTTLS upgrade, resolving nothing,
  so a connection cannot become a different peer's by being wrapped;
- acquire a rate-limit budget before a socket is created. `SMTPProbeService`
  takes a `RateLimiter` with no default, so a caller that has not supplied one
  cannot construct it. `acquire` is given an account, the recipient's domain, and
  the MX host — never the local part — and `rate_limit_key` refuses an `@` in any
  component rather than trusting the caller, so no component can be a mailbox.
  **The budget Phase 4 enforces partitions on the domain alone**: the account and
  the MX host are validated and carried but divide nothing yet. Per-account
  isolation waits for an authenticated principal in Phase 6, because a
  caller-supplied account string used as a partition is bypassed by sending a
  different string — and refusing an `@` is a shape check, not a provenance
  guarantee;
- **bound how many endpoints one request may reach.** A `MailRoute`'s length is
  whatever a DNS answer says, so `plan_attempts` caps the plan and de-duplicates
  it on `(MX host, address, port)` before anything connects. Without the cap, one
  request is as many outbound connections as an attacker's zone cares to publish;
- **keep Phase 2's candidate ordering and never randomize it.** MX preference is
  the publisher's instruction; a randomized scan would make a verification
  unreproducible, and picking a different endpoint to get a different answer is
  the rotation this project forbids outright;
- isolate worker egress and credentials;
- cap reads and time.

### Tarpit and resource exhaustion

Controls:

- global and per-destination concurrency;
- connect, banner, command, TLS, and total session timeouts;
- line, reply, and transcript limits;
- **bound the work, not only the input.** A reply within the line and count
  limits is still 80 KB, and reducing it to a 120-character diagnostic used a
  quadratic pattern over all of it: 153 ms of CPU per reply. Read caps do not
  imply bounded processing, so the sanitizer examines a fixed prefix and its
  pattern is linear (ADR 0008);
- cancellation-safe resource cleanup. The connection is an async context
  manager and its close is idempotent and never raises, so it is safe in a
  `finally`; every path in `application/smtp_connect.py` that does not return a
  session closes first;
- **a close that cannot be interrupted part way.** `close` performs no `await`,
  so it offers no point at which a cancellation can be delivered, and the
  release runs from a `finally` regardless. An earlier version wrapped a no-op
  `await` in `asyncio.timeout` to look bounded; all it did was create the one
  cancellation point in the function, and a cancellation there left `is_closed`
  true with the descriptor still open — a leak that no retry would ever fix,
  because the object reported itself already closed;
- **process control is never a transport failure.** `CancelledError`,
  `KeyboardInterrupt`, `SystemExit`, `GeneratorExit`, and `AssertionError`
  propagate rather than becoming a `ConnectionFailed`. A worker told to stop
  must not be handed a result about the network instead, and this project's own
  invariant failures — including the test suite's network guard — must fail
  loudly rather than be attributed to a remote host. The socket is closed before
  the exception continues, so re-raising leaks nothing;
- per-operation deadlines that are validated values, not free integers: a
  timeout must be positive, finite, not a boolean, and within a maximum, because
  a bound nobody would reach is not a bound;
- bounded reads: a per-line cap, a per-connection total, and a per-read
  deadline, so a peer that never sends a terminator cannot make a read run
  forever. Both forms of an over-long line — arriving complete and arriving in
  pieces — end in a typed bounded-read failure that abandons the connection;
  which of the two bounds is named depends on which is reached first, and both
  are equally terminal. Once the total is spent no further socket read is
  attempted at all, so a spent connection fails immediately rather than costing
  one read deadline per call;
- **a total session deadline on top of the per-operation ones, and it
  dominates.** A per-read deadline bounds one read; a dialogue of eight steps
  bounds nothing useful, because a peer answering each stage just inside its
  deadline holds a worker for four minutes without ever timing out. Every awaited
  step of the dialogue runs inside the remaining `SessionBudget`, measured
  against a monotonic clock so a wall-clock adjustment cannot move it (ADR 0009);
- **the connect is inside that budget too.** It starts before the socket does, so
  one probe costs `SessionBudget` rather than `connect_seconds + SessionBudget`,
  and the effective connect bound is the smaller of the transport's own timeout
  and what is left. A budget already spent opens no socket at all. Waiting for a
  rate-limit lease is outside the budget on purpose, so queue depth is never
  recorded as a remote timeout;
- **each awaited step is pinned individually.** A peer that goes silent at one
  named stage must still end the session, for all sixteen of them, and an
  inspection requires every `connection` call in the dialogue to sit inside the
  deadline wrapper. The property held before and nothing tested it: removing the
  wrapper from the read step, the write step, or the handshake each left the
  whole suite passing, because whichever step ran next tripped the budget
  instead;
- bounded capability parsing: an EHLO keyword is bounded in length, the count is
  capped, and nothing branches on one;
- **a bounded wait for a budget, and it is not the session deadline.** The
  rate-limit wait sits outside the SMTP budget on purpose, so queue depth is
  never recorded as a remote timeout — which leaves the wait itself needing a
  bound. One deadline covers all three acquisitions, so three budgets cannot cost
  three waits, and pacing refuses *before* suspending when the delay could not
  fit anyway rather than holding a concurrency slot to wait out a budget it
  cannot meet. Exceeding it raises `RateLimitTimeout`, which is not a
  `TimeoutError` and not an `OSError`, so a handler written for a remote timeout
  cannot catch this project's own scheduling;
- **a concurrency slot that is always given back.** A refusal, an exception, and
  a cancellation all unwind whatever was already acquired. A slot held by a
  cancelled caller removes capacity from the process permanently, and nothing
  ever counts it again — the same shape as the descriptor leak the 4B review
  found in `close`. `except BaseException` is deliberate: `CancelledError` does
  not derive from `Exception`, and a mutation to the narrower clause passed the
  whole suite until a test cancelled a caller that was actually *holding*
  something;
- **bounded limiter state.** Per-domain buckets are evicted on an idle TTL and a
  least-recently-used cap, and an entry in use is never evicted. Without it, a
  caller supplying a new domain every time is a memory leak with a remote
  trigger and nothing in the process would notice;
- bounded retries;
- fair queueing.

### SMTP command injection

Controls:

- structured address object;
- reject CR/LF/NUL/control characters before any network use;
- command encoder accepts typed values, not arbitrary lines. There are six
  encoder functions, one per allowed command, and none takes a command name, so
  no caller can name a command the enum does not have;
- the CRLF is appended in one place, which re-checks the assembled line;
- local part is never interpolated without validation;
- `scripts/check_forbidden_smtp.py` refuses fourteen commands in every
  production SMTP path, reading the first SMTP verb of each string literal so
  that `AUTH PLAIN ...` and `BDAT 42` are caught while `authentication` and
  `send_timeout` are not, and refuses a wire line whose verb comes from a
  run-time value in any of the four ordinary forms — f-string, percent
  formatting, `str.format`, or leading concatenation (ADR 0008);
- the scanner defends against accident and drift, **not** against a committer
  deliberately obfuscating a command. Structure carries that load: the closed
  enum, the six encoders with no name parameter, the state machine, and a
  transport port with no arbitrary-bytes method.

### Sender identity misuse

Threat: the envelope sender is derived from the address being probed, or from
request input, so a probe presents a forged or attacker-chosen return path.

Controls:

- `SenderIdentityProvider` supplies the identity from operator-controlled
  configuration only, and `current_identity()` takes no argument so it cannot
  depend on the target;
- `EnvelopeSender` and `EhloIdentity` fix the shape; the port owns provenance;
- the implementation reads a mapping the caller loaded deliberately. No
  environment variable, no ambient default, no unknown key accepted, and no
  default identity — an unconfigured deployment does not probe, because inventing
  a plausible EHLO name would put an unowned host name on the wire;
- the configured sender may not be the null reverse path. `docs/requirements.md`
  section 9 wants SPF, a PTR, and monitored `postmaster` and `abuse` channels,
  and `MAIL FROM:<>` followed by one `RCPT TO` is the shape a receiving site
  fingerprints as harvesting (ADR 0009);
- the EHLO name and the sender's domain must be the same name or one a subdomain
  of the other. An alignment check, not an ownership proof: it catches the
  configuration mistake that turns a probe into apparent forgery;
- a test asserts the wire bytes, not only the type. A mutation that built
  `MAIL FROM` from the probe target passed every behavioural test until one
  looked at what the command actually carried;
- one stable identity per deployment, never rotated to change an answer.

### Plaintext exposure of the recipient

Threat: the address being checked travels in `RCPT TO`, in the clear, to a host
chosen by a DNS answer.

Controls:

- `TLSPolicy.REQUIRED` by default. A server advertising no `STARTTLS` ends the
  probe as a non-target `TLS_ERROR` rather than continuing in plaintext;
- certificate and host name verification always on, with no parameter that can
  change either. The one seam adds a trust anchor and cannot remove one;
- **a trust anchor comes from operator configuration only.** `TLSTrust` cannot
  turn verification off, but it can widen it, and request, user, or API input
  must never supply a CA file, a PEM body, a trust anchor, or a verification
  override — choosing who signs the certificate this project trusts is
  `CERT_NONE` by a longer route. No such path exists today; an inspection test
  refuses a `TLSTrust` constructed anywhere in `src/` outside the module holding
  the system-trust default, and refuses any production module that reads the
  environment. `plans/phase-04-smtp.md` carries it as a Phase 6 stop condition;
- **a `TLSUpgradeRequest` authorizes one connection, not any connection.** The
  peer it carries is compared against the endpoint the connection actually
  reached, before a handshake byte moves, so a request built from another
  connection's `ConfirmedPeer` cannot supply that host's name as SNI. Two
  barriers — this comparison and the `getpeername()` re-read — and each has its
  own test, because the review found that removing this one broke nothing;
- no plaintext fallback after a failed handshake, under either policy, and no
  transition back to plaintext in the state machine;
- the upgrade is refused when anything is already buffered, because those bytes
  are plaintext an attacker could have injected before it (CVE-2011-0411);
- **a server without TLS is never an invalid mailbox.** `TLS_ERROR` is in
  `NON_TARGET_OUTCOMES`, so the conservative default cannot become a wrong
  answer about an address.

### Message content submission

Threat: a change adds a path capable of transmitting a message, defeating the
central product promise.

Controls:

- no message-content command, state, method, or enum member exists;
- the scanner refuses `DATA`, `BDAT`, `SEND`, `SOML`, `SAML`, and `BURL`, and
  its own regression tests fail if it stops;
- the state machine has no transaction-body state to reach;
- `RecipientObservation.no_message_data_sent` is derived and always true, and is
  published so that a test can check the promise;
- at most one `RCPT TO` per session, refused by two independent barriers.

### False verdicts

Controls:

- separate evidence from verdict;
- classify bare ambiguous codes conservatively;
- ruleset versioning;
- controlled fixtures;
- provider metadata cannot determine a verdict alone;
- confidence is categorical until calibrated.

### Privacy leakage

Controls:

- redaction;
- HMAC correlation;
- encrypted short-lived raw evidence;
- minimal retention;
- role-based administrative access;
- deletion tests;
- no full addresses in metrics.

### Dataset compromise or licensing failure

Controls:

- pinned data artifacts;
- checksums;
- source/license/version metadata;
- review updates as code;
- regression tests;
- no runtime arbitrary downloads.

## 4. Abuse response

Required controls before service-active:

- suspend API key;
- suspend account;
- block destination domain/MX;
- disable active probing globally;
- disable sender identity;
- preserve an incident audit trail;
- delete unnecessary submitted data;
- investigate remote complaints.

## 5. Phase 7 control checklist

`prompts/07-hardening.md`'s acceptance criterion: each implemented control
mapped to its code and its tests. Read with section 3, which says *why* each
exists; this says where it is and what fails when it stops working.

### Layered budgets

| Layer | Code | Test |
|---|---|---|
| API key | `application/abuse.py`, `BudgetLayer.API_KEY` | `test_abuse_budgets.py` |
| Account | `application/abuse.py`, `BudgetLayer.ACCOUNT` | `test_abuse_budgets.py` |
| Source IP | `application/abuse.py` + `domain/source.py` | `test_abuse_budgets.py`, `test_source_identity.py` |
| Target address HMAC | `application/abuse.py`, `BudgetLayer.TARGET` | `test_abuse_budgets.py` |
| Target domain | `application/abuse.py` **and** Phase 4 pacing | `test_abuse_budgets.py` |
| Target MX | `application/abuse.py`, preferred exchanger | `test_abuse_budgets.py` |
| Sender identity | `application/abuse.py` | `test_abuse_budgets.py` |
| Global concurrency | `application/admission.py`, since Phase 6 | `test_admission_and_deadline.py` |
| Daily total | `application/abuse.py`, a day-long window | `test_abuse_budgets.py` |

Spending is all-or-nothing, so a refusal by one layer spends none of the others.
Every verification charges the caller's layers and every verification that will
probe also charges the destination layers, so neither a cache hit nor section
14's retry is free. ADR 0016.

### Queue fairness

One principal may hold at most `queue_share` of the waiting slots, so a caller
that can issue requests faster than they are served cannot make every other
account's request answer `AdmissionRefused` while holding no capacity at all.
Phase 6's review carried this as F11. `application/admission.py`;
`tests/unit/application/test_queue_fairness.py`.

### Administrative controls

| Control | Code | Test |
|---|---|---|
| Disable active globally | `AdminControl.set_active_probing` | `test_admin_controls.py` |
| Suspend key / account | `suspend_key`, `suspend_account` | `test_admin_controls.py` |
| Block domain / MX | `block_domain`, `block_exchanger` | `test_admin_controls.py` |
| Disable sender identity | `disable_sender` | `test_admin_controls.py` |
| Inspect safe audit events | `audit_events` | `test_admin_controls.py` |
| Trigger deletion | `application/retention.py` | `test_retention.py` |

The kill switch stops the enqueue **and** the worker: a switch that stopped only
new work would leave the queue connecting to remote hosts after an operator said
stop. Suspension is immediate because the state is read on every decision and is
replaced whole rather than mutated.

### Privacy

| Control | Code | Test |
|---|---|---|
| Versioned HMAC correlation | `security/identifiers.py` | `test_identifiers.py` |
| Ordinary log redaction | `security/redaction.py` | `test_redaction.py` |
| No address in logs, events, metrics, audit | every surface | `test_privacy_corpus.py` |
| Scheduled deletion | `application/retention.py` | `test_retention.py` |
| Deletion failure alerting | `MetricName.DELETION_FAILURE` | `test_retention.py` |
| Admin access audit | `application/admin.py` | `test_admin_controls.py` |

Raw SMTP diagnostics are **not retained at all**, so `docs/privacy.md` section
3's encrypted-diagnostic retention has nothing to encrypt. That is the
privacy-preserving half holding by absence; ADR 0016 records it as a Phase 8
stop condition rather than as a gap.

### Observability

Metric labels are closed enumerations, so a target, a local part, a job
identifier, an API key, an idempotency key, and a source address are all
unrepresentable rather than merely absent. `ports/metrics.py`;
`tests/unit/test_metrics_cardinality.py`.

### Abuse indicators

Five, all pure, all reporting-only: numeric sequences, dictionary-style
attempts when configured, concentrated same-domain enumeration, multiple keys
from one source, and exploration after a positive result. `domain/indicators.py`;
`tests/unit/domain/test_indicators.py`. They hold shapes rather than addresses,
and an admin summary shows a count and a name.

### Failure behaviour

| Failure | Behaviour | Test |
|---|---|---|
| Quota store unavailable | active refused, passive still served | `test_abuse_budgets.py` |
| Quota table full of live counters | refused, never evicts a live budget | `test_quota_store.py` |

**The budget layers, named.** Enumeration is bounded by several independent
counters rather than one, so exhausting a single dimension does not open the
rest. The layers are the **API key**, the **account**, the **source IP**, the
**target domain**, and a **daily total**. The accept-all experiment carries a
*separate* domain budget of its own, which is why an ordinary verification's
target-domain budget can never be spent on a control probe.
| Operator sink raises | never changes a verdict | `test_failure_injection.py` |
| Metrics sink raises | never changes a verdict | `test_failure_injection.py` |
| Retention run fails | counted and audited, never propagated | `test_retention.py` |

### Provider neutrality

No abuse threshold, budget, indicator, or administrative default is keyed to a
provider's identity. An inspection test refuses a provider name in every Phase 7
module, because a behavioural test cannot enumerate the providers nobody thought
of — the same control section 3 applies to reply parsing.

## 6. Residual risk

Even a carefully limited service may be treated as a harvesting source by
remote operators. Active probing must remain optional, rate limited, monitored,
and easy to disable.
