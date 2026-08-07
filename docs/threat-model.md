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
  a session requires a `ConfirmedPeer` and verifies it in `__post_init__`, so
  none of the three checks can be skipped by forgetting it or by passing a
  value mypy never sees (ADR 0008);
- connect with the family the destination belongs to and never rely on
  `AI_V4MAPPED`, so a dual-stack socket does not report an IPv4 peer in a mapped
  form the policy must refuse. The transport normalizes; the policy never
  unwraps a mapped address into a trusted public IPv4;
- allow only port 25, and confirm the peer reached it;
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
- cancellation-safe resource cleanup;
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
- one stable identity per deployment, never rotated to change an answer.

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

## 5. Residual risk

Even a carefully limited service may be treated as a harvesting source by
remote operators. Active probing must remain optional, rate limited, monitored,
and easy to disable.
