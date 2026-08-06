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
- validate immediately before connect;
- validate actual peer address;
- isolate worker egress and credentials;
- cap reads and time.

### Tarpit and resource exhaustion

Controls:

- global and per-destination concurrency;
- connect, banner, command, TLS, and total session timeouts;
- line, reply, and transcript limits;
- cancellation-safe resource cleanup;
- bounded retries;
- fair queueing.

### SMTP command injection

Controls:

- structured address object;
- reject CR/LF/NUL/control characters before any network use;
- command encoder accepts typed values, not arbitrary lines;
- local part is never interpolated without validation.

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
