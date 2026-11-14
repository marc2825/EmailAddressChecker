# Security policy

## Reporting a vulnerability

Please report security issues privately.

**Preferred:** when enabled for this repository, use GitHub's private
vulnerability reporting feature (repository → Security → Report a vulnerability).
If it is not available, open an issue that describes the *class* of problem and
asks for a private channel — do not include exploit details in a public issue.

Please give us a chance to coordinate before publishing exploitable details.

We do not currently offer a bug bounty, a guaranteed response time, or CVE
assignment. That is a statement of what exists, not of how seriously reports are
taken.

## In scope

This project performs active network interaction with third-party mail
exchangers when an operator explicitly enables it. Security issues include, but
are not limited to:

- any path that could send message content, or issue `DATA`, `AUTH`, `VRFY`,
  or `EXPN`;
- any path that touches more than one recipient in a single verification
  operation, or replays at the recipient stage;
- destination-safety bypasses: reaching private or reserved addresses,
  defeating selected-IP or actual-peer validation, or evading an operator block
  or destination allowlist through fallback;
- weakening TLS requirements for active SMTP;
- privacy failures: a complete email address in ordinary logs, evidence
  outliving its retention, or account deletion leaving recoverable data;
- authentication, quota, or rate-limit bypass in a service profile.

## Responsible use

Active SMTP probing touches infrastructure you do not own. If you enable it:

- **You are responsible for authorization.** Probe only addresses and domains
  you own or have explicit permission to test.
- Comply with your hosting provider's acceptable-use policy, the receiving
  sites' terms, and applicable law and policy in your jurisdiction.
- Do not bypass this project's destination controls, rate limits, or safety
  checks — they exist to keep the traffic distinguishable from harvesting.
- Do not use this project for address enumeration, harassment, or building
  lists of addresses without consent.

Active probing is **not** authorized by default, and publishing this source does
not authorize it. See [docs/readiness-checklist.md](docs/readiness-checklist.md)
for the per-deployment gates an operator must complete first, and
[docs/operations.md](docs/operations.md) for the operator controls.

## Safety boundary

The project never issues `DATA`, `AUTH`, `VRFY`, or `EXPN`; stops at the
`RCPT` evidence boundary; touches at most one recipient per ordinary
verification operation; never replays at the recipient stage; requires TLS for
active SMTP; and rejects unsafe destinations. See
[docs/threat-model.md](docs/threat-model.md) and
[docs/architecture.md](docs/architecture.md).

Remote CLI connections require HTTPS. The only HTTP exception is a URL using
exactly `127.0.0.1` or `[::1]` for local development. Hostname resolution does not
grant an exception. All redirects are refused and environment proxies are
disabled, so deployments must supply an explicit HTTPS validator URL.

Required SMTP TLS also applies to internal library dialogues. Missing STARTTLS
or certificate/hostname/handshake failures stop before `MAIL FROM` and `RCPT TO`;
they are not evidence of an invalid address. The former opportunistic setting
has been removed; migrate to `TLSPolicy.REQUIRED`. See
[ADR 0021](docs/adr/0021-required-encryption-at-network-boundaries.md).
