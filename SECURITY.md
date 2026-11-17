# Security policy

## Reporting a vulnerability

Report security issues privately. If GitHub private vulnerability reporting is enabled for this repository, use it (Security → Report a vulnerability). Otherwise, open an issue that names only the class of problem and asks for a private channel; do not put exploit details in a public issue.

Please let us coordinate before you publish exploitable details. There is no bug bounty, guaranteed response time, or CVE assignment at present; this does not reflect how seriously reports are taken.

## In scope

When an operator enables it, this project talks to third-party mail exchangers. Security issues include, among others:

- any path that could send message content or issue `DATA`, `AUTH`, `VRFY`, or `EXPN`;
- any path that touches more than one recipient in one verification, or replays at the recipient stage;
- destination-safety bypasses: reaching private or reserved addresses, defeating selected-IP or connected-peer validation, or using fallback to evade an operator block or destination allowlist;
- weaker TLS requirements for active SMTP;
- privacy failures: a complete email address in ordinary logs, evidence kept past its retention, or account deletion that leaves recoverable data;
- bypassing authentication, quotas, or rate limits in a service profile.

## Responsible use

Active SMTP probing touches infrastructure you do not own. If you enable it:

- You are responsible for authorization. Probe only addresses and domains you own or have explicit permission to test.
- Comply with your hosting provider's acceptable-use policy, the receiving sites' terms, and the law and policy that apply to you.
- Do not bypass the destination controls, rate limits, or safety checks. They keep the traffic distinguishable from address harvesting.
- Do not use this project to enumerate addresses, harass anyone, or build address lists without consent.

Active probing is not authorized by default, and publishing this source does not authorize it. An operator must first complete the per-deployment checks in [docs/readiness-checklist.md](docs/readiness-checklist.md); the operator controls are in [docs/operations.md](docs/operations.md).

## Safety boundary

The project never issues `DATA`, `AUTH`, `VRFY`, or `EXPN`, stops at the `RCPT` evidence boundary, touches at most one recipient per ordinary verification, never replays at the recipient stage, requires TLS for active SMTP, and rejects unsafe destinations. See [docs/threat-model.md](docs/threat-model.md) and [docs/architecture.md](docs/architecture.md).

Remote CLI connections require HTTPS. The only HTTP exception is a URL whose host is exactly `127.0.0.1` or `[::1]`, for local development; a name that resolves to loopback does not qualify. Every redirect is refused and proxy environment variables are ignored, so a deployment must give an explicit HTTPS validator URL.

TLS is required for SMTP in library dialogues too. A missing STARTTLS or a certificate, hostname, or handshake failure stops the dialogue before `MAIL FROM` and `RCPT TO`, and is not evidence that an address is invalid. The former opportunistic setting has been removed; use `TLSPolicy.REQUIRED`. See [ADR 0021](docs/adr/0021-required-encryption-at-network-boundaries.md).
