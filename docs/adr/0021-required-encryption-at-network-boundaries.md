# ADR 0021: Require encryption at credential and recipient boundaries

- Status: Accepted
- Date: 2026-11-15
- Supersedes: ADR 0009's availability of opportunistic plaintext probing

## Context

The remote client rejected redirects but allowed bearer credentials and submitted
addresses over external HTTP. Its default urllib opener inherited environment
proxies. Production SMTP composition selected required TLS, but the internal
dialogue also accepted `TLSPolicy.OPPORTUNISTIC`, contradicting the security policy
and allowing STARTTLS stripping to expose the recipient.

## Decision

Remote validator URLs require HTTPS, except HTTP to exactly `127.0.0.1` and `::1`
IP literals. No hostname, DNS answer, abbreviated IPv4 spelling, IPv6 scope or
mapped address grants this exception. The exception supports local development
without a new switch. Local users/processes remain trusted with the local key.

Validate at CLI preparation and client construction, before any HTTP request.
Refuse userinfo, control characters (including encoded controls), malformed
authorities/ports and ambiguous authority delimiters. Job identifiers are bounded
path segments. Error categories and object representations omit credentials and
submitted addresses. Non-ASCII hostname input must use its ASCII IDNA spelling.
Bearer keys must be printable ASCII; malformed key files receive a redacted CLI
input error before client construction.

Disable environment proxies explicitly. Every redirect, including same-origin
and scheme upgrades, remains refused. Operators needing a gateway use an
explicit HTTPS validator endpoint. HTTPS certificate and hostname verification
remain standard-library defaults; there is no verification-off setting.

`TLSPolicy.REQUIRED` is the only SMTP policy. Keep the enum and settings field
for callers already selecting required TLS. Remove `OPPORTUNISTIC` and its
plaintext continuation. A missing STARTTLS, invalid certificate, name mismatch,
handshake failure or timeout stops before sender/recipient commands; these remain
non-target failures, never evidence that the mailbox is invalid. No command,
state transition or recipient-touch budget is broadened. Scripted tests simulate
successful TLS and real TLS tests stay restricted to loopback.

## Compatibility and consequences

External HTTP users must change `--remote` to HTTPS. Local users must replace
`localhost` with an exact loopback literal, or use HTTPS. Proxy environment
variables no longer route validator credentials. Callers selecting opportunistic
SMTP must use `TLSPolicy.REQUIRED`; there is no insecure replacement. These
intentional restrictions prioritize credential and address confidentiality.

No runtime dependency is added. Dependency security minimums are recorded in
ADR 0006. TLS authenticates a server name; it does not prove mailbox existence,
authorization to probe, final delivery or production readiness.
