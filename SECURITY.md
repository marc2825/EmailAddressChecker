# Security policy

## Scope

This project performs active network interaction with mail exchangers in later
Phases. Security issues include, but are not limited to:

- any code path capable of transmitting SMTP `DATA`;
- SSRF or connection to private/reserved networks;
- bypass of authentication, quotas, or destination rate limits;
- complete email addresses written to ordinary logs;
- unbounded reads, connections, retries, or concurrency;
- provider account enumeration;
- identity or IP rotation intended to avoid remote controls.

## Reporting

Do not open a public issue containing exploitable details. Use a private
maintainer channel before public release. Until a contact address is selected,
keep the repository private.

## Supported versions

Before public release, document supported versions and a security contact.

## Emergency response

The service-active deployment must have:

- a global active-probe kill switch;
- per-account and per-API-key suspension;
- per-domain and per-MX blocking;
- immediate sender-identity disablement;
- short retention of raw SMTP evidence;
- an incident log and owner.
