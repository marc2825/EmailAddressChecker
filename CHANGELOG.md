# Changelog

This file records user-visible changes. Design reasons are in the [architecture decisions](docs/adr/), and past release checks are in the [release report](docs/release-report.md).

## [0.1.0] — Unreleased

First release candidate, for Python 3.12+.

### Security

- Remote validators require HTTPS; HTTP is allowed only for the exact loopback IP literals. Proxy environment variables are ignored, and every redirect is still refused.
- Opportunistic plaintext SMTP is removed; `TLSPolicy.REQUIRED` applies everywhere.
- dnspython 2.9.2 or later is required for its upstream security fixes.
- The documented safety conditions for an HTTP binding, lost in an earlier documentation cleanup, are restored, and citations of private development files are replaced with public documents.

Configurations that use HTTP, rely on proxies, or set the opportunistic library policy need the migration in [ADR 0021](docs/adr/0021-required-encryption-at-network-boundaries.md).

### Added

- Conservative email checks from syntax and DNS/MX evidence, with a separate, explicitly authorized active SMTP capability.
- Passive CSV/TXT batch processing: JSON/CSV results in input order, duplicate handling, progress reporting, bounded work, and atomic file output.
- Offline wildcard expansion with configurable candidate sets and generation limits.
- Validated TOML budget configuration, and reports of versions and datasets.
- The `email-address-checker` package distribution; the CLI and import name stay `emailcheck`.

### Fixed

- The service batch CSV parser accepts a leading UTF-8 byte order mark, as the local CLI already did. Spreadsheet "CSV UTF-8" exports were refused for lacking an `email` column (issue #2).
- The DNS cache locks each key separately instead of using 64 shared stripes, so a slow lookup no longer delays unrelated domains. Identical concurrent lookups are still combined into one (issue #2).

- The service batch CSV parser follows the local CLI's reading rules: a repeated column name or broken CSV syntax refuses the file, a row with the wrong number of fields is rejected, and only ASCII whitespace around an address is trimmed, as the address parser does.

### Documentation and tests

- Single-label (`user@localhost`) and unbracketed numeric (`user@192.0.2.1`) domains are documented as DNS names, judged by DNS and the destination policy and never read as address literals ([ADR 0005](docs/adr/0005-idna-uts46-domain-encoding.md), judgment 11).
- The [architecture](docs/architecture.md#component-reachability) lists which service components are library-only and the order for connecting them.
- Specification tests and structural tests are separated by the `inspection` and `docs_contract` markers (`make test-spec`, `make test-structure`), and CI runs them as separate steps.
- Planned work is listed in [ROADMAP.md](ROADMAP.md).
- The documentation is rewritten for readability, without changing documented behavior. Current behavior is described in the main documents; ADRs are kept only for the most important decisions, and [docs/adr/README.md](docs/adr/README.md) maps each retired ADR to where its rules now live.

### Notes

- Neither a mail route nor an SMTP acceptance proves that a mailbox exists.
- The disposable-domain, free-mail, and provider datasets are empty; the role-account list is included.
- Active batch processing is internal and not exposed through the CLI or an API. Active SMTP requires a separately authorized deployment.
- Packaging and publishing workflows are ready, but 0.1.0 has not been published to PyPI.
