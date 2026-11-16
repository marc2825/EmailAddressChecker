# Changelog

This file records user-visible changes. Implementation details and design rationale belong in the [architecture decisions](docs/adr/); historical release checks are recorded in the [release report](docs/release-report.md).

## [0.1.0] — Unreleased

Initial release candidate for Python 3.12+.

### Security

- Require HTTPS for remote validators; HTTP is restricted to exact loopback IP
  literals. Disable environment proxies and continue refusing every redirect.
- Remove opportunistic plaintext SMTP; use `TLSPolicy.REQUIRED` everywhere.
- Require dnspython 2.9.2+ for its upstream security fixes.
- Restore documented HTTP-binding safety conditions removed during documentation
  cleanup, and replace private-development citations with public contracts.

Existing HTTP, proxy-dependent and opportunistic-library configurations need
the migration described in [ADR 0021](docs/adr/0021-required-encryption-at-network-boundaries.md).

### Added

- Conservative email checks using syntax and DNS/MX evidence, with a separate, explicitly authorized active SMTP capability.
- Passive CSV/TXT batch processing with ordered JSON/CSV results, duplicate handling, progress reporting, bounded work, and atomic file output.
- Offline wildcard expansion with configurable candidate sets and generation limits.
- Validated TOML budget configuration and version/dataset reporting.
- Python package distribution (`email-address-checker`) while retaining the `emailcheck` CLI and import name.

### Fixed

- The service batch CSV parser accepts a leading UTF-8 byte order mark, as the
  local CLI already did; spreadsheet "CSV UTF-8" exports were refused for
  lacking an `email` column (issue #2).
- The DNS cache locks per key instead of on 64 shared stripes, so a slow
  lookup no longer delays unrelated domains; identical concurrent lookups are
  still coalesced (issue #2).

### Documentation and tests

- State that single-label (`user@localhost`) and unbracketed numeric
  (`user@192.0.2.1`) domains are accepted as DNS names and judged by DNS and
  the destination policy, never reinterpreted as address literals
  ([ADR 0005](docs/adr/0005-idna-uts46-domain-encoding.md) judgment 11).
- List which service components are library-only and the prerequisite order
  for connecting them ([architecture](docs/architecture.md#component-reachability)).
- Separate specification tests from structural tests with the `inspection` and
  `docs_contract` markers (`make test-spec`, `make test-structure`); CI runs
  them as separate steps.

### Notes

- A mail route or SMTP acceptance does not prove that a mailbox exists.
- Disposable-domain, free-mail, and provider datasets are currently empty; the role-account list is included.
- Active batch processing remains internal and is not exposed through the public CLI/API. Active SMTP requires a separately authorized deployment.
- Packaging and publishing workflows are prepared; **version 0.1.0 has not been published to PyPI**.
