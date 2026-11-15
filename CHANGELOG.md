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

### Notes

- A mail route or SMTP acceptance does not prove that a mailbox exists.
- Disposable-domain, free-mail, and provider datasets are currently empty; the role-account list is included.
- Active batch processing remains internal and is not exposed through the public CLI/API. Active SMTP requires a separately authorized deployment.
- Packaging and publishing workflows are prepared; **version 0.1.0 has not been published to PyPI**.
