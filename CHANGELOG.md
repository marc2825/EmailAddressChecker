# Changelog

## 0.1.0 — unreleased

- Add offline, bounded local-part wildcard generation with configurable tokens.
- Add ordered passive CSV/TXT and multiple-address checks, JSON/CSV results,
  explicit deduplication, progress, cancellation and atomic local output.
- Add strict TOML budget settings and effective configuration reporting.
- Reuse bounded TTL DNS caching with task-local hit reporting; separate optional
  passive budgets from Active budgets and enforce shared MX pacing/backoff.
- Prepare Hatchling wheel/sdist metadata, install smoke tests and approval-gated
  OIDC release workflows. Import and CLI remain `emailcheck`.
- Preserve Active authorization, one-recipient-touch, TLS, destination, privacy
  and job recovery invariants. No package upload or Active operation authorized.
- Validate Python 3.12–3.14; correct the test CA's strict X.509 extensions and
  explicitly enable SQLite batch secure deletion across builds. Upgrade development
  pytest to a version fixing its known temporary-directory vulnerability.
