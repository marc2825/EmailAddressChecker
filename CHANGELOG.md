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

- Conservative email checks from syntax and DNS/MX evidence, and an opt-in single-address SMTP check.
- Passive CSV/TXT batch processing: JSON/CSV results in input order, duplicate handling, progress reporting, bounded work, and atomic file output.
- Offline wildcard expansion with configurable candidate sets and generation limits.
- Validated TOML budget configuration, and reports of versions and datasets.
- The `email-address-checker` package distribution; the CLI and import name stay `emailcheck`.
- `emailcheck explain [CODE]` describes every status, confidence level, reason code, risk flag, and row state; `emailcheck versions` and `emailcheck deployment` are the subcommand forms of `--report-versions` and `--check-deployment`.

### Changed

- On a terminal, `check` and `batch` print a readable view: for one address, what each step (syntax, DNS, mailbox) found, with risk flags shown apart; for several, one line per row and a summary. Pipes and files still get JSON or CSV, and `--output-format text|json|csv` chooses explicitly.
- CLI messages are in Japanese or English, following `LC_ALL`, `LC_MESSAGES`, and `LANG`. Colour is used only on a terminal and never with `NO_COLOR` or `TERM=dumb`. These are the only environment variables read ([ADR 0009](docs/adr/0009-smtp-dialogue-and-tls.md)).
- The screen shows addresses in the redacted log form (`a***@example.com`); `--include-address` shows them in full, with terminal control characters escaped.
- Errors say what went wrong and how to fix it, instead of one generic refusal, and a mistyped command is no longer checked as an address.
- `--progress` counts against the total, and a saved batch ends with a summary on stderr when stderr is a terminal or `--progress` is given.
- CSV output writes booleans as `true` and `false`, like the JSON output.

### Fixed

- A domain containing a character that UTS-46 would delete (such as U+200B or U+00AD) is invalid instead of being checked as a different domain ([ADR 0005](docs/adr/0005-idna-uts46-domain-encoding.md), judgment 12; issue #3).
- Operator log lines show the event, reason, domain, and detail, and one abuse refusal is logged once (issue #3).
- Ctrl-C works while batch input is being read, and batch input must be a regular file (issue #3).
- `expand` writes nothing when any candidate fails (issue #3).
- Both CSV readers skip blank lines, reject an empty address cell as empty input, and refuse a file containing NUL (issue #3).
- The service batch CSV parser accepts a leading UTF-8 byte order mark, as the local CLI already did. Spreadsheet "CSV UTF-8" exports were refused for lacking an `email` column (issue #2).
- The DNS cache locks each key separately instead of using 64 shared stripes, so a slow lookup no longer delays unrelated domains. Identical concurrent lookups are still combined into one (issue #2).

- The service batch CSV parser follows the local CLI's reading rules: a repeated column name or broken CSV syntax refuses the file, a row with the wrong number of fields is rejected, and only ASCII whitespace around an address is trimmed, as the address parser does.

### Local Active Mode (ADR 0022)

- `emailcheck check ADDRESS --mode active --config FILE` checks one address over SMTP from the user's own machine, with no server, account, or API key. It sends EHLO, STARTTLS, MAIL FROM, one RCPT TO, and RSET or QUIT, and never a message.
- It needs an `[smtp]` section (`ehlo_hostname`, `envelope_sender`, `acknowledged`); `emailcheck config example` prints one. Until `acknowledged = true`, it prints what a probe reveals and requires, and contacts nothing.
- The evidence ladder separates "SMTP not run", "tried without an answer", and the server's answer, and gives a hint for a blocked port 25, a TLS failure, or a policy refusal. Rows report `smtp_executed` (whether the SMTP step ran), and refused rows add `refusal` (`deadline`, `limit`, or `capacity`).
- `batch` stays passive only. The `local-active` profile reuses the existing SMTP pipeline and adds no job, store, or service component.
- `docs/evaluation.md` compares the two modes on scripted servers, and `docs/comparison.md` compares other tools and lists the limits of SMTP checks.

### Release preparation (issue #7)

- The PyPI page is `docs/pypi.md`, with absolute links pinned to the version tag; the repository README files keep their relative links.
- A tag push publishes to TestPyPI only. PyPI needs a manual run on the tag with the tag typed again, then the `pypi` Environment approval.
- CI fails below 93% test coverage and runs the install and smoke tests on macOS as well.
- The README files state the scope: a CLI that checks syntax and DNS/MX without SMTP, the supported Python surface (syntax parsing and the vocabulary), the CLI compatibility policy, and privacy and acceptable-use notes.

### Documentation and tests

- Single-label (`user@localhost`) and unbracketed numeric (`user@192.0.2.1`) domains are documented as DNS names, judged by DNS and the destination policy and never read as address literals ([ADR 0005](docs/adr/0005-idna-uts46-domain-encoding.md), judgment 11).
- The [architecture](docs/architecture.md#component-reachability) lists which service components are library-only and the order for connecting them.
- Specification tests and structural tests are separated by the `inspection` and `docs_contract` markers (`make test-spec`, `make test-structure`), and CI runs them as separate steps.
- Planned work is listed in [ROADMAP.md](ROADMAP.md).
- The documentation is rewritten for readability, without changing documented behavior. Current behavior is described in the main documents; ADRs are kept only for the most important decisions, and [docs/adr/README.md](docs/adr/README.md) maps each retired ADR to where its rules now live.

### Notes

- Neither a mail route nor an SMTP acceptance proves that a mailbox exists.
- The disposable-domain, free-mail, and provider datasets are empty; the role-account list is included.
- Active batch processing is internal and not exposed through the CLI or an API. Local Active Mode checks one address per command; a service deployment still needs the readiness checklist.
- Packaging and publishing workflows are ready, but 0.1.0 has not been published to PyPI.
