# Project status

EmailAddressChecker provides conservative email deliverability estimates. It does not verify mailbox existence or guarantee delivery.

## Available functionality

| Component | Status | Scope |
| --- | --- | --- |
| Syntax and DNS/MX checks | Available | Local checks do not contact SMTP servers. |
| Local batch checks | Available | CSV/TXT input, ordered JSON/CSV output, bounded concurrency and duplicate handling. |
| Address candidate expansion | Available | Offline wildcard expansion with configurable substitutions and output limits. |
| Risk classification | Partial | Role-address data is included; disposable-domain, free-mail and provider datasets are currently empty. |
| Active SMTP checks | Restricted | Library and service components exist, but require a separately configured, explicitly authorized deployment. |
| Active batch service | Not publicly exposed | The controlled batch subsystem is implemented but is not wired to the public CLI or API. |
| Package release | Pending | Version 0.1.0 is marked unreleased; packaging and publishing workflows are prepared. |

## Limitations

- Local checks cannot establish whether an individual mailbox exists. DNS/MX records describe mail routing, not recipient acceptance.
- SMTPUTF8 local parts and certain valid but unsupported address forms produce an unknown result rather than a false invalid verdict.
- Local batch processing has input, concurrency and quota limits. It has no persistent checkpoint or automatic resume; `--start-row` starts a new run.
- Local quota and rate-limit state is process-scoped. Independent processes or replicas do not share a global enforcement budget.
- Missing classification datasets provide no positive or negative classification evidence.

See the [README](README.md), [Japanese CLI reference](docs/usage-ja.md) and [status model](docs/status-model.md) for usage and result semantics.

## Active deployment

Active probing is disabled by default and must be explicitly authorized for targets the operator owns or has permission to test. Authentication, sender identity, destination controls, rate limits, TLS, monitoring and incident procedures are deployment responsibilities.

Before enabling active checks, complete the [readiness checklist](docs/readiness-checklist.md) and follow the [operations guide](docs/operations.md). `emailcheck --check-deployment` is an advisory configuration report, **not** an approval or a live connectivity test; its exit code is always zero.

Publishing the source or passing CI does not authorize external probing or certify production readiness.

## Release and verification

For the current implementation, consult [CI](https://github.com/marc2825/EmailAddressChecker/actions) and run `make check`. Release status and package-publishing steps are documented in [CHANGELOG.md](CHANGELOG.md) and [docs/releasing.md](docs/releasing.md). Historical release-preparation results are retained in [docs/release-report.md](docs/release-report.md).
