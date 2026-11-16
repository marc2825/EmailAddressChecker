# Project status

EmailAddressChecker estimates email deliverability conservatively. It does not verify that a mailbox exists and does not guarantee delivery.

## Functionality

| Component | Status | Scope |
| --- | --- | --- |
| Syntax and DNS/MX checks | Available | Local checks do not contact SMTP servers. |
| Local batch checks | Available | CSV/TXT input, JSON/CSV output in input order, bounded concurrency, duplicate handling. |
| Candidate expansion | Available | Offline wildcard expansion with configurable substitutions and output limits. |
| Risk classification | Partial | Role-address data is included; the disposable-domain, free-mail, and provider datasets are empty. |
| Active SMTP checks | Restricted | Requires a separately configured, explicitly authorized deployment. |
| Service components | Library only | API-key auth, the HTTP request handler, job/verdict/account stores, the executor, retention, active batch, the accept-all experiment, and the beta harness are tested but not reachable from the CLI. No HTTP server ships. See [component reachability](docs/architecture.md#component-reachability). |
| Package release | Pending | 0.1.0 is unreleased; packaging and publishing workflows are ready. |

## Roadmap for service components

Nothing in 0.1.0 exposes a public service. Each step below is a separate, reviewed change, in this order:

1. An HTTP binding for the existing request handler, passive endpoint first, with a dependency ADR and the documented binding stop conditions.
2. Active jobs behind it, only for a deployment that has completed the readiness checklist.
3. Active batch upload for operator-approved accounts.

The accept-all experiment and the beta harness stay operator tooling. Configuration alone never makes any of these reachable from the CLI. Details are in the [architecture](docs/architecture.md#component-reachability).

## Limitations

- Local checks cannot show whether a mailbox exists. DNS/MX records describe mail routing, not whether a recipient is accepted.
- SMTPUTF8 local parts and some valid but unsupported address forms give `unknown`, never a false `invalid`.
- Local batch processing has input, concurrency, and quota limits. It has no checkpoint or automatic resume; `--start-row` starts a new run.
- Local quota and rate-limit state belongs to one process. Separate processes or replicas do not share a budget.
- Empty classification datasets give no evidence either way.

Usage and result meanings are in the [README](README.md), the [Japanese CLI reference](docs/usage-ja.md), and the [status model](docs/status-model.md).

## Active deployment

Active probing is off by default. It must be explicitly authorized, and only for targets the operator owns or has permission to test. The deployment is responsible for authentication, sender identity, destination controls, rate limits, TLS, monitoring, and incident procedures.

Before enabling it, complete the [readiness checklist](docs/readiness-checklist.md) and follow the [operations guide](docs/operations.md). `emailcheck --check-deployment` only reports on configuration. It is not an approval or a connectivity test, and it always exits with 0.

Neither publishing the source nor passing CI authorizes external probing or certifies a deployment as production-ready.

## Release and verification

Check [CI](https://github.com/marc2825/EmailAddressChecker/actions) for the current state and run `make check` locally. Release status and publishing steps are in [CHANGELOG.md](CHANGELOG.md) and [docs/releasing.md](docs/releasing.md); past release-preparation results are in [docs/release-report.md](docs/release-report.md).
