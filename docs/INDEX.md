# Documentation

Start with the [README](../README.md) or [日本語README](../README.ja.md). For current capabilities and limitations, see [Project status](../STATUS.md).

## Using EmailAddressChecker

| Guide | Contents |
| --- | --- |
| [日本語CLIリファレンス](usage-ja.md) | Input formats, command options, batch limits, output and exit codes. |
| [Configuration](../config/README.md) | Effective CLI settings and the distinction between working files and deployment examples. |
| [Result model](status-model.md) | Verdicts, evidence, reason codes, confidence and risk flags. |
| [Classification datasets](../src/emailcheck/data/passive/README.md) | Included data and currently unavailable classifications. |

## Developing and maintaining

| Guide | Contents |
| --- | --- |
| [Contributing](../CONTRIBUTING.md) | Setup, checks, coding rules and pull requests. |
| [Architecture](architecture.md) | Components, dependency boundaries and deployment profiles. |
| [Requirements](requirements.md) | Functional scope and constraints. |
| [Test strategy](test-strategy.md) | Fixtures, coverage goals and safety checks. |
| [Architecture decisions](adr/) | Rationale for durable design choices. |
| [Data-source policy](data-sources.md) | Provenance, licensing and updates for classification datasets. |

## Operating and releasing

| Guide | Contents |
| --- | --- |
| [Security policy](../SECURITY.md) | Responsible use and vulnerability reporting. |
| [Threat model](threat-model.md) | Network, abuse and privacy risks. |
| [SMTP state machine](smtp-state-machine.md) | Allowed commands and protocol behavior. |
| [Operations](operations.md) | Sender identity, rate limits, monitoring and incident response. |
| [Readiness checklist](readiness-checklist.md) | Human approval gates for active SMTP deployments. |
| [Privacy](privacy.md) | Data handling, retention and deletion. |
| [Runbooks](runbooks/) | Incident and operational procedures. |
| [Release instructions](releasing.md) | Building, validating and publishing packages. |

## Records and templates

- [Changelog](../CHANGELOG.md) — user-visible changes and release history.
- [公開後セキュリティ監査](security-audit.md) — findings, fixes, validation and release boundaries.
- [Release preparation report](release-report.md) — historical 0.1.0 validation record (Japanese).
- [Beta report template](beta-report-template.md) — evidence collection for a controlled deployment.

The authoritative behavior is defined, in precedence order, by [requirements](requirements.md), [status model](status-model.md), [threat model](threat-model.md), [SMTP state machine](smtp-state-machine.md) and accepted [ADRs](adr/). The [contribution rules](../CONTRIBUTING.md) also set safety requirements for changes. Historical Phase records describe past work; current implementation and validation take precedence over old measurements.
