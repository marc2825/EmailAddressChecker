# Documentation

Start with the [README](../README.md) or the [日本語README](../README.ja.md). Current capabilities and limitations are in [Project status](../STATUS.md).

## Using EmailAddressChecker

| Guide | Contents |
| --- | --- |
| [日本語CLIリファレンス](usage-ja.md) | Input formats, options, batch limits, output, and exit codes. |
| [Configuration](../config/README.md) | Which configuration files the CLI reads, and which are only deployment examples. |
| [Status model](status-model.md) | Verdicts, evidence, reason codes, confidence, and risk flags. |
| [Classification datasets](../src/emailcheck/data/passive/README.md) | Included data and classifications not yet available. |

## Developing and maintaining

| Guide | Contents |
| --- | --- |
| [Contributing](../CONTRIBUTING.md) | Setup, checks, coding rules, and pull requests. |
| [Architecture](architecture.md) | Components, dependency boundaries, and deployment profiles. |
| [Requirements](requirements.md) | Functional scope and constraints. |
| [Test strategy](test-strategy.md) | Fixtures, coverage goals, and safety checks. |
| [Architecture decisions](adr/) | Reasons for lasting design choices. |
| [Data-source policy](data-sources.md) | Provenance, licensing, and updates of classification datasets. |

## Operating and releasing

| Guide | Contents |
| --- | --- |
| [Security policy](../SECURITY.md) | Responsible use and vulnerability reporting. |
| [Threat model](threat-model.md) | Network, abuse, and privacy risks. |
| [SMTP state machine](smtp-state-machine.md) | Allowed commands and protocol behavior. |
| [Operations](operations.md) | Sender identity, rate limits, monitoring, and incident response. |
| [Readiness checklist](readiness-checklist.md) | Human approvals required before an active SMTP deployment. |
| [Privacy](privacy.md) | Data handling, retention, and deletion. |
| [Runbooks](runbooks/) | Incident and operational procedures. |
| [Release instructions](releasing.md) | Building, validating, and publishing packages. |

## Records and templates

| Document | Contents |
| --- | --- |
| [Changelog](../CHANGELOG.md) | User-visible changes and release history. |
| [公開後セキュリティ監査](security-audit.md) | Post-publication audit: findings, fixes, validation, and release boundaries. |
| [Release preparation report](release-report.md) | Validation record for 0.1.0 (Japanese). |
| [Beta report template](beta-report-template.md) | Evidence to collect from a controlled deployment. |

When documents disagree, this order decides: [requirements](requirements.md), [status model](status-model.md), [threat model](threat-model.md), [SMTP state machine](smtp-state-machine.md), then accepted [ADRs](adr/). The [contribution rules](../CONTRIBUTING.md) also set safety requirements for changes. Records of past Phases describe past work; the current implementation and its validation override old measurements.
