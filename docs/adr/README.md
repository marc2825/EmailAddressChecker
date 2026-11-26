# Architecture decision records

Current behavior is described in the main documents ([requirements](../requirements.md), [architecture](../architecture.md), [status model](../status-model.md), [SMTP state machine](../smtp-state-machine.md), [threat model](../threat-model.md), [privacy](../privacy.md), [operations](../operations.md)). ADRs are kept only for the most important decisions, where the reasons matter as much as the rule.

## Current ADRs

| ADR | Decision |
| --- | --- |
| [0002](0002-status-risk-separation.md) | Deliverability status and risk flags are separate |
| [0003](0003-restricted-smtp-state-machine.md) | A purpose-built SMTP state machine with no message submission |
| [0004](0004-categorical-confidence.md) | Categorical confidence until calibration |
| [0005](0005-idna-uts46-domain-encoding.md) | IDNA encoding (`idna` dependency) and the address syntax judgments |
| [0006](0006-dnspython-resolver-and-destination-policy.md) | `dnspython` as the resolver, and an explicit destination policy |
| [0008](0008-smtp-safety-gate.md) | The forbidden-command scanner and the structural SMTP safety barriers |
| [0009](0009-smtp-dialogue-and-tls.md) | `WireCommand` as the write capability, and required TLS |
| [0019](0019-operation-recipient-budget-and-atomic-job-identity.md) | One recipient touch per operation, atomic job identity, crash semantics |
| [0021](0021-required-encryption-at-network-boundaries.md) | HTTPS for remote validators and TLS for SMTP, with migration notes |
| [0022](0022-local-active-mode.md) | Local Active Mode: one SMTP check from the user's machine, no service |

A new ADR is needed for a new production dependency, a new SMTP command, or a change to any decision above.

## Retired ADRs

These were folded into the main documents on 2026-11-17. Code and tests may still cite them by number; the table says where their rules live now. The original text is in the git history, for example `git show ae4f248:docs/adr/0014-bounded-asynchronous-active-jobs.md`.

| ADR | Topic | Now described in |
| --- | --- | --- |
| 0001 | Python-only MVP | [architecture](../architecture.md), section 3 |
| 0007 | Passive classification and datasets | [data-sources](../data-sources.md) |
| 0010 | SMTP recipient evidence mapping | [status model](../status-model.md), section 7 |
| 0011 | Verification orchestration and rate limiting | [architecture](../architecture.md), section 4; [threat model](../threat-model.md) |
| 0012 | Evidence aggregation and final status | [status model](../status-model.md), sections 3 and 4 |
| 0013 | Production composition and the public boundary | [architecture](../architecture.md), sections 3 and 4 |
| 0014 | Bounded asynchronous active jobs | [architecture](../architecture.md), section 4; [ADR 0019](0019-operation-recipient-budget-and-atomic-job-identity.md) |
| 0015 | Verdict cache and TTL | [architecture](../architecture.md), section 4; [requirements](../requirements.md), section 13 |
| 0016 | Abuse controls, privacy, and observability | [threat model](../threat-model.md), section 5; [privacy](../privacy.md); [operations](../operations.md) |
| 0017 | Accept-all control experiment | [architecture](../architecture.md), section 4 |
| 0018 | Controlled batch execution | [architecture](../architecture.md), section 4; [privacy](../privacy.md), section 7 |
| 0020 | Local batch, offline expansion, and release | [architecture](../architecture.md), section 4; [usage-ja](../usage-ja.md) |
