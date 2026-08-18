# EmailAddressChecker

A conservative email deliverability verifier.

**It estimates deliverability. It does not prove that a mailbox exists.**

That distinction is the point of the project. An SMTP server accepting a
recipient tells you the server accepted a recipient — not that a person reads
mail there, not that a later message will arrive. Many tools quietly round that
up. This one refuses to, and the refusal is enforced by tests rather than by
good intentions.

## What it does

- **Syntax validation** — RFC-shaped parsing with IDNA/Unicode handling, without
  silently broadening what it accepts.
- **DNS and MX analysis** — MX resolution with TTL policy, address lookup, and
  explicit Null MX (`.`) handling.
- **Passive classification** — disposable, free-mail, role-account, and provider
  patterns from versioned local datasets, with content-derived cache identity so
  a dataset edit cannot serve a stale verdict.
- **Restricted SMTP evidence** — an optional active check that stops at the
  `RCPT` stage and never transmits message content.
- **Conservative aggregation** — structured evidence folded into one published
  status, with ambiguity resolving downward.
- **Risk flags** — reported separately from deliverability, never mixed into it.
- **CLI** — `emailcheck`, which performs no SMTP for a local check.

Two subsystems exist in the codebase but are **not** ordinary public features.
The accept-all experiment is optional, disabled by default, and gated behind
operator authorization, a separate budget, and a separate cache. The batch
subsystem is deliberately not composed into the shipped stack and is reachable
from no request surface.

## Verdicts

Four published statuses, and no fifth:

| Status | Meaning |
|---|---|
| `likely_deliverable` | Evidence supports delivery being likely. Not proof of a mailbox. |
| `invalid` | Authoritative evidence that the address cannot receive mail. |
| `temporary_unknown` | A transient condition prevented a conclusion. Ask again later. |
| `unknown` | Evidence was absent or ambiguous. |

Risk flags — disposable, role account, accept-all suspected, domain
configuration anomaly, and others — are carried **separately** from status. A
flag never upgrades or downgrades the verdict on its own.

Two consequences worth stating plainly:

- **A bare `250` is not mailbox-existence proof.** Many servers accept every
  recipient.
- **An ambiguous permanent failure is not automatically `invalid`.** A bare
  `550` becomes `unknown`; only an authoritative enhanced status code such as
  `5.1.1` supports `invalid`.

See [docs/status-model.md](docs/status-model.md) for the full mapping.

## Safety model

- **Active probing is not authorized by default.** It must be explicitly
  configured *and* explicitly authorized, and publishing this source authorizes
  nothing.
- **TLS is required** for active SMTP under the current policy.
- **At most one recipient touch per ordinary verification operation** — in
  total, across MX fallback, temporary replies, lost replies, partial writes,
  retries, and restarts.
- **No recipient-stage replay.** A retry is available only to an attempt that
  provably did not reach the recipient.
- **No `DATA`, no `AUTH`, no `VRFY`, no `EXPN`**, and no message content of any
  kind. A repository check enforces this against the source.
- **Unsafe destinations are rejected** — private and reserved ranges, with the
  selected IP and the actual peer both validated.
- **Operator controls** — a global kill switch, account and key suspension, and
  domain and exchanger blocks, each audited.
- **Per-deployment readiness** is required before any external beta.

## Installation

Python 3.12 or newer. There is no published package or container image; install
from a checkout:

```bash
git clone https://github.com/marc2825/EmailAddressChecker.git
cd EmailAddressChecker
python -m venv .venv && source .venv/bin/activate
python -m pip install -e .
```

## Quick start

A local check is passive. It performs **no SMTP** and contacts no mail server:

```bash
emailcheck user@example.com
emailcheck user@example.com --json
```

Other read-only commands:

```bash
emailcheck --check-deployment    # advisory gate report; contacts nothing
emailcheck --report-versions     # aggregation ruleset and dataset versions
```

> **Active probing is a separate decision.** Enabling it means connecting to
> third-party mail exchangers from your address. Before doing so you must
> complete [docs/readiness-checklist.md](docs/readiness-checklist.md) — static
> IP, outbound port 25, PTR and forward DNS, SPF, monitored sender and abuse
> mailboxes, reviewed hosting terms, a tested kill switch, tested rate limits,
> blocked private-network egress, tested retention deletion, and a named
> incident owner — and probe only addresses you own or are explicitly
> authorized to test.

## Configuration

See [`.env.example`](.env.example) for the shape. It ships with the
`local-passive` profile, active probes disabled, and placeholder values only.

Never commit real configuration. The correlation/HMAC key is rejected if empty,
and a deployment with a persistent store must configure the account-state
authority or it will refuse to start.

## Development

```bash
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy src
python scripts/check_forbidden_smtp.py
make check
```

The default test path and CI are **offline**: no external DNS, SMTP, or HTTP.
Tests needing a server bind to loopback; the rest use fakes, scripted
transports, and fake clocks.

## Architecture

```
apps → application → ports/domain ← adapters
                          ↑
                    composition.py
```

- [docs/architecture.md](docs/architecture.md) — layering, persistence, fencing.
- [docs/threat-model.md](docs/threat-model.md) — what this defends against.
- [docs/status-model.md](docs/status-model.md) — evidence to verdict.

## Responsible operation

- [SECURITY.md](SECURITY.md) — reporting and responsible use.
- [docs/operations.md](docs/operations.md) — operator controls and runbooks.
- [docs/readiness-checklist.md](docs/readiness-checklist.md) — deployment gates.

Publication, implementation readiness, and deployment authorization are three
different things. This repository being public means only the first.

## Project status

See [STATUS.md](STATUS.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
