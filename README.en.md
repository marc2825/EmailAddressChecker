# EmailAddressChecker

[日本語](README.md) | [English](README.en.md)

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/teaser-dark.svg">
    <img src="docs/assets/teaser-light.svg" width="100%" alt="EmailAddressChecker logo">
  </picture>
</p>

A Python CLI that checks email addresses **conservatively** from their syntax and their domain's DNS/MX records, **without sending any email**.

- Local checks never connect to SMTP servers. They cannot establish that a particular mailbox exists or that a message will be delivered.
- When the evidence is not decisive, the answer is `unknown`, which does not mean invalid.
- No HTTP server ships. SMTP checks are for separately configured, authorized deployments.

## When to use it

It is for checking and cleaning lists of addresses from the command line:

- CSV/TXT batches: input order kept, duplicate handling, row and size limits, and file output that is never left half written
- machine-readable JSON/CSV with stable reason codes
- results that explain themselves: how far syntax, DNS, and the mailbox were checked, and `emailcheck explain` for every code
- Japanese and English messages
- privacy by default: files omit addresses, the screen shows them redacted, and CSV cells are escaped against spreadsheet formulas

To validate syntax inside a Python program, a syntax-validation library such as [email-validator](https://pypi.org/project/email-validator/) is a better fit.

> **Release status:** v0.1.0 is not yet published to PyPI. The supported local CLI is available from the repository; the service components are not a ready-to-deploy HTTP service.

## Features

| Feature | Available behavior |
| --- | --- |
| Address validation | Supported ASCII mailbox syntax, internationalized domain names (IDNA), and DNS/MX mail routing |
| Batch processing | UTF-8 CSV/TXT input, ordered JSON/CSV output, duplicate handling, and bounded concurrency |
| Candidate generation | Offline expansion of `*` patterns with configurable substitutions and output limits |
| Risk indicators | Role-address classification; other classification datasets are currently unavailable |
| Active SMTP checks | Restricted library components for separately authorized deployments; not part of local `check` or `batch` |

## Installation

Requires **Python 3.12 or later**.

```bash
git clone https://github.com/marc2825/EmailAddressChecker.git
cd EmailAddressChecker
python -m pip install .
```

Once 0.1.0 is on PyPI, any of these works:

```bash
pipx install email-address-checker
uv tool install email-address-checker
python -m pip install email-address-checker
```

CI installs and runs the package on Linux, Windows, and macOS; the full test suite runs on Linux.

The command and importable module are both named `emailcheck`.

## Quick start

**Check one or more addresses (syntax and DNS only):**

```bash
emailcheck check alice@example.com bob@example.org
```

**Check a CSV file** containing an `email` column:

```bash
emailcheck batch addresses.csv --output results.csv
```

**Check a TXT file** with one address per line:

```bash
emailcheck batch addresses.txt --format txt --output results.json
```

**Skip duplicate addresses and show progress:**

```bash
emailcheck batch addresses.csv --duplicates skip --progress --output results.json
```

**Generate address candidates offline:**

```bash
emailcheck expand 'a**ce@example.com' --chars abc --output candidates.csv
```

To see the **upper bound** on candidate count without writing a file:

```bash
emailcheck expand 'a**ce@example.com' --charset lower --dry-run
```

**Look up what a status or reason code means:**

```bash
emailcheck explain mx_available
```

On a terminal, one address shows what each step found:

```text
$ emailcheck check alice@example.com
a***@example.com
invalid  Invalid (confidence high)
The domain declares in DNS that it accepts no mail (RFC 7505).

  ✓ Syntax    valid form
  ✗ DNS / MX  domain accepts no mail (null MX)  null_mx
  – Mailbox   not reached

This is an estimate. It does not prove that a mailbox exists or is in use.
No message content was sent.
```

Two or more addresses print one line each, then a summary. Messages are in Japanese or English, following `LC_ALL`, `LC_MESSAGES`, and `LANG` (`LANG=C` gives English); `NO_COLOR` turns colour off. The original single-address form, `emailcheck alice@example.com --json`, remains available. For full command options, see the [Japanese CLI reference](docs/usage-ja.md).

## Understanding results

| `status` | Meaning |
| --- | --- |
| `invalid` | Supported syntax or authoritative mail-routing/recipient evidence rules out delivery. |
| `unknown` | Evidence is inconclusive, ambiguous, or the address form is unsupported. |
| `temporary_unknown` | A temporary failure prevents a reliable conclusion. |
| `likely_deliverable` | Qualified, recipient-specific positive evidence was obtained; delivery is **not** guaranteed. |

**DNS/MX records do not prove that a mailbox exists.** In particular, local DNS-only checks cannot establish `likely_deliverable` from mail routing alone. Positive recipient-specific evidence requires a separately authorized active check.

`confidence` is a category, not a probability. Operational states such as `refused` and `failed` are separate from delivery statuses. `emailcheck explain <code>` describes any of these values. See the [status and evidence model](docs/status-model.md).

## Input, output, and limits

- CSV must be UTF-8 (a leading BOM is supported) with exactly one `email` header; TXT uses one address per line.
- A terminal gets a readable view; a pipe or file gets JSON in input order, or CSV with `--output-format csv` or a `.csv` output name.
- The screen shows addresses redacted (`a***@example.com`) and files omit them. Add `--include-address` only when the full address is needed.
- The default batch limits are **10,000 rows** and **4 MiB**. The default passive quota is **1,000 checks per hour per key**; a large batch may therefore contain refused rows.
- Local limits and quotas apply **per process**, not across multiple CLI invocations or workers.
- There is no checkpoint-based resume. `--start-row` starts a new passive run from the specified row.

To use the included budget configuration, which raises the passive hourly quota:

```bash
emailcheck batch addresses.csv --config config/budgets.toml --output results.csv
```

Keep input/output files containing addresses private. Passing sensitive addresses directly as arguments may leave them in shell history. See the [configuration reference](config/README.md) and [privacy guide](docs/privacy.md).

## Using it from Python

In 0.1.0 the supported Python surface is the syntax parser (`emailcheck.parse_address`) and the published vocabulary (the names in `emailcheck.__all__`, such as `Status`, `ReasonCode`, and `RiskFlag`). There is no Python API for DNS checks; call the CLI and read its JSON. Other modules are internal and may change without notice.

## Privacy and acceptable use

- The domains you check are sent to your DNS resolver.
- Addresses typed as arguments can stay in shell history; pass sensitive lists in a file.
- Use candidate generation (`emailcheck expand`) only for addresses you own or are allowed to work with, never to guess or enumerate other people's addresses.

## Scope and safety

The local CLI provides passive syntax/DNS checks and offline candidate generation. The repository also includes **library-only** authentication, HTTP handlers, job stores, and restricted SMTP-verification components. **No HTTP server ships**, and those service components are not available from the installed local commands.

Active SMTP probing is disabled by default. It requires explicit authorization, verified TLS, sender identity, destination controls, authentication, rate limits, and a separately configured deployment. The legacy `--remote` client requires HTTPS, except for HTTP to the exact loopback IP literals `127.0.0.1` and `[::1]` during local development; it rejects redirects and does not use environment proxies.

Only probe addresses and systems you own or have explicit permission to test. See [Security](SECURITY.md), [architecture and component reachability](docs/architecture.md#component-reachability), and the [deployment checklist](docs/readiness-checklist.md).

### Known limitations

- Mailbox existence and successful delivery cannot be guaranteed, even after an authorized SMTP check.
- Some valid address forms, including quoted local parts and SMTPUTF8 local parts, are unsupported and return `unknown` rather than a false `invalid`.
- Disposable-domain, free-mail, and provider-classification datasets are currently empty; an absent risk flag does **not** mean an address is safe.
- Active batch processing, the accept-all experiment, and other service components are not exposed through the local CLI.

For the current feature scope and roadmap, see [STATUS.md](STATUS.md).

## Development

```bash
python -m pip install -e '.[dev]'
python -m pytest
```

Run `make check` where Make is available for linting, formatting, typing, tests, safety invariants, and a CLI smoke check. Individual cross-platform commands are listed in the [test strategy](docs/test-strategy.md).

Further reading: [Documentation index](docs/INDEX.md) · [Contributing](CONTRIBUTING.md) · [Release procedure](docs/releasing.md) · [Changelog](CHANGELOG.md)

## License

[Apache License 2.0](LICENSE).