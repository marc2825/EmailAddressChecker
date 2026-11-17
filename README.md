# EmailAddressChecker

[English](README.md) | [日本語](README.ja.md)

EmailAddressChecker is a Python CLI and library that checks an email address's syntax, its domain's DNS mail routing, and its likely deliverability without sending any email. It reports what the evidence supports. It cannot tell you that a mailbox exists or that a message will arrive.

Local checks never connect to SMTP servers. Active SMTP probing is a separate, restricted feature for operators.

## Features

- Passive checks of address syntax and DNS/MX records.
- Batch checks of CSV or TXT files, with results in input order as JSON or CSV.
- Offline expansion of `*` patterns into candidate addresses.
- Optional active checks through a separately configured, authorized remote validator.

## Installation

Requires Python 3.12 or later. Version 0.1.0 is not on PyPI yet, so install from the repository:

```bash
git clone https://github.com/marc2825/EmailAddressChecker.git
cd EmailAddressChecker
python -m pip install .
```

The command and the Python package are both named `emailcheck`.

## Quick start

```bash
# Check one or more addresses (DNS only)
emailcheck check alice@example.com bob@example.org

# Check a CSV file with an "email" column
emailcheck batch addresses.csv --output results.csv

# Check a TXT file with one address per line
emailcheck batch addresses.txt --format txt --output results.json

# Skip repeated addresses and show progress
emailcheck batch addresses.csv --duplicates skip --progress --output results.json

# Generate candidates offline
emailcheck expand 'a**ce@example.com' --chars abc --output candidates.csv

# Show only the maximum number of candidates
emailcheck expand 'a**ce@example.com' --charset lower --dry-run
```

The original single-address form still works: `emailcheck alice@example.com --json`.

### Input and output

CSV input is UTF-8 with an `email` column. A leading byte order mark, which spreadsheet exports add, is accepted. TXT input has one address per line. Results keep the input order. Output is JSON unless you pass `--output-format csv` or an output file name ending in `.csv`.

Results leave out the input addresses unless you pass `--include-address`. Keep input and output files that contain addresses private, and pass sensitive addresses in a file rather than as arguments, which can remain in shell history.

A batch may hold 10,000 rows by default, but the default passive quota is 1,000 checks per hour per key, so a larger run may return refused rows unless you raise the quota in [config/budgets.toml](config/budgets.toml):

```bash
emailcheck batch addresses.csv --config config/budgets.toml --output results.csv
```

Limits and quotas apply within one process and are not shared between processes. See the [configuration reference](config/README.md).

## Results

| Status | Meaning |
| --- | --- |
| `likely_deliverable` | There is positive delivery evidence. The mailbox is still not guaranteed to exist. |
| `invalid` | Syntax or mail routing definitely fails, or there is authoritative negative evidence. |
| `temporary_unknown` | A temporary problem prevented a reliable conclusion. |
| `unknown` | The evidence is insufficient or ambiguous, or the address form is unsupported. |

`confidence` is a category, not a probability. Working MX records do not prove that any particular mailbox exists. Processing states such as `refused` and `failed` are reported separately from these statuses. The [status model](docs/status-model.md) gives the evidence rules and reason codes.

## Scope and safety

The active path is off by default. It needs an authorized deployment with authentication, destination controls, rate limits, and an explicit decision by the operator. It never sends a message, and it is not an unrestricted bulk SMTP checker. Use it only on systems and addresses you own or are expressly authorized to test; see [SECURITY.md](SECURITY.md) and the [deployment checklist](docs/readiness-checklist.md).

The legacy `--remote` client requires HTTPS. For local development it accepts HTTP only for the exact addresses `127.0.0.1` and `[::1]`; `localhost` is not accepted. It follows no redirects and ignores proxy environment variables. Active SMTP requires verified TLS in both the production composition and the library dialogue; the former `OPPORTUNISTIC` policy has been removed. See [ADR 0021](docs/adr/0021-required-encryption-at-network-boundaries.md) for migration details.

The disposable-domain, free-mail, and provider datasets are empty for now, so a missing flag does not mean the address is clean. Role-address classification is included. See the [dataset status](src/emailcheck/data/passive/README.md).

The repository also contains service components (API-key authentication, an HTTP request handler, job and verdict stores, active batch) that are available only as a library. No HTTP server ships, and the installed command does not use them. See [component reachability and roadmap](docs/architecture.md#component-reachability).

## Development

```bash
python -m pip install -e '.[dev,release]'
python -m pytest
```

Start from the [documentation index](docs/INDEX.md) for architecture, testing, and releases, and see [CONTRIBUTING.md](CONTRIBUTING.md) to contribute.

Licensed under [Apache 2.0](LICENSE).
