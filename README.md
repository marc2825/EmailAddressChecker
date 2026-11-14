# EmailAddressChecker

[English](README.md) | [日本語](README.ja.md)

EmailAddressChecker is a Python CLI and library for checking email address syntax, DNS mail routing, and estimated deliverability. It reports what the available evidence supports—**not whether a mailbox definitely exists or will receive a message**.

Local checks never connect to SMTP servers. Active SMTP probing is a separate, restricted operator feature.

## Features

- **Passive validation:** Check address syntax and DNS/MX records without SMTP connections.
- **Batch processing:** Check CSV or TXT files and export ordered JSON or CSV results.
- **Offline generation:** Expand `*` patterns into candidate addresses without network access.
- **Optional active checks:** Use an explicitly configured, authorized remote validator for limited SMTP probing.

## Installation

Requires **Python 3.12+**. Version 0.1.0 has not been published to PyPI; install from the repository:

```bash
git clone https://github.com/marc2825/EmailAddressChecker.git
cd EmailAddressChecker
python -m pip install .
```

The command is `emailcheck`; the Python package is also named `emailcheck`.

## Quick start

```bash
# Check one or more addresses (passive; DNS only)
emailcheck check alice@example.com bob@example.org

# Process a CSV file with an "email" column
emailcheck batch addresses.csv --output results.csv

# Process a TXT file containing one address per line
emailcheck batch addresses.txt --format txt --output results.json

# Skip repeated addresses and show progress
emailcheck batch addresses.csv --duplicates skip --progress --output results.json

# Generate candidates locally
emailcheck expand 'a**ce@example.com' --chars abc --output candidates.csv

# Preview the maximum number of candidates
emailcheck expand 'a**ce@example.com' --charset lower --dry-run
```

The original single-address command is also supported: `emailcheck alice@example.com --json`.

### Input and output

CSV input must be UTF-8 with an `email` column; TXT input contains one address per line. Results preserve input order. JSON is the default output format; use `--output-format csv` or an `.csv` output filename for CSV.

Results omit input addresses unless `--include-address` is specified. Keep input files and outputs containing addresses private. For sensitive addresses, prefer file input over shell arguments, which may remain in command history.

The default batch limit is **10,000 rows**, but the default passive quota is **1,000 checks per hour per key**. Larger runs may produce refused rows unless you adjust the quota. Configure local budgets with [config/budgets.toml](config/budgets.toml):

```bash
emailcheck batch addresses.csv --config config/budgets.toml --output results.csv
```

Limits and quotas are enforced within a process, not across independent processes. See the [configuration reference](config/README.md) for details.

## Understanding results

| Status | Meaning |
| --- | --- |
| `likely_deliverable` | Positive delivery evidence, but no guarantee that the mailbox exists. |
| `invalid` | A definite syntax or mail-routing failure, or authoritative negative evidence. |
| `temporary_unknown` | A temporary problem prevented a reliable conclusion. |
| `unknown` | Evidence is insufficient, ambiguous, or the address form is unsupported. |

`confidence` is a category, not a probability. A domain with working MX records does **not** prove that any particular mailbox exists. Processing states such as `refused` or `failed` are separate from these delivery statuses.

See the [status model](docs/status-model.md) for the evidence rules and reason codes.

## Scope and safety

Passive checks use DNS but do not contact SMTP servers. Pattern expansion is entirely offline. The optional active path is not enabled by default: it requires an authorized deployment with authentication, destination controls, rate limits, and an explicit operator decision. It does not send email messages or provide an unrestricted bulk SMTP checker.

Disposable-domain, free-mail, and provider-classification datasets are currently unpopulated; absence of a flag must not be interpreted as a clean result. Role-address classification is included. See [dataset status](src/emailcheck/data/passive/README.md).

Use active probing only on systems and addresses you own or are expressly authorized to test. See [SECURITY.md](SECURITY.md) and the [deployment checklist](docs/readiness-checklist.md).

## Development and documentation

```bash
python -m pip install -e '.[dev,release]'
python -m pytest
```

For architecture, testing, and release procedures, start with the [documentation index](docs/INDEX.md). Contributions are covered in [CONTRIBUTING.md](CONTRIBUTING.md).

Licensed under [Apache 2.0](LICENSE).
