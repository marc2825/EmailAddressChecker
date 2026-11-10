# EmailAddressChecker

Conservative, evidence-based email deliverability estimates for Python 3.12+.
**An estimate is not proof that a mailbox exists.** Local checks use syntax,
DNS/MX and versioned classification data; they never connect to SMTP servers.
Candidate expansion works completely offline.

Distribution: `email-address-checker`; Python import and command: `emailcheck`.
Version 0.1.0 is prepared for a first release; **it has not been uploaded to PyPI**.
See [日本語ガイド](docs/usage-ja.md) and [release instructions](docs/releasing.md).

## Install

After publication:

```bash
python -m pip install email-address-checker
uv tool install email-address-checker
pipx install email-address-checker
```

Until then, install a locally built wheel (no checkout needed at runtime):

```bash
python -m pip install dist/email_address_checker-0.1.0-py3-none-any.whl
uv tool install ./dist/email_address_checker-0.1.0-py3-none-any.whl
pipx install ./dist/email_address_checker-0.1.0-py3-none-any.whl
```

For development: `python -m pip install -e '.[dev,release]'` in a virtual
environment. The only runtime dependencies are `dnspython` and `idna`; there
are no optional runtime extras. Windows and Linux are CI targets;
Python 3.12, 3.13 and 3.14 have CI jobs. See the release report for tests actually run.

## Checks and output

```bash
emailcheck user@example.com --json             # original interface retained
emailcheck check user@example.com
emailcheck check a@example.com b@example.org --output results.json
emailcheck batch input.csv --output result.csv
emailcheck batch addresses.txt --format txt --output results.json
emailcheck batch input.csv --mode passive --progress --duplicates skip
python -m emailcheck --version
```

CSV is UTF-8 (optional BOM), with one unique `email` header; additional uniquely
named columns are ignored. TXT has one address per line. No trimming or comment
syntax is applied to addresses. Blank TXT lines are checked as empty inputs.
Malformed CSV rows with the wrong column count are `rejected` while other rows
continue. Unrecoverable CSV quoting/encoding errors or file/row limit violations
abort the command. A preflight pass checks the entire input before DNS starts.

`check` and `batch` stream a JSON array by default. `--output-format csv` selects
CSV; a `.csv` output filename also selects it. Both formats preserve input order.
The legacy single-address JSON shape is unchanged; new commands add operational
metadata around the same public verdict fields. For example:

```bash
emailcheck check bad --output-format json
emailcheck check bad --output-format csv
```

The JSON result includes these fields (abbreviated):

```json
[{"row":1,"state":"completed","status":"invalid","confidence":"high",
  "primary_reason":"invalid_syntax","reasons":["invalid_syntax"],
  "risk_flags":[],"checks":{"syntax":{"result":"invalid_syntax"}},
  "smtp_executed":false,"dns_cache_used":false,"verdict_cache_used":false}]
```

CSV carries the same columns; lists/maps are JSON inside quoted CSV cells.
Results also include `ruleset` and `dataset_versions`. `confidence` is categorical,
not a calibrated probability. No SMTP transcript or raw evidence detail is exposed.

| Status | Meaning |
|---|---|
| `likely_deliverable` | Evidence supports likely delivery, not mailbox existence. |
| `invalid` | Authoritative negative evidence, including invalid syntax. |
| `temporary_unknown` | A transient condition prevents a conclusion. |
| `unknown` | Evidence is absent, ambiguous or syntax is unsupported. |

A DNS/MX result for Gmail says nothing about whether a particular Gmail mailbox
exists. A bare SMTP `250` is also not existence proof. Risk flags remain separate
from deliverability. See [status model](docs/status-model.md).

Operational `state` is separate: `completed`, `duplicate`, `rejected`, `refused`,
or `failed`. A refused/failed row has **no fabricated status**. Processing errors
carry fixed categories, never the exception text. Exit codes: 0 completed
(including negative verdicts), 2 input/configuration/output error, 3 row processing
refusals/failures, 130 interruption. Legacy remote exit codes remain unchanged.

### Duplicates, limits and cancellation

- `--duplicates keep` (default) checks every row and spends its ordinary quota.
  `--duplicates skip` emits a `duplicate` row with `duplicate_of` referencing the
  first row. It does not copy an earlier verdict or charge for skipped rows.
  Dedup uses the existing normalized address identity, preserving local-part case.
- Default limits: 10,000 rows, 4 MiB input and 8 in-flight rows. Hard ceilings:
  50,000 rows, 8 MiB and 64 in-flight rows. Results are buffered only for one
  bounded window. Digests for deduplication are bounded by the row limit.
- Ctrl-C cancels and joins outstanding local tasks. Files are written to a private
  temporary file in the destination directory, flushed and replaced only on
  success. Existing outputs survive errors/cancellation. A forced process kill
  may leave a private `.emailcheck-*` temporary file: remove it after review.
- Standard output is a stream and may be partial on interruption. Prefer
  `--output` for an atomic artifact. `--progress` writes counts only to stderr.
- `--start-row N` starts a **new passive run** from that logical input row (CSV
  header excluded), retaining original row numbers and earlier duplicate identity.
  It does not append/merge outputs or restore prior DNS results. Local runs have
  no durable checkpoint. The separately gated Active BatchService retains its
  existing persistent resume/cancel/deletion behavior.

## Offline wildcard generation

```bash
emailcheck expand 'm**rc@example.com' --charset lower --dry-run
# {"candidate_count_upper_bound": 676, "max_candidates": 10000}
emailcheck expand 'm**rc@example.com' --chars abc --output candidates.csv
emailcheck expand 'm**rc@example.com' --slot '["a","b"]' --slot '["0","1"]'
emailcheck expand 'm*rc@example.com' --candidate a --candidate ab --candidate abc
emailcheck expand 'm*rc@example.com' --candidates-file tokens.txt
emailcheck expand 'm**rc@example.com' --slot-file first.txt --slot-file second.txt
emailcheck batch candidates.csv --mode passive --output results.csv
```

Each unescaped `*` in the local part independently chooses one token. Output is
in Cartesian-product order, with the rightmost slot changing fastest. Presets:
`lower` = a–z, `upper` = A–Z, `digits` = 0–9, `alnum` = a–z, A–Z, then 0–9.
`--chars` splits a string into individual characters; repeated `--candidate`
options supply whole strings. `--slot` is one JSON array per star. Global choices
and position-specific choices cannot be mixed.

UTF-8 token files contain one literal token per line; blank lines represent an
empty token and an empty file is rejected. A final newline adds no extra token.
No comments or escapes are interpreted in files. `--candidate ''` or a JSON
`""` explicitly removes a star. Each token is at most 64 characters; a pool has
at most 10,000 input entries and 1 MiB of UTF-8 content. Patterns are at most
254 characters. Domain wildcards, control characters, `@` and backslashes in
tokens are rejected. In patterns `\*` means a literal star; only `\*` and `\\`
escapes are recognized. The existing parser then validates generated addresses.
Unicode domains use existing IDNA rules; Unicode local parts (SMTPUTF8) remain
unsupported and are refused for expansion. Normal checks report them as `unknown`.

Duplicates in a pool are removed in first-seen order. Concatenation collisions
are suppressed during generation. The dry-run number is therefore an **upper
bound on unique output**, computed without expanding the product. The cap applies
to the product before collision suppression. Default cap is the configured
`batch.max_rows` (10,000); `--max-candidates` may lower it, never exceed it.
Invalid later candidates abort generation, preserving an existing output file.
Dry-run checks structure and a representative candidate; full syntax validation
happens lazily during generation. An address without stars produces one candidate.

CSV has an `email` header and can feed `batch` directly. Formula-like addresses
are rejected for generated CSV; use `--output-format txt` if those are intentional.
There is no generate-and-SMTP command, remote batch switch or automatic account
enumeration. The generator iterator can feed the passive library interface.

## Configuration and rate control

```bash
emailcheck config show --config config/budgets.toml
emailcheck check user@example.com --config config/budgets.toml
emailcheck batch input.csv --config config/budgets.toml --output results.csv
```

See [config/budgets.toml](config/budgets.toml) for a complete working example.
Only `[batch]`, `[rate_limit]`, `[quota]`, and `[passive_quota]` are accepted.
Unknown fields, wrong types, booleans as counts, nonfinite values and unsafe
bounds are errors. No setting changes TLS, credentials, destinations or readiness.
Default settings preserve the existing limits. `[passive_quota]` uses a separate
store from Active `[quota]`; local batch and single checks share the same service
and quota within a process. Default per-key allowance is 1,000/hour, so a larger
batch can produce refused rows unless the passive budget is explicitly configured.
The `batch.max_in_flight_per_domain` and `batch.max_in_flight_per_mx` fields retain
the Active scheduler's schema; local passive work uses only the global window
bound and coalesces DNS requests. Passive checks do not consume SMTP pacing tokens
or destination quotas. `config/local-passive.toml` is an older deployment example,
not the CLI budget schema; use `config/budgets.toml` with `--config`.

`[rate_limit]` governs SMTP global concurrency and domain **and MX** concurrency
and token buckets. Domain settings apply equally to each MX; multiple domains
on one exchanger share that budget across accounts. Temporary SMTP replies
back off later operations to the domain and MX for at least 60 seconds. This
never retries a touched recipient. Safe existing pre-recipient retries still
consume ordinary budgets. Quota exhaustion is an operational refusal.

These stores are **in-process**, not distributed. Each CLI invocation starts
fresh local budgets. Deployments require `worker_processes=1`; independent
replicas/processes are unsupported for globally enforced Active budgets. A shared
atomic quota/pacing store and durable worker coordination are deferred; SQLite
job identity alone is not a distributed rate limiter. See [ADR 0020](docs/adr/0020-local-batch-and-release.md).

## Python library

Offline generation:

```python
from emailcheck.application.expansion import plan_expansion

for candidate in plan_expansion("m**rc@example.com", candidates="ab"):
    print(candidate)
```

Passive checking (DNS may be contacted, SMTP cannot be):

```python
import asyncio
import secrets
from emailcheck.application.local_batch import InputRow, passive_rows
from emailcheck.classification.repository import load_shipped_datasets
from emailcheck.composition import Deployment, build_verification_stack
from emailcheck.settings import load_settings


async def main():
    key = secrets.token_urlsafe(32)
    deployment = Deployment(
        api_keys={"local": key},
        correlation_key=secrets.token_bytes(32),
        passive_datasets=load_shipped_datasets(),
    )
    stack = build_verification_stack(load_settings().apply(deployment))
    principal = stack.authenticator.authenticate(key)
    assert principal is not None
    try:
        rows = (InputRow(i, value) for i, value in enumerate(["user@example.com"], 1))
        async for result in passive_rows(rows, service=stack.verification, principal=principal):
            print(result)
    finally:
        await stack.aclose()


asyncio.run(main())
```

## Safety, privacy and limitations

- Local output omits addresses; `--include-address` is an explicit local-only
  choice. Spreadsheet formula cells are escaped in result CSV. Protect inputs,
  candidates and outputs as personal data. Shell positional addresses may remain
  in shell history; use files for sensitive input. Progress contains only counts.
- No local job database or retained input is created. Outputs are user-owned
  files with user-managed retention. Existing service account isolation, deletion
  fences and retention remain unchanged. DNS cache keys never contain local parts;
  positive/negative TTLs are preserved and cache size is bounded.
- Three classification datasets (disposable, free-mail, provider) remain empty
  pending verified redistributable sources. The authored role list is included.
  Absence is not a negative classification. `emailcheck --report-versions` reports
  the actual shipped snapshot. See [dataset policy](docs/data-sources.md).
- Active SMTP is a separate operator deployment: only owned/explicitly authorized
  targets, reviewed readiness, configured identity, TLS, destination allowlists
  where required, authentication, audit, kill switch and budgets. The legacy
  single-address `--remote URL --remote-key-file PATH [--wait]` interface remains.
  No Active bulk surface is added. See [readiness](docs/readiness-checklist.md).
- At most one `RCPT TO` per ordinary operation across retries/restarts; no message
  body, `DATA`, `AUTH`, `VRFY` or `EXPN`. Private/reserved destinations and mismatched
  peers are rejected. A passing suite or a release is not Active operation approval.

## Development and license

```bash
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy src
python scripts/check_forbidden_smtp.py
python -m build
python -m twine check dist/*
python scripts/check_artifacts.py
python scripts/smoke_distribution.py
```

Tests use fakes and explicitly guarded loopback fixtures; no third-party DNS or
SMTP connections. See [CONTRIBUTING.md](CONTRIBUTING.md),
[architecture](docs/architecture.md), [security](SECURITY.md), and [STATUS.md](STATUS.md).
Apache-2.0, see [LICENSE](LICENSE).
