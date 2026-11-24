# Privacy and data handling

EmailAddressChecker processes email addresses, which can identify people, and information about their domains. It keeps as little as it can and keeps network observations out of logs, error responses, and other accounts.

This page describes how the software handles data. It does not claim regulatory compliance or secure physical erasure. The abuse model and operator duties are in the [threat model](threat-model.md), the [security policy](../SECURITY.md), and the [operations guide](operations.md).

## 1. Data categories

| Data | Purpose | Handling |
| --- | --- | --- |
| Submitted address | Syntax and delivery assessment | Processed for the request; not written to routine logs |
| Normalized domain and MX | DNS routing and destination controls | May appear in bounded domain/MX metrics and caches |
| Target HMAC | Internal correlation and deduplication | Keyed digest, not a plain hash of an address |
| Account and API-key identities | Authentication, ownership, quotas | Scoped to the authenticated principal |
| DNS and structured SMTP evidence | Conservative verdict | Normalized and bounded; raw protocol text is not public output |
| Jobs, results, timestamps, audit metadata | Asynchronous operations and safety controls | Subject to the store's retention policy |
| Local CLI files | Inputs and results the user asked for | Owned and kept by the user, outside service retention |

Addresses and domain names may be personal data. HMAC identifiers, redaction, and aggregation reduce exposure but are not anonymization.

## 2. Data minimization

- Local checks use DNS and never contact SMTP. Offline candidate expansion uses neither DNS nor SMTP.
- Public results contain approved statuses, reason codes, and safe summaries, never raw SMTP transcripts or untrusted server messages.
- Ordinary logs and metrics never contain complete email addresses, raw credentials, or network-library exception text.
- Raw diagnostic replies are not kept at all. Bounded, sanitized diagnostics are kept, and they are not anonymized.
- Local output files leave out addresses unless the user passes `--include-address`, and CSV cells are escaped against spreadsheet formulas. In the text view, a parsed address is shown in the redacted log form (`a***@example.com`) and an unparseable input not at all; `--include-address` shows it in full, with terminal control characters escaped.
- Addresses passed as shell arguments can remain in shell history or process listings; use files for sensitive input.

## 3. Retention defaults

Service retention and local files are separate. The service policies are:

| Data | Policy |
| --- | --- |
| Retained plaintext request or completed job input | Expires after 24 hours; a retention sweep removes it |
| Raw SMTP replies | Not retained; there is no encrypted archive, so there is nothing to encrypt |
| Result history | Off by default; at most 30 days when enabled |
| Cached verdicts | Expire by the TTL of the evidence that decided them |
| HMAC and aggregate audit data | Defined by policy, with deletion support |
| In-memory audit events | Bounded by the size of the audit ring |

These are separate classes. A DNS or verdict TTL describes how fresh evidence is; it is never used as a job or audit retention. Account and billing data managed outside this project need their own policies.

`RetentionScheduler` runs bounded sweeps at the configured interval, and operators can run the same sweep with `VerificationStack.run_retention`. Retention times are expiry cutoffs, not exact deletion times: deletion can happen up to one interval later, and longer if a sweep fails or the process stops. Failures are reported and audited, and an unfinished sweep continues on the next run.

## 4. Redaction

Logs and displays may mask a local part (`alice@example.com` becomes `a***@example.com`), but the domain, or even the first character, can still identify a person. Redaction protects against accidental exposure. It is not anonymization and does not justify longer retention or public disclosure.

## 5. HMAC

Correlation uses HMAC-SHA-256 with its own secret key, separate from any encryption key, over a versioned, normalized target. `security/identifiers.py` defines the construction. The canonicalization version is part of the HMAC input, not a column beside it, so two canonical forms can never produce the same digest; a verdict store written before the version existed (schema 2) is refused.

A plain hash of an address is not enough, because possible addresses are easy to guess. HMAC values are still account-related operational data and follow the retention and deletion policy.

## 6. Access

Authentication decides which account owns a job or stored result. Results and job state are visible only to that account; request parameters never grant access to another account's data. The public result never contains secrets or raw diagnostic replies, and administrative access to sensitive diagnostics must be restricted and logged.

There is no public route for deleting an account. Account deletion is an operator operation.

## 7. Deletion

`VerificationStack.delete_account_data(account)` runs `AccountDeletionService`. Records are deleted by owning account, not by email address: two accounts that checked the same address own separate results.

The protocol stops in-flight writes, including writes from other service instances, from recreating deleted data:

1. Advance the account's durable generation in `AccountStateStore` before removing anything.
2. Raise each persistent store's local generation fence.
3. Delete the account's records in each store.
4. Report every store that could not be processed. A partial failure is never reported as complete, and the operation can be retried.

Every write to a persistent account-owned store checks the generation inside the same transaction as the write. Checking `accounts.db` and then writing to another SQLite database without that local fence would let a deleted record come back in the gap.

Each persistent store is bound to one account-state authority; a mismatched authority or an unsupported old schema is refused. A persistent verdict or job store requires `account_state_path` to be configured. In-memory suspension and tombstones help local cleanup but do not replace durable fencing across processes.

### Stores covered

| Store | Deletion support | In the shipped stack |
| --- | --- | --- |
| Verdict cache/store | Implemented | Composed |
| Job store, idempotency and result projections | Implemented | Composed |
| In-process job registry | Implemented | Composed |
| Active batch store and results | Implemented | Not composed |

Active batch is not reachable from the CLI. An operator who composes it must give the batch store the same account-state authority and include it in the same deletion service.

Limits: deletion is not atomic across several SQLite stores and an in-memory registry, and partial failures are reported for recovery. Logical deletion does not erase existing backups, snapshots, or old WAL and journal copies. The batch SQLite adapter enables `secure_delete`, which is still not forensic erasure. Operators manage storage-level and backup retention themselves.

## Local CLI files

The local `check`, `batch`, and `expand` commands create no job database and no resume checkpoint. Users control the retention of and access to their input files, candidate files, standard output, shell history, and saved results.

With `--output`, results go to a private temporary file in the destination directory, which replaces the destination only after the run completes. Normal errors and cancellation remove the temporary file; a forced kill can leave `.emailcheck-*` files to review and delete. Standard output may be incomplete if interrupted.

Local deduplication uses short-lived keyed digests. `--start-row` starts a new passive run and does not recover stored addresses or earlier DNS results.

## Operator responsibilities

Restrict access to files and backups, configure retention for each deployment, test deletion and recovery, and monitor failures. Do not enable active SMTP without documented authorization, a sender identity, destination controls, rate limits, TLS, and incident procedures. Get legal and privacy review before production use, especially when processing other people's addresses or data across jurisdictions.

See the [readiness checklist](readiness-checklist.md) and the [privacy deletion runbook](runbooks/privacy-deletion.md).
