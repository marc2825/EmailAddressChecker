# Privacy and data handling

EmailAddressChecker processes potentially identifying email addresses and information about their domains. It aims to minimize retention and prevent network observations from leaking into logs, error responses, or unrelated accounts.

This page describes the software's data-handling boundaries. It is **not** a claim of regulatory compliance or secure physical erasure. For the abuse model and operator responsibilities, see the [threat model](threat-model.md), [security policy](../SECURITY.md), and [operations guide](operations.md).

## 1. Data categories

| Data | Purpose | Handling |
| --- | --- | --- |
| Submitted address | Syntax and delivery assessment | Processed for the request; not written to routine logs |
| Normalized domain and MX | DNS routing and destination controls | May appear in bounded domain/MX metrics and caches |
| Target HMAC | Internal correlation and deduplication | Keyed digest, not a plain hash of an address |
| Account and API-key identities | Authentication, ownership, quotas | Scoped to the authenticated principal |
| DNS and structured SMTP evidence | Conservative verdict | Normalized and bounded; raw protocol text is not public output |
| Jobs, results, timestamps, audit metadata | Asynchronous operations and safety controls | Subject to applicable store and retention policy |
| Local CLI files | User-requested inputs and results | Owned and retained by the user, outside service retention |

Addresses and domain names may be personal data. HMAC identifiers, redaction, and aggregation reduce exposure but should not be presented as anonymization.

## 2. Data minimization

- Local checks use DNS and **never contact SMTP**. Offline candidate expansion contacts neither DNS nor SMTP.
- Public results expose approved statuses, reason codes, and safe summaries, not raw SMTP transcripts or untrusted server messages.
- Ordinary logs and metrics do not contain complete email addresses, raw credentials, or network-library exception text.
- Raw diagnostic replies are **not retained by the current stack**. Bounded, sanitized diagnostic information is not a substitute for anonymization.
- Local output omits addresses unless the user explicitly selects `--include-address`. CSV result cells escape spreadsheet formula prefixes.
- CLI addresses passed as shell arguments may remain in shell history or process listings; use files for sensitive inputs.

## 3. Retention defaults

Service-side retention and local files are distinct. The documented service policies include:

| Data | Policy / boundary |
| --- | --- |
| Retained plaintext request or completed job input | 24-hour expiry cutoff under the relevant service policy; actual removal depends on a retention sweep |
| Raw SMTP replies | Not retained in the shipped stack; no encrypted raw-reply archive is implemented |
| Result history | Disabled by default, or limited to 30 days when explicitly enabled |
| Cached verdicts | Expire according to evidence/cache-specific TTLs |
| HMAC, aggregate audit data | Policy-defined, with deletion support |
| In-memory audit events | Bounded by the audit ring's capacity |

These are separate data classes: a DNS cache TTL is **not** a job-retention deadline, and neither is an audit-retention promise. Account and billing data, if managed outside this project, require their own policies.

`RetentionScheduler` runs bounded sweeps at the configured interval; operators can invoke the same operation with `VerificationStack.run_retention`. Retention timestamps are expiry cutoffs, **not an exact wall-clock deletion guarantee**: actual scheduled deletion can occur up to a scheduling interval later, and failures or a stopped process can delay it further. Failures are reported and auditable; unfinished sweeps continue on subsequent runs.

## 4. Redaction

Routine presentation may mask a local part (for example, `alice@example.com` as `a***@example.com`), but the remaining domain or even an initial character can still identify a person. Redaction is a defense against accidental exposure, **not anonymization**; it does not justify unbounded retention or public disclosure.

## 5. HMAC

Correlation uses HMAC-SHA-256 with a dedicated secret key, distinct from any encryption key over a versioned, normalized target representation. `security/identifiers.py` defines the construction and its canonicalization version. The version is included in the authenticated input, not merely stored beside the digest.

A plain hash of an email address is insufficient because possible addresses are easy to guess. HMAC output is still account-related operational data and remains subject to the appropriate retention and deletion policy.

## 6. Access

Authentication establishes the account that owns a job or stored result. Results and job state are scoped to that owner; request parameters do not grant access to another account's data. Secret material and raw diagnostic replies are not returned through the public result contract. Administrative access to any sensitive diagnostic material must be restricted and logged.

The current application does not expose a public administrative account-deletion route. Account deletion is an operator-level service operation.

## 7. Deletion

`VerificationStack.delete_account_data(account)` invokes `AccountDeletionService`. Records are deleted by **owning account**, not by email target: two accounts checking the same address own separate results.

The deletion protocol protects against in-flight writes, including those from other service instances:

1. Advance the account's durable generation in `AccountStateStore` **before** removing records.
2. Raise each persistent store's local account-generation fence.
3. Delete that account's owned records in each store.
4. Report every store that could not be processed. A partial failure is not reported as complete; the operation may be retried.

A write to a persistent account-owned store must validate the generation **within the same store transaction as that write**. Checking `accounts.db` and then writing to another SQLite database without a local transactional fence would permit a deleted record to be recreated during the gap.

Each persistent store is bound to one account-state authority; incompatible authorities and unsupported old schemas are refused. A configured persistent verdict or job store requires a configured `account_state_path`. In-memory suspension and tombstones help local cleanup but do not replace durable cross-process fencing.

### Stores covered

| Store | Deletion support | In the shipped stack |
| --- | --- | --- |
| Verdict cache/store | Implemented | Composed |
| Job store, idempotency and result projections | Implemented | Composed |
| In-process job registry | Implemented | Composed |
| Internal active batch store and artifacts | Implemented | **Not composed** |

The internal active batch subsystem is not exposed through the public CLI/API. If an operator composes it in a separate deployment, the batch store must use the **same** account-state authority and participate in the same deletion service.

**Limits of the guarantee:** deletion is not atomic across multiple SQLite stores and an in-memory registry; partial failures are reported for recovery. Logical deletion does not erase preexisting backups, snapshots, or historical WAL/journal copies. The batch SQLite adapter enables `secure_delete` for its connections, but this is not a forensic-erasure guarantee. Operators must manage storage-level and backup retention separately.

## Local passive CLI artifacts

The local `check`, `batch`, and `expand` commands do not create a persistent job database or a durable resume checkpoint. Users control retention and access for input files, generated candidate files, stdout, shell history, and explicitly saved results.

When `--output` is used, results are written to a private temporary file in the destination directory and replace the destination only after successful completion. Normal errors and cancellation clean up the temporary file; a forced process termination may leave `.emailcheck-*` files for the user to review and remove. Standard output may be partial if interrupted.

Local deduplication uses ephemeral keyed digests. `--start-row` starts a new passive run; it does not recover stored addresses or previous DNS results.

## Operator responsibilities

Restrict access to files and backups, configure retention for each deployment, test deletion and recovery, and monitor failures. Do not enable active SMTP without documented authorization, sender identity, destination controls, rate limits, TLS, and incident procedures. Obtain appropriate legal and privacy review before production use, particularly when processing other people's addresses or data across jurisdictions.

See the [readiness checklist](readiness-checklist.md) and [privacy deletion runbook](runbooks/privacy-deletion.md).
