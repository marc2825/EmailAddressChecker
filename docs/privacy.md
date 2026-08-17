# Privacy and data handling

## 1. Data categories

- submitted address;
- normalized domain;
- target HMAC;
- account and API-key identifiers;
- DNS evidence;
- SMTP structured evidence;
- bounded raw diagnostic;
- timestamps and latency;
- abuse features.

## 2. Data minimization

Default behavior:

- process the plaintext address only for the active job;
- redact in ordinary logs;
- use HMAC for correlation;
- aggregate metrics by domain/MX and reason;
- do not keep raw protocol text unless debugging retention is explicitly enabled.

## 3. Retention defaults

- plaintext request: 24 hours;
- encrypted raw SMTP diagnostic: 24 hours. **Nothing is retained today**, so
  there is nothing to encrypt: Phase 4 keeps a bounded sanitized diagnostic and
  no raw reply, and section 2's default is not to keep raw protocol text unless
  debugging retention is explicitly enabled. Implementing the encryption needs a
  cryptographic dependency, its own ADR, and a Phase permitted to install one;
  ADR 0016 records it as a Phase 8 stop condition. The privacy-preserving half
  of this line holds by absence, which is the stronger form;
- result history: disabled by default or 30 days when explicitly enabled;
- HMAC and aggregate audit data: policy-defined, with deletion support;
- account and billing records: separate policy.

## 4. Redaction

Examples:

```text
alice@example.com → a***@example.com
a@example.com     → *@example.com
```

Do not rely on redaction as anonymization. Domain and local-part patterns can
remain identifying.

## 5. HMAC

Use a secret key distinct from encryption keys.

```text
HMAC-SHA-256(key, canonical_input_version || normalized_target)
```

Store the canonicalization version. A plain unsalted hash is not sufficient
because addresses are guessable.

`security/identifiers.py` implements this. The version is part of the HMAC
**input** rather than a column beside it, so two canonicalizations cannot
collide onto one digest. Adding it changed every digest this project produces,
once, and `adapters/storage/sqlite_store.py` moved its schema version in the
same change even though no column did: a store whose rows have all become
unreachable looks like a cache that never hits, which is a worse failure than
one that refuses to open. ADR 0016.

## 6. Access

- raw evidence administrator-only;
- account users see their safe normalized results;
- support access is logged;
- secret material is never returned;
- API errors do not contain raw remote replies.

## 7. Deletion

**Scheduled since Remediation B.** `RetentionScheduler` runs the sweep on
`RetentionSettings.interval_seconds` for every profile that owns persistent
service state, and `VerificationStack.run_retention` is the operator trigger for
the same operation. The effective deletion time is therefore the retention
cutoff **plus at most one scheduling interval**; the windows below are cutoffs,
not wall-clock guarantees.

**Logical deletion, not physical erasure.** A sweep deletes rows and sets
retained plaintext to `NULL`. It does not overwrite SQLite free pages, rewrite
the write-ahead log, or reach a backup taken before it ran. Anyone who needs
those guarantees needs storage-level or backup-level erasure, which this project
does not perform and does not claim.

`application/retention.py` implements this, and keeps **three retentions
separate**: a cached verdict expires on its own `expires_at` (ADR 0015, from
`docs/requirements.md` section 13), a finished job record lives
`job_retention_seconds` — this document's 24 hours — and an audit event lives
as long as the ring holds it. Section 13's TTLs price *evidence classes*, so
using one as a job or log retention would apply a deliverability-freshness rule
to a privacy question.

A sweep is bounded per run and reports whether more remain, so a backlog is
cleared over several runs rather than in one statement holding a write lock. A
failure is counted and audited rather than propagated: a sweep that raised into
a scheduler would stop the schedule.

Implement and test:

- scheduled expiry;
- account-requested deletion;
- API-key revocation;
- deletion of plaintext separate from aggregate metrics;
- deletion failure alerting.

Obtain legal review before commercial or cross-border production use.
