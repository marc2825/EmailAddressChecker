# ADR 0020: Offline expansion, local passive orchestration, and distribution

- Status: Accepted
- Date: 2026-10-22
- Updates: ADR 0018's CLI exclusion only for local passive processing.

The active BatchService wraps authenticated, approved, durable JobService work.
Connecting it to the local CLI would import Active authorization and retention
obligations into a passive command. It remains uncomposed and API uploads remain
absent. New `passive_rows` instead calls AddressVerificationService with
`active=False`; the CLI constructs a stack without an SMTP component. It reuses
BatchLimits, the address parser/identity, admission, AbuseGuard, public result
projection, classifier and DNS policy. Existing persistence/deletion code remains.

Expansion is a separate offline iterator. Product size is computed before product
iteration, default 10,000 and hard ceiling BatchLimits.MAX_ROWS (50,000). Pools,
patterns and input bytes have independent bounds. Pool dedup is stable; colliding
concatenations are suppressed with bounded SHA-256 digests. Unicode domains retain
IDNA handling; unsupported SMTPUTF8 local parts are refused. No Active bulk or
remote expansion path exists. Future one-command checking must compose this
iterator with passive_rows, not JobService.

Local results preserve the aggregator's statuses and public field allowlist.
Operational refusals have no status. Row ordinals correlate results with input;
addresses require explicit opt-in and result CSV escapes formula cells. Generated
CSV refuses formula-like addresses to preserve round-trip identity. Output files
are private temporary files atomically replaced on success, including Ctrl-C
cleanup. A hard kill may leave a temporary file; no crash-resume claim is made.
`--start-row` is a new passive suffix run; persistent Active resume remains separate.

The DNS adapter reuses InMemoryDNSCache, with separate record-type keys, bounded
entry counts, per-key locks coalescing concurrent requests, and remaining TTLs
on hits. No TTL is restarted by reading a cached answer. DNS sharing crosses
accounts only for public domain records, never verdicts or address identity.

*Amended 2026-11-16 (issue #2):* the original design used a fixed pool of 64
striped locks held across the upstream query, so a slow lookup (up to the
resolver timeout) delayed unrelated keys that shared its stripe. Locks are now
created per key and dropped when no caller holds or awaits them: identical
concurrent lookups still reach the resolver once, different keys never wait on
each other, and the lock table is bounded by in-flight callers. Cancellation
stays local to the cancelled caller.

TOML exposes budgets only. Defaults of existing programmatic Deployment remain
compatible; an explicitly configured passive quota gets an independent store and
shares administrative switches. Batch rows and single checks spend the ordinary
service budgets. The CLI example raises only the passive caller budget. SMTP
pacing now constrains MX hosts across recipient domains as well as domains; one
acquisition has one wait deadline and cancellation releases all held counters.
Temporary replies defer subsequent domain/MX work for 60 seconds without replay.
Spent buckets and cooldowns are not evicted to reset capacity; exhaustion refuses
new destination state. Active retry and recipient-touch semantics stay unchanged.

`worker_processes` must be one. This cannot detect separate deployments launched
by another process manager: no global multi-process enforcement is claimed.
Future shared stores need atomic all-layer consumption, monotonic lease expiry,
fail-closed availability, shared kill switches, and fencing across worker crashes.
The existing QuotaStore/RateLimiter ports are the integration seams; SQLite job
identity and account deletion fences do not implement shared pacing.

The distribution is `email-address-checker` 0.1.0. `emailcheck` remains the import
and CLI. Hatchling reads a single version from __init__.py. Runtime datasets are
package resources. Source artifacts use an explicit allowlist; test TLS keys are
public throwaway fixtures documented in tests/fixtures/tls/README.md, not secrets.
Human-approved GitHub Environments and explicitly enabled repository settings
are prerequisites to OIDC publishing; creating workflow files publishes nothing.
