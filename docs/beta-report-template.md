# Beta evaluation report — template

`prompts/08-limited-beta.md` work item 7. Copy this file per beta run, fill it
in, and keep the machine-readable `BetaReport` JSON beside it.

Every section below is filled from `application/beta.py`'s `BetaReport` — the
same object the harness produces — so the narrative and the JSON cannot drift.
Where a field name appears in `code font`, that is the field to read.

---

## 0. What this report is not

**Read this section before any number in this document.** It is first because
every mistake this report can cause is a mistake of over-reading.

- **This is not an accuracy measurement.** `docs/requirements.md` section 1 says
  this project does not prove that a mailbox exists, is owned, is in use, or
  will accept delivery. A beta does not change that. The harness therefore
  reports `consistent`, `contradicts`, `inconclusive`, and `not_applicable` —
  and deliberately has no value called `correct`.
- **`consistent` is two observations pointing the same way**, not a proof that
  either was right. An arranged mailbox answering `likely_deliverable` is
  agreement between an arrangement and an SMTP reply.
- **The sample is tiny and is not a sample of anything.** The corpus is owned or
  explicitly authorized infrastructure, capped at 50 targets per run. It is not
  a random sample of the internet, of any provider, or of any customer's list.
  No rate computed here generalizes.
- **The controlled truth is what an operator arranged**, and an operator can be
  wrong about their own arrangement. A `contradicts` row is a prompt to check
  both sides.
- **This report makes no policy decision.** Nothing in it approves production
  use, changes a `TLSPolicy`, lifts a deployment gate, or authorizes a wider
  beta. Those are human decisions recorded elsewhere.

---

## 1. Run identity

| Field | Value | Source |
| --- | --- | --- |
| Run label | | operator |
| Started (UTC) | | `started_at` |
| Finished (UTC) | | `finished_at` |
| Dry run | | `dry_run` |
| Operator | | operator |
| Authorization reference | | corpus entries' `authorization` |

**If `dry_run` is `true`, no external connection was made** and every row below
is a refusal, not a measurement. Say so in one sentence at the top of the
summary rather than leaving a reader to notice it in a table.

## 2. Versions

A result whose ruleset and dataset versions nobody recorded cannot be compared
with a later one. These come from the report, which reads them from the
production objects.

| Field | Value | Source |
| --- | --- | --- |
| Aggregation ruleset | | `ruleset` |
| Canonical input version | | `canonical_input_version` |
| Dataset versions | | `dataset_versions` |

Three datasets report `unavailable-by-declaration`. That is the Phase 8
declaration in `src/emailcheck/data/passive/README.md` and ADR 0007, and it means those signals
produced **no evidence in either direction** during this run. Do not read a
missing disposable or free-mail flag in any row as a negative finding.

## 3. Corpus

| Field | Value | Source |
| --- | --- | --- |
| Targets in corpus | | `corpus_size` |
| Targets selected for this run | | `selected_targets` |
| By controlled truth | | `corpus_by_truth` |
| Run truncated | | `truncated` |

**No address appears anywhere in this report.** Rows are keyed by
`target_digest`, an HMAC. To look one up, an operator matches the digest against
their own corpus; the report cannot be used to recover the address, and it must
not be annotated with addresses when it is circulated.

## 4. Execution

**Fill this in before section 5.** It is the denominator: a deliverability
distribution over eleven completed targets out of fifty selected is a different
document from one over fifty.

`execution_summary` gives it, and it sums to `selected_targets` exactly — every
selected target lands in one state and none is lost.

| Execution state | Count | What it means |
| --- | --- | --- |
| `completed` | | The verification ran to a verdict. The only state with a `status`. |
| `refused` | | A local operational refusal — admission, a budget, a kill switch, the harness. Not a fact about the address. |
| `timed_out` | | **Started, so a remote host was contacted**, and the run's budget expired before an answer. No verdict exists. |
| `not_run` | | Never started. The budget expired first, or this was a dry run. |
| **Total** | | must equal `selected_targets` |

If `truncated` is `true`, say so in the first sentence of the summary. A
truncated run is not a smaller complete run: the targets it did not reach were
not selected against, they simply ran out of time, and any rate computed over
them is a rate over an arbitrary prefix of the corpus.

Every `timed_out` row is an **outbound contact with no recorded answer**. List
their digests. They count toward this run's outbound activity even though they
contribute nothing to section 5.

## 5. Deliverability outcomes

`status_summary` gives the distribution, **over `completed` rows only**.
Execution states are not statuses and never appear here — `not_run` is not a
kind of `unknown`.

| Status | Count | Share of completed |
| --- | --- | --- |
| `likely_deliverable` | | |
| `invalid` | | |
| `temporary_unknown` | | |
| `unknown` | | |

### Agreement

| Agreement | Count | What it means |
| --- | --- | --- |
| `consistent` | | The verdict pointed the same way as the arrangement. |
| `contradicts` | | It pointed the other way. **Audit every one.** |
| `inconclusive` | | The verdict was `unknown` or `temporary_unknown`; nothing to compare. |
| `not_applicable` | | The arrangement predicts no recipient answer — accept-all and Null MX — or no verification completed. |

These four strings are the whole published vocabulary. A report using any other
word for agreement is not this report.

A high `inconclusive` count is not a failure. `AGENTS.md` requires ambiguous
evidence to resolve to `unknown` or `temporary_unknown`, so a run against
providers that answer opaquely *should* produce them, and a run that produced
none would be the surprising result.

### Contradictions

`contradictions` lists them. One subsection per row, and none may be omitted:

- `target_digest`:
- Controlled truth:
- Status, confidence, `primary_reason`:
- `stage_reached`, `tls_negotiated`, `tls_reason`:
- What was re-checked on the arrangement side:
- Conclusion — defect, arrangement error, or unexplained:
- Follow-up: link the investigation, using
  [runbooks/false-invalid-investigation.md](runbooks/false-invalid-investigation.md)
  for any contradiction where an arranged-receiving target answered `invalid`.

A `contradicts` row where the arrangement was `owned_mailbox` and the status was
`invalid` is the most serious result this project can produce. It gets its own
escalation, not a line in a table.

## 6. TLS

From `tls_summary`, which counts `tls_reason` across the rows. ADR 0009's
measurement obligation is what this section exists for.

| Outcome | Count | Share |
| --- | --- | --- |
| `negotiated` | | |
| `not_offered` | | |
| `command_rejected` | | |
| `handshake_failed` | | |
| `certificate_invalid` | | |
| `hostname_mismatch` | | |
| `timeout` | | |
| `peer_changed` | | |

**`not_offered` is its own category and must never be merged into a failure bucket.**
A server that advertises no `STARTTLS` has not failed at anything: it
has told you what it supports. Counting it as a handshake failure would inflate
a "TLS is broken" number with servers that are behaving exactly as configured,
and it is the one distinction this section exists to preserve.

Each of these reasons is about the transport and **never about the recipient**.
No row in this section is evidence about any mailbox.

### What one row's TLS value actually describes

**A row carries the preferred reachable exchanger's recorded TLS detail, not a
per-attempt transcript.** One verification may touch more than one exchanger:
Phase 4E falls through to the next candidate on a failure *before* the recipient
stage, so a verification that ends in a recipient answer can carry evidence from
two or three attempts. `tls_reason` on the row is the earliest of those — the
host MX preference names first, and the one a receiving operator would recognise
as the one approached.

So this table is a distribution over **verifications**, not over exchangers, and
it is **not a complete per-attempt TLS measurement**. A domain whose primary
exchanger offers no `STARTTLS` and whose secondary does is counted here as
`not_offered`, and this report cannot tell you the secondary offered it.

Any representative `tls_reason = not_offered` analysis has to account for that
aggregation. State it explicitly wherever this section's numbers are carried
forward, and treat the `not_offered` count as an upper bound on domains with no
`STARTTLS` anywhere rather than as a measurement of one.

Nothing further is available to close the gap from this report: **no raw SMTP or
TLS transcript is retained**, by design — `docs/privacy.md` sections 2 and 3
keep raw protocol text out, and Phase 4 keeps a bounded sanitized diagnostic
instead. Measuring per attempt would need instrumentation added on the
production path under an authorized run, not a different reading of this table.

> **Policy decision: NOT made by this report.**
>
> This section measures what happened. It does not decide whether
> `TLSPolicy.REQUIRED` stays as it is, and filling it in does not resolve ADR
> 0009's open obligation. Changing a TLS policy needs its own ADR, its own
> review, and a measurement over a representative population — which a corpus of
> at most 50 owned targets is not, by construction. If this report is being
> cited in a policy discussion, cite it as one small controlled observation.

## 7. Session behaviour

`prompts/08-limited-beta.md`'s beta metrics, as far as this run can speak to
them:

| Metric | Value | Source |
| --- | --- | --- |
| Median session time | | `elapsed_milliseconds` across completed rows |
| P95 session time | | `elapsed_milliseconds` across completed rows |
| Connections per job | | **not measured by this report** — see below |
| Stages reached | | `stage_reached` distribution |
| Remote policy block rate | | rows whose reason is a policy block |
| Temporary retry outcome | | rows that retried, and what changed |
| Abuse and complaint events | | from the incident log, not from this report |

**`connections per job` is not in this schema and no test in this repository
measures it.** The transport-level loopback file counts connection pairs it
created itself, which is fixture accounting; the scripted-server file counts
`RCPT TO`, not connections. Populating this row needs instrumentation on the
production path during an authorized run — until then, write "not measured"
rather than the number of attempted rows, which assumes one connection per
verification instead of observing it.

Timings from a corpus of this size are anecdotes with error bars, not
percentiles. Report them; do not size capacity from them.

## 8. Refusals

Rows whose `execution_state` is `refused` never reached a destination; `refused`
carries the refusal's category. Group them, and confirm each is the harness
behaving correctly. A refusal is not a failed measurement; it is the allowlist
and the budgets working.

## 9. Conclusions and follow-up

- What was learned, in sentences that do not overstate section 0's limits:
- Defects found, with the test that now pins each:
- Changes to the corpus or the arrangements:
- Whether another run is warranted, and what it would change:

## 10. What this report does not authorize

State explicitly, every time:

- Phase 8 remains **"ready for manual gate"**, not "production approved".
- Every deployment gate in [readiness-checklist.md](readiness-checklist.md)
  still requires human verification, and this report verifies none of them.
- `BetaAuthorization.external_probing_authorized` is set by a person, per run,
  and nothing in this report sets or implies it.
- ADR 0009's TLS obligation is not resolved by this report.

---

### Attachments

- `beta-report-<label>.json` — the `BetaReport` as JSON, unedited.
- The corpus authorization records, held separately. **Do not attach a file
  containing the target addresses to a circulated report.**
