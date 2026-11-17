# Beta evaluation report template

Copy this file for each beta run, fill it in, and keep the machine-readable `BetaReport` JSON beside it. Every section is filled from the `BetaReport` that `application/beta.py` produces, so the text and the JSON cannot drift; a name in `code font` is the field to read.

---

## 0. What this report is not

Read this section before any number below. Every mistake this report can cause comes from reading too much into it.

- This is not an accuracy measurement. The project does not prove that a mailbox exists, is owned, is in use, or will accept delivery (`docs/requirements.md` section 1), and a beta does not change that. The harness reports `consistent`, `contradicts`, `inconclusive`, and `not_applicable`, and has no value called `correct`.
- `consistent` means two observations point the same way, not that either is right. An arranged mailbox answering `likely_deliverable` is agreement between an arrangement and an SMTP reply.
- The sample is tiny and represents nothing. The corpus is owned or explicitly authorized infrastructure, at most 50 targets per run, not a random sample of the internet, a provider, or a customer list. No rate computed here generalizes.
- The controlled truth is what an operator arranged, and operators can be wrong about their own arrangements. A `contradicts` row means checking both sides.
- This report makes no policy decision. It does not approve production use, change a `TLSPolicy`, lift a deployment gate, or authorize a wider beta; people make those decisions and record them elsewhere.

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

If `dry_run` is `true`, no external connection was made and every row below is a refusal, not a measurement. Say so in the first sentence of the summary.

## 2. Versions

Results can be compared with later runs only if these are recorded. The report reads them from the production objects.

| Field | Value | Source |
| --- | --- | --- |
| Aggregation ruleset | | `ruleset` |
| Canonical input version | | `canonical_input_version` |
| Dataset versions | | `dataset_versions` |

Three datasets report `unavailable-by-declaration` (see `src/emailcheck/data/passive/README.md` and `docs/data-sources.md`). They produced no evidence in either direction during this run, so a missing disposable or free-mail flag in any row is not a negative finding.

## 3. Corpus

| Field | Value | Source |
| --- | --- | --- |
| Targets in corpus | | `corpus_size` |
| Targets selected for this run | | `selected_targets` |
| By controlled truth | | `corpus_by_truth` |
| Run truncated | | `truncated` |

No address appears anywhere in this report. Rows are keyed by `target_digest`, an HMAC; an operator matches it against their own corpus. The report cannot be used to recover an address and must not be annotated with addresses when it is circulated.

## 4. Execution

Fill this in before section 5, because it is the denominator: a distribution over eleven completed targets out of fifty selected is a different finding from one over fifty.

`execution_summary` places every selected target in exactly one state.

| Execution state | Count | Meaning |
| --- | --- | --- |
| `completed` | | The verification reached a verdict. The only state with a `status`. |
| `refused` | | A local operational refusal: admission, a budget, a kill switch, or the harness. Not a fact about the address. |
| `timed_out` | | Started, so a remote host was contacted, but the run's budget expired before an answer. No verdict. |
| `not_run` | | Never started: the budget ran out first, or this was a dry run. |
| Total | | must equal `selected_targets` |

If `truncated` is `true`, say so in the first sentence of the summary. A truncated run is not a smaller complete run: the targets it missed were not selected against, they ran out of time, so any rate over the run describes an arbitrary prefix of the corpus.

Each `timed_out` row is an outbound contact with no recorded answer. List their digests; they count toward this run's outbound activity even though they add nothing to section 5.

## 5. Deliverability outcomes

`status_summary` gives the distribution over `completed` rows only. Execution states are not statuses and never appear here; `not_run` is not a kind of `unknown`.

| Status | Count | Share of completed |
| --- | --- | --- |
| `likely_deliverable` | | |
| `invalid` | | |
| `temporary_unknown` | | |
| `unknown` | | |

### Agreement

| Agreement | Count | Meaning |
| --- | --- | --- |
| `consistent` | | The verdict pointed the same way as the arrangement. |
| `contradicts` | | It pointed the other way. Audit every one. |
| `inconclusive` | | The verdict was `unknown` or `temporary_unknown`, so there is nothing to compare. |
| `not_applicable` | | The arrangement predicts no recipient answer (accept-all, Null MX), or no verification completed. |

These four strings are the whole vocabulary; a report using another word for agreement is not this report.

A high `inconclusive` count is not a failure. Ambiguous evidence must resolve to `unknown` or `temporary_unknown` (`CONTRIBUTING.md`), so a run against providers that answer opaquely should produce them.

### Contradictions

`contradictions` lists them. Write one subsection per row and omit none:

- `target_digest`:
- Controlled truth:
- Status, confidence, `primary_reason`:
- `stage_reached`, `tls_negotiated`, `tls_reason`:
- What was re-checked on the arrangement side:
- Conclusion (defect, arrangement error, or unexplained):
- Follow-up: link the investigation; use [runbooks/false-invalid-investigation.md](runbooks/false-invalid-investigation.md) whenever an arranged receiving target answered `invalid`.

A `contradicts` row where the arrangement was `owned_mailbox` and the status was `invalid` is the most serious result this project can produce. Escalate it separately, not as a line in a table.

## 6. TLS

From `tls_summary`, which counts `tls_reason` across the rows. This section exists for the measurement obligation in ADR 0009.

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

`not_offered` is its own category and must never be merged into a failure bucket. A server that advertises no `STARTTLS` has failed at nothing; it has stated what it supports, and counting it as a handshake failure would inflate a "TLS is broken" number with servers behaving as configured.

Every reason here is about the transport, never about the recipient. No row in this section is evidence about a mailbox.

### What one row's TLS value describes

A row carries the TLS detail of the preferred reachable exchanger, not a per-attempt transcript. One verification can try several exchangers, because it falls through to the next candidate on a failure before the recipient stage; `tls_reason` is from the earliest attempt, the host that MX preference names first.

This table is therefore a distribution over verifications, not over exchangers, and it is not a complete per-attempt TLS measurement. A domain whose primary exchanger offers no `STARTTLS` and whose secondary does is counted as `not_offered`. Wherever these numbers are carried forward, say so, and treat the `not_offered` count as an upper bound on domains with no `STARTTLS` anywhere.

The gap cannot be closed from this report: no raw SMTP or TLS transcript is retained, by design (`docs/privacy.md` sections 2 and 3). Per-attempt measurement would need instrumentation on the production path during an authorized run.

> **Policy decision: NOT made by this report.**
>
> This section measures what happened. It does not decide whether `TLSPolicy.REQUIRED` stays as it is, and filling it in does not resolve ADR 0009's open obligation. Changing a TLS policy needs its own ADR, its own review, and a measurement over a representative population, which a corpus of at most 50 owned targets is not, by construction. In a policy discussion, cite this report as one small controlled observation.

## 7. Session behaviour

| Metric | Value | Source |
| --- | --- | --- |
| Median session time | | `elapsed_milliseconds` across completed rows |
| P95 session time | | `elapsed_milliseconds` across completed rows |
| Connections per job | | **not measured by this report** (see below) |
| Stages reached | | `stage_reached` distribution |
| Remote policy block rate | | rows whose reason is a policy block |
| Temporary retry outcome | | rows that retried, and what changed |
| Abuse and complaint events | | from the incident log, not from this report |

Connections per job is not in this schema, and no test in this repository measures it: the loopback transport test counts connection pairs it created itself, and the scripted-server test counts `RCPT TO`, not connections. Write "not measured" until there is instrumentation on the production path during an authorized run; the number of attempted rows assumes one connection per verification instead of observing it.

Timings from a corpus this small are anecdotes, not percentiles. Report them, but do not size capacity from them.

## 8. Refusals

Rows whose `execution_state` is `refused` never reached a destination, and `refused` carries the category. Group them and confirm that each is the harness behaving correctly. A refusal is not a failed measurement; it is the allowlist and the budgets working.

## 9. Conclusions and follow-up

- What was learned, without overstating the limits in section 0:
- Defects found, with the test that now pins each:
- Changes to the corpus or the arrangements:
- Whether another run is warranted, and what it would change:

## 10. What this report does not authorize

State every time:

- Phase 8 is still "ready for manual gate", not "production approved".
- Every deployment gate in [readiness-checklist.md](readiness-checklist.md) still needs human verification, and this report verifies none of them.
- A person sets `BetaAuthorization.external_probing_authorized` for each run; nothing in this report sets or implies it.
- This report does not resolve ADR 0009's TLS obligation.

---

### Attachments

- `beta-report-<label>.json`: the `BetaReport` as JSON, unedited.
- The corpus authorization records, kept separately. Never attach a file containing target addresses to a circulated report.
