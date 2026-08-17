# Status and evidence model

## 1. Separation of concerns

The system has four independent concepts:

1. **check result**: what one layer observed;
2. **reason code**: normalized interpretation;
3. **risk flag**: policy-relevant attribute unrelated to deliverability truth;
4. **verdict**: conservative aggregate.

Do not store only the final status.

Asynchronous job state is outside these four concepts. `JobState`,
`JobAdmission`, and `JobFailure` describe this service's operation and executor
handoff; none is mailbox evidence and none may be converted into a
deliverability `Status`. In particular, `admission_failed` and `interrupted`
carry no mailbox result.

## 2. Statuses

### likely_deliverable

Positive delivery-stage evidence exists and no stronger contradictory evidence
exists. This is not mailbox existence proof.

### invalid

Strong, target-specific, non-temporary evidence indicates the input cannot be
delivered as addressed.

Examples:

- invalid supported syntax;
- NXDOMAIN;
- Null MX;
- no MX and no implicit A/AAAA route;
- RCPT-stage enhanced code explicitly indicating recipient does not exist.

### A note on `no_message_data_sent`

It is a **safety assertion**, not a status, a confidence, or a reason, and
nothing in this document derives one from the other. A malformed or missing
value at the remote boundary is a protocol-validation failure — never
`Status.INVALID` or any other published status, because a remote server's broken
JSON says nothing about an address.

### temporary_unknown

Evidence explicitly indicates a condition expected to change.

Examples:

- DNS SERVFAIL;
- SMTP 4xx;
- bounded connection timeout when service health is normal;
- explicitly reported temporary mailbox/storage condition.

**This status is not a retry instruction, and reading it as one was a defect.**
The four examples above are one status and two very different situations: a
SERVFAIL opened no socket, while an SMTP 4xx is a reply to `RCPT TO` and means
this project has already named the address to a mail server. `docs/requirements.md`
section 14's automatic retry is decided on that protocol fact — carried
separately as `RecipientTouch` — and never on the status, because the status
cannot express the difference. A caller reading `temporary_unknown` learns that
the condition may change; whether *this service* will try again is
section 14's question and ADR 0019's answer.

### unknown

The system cannot make a reliable target-specific determination.

Examples:

- unsupported syntax;
- policy or reputation block;
- sender rejected;
- bare ambiguous permanent code;
- `252`;
- STARTTLS failure;
- remote server hides recipient validity;
- accept-all suspected.

## 3. Confidence

MVP confidence is categorical:

- `high`;
- `medium`;
- `low`.

`calibrated` is false and `score` is null until a calibration study is
completed. `Confidence` refuses a score while `calibrated` is false, so the
number cannot appear without the study being declared.

**The level is a lookup on the primary reason and nothing else** — no sum, no
average, no product, no count. There is no calibration study, so there is no
evidence for any arithmetic; a table also makes duplicate evidence, input order,
and unrelated extra observations structurally unable to move it. Where the table
below gives a range, the lower level is used. ADR 0012 records each choice.

Guidelines:

| Evidence | Typical confidence |
|---|---|
| Syntax violates supported grammar | high |
| NXDOMAIN / Null MX | high |
| Explicit RCPT `5.1.1` | medium or high |
| RCPT `250` | medium |
| Bare `550` | low |
| Policy block | low |
| Timeout | low or medium |
| Passive risk list | not confidence evidence |

## 4. Aggregation precedence

The aggregator uses structured evidence, not arbitrary strings.

1. supported hard invalid;
2. unsupported input;
3. explicit temporary condition;
4. policy/opaque failure;
5. accepted recipient;
6. residual non-blocking evidence — route and passive metadata, with no
   qualifying positive answer.

A later network error must not erase a hard passive invalid result because the
network probe should never have occurred.

> **Tier 6 was called "passive-only unknown" and holds more than passive
> evidence.** `mx_available` and `implicit_mx_available` land there too: a route
> is not a blocker and is not an answer, so it belongs with the risk metadata
> rather than in tier 4. Both readings produce `unknown`, so nothing behavioural
> ever depended on the label — the document was simply narrower than the code,
> and the independent review found it that way.

`application/aggregate.py` is the only implementation. Each observation is
assigned a tier, and **the lowest non-empty tier decides**; nothing counts
observations, weights them, or reads `EvidenceStrength`.

### 4.1 The two gates

Only two functions can produce a decisive status, and each condition is pinned
by a test in which the others pass.

> **`invalid` requires all three of:** a reason among the five section 2 lists,
> an observation that is about the target, and one that is not temporary.

Strength is not one of them. `application/aggregate.py` does not import
`EvidenceStrength` at all, so section 7.6 stop condition B is closed by absence
rather than by discipline.

> **`likely_deliverable` requires all three of:** no tier 1–4 evidence, a
> `mx_available` or `implicit_mx_available` observation, and a qualifying
> recipient acceptance that is about the target and not temporary.

The route requirement is the one condition not stated in section 2, and ADR 0012
records why it is required anyway: a lone `rcpt_accepted` is an evidence set the
pipeline cannot produce — an acceptance implies a route was resolved and
connected to — and an aggregator must not assume its input is coherent. It is
also what makes "a bare SMTP `250` is not automatically `likely_deliverable`"
true of the function rather than only true of how the caller happens to be
wired. A lone acceptance is `unknown`.

### 4.2 Targetness, and what it is read from

`is_about_the_target` reads the producer's own statement first: gate 4D
publishes `about_the_target` on every piece of SMTP evidence, and it knows the
stage the dialogue reached and how many recipients were attempted, which the
aggregator does not. Absent such a statement, membership of a published
target-specific set decides, and **an unclassified reason is not target
evidence**. The positive form is deliberate — the negative one fails open.

### 4.3 Tier 4 is the complement

An observation matching none of tiers 1, 2, 3, 5, or the small explicit tier-6
set lands in tier 4, which is `unknown` and which blocks a positive verdict. A
reason code added in a later Phase and forgotten resolves to `unknown` rather
than being ignored.

### 4.4 What puts an observation in tier 3

**The `Evidence.temporary` flag, and nothing else.** There is no second list of
"temporary reason codes" to keep in step with the producers; the aggregator reads
the boolean each producer already publishes, which `docs/status-model.md`
section 7.5 fixes for the SMTP mapper and the DNS and syntax producers set the
same way.

That is fail-safe in both directions, which is why one flag is enough. A flag
wrongly set to true moves an observation *up* into `temporary_unknown`, which
claims less than `invalid` and less than `likely_deliverable`. A flag wrongly set
to false drops it into tier 4, which is `unknown` and still blocks a positive
verdict. **Neither error can reach `likely_deliverable`**, and neither can turn a
retryable condition into a permanent one, so the disagreement between a reason's
semantics and its flag is a loss of retry advice rather than a wrong answer.

### 4.5 Duplicates and independence

Distinct reasons are collapsed before any rule runs, so nothing downstream can
count them: ten copies of one observation decide what one decides. Where two
observations carry one reason and disagree, the lower tier wins.

Gate 4E produces this shape routinely — three pre-recipient failures for one
address are three attempts at one question, not three answers to it. Evidence
from different layers is not treated as independent either: syntax, DNS, SMTP,
and passive observations of one address are correlated in ways nobody has
measured, so no Bayesian-looking arithmetic exists. See ADR 0012.

### 4.6 The primary reason

Chosen from the deciding tier by an explicit total order over every published
reason code, never from the enum's declaration order and never from a set.
`reason_codes` reports every distinct reason sorted by tier and then by that
order, so the primary reason is always first and reading only it loses ordering
rather than information.

**That last property is enforced by `Verdict`, not merely described here.** The
two orderings are computed by two functions, and the independent review found
that ranking `reason_codes` by the enum's declaration order left
`primary_reason` correct, put a different reason at the head of the list, and
broke no test. A verdict whose reason codes do not lead with its primary reason
is now unconstructible.

`internal_error` leads tier 4: a failure of this project's own must not hide
behind a remote server's answer, though it does not outrank a hard invalid or an
explicit temporary condition.

### 4.7 The empty set

`aggregate_evidence(())` is `unknown` with `primary_reason` of `null`. There is
no published reason code meaning "nothing was observed", and the absence of
contradictory evidence is not positive evidence.

## 5. Public reason codes

Reason codes are stable API vocabulary. Additions are backwards compatible;
renames and semantic changes require an API version or migration.

The enum in `src/emailcheck/domain/reasons.py` is the machine-readable source of
truth. Documentation must remain synchronized. The table below is the complete
published set; `tests/test_docs_reason_codes.py` fails when it and the enum
diverge.

A reason code records *what was observed*, not the final status. The
aggregation precedence in section 4 decides the status, so one code may appear
under different statuses depending on the other evidence present.

| Reason code | Evidence layer | Meaning |
|---|---|---|
| `invalid_syntax` | `syntax` | Input violates the supported address grammar. |
| `unsupported_quoted_local_part` | `syntax` | Quoted local part; outside MVP support, not evidence of invalidity. |
| `unsupported_domain_literal` | `syntax` | Address literal domain; outside MVP support. |
| `unsupported_smtputf8` | `syntax` | Local part requires SMTPUTF8; outside MVP support. |
| `domain_nxdomain` | `dns` | Authoritative NXDOMAIN for the domain. |
| `dns_temporary_failure` | `dns` | SERVFAIL, timeout, or malformed answer worth one bounded retry. |
| `null_mx` | `dns` | RFC 7505 Null MX; the domain declares that it accepts no mail. |
| `no_mail_route` | `dns` | No MX and no implicit A/AAAA route. |
| `mx_available` | `dns` | Ordered MX candidates exist; a route, not recipient evidence. |
| `implicit_mx_available` | `dns` | No MX; A/AAAA is used as the implicit route. |
| `mx_configuration_anomaly` | `dns` | MX records exist but none is usable; never proof that the domain refuses mail. |
| `unsafe_destination` | `dns` | The destination policy rejected the resolved address. |
| `disposable_domain` | `passive_classification` | Domain is on the disposable dataset; risk only. |
| `role_account` | `passive_classification` | Local part is on the role dataset; risk only. |
| `free_mail` | `passive_classification` | Domain is on the free-mail dataset; risk only. |
| `provider_opaque` | `passive_classification` | Provider family is known to hide recipient validity. |
| `smtp_connection_timeout` | `smtp` | A bounded connect, banner, or command deadline expired. |
| `smtp_connection_refused` | `smtp` | The MX candidate refused the connection. |
| `smtp_banner_invalid` | `smtp` | The greeting was unusable or not a valid reply. |
| `smtp_protocol_error` | `smtp` | A reply after the greeting could not be parsed, or a bound on reply size was reached; never target evidence. |
| `smtp_tls_failure` | `smtp` | STARTTLS or the handshake failed; never mailbox invalidity. |
| `smtp_policy_blocked` | `smtp` | Reputation, policy, or security rejection unrelated to the target. |
| `mail_from_rejected` | `smtp` | The envelope sender was rejected; not target-address evidence. |
| `rcpt_accepted` | `smtp` | RCPT accepted at that stage; not proof the mailbox exists. |
| `rcpt_forwarded` | `smtp` | RCPT accepted for forwarding (`251`). |
| `rcpt_unverifiable` | `smtp` | The server declined to verify the recipient (`252`). |
| `rcpt_rejected_address` | `smtp` | RCPT-stage evidence explicitly identifying the recipient as nonexistent. |
| `rcpt_rejected_policy` | `smtp` | RCPT rejected for policy or security reasons (`5.7.x`). |
| `smtp_temporary_failure` | `smtp` | Explicit `4xx` temporary response. |
| `smtp_ambiguous_permanent_failure` | `smtp` | Permanent rejection that no enhanced code disambiguates. |
| `mailbox_full` | `smtp` | Explicitly reported temporary mailbox or storage condition. |
| `accept_all_suspected` | `accept_all` | The destination appears to accept every recipient (Phase 9). |
| `internal_error` | `internal` | A local failure prevented a determination; never target invalidity. |

## 6. Check summaries

Each layer returns a safe summary:

```json
{
  "syntax": {"result": "pass"},
  "dns": {
    "result": "pass",
    "mx_hosts": ["mx.example.net"],
    "null_mx": false
  },
  "smtp": {
    "result": "accepted",
    "basic_code": 250,
    "enhanced_code": null
  }
}
```

Remote text is not a public API contract. It may be normalized internally and
stored encrypted for a short retention period.

## 7. SMTP observation to evidence, for Phase 4D

Gate 4C produces a `SessionReport` and stops. This section fixes what Phase 4D
may turn one into, and it is written **before** that code exists: a mapping
authored alongside its implementation is a mapping shaped by whatever the
implementation happened to make easy.

Nothing here is a status. A reason code records what was observed; section 4
decides the status, with the syntax, DNS, and passive evidence in front of it.

### 7.1 The input is the whole report, never one field

A mapping reads the combination:

```text
observation.outcome           RecipientStageOutcome
stage_reached                 DialogueStage
observation.basic_code        the reply's three digits
observation.enhanced_code     the RFC 3463 code, when the reply carried a valid one
deadline_exhausted            whether this project's own budget ran out
tls.negotiated, tls.reason    TLSOutcomeDetail
observation.defect            why a reply could not be parsed
```

**`outcome` alone is not enough, and neither is any derived property.** A `550`
to `MAIL FROM` and a lost connection at the banner are both `CONNECTION_ERROR`,
because `RecipientStageOutcome` describes the *recipient stage* and neither
session reached it — `stage_reached` is what separates them. That taxonomy is a
reviewed 4A contract and Phase 4D does not extend it.

**`is_about_the_target` is a filter, not a classifier.** It answers "could this
observation possibly concern the address", and it is true for every 2xx
including `252`. A mapping that branches on it, or on `outcome is ACCEPTED`,
without reading `basic_code` first is wrong in the direction this project must
never be wrong in. See section 7.4.

### 7.2 Before the recipient stage

None of these is evidence about the target address. Each maps to a reason code
whose meaning is "the probe did not get an answer about the recipient", and
section 4 resolves all of them to `unknown` or `temporary_unknown`.

| What was observed | How to recognise it | Phase 4D reason code |
|---|---|---|
| No connection was made | `stage_reached` is `connected`, no reply | `smtp_connection_refused` or `smtp_connection_timeout`, from the transport failure |
| The session budget ran out before a dialogue | a refusal carrying `deadline_exhausted` | `smtp_connection_timeout` |
| The greeting was unusable | `stage_reached` is `banner`, outcome `protocol_error` | `smtp_banner_invalid` |
| The greeting refused the session | `stage_reached` is `banner`, a `4xx` or `5xx` reply | `smtp_policy_blocked` |
| A later reply was unreadable | outcome `protocol_error`, `stage_reached` past `banner` | `smtp_protocol_error` |
| EHLO was refused | `stage_reached` is `ehlo` or `ehlo_after_tls`, a non-2xx reply | `smtp_policy_blocked` |
| The server advertised no STARTTLS and the policy requires it | outcome `tls_error`, `tls.reason` is `not_offered` | `smtp_tls_failure` |
| The STARTTLS command was refused | outcome `tls_error`, `tls.reason` is `command_rejected` | `smtp_tls_failure` |
| The handshake failed | outcome `tls_error`, `tls.reason` is `handshake_failed`, `certificate_invalid`, `hostname_mismatch`, `timeout`, or `peer_changed` | `smtp_tls_failure` |
| The envelope sender was rejected | `stage_reached` is `mail_from`, a `4xx` or `5xx` reply | `mail_from_rejected` |
| The connection was lost or timed out mid-dialogue | outcome `connection_error`, `deadline_exhausted` false | `smtp_connection_timeout` |
| This project's own budget stopped the session | `deadline_exhausted` true | `smtp_connection_timeout` |
| This project failed | outcome `internal_error` | `internal_error` |

Three consequences are not negotiable:

- **a `550` to `MAIL FROM` is never `rcpt_rejected_address` and never
  contributes to `invalid`.** `docs/requirements.md` section 9 puts sender,
  connection, reputation, and policy failures outside target-address invalidity;
- **a TLS failure is never mailbox invalidity**, whichever of the seven reasons
  it carries. `TLS_ERROR` is in `NON_TARGET_OUTCOMES` and Phase 4D must not
  widen that;
- **the pre-handshake plaintext refusal and a genuine handshake failure are one
  category.** Refusing the upgrade because the read buffer was not empty
  (CVE-2011-0411) reports `tls_handshake_failed`, the same as a certificate the
  library rejected. They are different diagnostics and the same evidence: not
  about the target, no plaintext fallback, `unknown`.

### 7.3 At the recipient stage

Only these rows may produce target-specific evidence, and only when the report
has **reached or passed** the `RCPT TO` stage. With the current state model that
means `stage_reached` is one of:

- `rcpt_to`;
- `cleanup`.

subject also to both of:

- the outcome is one a recipient answer produces — `accepted`, `rejected`, or
  `temporary_failure`;
- `recipients_attempted` is exactly `1`.

> **`cleanup` is the value a real session reports, not `rcpt_to`.** A dialogue is
> *in* `rcpt_to` only while the command is outstanding; once the reply has been
> read it moves on, so `application/smtp_dialogue.py` records every completed
> recipient exchange with `stage_reached = cleanup`. Both a `250` and a
> `550 5.1.1` arrive that way.
>
> **A Phase 5 filter written as `stage_reached == "rcpt_to"` therefore discards
> every recipient answer this project produces.** An earlier version of this
> section said the evidence was produced "only when `stage_reached` is
> `rcpt_to`", which described a state no session reaches; the code was right and
> this text was wrong. `application/smtp_evidence.py` derives the permitted set
> from `STAGE_ORDER` rather than listing it, so a stage added after `RCPT_TO` in
> a later gate is included rather than silently treated as pre-recipient.

The three conditions above are independent barriers, and each is pinned by its
own test: a `550 5.1.1` carried by a `connection_error`, one with no recipient
attempted, and one at `mail_from` must each stay non-target evidence, and each
of those tests fails when its own barrier alone is removed. "A `MAIL FROM 550`
becomes a recipient rejection" is the worst mistake available here, so no single
check carries it.

| What was observed | How to recognise it | Phase 4D reason code |
|---|---|---|
| Recipient accepted | outcome `accepted`, `basic_code` 250 | `rcpt_accepted` |
| Accepted for forwarding | outcome `accepted`, `basic_code` 251 | `rcpt_forwarded` |
| The server declined to verify | outcome `accepted`, `basic_code` **252** | `rcpt_unverifiable` |
| Explicit temporary condition | outcome `temporary_failure`, `basic_code` 450, 451, or 452 | `smtp_temporary_failure` |
| Temporary mailbox or storage condition | enhanced code `4.2.2` **or** `5.2.2` | `mailbox_full` |
| Recipient explicitly does not exist | outcome `rejected`, enhanced code `5.1.1` | `rcpt_rejected_address` |
| Policy or security rejection | outcome `rejected`, enhanced class `5.7.x` | `rcpt_rejected_policy` |
| Permanent rejection nothing disambiguates | outcome `rejected`, no usable enhanced code | `smtp_ambiguous_permanent_failure` |
| The reply was not a reply | outcome `protocol_error`, a `defect`, at any stage past the greeting | `smtp_protocol_error` |

The branch order is part of the specification, because two rows can match one
reply. `252` is read first, then `X.2.2`, then the basic class, then the enhanced
code for a permanent rejection. Only the first two are cases where the enhanced
code outranks the basic class.

**`X.2.2` is a storage condition in either class.** `docs/requirements.md`
section 9 names `552` with an explicit `X.2.2` as a *temporary* mailbox or
storage condition, so `552 5.2.2` is `mailbox_full` and temporary, exactly as
`452 4.2.2` is. A permanent basic code with an enhanced code that contradicts it
is the one place in this mapping where the enhanced code wins, and it wins toward
the conservative answer. A class-2 code cannot: `250 2.2.2` is a success code and
is read as an ordinary acceptance.

Two rules carried from `docs/requirements.md` section 9:

- **`250` is not mailbox existence.** An accept-all server says it to everyone,
  so `rcpt_accepted` supports `likely_deliverable` at *medium* confidence and
  never at high;
- **a bare `550` is ambiguous.** Without an enhanced code that identifies the
  recipient, a permanent rejection may be policy, reputation, or greylisting
  expressed badly. It is `smtp_ambiguous_permanent_failure`, and section 3 gives
  it low confidence.

### 7.4 `252` is not an acceptance

```text
252 Cannot VRFY user, but will accept message and attempt delivery
```

The server is saying it will not tell you. It is `unverifiable`, it belongs
under `unknown` in section 2, and it is **not**:

- an accepted recipient;
- `likely_deliverable`;
- evidence that the mailbox exists.

Gate 4C records it as `RecipientStageOutcome.ACCEPTED`, because at that layer
`ACCEPTED` means only "the command was answered in the 2xx class". That is
deliberate — the taxonomy describes the protocol, not the meaning — and it is
also the trap: `outcome` and `is_about_the_target` cannot tell `252` from `250`,
and only `basic_code` can.

> **Phase 4D entry condition.** `252` must be separated on `basic_code` before
> any generic handling of `ACCEPTED`. A mapping written as
>
> ```python
> if observation.outcome is RecipientStageOutcome.ACCEPTED:
>     ...  # rcpt_accepted
> ```
>
> classifies a refusal to verify as an acceptance, and section 4's precedence
> then promotes it to `likely_deliverable`. `plans/phase-04-smtp.md` records this
> as a stop condition, and `tests/unit/application/test_smtp_dialogue.py` pins
> that the two are indistinguishable without the code, so the danger is visible
> rather than remembered.

### 7.5 The shape of the evidence Phase 4D produces

`application/smtp_evidence.py` implements the tables above. It is a pure
function: a `SessionReport` and a timestamp in, `Evidence` out. No socket, no
clock, no resolver, no rate limiter, no storage, and no retry — even
`observed_at` is a parameter, because a mapper that read a clock would be a
mapper whose output depended on when it ran.

**One piece of evidence per session.** The TLS detail, the deadline flag, and the
cleanup status are carried as *details* on that one item rather than as evidence
of their own. That is what makes two requirements structural instead of
remembered: a cleanup failure cannot overwrite the recipient's answer, and
cleanup cannot reach a verdict on its own, because there is nothing for an
aggregator to weigh it as.

The return type is a tuple so the shape is stable for Phase 5 and for a later
gate that may add a second item. Order is fixed: the primary observation first.
Nothing iterates a set, so the same report always yields the same tuple with the
same detail keys in the same order.

| Field | How it is chosen |
|---|---|
| `layer` | `smtp`, except `internal_error` (`internal`) and `unsafe_destination` (`dns`, because that code belongs to the DNS layer whichever component notices it) |
| `reason` | the tables in 7.2 and 7.3 |
| `strength` | `strong` only for `rcpt_rejected_address`; `moderate` for an acceptance, a forward, and an explicit temporary condition; `weak` for everything ambiguous, non-target, or unverifiable |
| `temporary` | true for `4xx`, for `mailbox_full` in either class, and for a timeout or refused connection; false for everything else |
| `source_version` | the ruleset version, so a stored result records which rules produced it |

`rcpt_accepted` is never `strong`: section 3 caps an accepted recipient at medium
confidence, and an accept-all server says `250` to everyone.

**Two published sets accompany the mapping**, so Phase 5 filters rather than
re-derives: `NON_TARGET_SMTP_REASONS` and `RECIPIENT_STAGE_REASONS`. A third,
`POSITIVE_RECIPIENT_REASONS`, holds `rcpt_accepted` and `rcpt_forwarded` and
**not** `rcpt_unverifiable` — the two sets differing by exactly that member is
section 7.4 expressed as code.

**The two sets partition every reason the mapper emits, and the partition is
tested.** A reason may be in neither only by mistake, so no reason may be missing
from both and none may be in both. The `about_the_target` detail is derived
*from* `RECIPIENT_STAGE_REASONS` rather than from the absence of
`NON_TARGET_SMTP_REASONS`, which makes an unclassified reason **non-target**
rather than target evidence: the first form fails closed and the second fails
open, and they differ exactly when someone has forgotten to update a set.

**What details may contain**: the basic code, a validated enhanced code, the
bounded sanitized diagnostic, the stage, the reply defect, the TLS reason, the
deadline flag, the cleanup category, the recipient count, `no_message_data_sent`,
and bounded timing. Every value is a string, an integer, a boolean, or null, and
`Evidence` refuses anything else at construction.

**What they may never contain**: a raw reply, a full address or submitted local
part, **a wire command or transcript this project issued**, a certificate, TLS or
library exception text, or a peer address.

That last one is stated precisely because the obvious wording claims more than
holds. The guarantee is:

> No raw reply, and no locally-issued wire command or transcript, is stored.
> The bounded sanitized remote diagnostic may itself contain SMTP command words,
> because a server is free to write `RCPT TO is not allowed here` in its own
> prose.

Remote prose is not a wire command. It is bounded, `@`-free, and stripped of
control characters by the Phase 4A sanitizer, and it is kept because it is the
only thing that tells an operator *why* a server answered as it did.

**`observed_at` is a timezone-aware timestamp**, on this and on every other
evidence producer. `Evidence` refuses a naive one, because comparing a naive
datetime with an aware one raises rather than answering, and Phase 5 orders
evidence from four producers. The SMTP mapper takes the timestamp as a parameter
rather than from a `Clock`, so this is the one producer whose timestamp comes
from an unvalidated caller — and `map_connect_failure`, which takes raw
primitives rather than validated domain values, checks its own arguments so that
both entry points answer to the same contract.

**Phase 4D produces no risk flag and no status.** Risk is orthogonal to
deliverability (section 1), the four flags belong to passive classification and
DNS, and nothing an SMTP reply says is one. An inspection test keeps `Status`,
`Verdict`, `Confidence`, and `RiskFlag` out of every application SMTP module.

### 7.6 Phase 5 stop conditions

Phase 4D publishes vocabulary that is easy to mistake for a decision. Two
readings are forbidden, and both are forbidden because they are the shortest
correct-looking code someone could write.

> **Stop condition A. `POSITIVE_RECIPIENT_REASONS` is a semantic category, not
> an aggregation rule.** Phase 5 **must not** map membership directly to a
> status:
>
> ```python
> if reason in POSITIVE_RECIPIENT_REASONS:
>     return Status.LIKELY_DELIVERABLE   # forbidden
> ```
>
> Membership says the server answered positively about the recipient *at that
> stage*. It does not say the address is deliverable, and an accept-all server
> says `250` to everyone. Every aggregation must run the section 4 precedence —
> hard invalid, unsupported input, explicit temporary condition, policy or opaque
> failure, and only then an accepted recipient.

> **Stop condition B. `EvidenceStrength.STRONG` means strong evidence, never
> final truth.** Phase 5 **must not** map strength directly to a status:
>
> ```python
> if evidence.strength is EvidenceStrength.STRONG:
>     return Status.INVALID              # forbidden
> ```
>
> `invalid` requires evidence that is target-specific, non-temporary, and
> carrying reason semantics that mean the address itself cannot be delivered to.
> **A reason in `NON_TARGET_SMTP_REASONS` never supports target invalidity,
> whatever its strength**, and neither does anything the mapper marks temporary.

Both stop conditions are closed. Section 4.1 is stop condition A and B expressed
as the two gates: the aggregator does not import `EvidenceStrength` at all, and
membership of `POSITIVE_RECIPIENT_REASONS` is one of three conditions rather than
an answer.

Two further items were required before Phase 5 rather than before Phase 4E, and
both were closed at the start of it:

- ~~**`RecipientStageOutcome` extension is silent.**~~ **Closed in Phase 5.** A
  member added to that enum fell through the classifier to the pre-recipient
  path and was reported as `smtp_connection_timeout` — temporary, non-target,
  and invented. `application/smtp_evidence.py` now names every member in an
  `assert_never` guard, so a new one fails under mypy *and* raises at run time.

  The guard is deliberately **not** the dispatch. Turning it into one would be
  tidier and would delete a reviewed barrier: `outcome not in _RECIPIENT_ANSWERS`
  in `_recipient_reply` is one of the three checks between a `MAIL FROM 550` and
  a recipient rejection, and a `match` routing `CONNECTION_ERROR` straight to
  the pre-recipient path would make it unreachable and its test vacuous.
  Exhaustiveness is worth having; it is not worth paying for with a barrier;
- **`LINE_TOO_LONG` and `TOTAL_LIMIT_EXCEEDED` map by entry point.** Through
  `map_connect_failure` they are `smtp_protocol_error` and permanent; reached
  mid-dialogue they arrive with no reply and become `smtp_connection_timeout`
  and temporary. The difference reaches the verdict — `unknown` against
  `temporary_unknown`.

  **The difference is kept, as deliberate entry-point provenance**, and is now
  pinned by tests rather than left as an accident. Collapsing it would need one
  of two things and both are worse: making the session path report a protocol
  error is impossible without changing a reviewed 4C contract, because a
  `SessionReport` carries no `TransportFailure` and that path genuinely cannot
  know which bound was hit; making the connect path report a timeout would throw
  away information the caller has. What bounds the difference is asserted
  instead: **both readings are non-target and neither can ever produce
  `invalid`**. See ADR 0012.
