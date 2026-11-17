# Status and evidence model

## 1. Separation of concerns

Four concepts are kept apart:

1. **check result**: what one layer observed;
2. **reason code**: the normalized interpretation of it;
3. **risk flag**: a policy attribute unrelated to whether the address is deliverable;
4. **verdict**: the conservative aggregate.

Never store only the final status.

Job state is outside these four. `JobState`, `JobAdmission`, and `JobFailure` describe this service's own operation and executor handoff. None of them is mailbox evidence or may be turned into a deliverability `Status`; `admission_failed` and `interrupted` in particular carry no mailbox result.

## 2. Statuses

### likely_deliverable

There is positive delivery-stage evidence and no stronger contradicting evidence. This does not prove that the mailbox exists.

### invalid

Strong, target-specific, non-temporary evidence shows that the input cannot be delivered as addressed. The five cases:

- syntax that violates the supported grammar;
- NXDOMAIN;
- Null MX;
- no MX and no implicit A/AAAA route;
- an enhanced code at the `RCPT` stage that explicitly says the recipient does not exist.

### temporary_unknown

The evidence explicitly reports a condition expected to change, for example:

- DNS SERVFAIL;
- SMTP 4xx;
- a bounded connection timeout while the service is otherwise healthy;
- an explicitly reported temporary mailbox or storage condition.

This status is not a retry instruction. A SERVFAIL opened no socket, while an SMTP 4xx answers `RCPT TO`, so the address has already been named to a mail server. The automatic retry in `docs/requirements.md` section 14 is decided on that protocol fact, carried separately as `RecipientTouch`, never on the status, which cannot express the difference. See ADR 0019.

### unknown

No reliable target-specific determination is possible, for example:

- unsupported syntax;
- policy or reputation block;
- sender rejected;
- a bare, ambiguous permanent code;
- `252`;
- STARTTLS failure;
- a server that hides whether recipients are valid;
- accept-all suspected.

### Notes

`domain_configuration_anomaly` reaches a verdict as a risk flag on the route observation (`Evidence.risk_flags`), not as `ReasonCode.MX_CONFIGURATION_ANOMALY`. That reason is in tier 4 and would lower the status to `unknown`, which is right for a route with nowhere to connect but wrong for a usable route that also publishes a Null MX. The flag is raised and the status precedence is unchanged.

`no_message_data_sent` is a safety assertion, not a status, confidence, or reason, and none of these is derived from another. A malformed or missing value at the remote boundary is a protocol-validation failure, never `Status.INVALID` or any other status, because a remote server's broken JSON says nothing about an address.

## 3. Confidence

Confidence is a category: `high`, `medium`, or `low`.

The level is looked up from the primary reason and nothing else: no sum, average, product, or count. Without a calibration study there is no basis for arithmetic, and a lookup also means duplicates, input order, and unrelated observations cannot move it. Where the table gives a range, the lower level is used.

| Evidence | Typical confidence |
|---|---|
| Syntax violates the supported grammar | high |
| NXDOMAIN / Null MX | high |
| Explicit `RCPT` `5.1.1` | medium or high |
| `RCPT` `250` | medium |
| Bare `550` | low |
| Policy block | low |
| Timeout | low or medium |
| Passive risk list | not confidence evidence |

`calibrated` is false and `score` is null until a calibration study is done, and `Confidence` refuses a score while `calibrated` is false. The range of a calibrated score is undefined: nothing in this project defines its scale, so the domain checks no range. Defining one would be a deliberate decision with its own ADR.

## 4. Aggregation precedence

The aggregator works on structured evidence, not strings. Each observation falls into one tier:

1. supported hard invalid;
2. unsupported input;
3. explicit temporary condition;
4. policy or opaque failure;
5. accepted recipient;
6. residual non-blocking evidence: route and passive metadata, with no qualifying positive answer.

`application/aggregate.py` is the only implementation. The lowest non-empty tier decides; nothing counts or weights observations or reads `EvidenceStrength`. Risk flags are derived after the status and are never read by it. A later network error must not erase a hard passive invalid result, because that network probe should never have run.

`mx_available` and `implicit_mx_available` are in tier 6: a route neither blocks nor answers, so it sits with the risk metadata.

### 4.1 The two gates

Only two functions can produce a decisive status, and each of their conditions is pinned by a test in which the others pass.

`invalid` requires all three of: a reason among the five section 2 lists, an observation about the target, and one that is not temporary. Strength is not a condition; `application/aggregate.py` does not import `EvidenceStrength` at all.

`likely_deliverable` requires all three of: no tier 1–4 evidence, an `mx_available` or `implicit_mx_available` observation, and a qualifying recipient acceptance that is about the target and not temporary. The pipeline never produces an acceptance without a route, but the aggregator does not assume coherent input, and this makes "a bare SMTP `250` is not automatically `likely_deliverable`" true of the function itself. A lone acceptance is `unknown`.

### 4.2 Targetness

`is_about_the_target` reads the producer's own statement first: SMTP evidence publishes `about_the_target`, because only the producer knows the stage reached and how many recipients were attempted. Without such a statement, membership of a published target-specific set decides. An unclassified reason is not target evidence; the positive form is used because the negative one would fail open.

### 4.3 Tier 4 is the default

An observation that matches none of tiers 1, 2, 3, 5, or the small explicit tier-6 set lands in tier 4. Tier 4 gives `unknown` and blocks a positive verdict, so a reason code added later and forgotten resolves to `unknown` instead of being ignored.

### 4.4 Tier 3

Tier 3 is decided by the `Evidence.temporary` flag, and nothing else. There is no separate list of temporary reason codes; every producer sets the flag (section 7.5 for SMTP).

One flag is enough because both possible errors are safe. A flag wrongly set to true moves an observation into `temporary_unknown`, which claims less than `invalid` or `likely_deliverable`. A flag wrongly set to false moves it into tier 4, which is `unknown` and still blocks a positive verdict. Neither error can reach `likely_deliverable` or make a retryable condition permanent; the cost is lost retry advice, not a wrong answer.

### 4.5 Duplicates and independence

Distinct reasons are collapsed before any rule runs, so ten copies of one observation decide what one decides. When two observations carry the same reason and disagree, the lower tier wins. Several pre-recipient failures for one address are attempts at one question, not separate answers. Evidence from different layers is not treated as independent either, so no probabilistic arithmetic exists.

### 4.6 The primary reason

The primary reason is chosen from the deciding tier by an explicit total order over every published reason code, never by enum declaration order or set iteration. `reason_codes` lists every distinct reason, sorted by tier and then by that order, so the primary reason always leads. `Verdict` enforces this: a verdict whose reason codes do not lead with its primary reason is unconstructible.

`internal_error` leads tier 4, so a failure of this project's own is not hidden behind a remote server's answer. It does not outrank a hard invalid or an explicit temporary condition, because those are still true. Hard-invalid evidence survives an `internal_error`; that combination is not reachable from the current pipeline, so this is a statement of policy, and a change that makes it reachable must revisit it deliberately.

### 4.7 The empty set

`aggregate_evidence(())` is `unknown` with a `primary_reason` of `null`. No reason code means "nothing was observed", and the absence of contradicting evidence is not positive evidence.

## 5. Public reason codes

Reason codes are stable API vocabulary. Additions are backwards compatible; renames and changes of meaning need an API version or a migration.

The enum in `src/emailcheck/domain/reasons.py` is the source of truth, and `tests/test_docs_reason_codes.py` fails when this table and the enum differ. A reason code records what was observed, not the final status; section 4 decides the status, so one code can appear under different statuses.

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

Remote text is not part of the public API. It may be normalized internally and stored encrypted for a short retention period.

## 7. SMTP observation to evidence

`application/smtp_evidence.py` turns a `SessionReport` into evidence as described here. Nothing in this section is a status: a reason code records what was observed, and section 4 decides the status together with the syntax, DNS, and passive evidence.

### 7.1 Inputs

The mapping reads these fields together:

```text
observation.outcome           RecipientStageOutcome
stage_reached                 DialogueStage
observation.basic_code        the reply's three digits
observation.enhanced_code     the RFC 3463 code, when the reply carried a valid one
deadline_exhausted            whether this project's own budget ran out
tls.negotiated, tls.reason    TLSOutcomeDetail
observation.defect            why a reply could not be parsed
```

`outcome` alone is not enough, and neither is any property derived from it. A `550` to `MAIL FROM` and a connection lost at the banner are both `CONNECTION_ERROR`, because `RecipientStageOutcome` describes the recipient stage and neither session reached it; `stage_reached` tells them apart.

`is_about_the_target` is a filter, not a classifier. It is true for every 2xx reply, `252` included. A mapping that branches on it, or on `outcome is ACCEPTED`, before reading `basic_code` errs in the one direction this project must never err in (section 7.4).

### 7.2 Before the recipient stage

None of these is evidence about the target address. Each reason means the probe got no answer about the recipient, and section 4 resolves all of them to `unknown` or `temporary_unknown`.

| What was observed | How to recognise it | Reason code |
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

These rules have no exceptions:

- A `550` to `MAIL FROM` is never `rcpt_rejected_address` and never contributes to `invalid`. Sender, connection, reputation, and policy failures are outside target-address invalidity (`docs/requirements.md` section 9).
- A TLS failure is never mailbox invalidity, whichever of the seven reasons it carries. `TLS_ERROR` is in `NON_TARGET_OUTCOMES`, and that set must not be widened.
- Refusing the upgrade because the read buffer was not empty (CVE-2011-0411) reports `tls_handshake_failed`, the same as a rejected certificate. The diagnostics differ; the evidence is the same: not about the target, no plaintext fallback, `unknown`.

#### The TLS default needs a measurement before it can change

`TLSPolicy.REQUIRED` is the default and the only supported policy (ADR 0021), so a destination that advertises no STARTTLS gives `smtp_tls_failure` with `tls.reason` `not_offered` instead of a plaintext session. How much real mail infrastructure still refuses TLS has not been measured. The Phase 8 readiness work names a representative measurement as the evidence needed before the default is reconsidered. Until it exists, relaxing the default is not one of the options: doing it on a guess would quietly turn a refusal to negotiate TLS into an ordinary probe.

### 7.3 At the recipient stage

Only these rows can produce target-specific evidence, and only when the report has reached or passed the `RCPT TO` stage, meaning `stage_reached` is `rcpt_to` or `cleanup`, and also:

- the outcome is one that a recipient answer produces: `accepted`, `rejected`, or `temporary_failure`;
- `recipients_attempted` is exactly `1`.

A real session reports `cleanup`, not `rcpt_to`. The dialogue is in `rcpt_to` only while the command is outstanding; after the reply is read it moves on, so `application/smtp_dialogue.py` records every completed recipient exchange with `stage_reached = cleanup`. A filter written as `stage_reached == "rcpt_to"` therefore discards every recipient answer this project produces. `application/smtp_evidence.py` derives the permitted set from `STAGE_ORDER`, so a stage added after `RCPT_TO` later is included instead of being treated as pre-recipient.

The three conditions are independent barriers, each pinned by its own test: a `550 5.1.1` carried by a `connection_error`, one with no recipient attempted, and one at `mail_from` must each stay non-target evidence, and each test fails when only its own barrier is removed. Turning a `MAIL FROM 550` into a recipient rejection is the worst possible mistake here, so no single check carries it.

| What was observed | How to recognise it | Reason code |
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

Two rows can match one reply, so the order is part of the rule: `252` first, then `X.2.2`, then the basic class, then the enhanced code of a permanent rejection.

`X.2.2` is a storage condition in either class. `docs/requirements.md` section 9 treats `552` with an explicit `X.2.2` as a temporary mailbox or storage condition, so `552 5.2.2` is `mailbox_full` and temporary, like `452 4.2.2`. This is the one place where an enhanced code overrides a permanent basic code, and it overrides toward the conservative answer. A class-2 code cannot: `250 2.2.2` is an ordinary acceptance.

Two more rules from `docs/requirements.md` section 9:

- `250` is not mailbox existence. An accept-all server says it to everyone, so `rcpt_accepted` supports `likely_deliverable` at medium confidence, never high.
- A bare `550` is ambiguous. Without an enhanced code that identifies the recipient, a permanent rejection may be policy, reputation, or badly expressed greylisting. It is `smtp_ambiguous_permanent_failure`, with low confidence.

### 7.4 `252` is not an acceptance

```text
252 Cannot VRFY user, but will accept message and attempt delivery
```

The server is declining to say. `252` is unverifiable and belongs under `unknown`. It is not:

- an accepted recipient;
- `likely_deliverable`;
- evidence that the mailbox exists.

The session layer records it as `RecipientStageOutcome.ACCEPTED`, because there `ACCEPTED` only means a 2xx reply. So `outcome` and `is_about_the_target` cannot tell `252` from `250`; only `basic_code` can. `252` must be separated on `basic_code` before any generic handling of `ACCEPTED`. This mapping is wrong:

```python
if observation.outcome is RecipientStageOutcome.ACCEPTED:
    ...  # rcpt_accepted
```

It treats a refusal to verify as an acceptance, which section 4 would then promote to `likely_deliverable`. `tests/unit/application/test_smtp_dialogue.py` pins that the two outcomes are indistinguishable without the code.

### 7.5 The evidence produced

`application/smtp_evidence.py` is a pure function: a `SessionReport` and a timestamp in, `Evidence` out. It uses no socket, clock, resolver, rate limiter, storage, or retry. `observed_at` is a parameter so the output never depends on when it ran.

A session yields one piece of evidence. The TLS detail, the deadline flag, and the cleanup status are details on that item, not evidence of their own, so a cleanup failure cannot overwrite the recipient's answer and cannot reach a verdict by itself. The return type is a tuple with the primary observation first, and no set is iterated, so one report always yields the same tuple with the same detail keys in the same order.

| Field | How it is chosen |
|---|---|
| `layer` | `smtp`, except `internal_error` (`internal`) and `unsafe_destination` (`dns`, because that code belongs to the DNS layer whichever component notices it) |
| `reason` | the tables in 7.2 and 7.3 |
| `strength` | `strong` only for `rcpt_rejected_address`; `moderate` for an acceptance, a forward, and an explicit temporary condition; `weak` for everything ambiguous, non-target, or unverifiable |
| `temporary` | true for `4xx`, for `mailbox_full` in either class, and for a timeout or refused connection; false otherwise |
| `source_version` | the ruleset version, so a stored result records which rules produced it |

`rcpt_accepted` is never `strong`: an accepted recipient is capped at medium confidence, and an accept-all server says `250` to everyone.

Three published sets come with the mapping, so aggregation filters instead of re-deriving:

- `NON_TARGET_SMTP_REASONS` and `RECIPIENT_STAGE_REASONS` partition every reason the mapper emits, and a test checks that no reason is in both or neither.
- `POSITIVE_RECIPIENT_REASONS` holds `rcpt_accepted` and `rcpt_forwarded` but not `rcpt_unverifiable`; that one-member difference is section 7.4 in code.

The `about_the_target` detail is derived from `RECIPIENT_STAGE_REASONS`, not from absence in `NON_TARGET_SMTP_REASONS`, so a reason missing from both sets fails closed as non-target evidence.

Details may contain the basic code, a validated enhanced code, the bounded sanitized diagnostic, the stage, the reply defect, the TLS reason, the deadline flag, the cleanup category, the recipient count, `no_message_data_sent`, and bounded timings. Every value is a string, integer, boolean, or null, and `Evidence` refuses anything else.

Details never contain a raw reply, a full address or submitted local part, a wire command or transcript this project issued, a certificate, TLS or library exception text, or a peer address. Stated precisely:

> No raw reply, and no locally-issued wire command or transcript, is stored. The bounded sanitized remote diagnostic may itself contain SMTP command words, because a server is free to write `RCPT TO is not allowed here` in its own prose.

Remote prose is not a wire command. It is bounded, contains no `@`, has control characters removed, and is kept because it is the only thing that tells an operator why a server answered as it did.

`observed_at` is timezone-aware on every evidence producer, and `Evidence` refuses a naive timestamp, because aggregation orders evidence from several producers and comparing naive with aware datetimes raises. The SMTP mapper takes the timestamp from its caller instead of a `Clock`, and `map_connect_failure`, which takes raw primitives, validates its own arguments so both entry points follow the same rules.

The SMTP mapper produces no risk flag and no status. Risk is independent of deliverability (section 1), and nothing an SMTP reply says is one of the flags. An inspection test keeps `Status`, `Verdict`, `Confidence`, and `RiskFlag` out of every application SMTP module.

### 7.6 Reading the evidence in aggregation

Two readings of this vocabulary are forbidden, because each is the shortest plausible code someone could write.

`POSITIVE_RECIPIENT_REASONS` is a semantic category, not an aggregation rule. Membership must not map directly to a status:

```python
if reason in POSITIVE_RECIPIENT_REASONS:
    return Status.LIKELY_DELIVERABLE  # forbidden
```

Membership says the server answered positively about the recipient at that stage. It does not make the address deliverable, and an accept-all server says `250` to everyone. Every aggregation runs the full section 4 precedence.

`EvidenceStrength.STRONG` means strong evidence, never final truth. Strength must not map directly to a status:

```python
if evidence.strength is EvidenceStrength.STRONG:
    return Status.INVALID  # forbidden
```

`invalid` needs evidence that is target-specific, not temporary, and whose reason means the address itself cannot receive mail. A reason in `NON_TARGET_SMTP_REASONS` never supports target invalidity, whatever its strength, and neither does anything marked temporary. Section 4.1 enforces both rules: the aggregator does not import `EvidenceStrength`, and positive membership is one of three conditions, not an answer.

`application/smtp_evidence.py` names every `RecipientStageOutcome` member in an `assert_never` guard, so a new member fails under mypy and at run time instead of falling through to the pre-recipient path as an invented, temporary `smtp_connection_timeout`. The guard is deliberately not the dispatch: the check `outcome not in _RECIPIENT_ANSWERS` in `_recipient_reply` is one of the three barriers between a `MAIL FROM 550` and a recipient rejection, and dispatching on the outcome would make it unreachable.

`LINE_TOO_LONG` and `TOTAL_LIMIT_EXCEEDED` keep their entry-point difference. Through `map_connect_failure` they are `smtp_protocol_error` and permanent; reached mid-dialogue they arrive with no reply and become `smtp_connection_timeout` and temporary, so the verdict is `unknown` in one case and `temporary_unknown` in the other. Removing the difference is worse either way: the session path cannot report a protocol error, because a `SessionReport` carries no `TransportFailure` and cannot know which bound was hit, and making the connect path report a timeout would discard information the caller has. Tests pin what bounds the difference: both readings are non-target and neither can ever produce `invalid`.
