# Status and evidence model

## 1. Separation of concerns

The system has four independent concepts:

1. **check result**: what one layer observed;
2. **reason code**: normalized interpretation;
3. **risk flag**: policy-relevant attribute unrelated to deliverability truth;
4. **verdict**: conservative aggregate.

Do not store only the final status.

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

### temporary_unknown

Evidence explicitly indicates a condition expected to change or worth one
bounded retry.

Examples:

- DNS SERVFAIL;
- SMTP 4xx;
- bounded connection timeout when service health is normal;
- explicitly reported temporary mailbox/storage condition.

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
completed.

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
6. passive-only unknown.

A later network error must not erase a hard passive invalid result because the
network probe should never have occurred.

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

Only these rows may produce target-specific evidence, and only when
`stage_reached` is `rcpt_to`.

| What was observed | How to recognise it | Phase 4D reason code |
|---|---|---|
| Recipient accepted | outcome `accepted`, `basic_code` 250 | `rcpt_accepted` |
| Accepted for forwarding | outcome `accepted`, `basic_code` 251 | `rcpt_forwarded` |
| The server declined to verify | outcome `accepted`, `basic_code` **252** | `rcpt_unverifiable` |
| Explicit temporary condition | outcome `temporary_failure`, `basic_code` 450, 451, or 452 | `smtp_temporary_failure` |
| Temporary mailbox or storage condition | a `4xx` reply with enhanced class `4.2.2` | `mailbox_full` |
| Recipient explicitly does not exist | outcome `rejected`, enhanced code `5.1.1` | `rcpt_rejected_address` |
| Policy or security rejection | outcome `rejected`, enhanced class `5.7.x` | `rcpt_rejected_policy` |
| Permanent rejection nothing disambiguates | outcome `rejected`, no usable enhanced code | `smtp_ambiguous_permanent_failure` |
| The reply was not a reply | outcome `protocol_error`, a `defect` | `smtp_banner_invalid` is **not** it; use `internal_error` only for this project's own faults, otherwise `smtp_ambiguous_permanent_failure` may not be used either — a malformed reply is `unknown`, and the reason code for it is added by 4D with its own ADR entry |

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
