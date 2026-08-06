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
