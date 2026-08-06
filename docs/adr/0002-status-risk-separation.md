# ADR 0002: Separate deliverability from risk

- Status: Accepted
- Date: 2026-08-03

## Decision

Use four deliverability statuses and independent risk flags. There is no
`risky` deliverability status.

## Rationale

Disposable, role, and free-mail properties do not establish whether an address
can receive mail. Combining these dimensions makes APIs hard to interpret and
encourages incorrect rejection policies.
