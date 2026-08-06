# ADR 0003: Restricted SMTP state machine

- Status: Accepted
- Date: 2026-08-03

## Decision

Implement a purpose-built recipient-stage SMTP client whose command and state
types do not include message submission.

## Rationale

A general mail-sending library exposes operations the product explicitly
forbids. A small state machine makes the no-message-content invariant testable.

## Consequences

The project owns reply parsing, timeout handling, and STARTTLS behavior. These
must be covered by scripted server tests.
