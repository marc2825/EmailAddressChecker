# ADR 0001: Python-only MVP

- Status: Accepted
- Date: 2026-08-03

## Context

The service is dominated by bounded network I/O. Python provides adequate async
support and a mature API/DNS ecosystem. Mixing Go and Python before measuring a
real bottleneck increases complexity.

## Decision

Use Python 3.12+ for domain code, API, CLI, and SMTP worker through the MVP.

## Consequences

- one type and test toolchain;
- low deployment complexity;
- SMTP protocol client will be a small restricted state machine rather than a
  general mail-sending client;
- Go may be reconsidered only with measured performance or packaging evidence.
