# ADR 0004: Categorical confidence before calibration

- Status: Accepted
- Date: 2026-08-03

## Decision

Return high/medium/low confidence, `calibrated=false`, and `score=null` in the
MVP.

## Rationale

A numeric score without a labeled and representative calibration set creates
false precision. Numeric probabilities may be added after controlled
evaluation.
