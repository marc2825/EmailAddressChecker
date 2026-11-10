# Documentation index

## Normative documents

The following files define behavior. In conflicts, the order below wins:

1. `docs/requirements.md`
2. `docs/status-model.md`
3. `docs/threat-model.md`
4. `docs/smtp-state-machine.md`
5. accepted ADRs
6. implementation comments

`CONTRIBUTING.md` carries the engineering and safety invariants a change must preserve.

Some ADRs and docstrings cite internal implementation material (`prompts/`,
`plans/`, `AGENTS.md`, `IMPLEMENTATION_STATUS.md`) that is not part of the
public repository. Those citations are provenance only and are never normative;
see "A note on historical citations" in `CONTRIBUTING.md`.

## Documents

- `requirements.md`: product scope and functional/non-functional requirements.
- `architecture.md`: components, ports, adapters, and deployment profiles.
- `status-model.md`: evidence, reasons, status, confidence, and risk flags.
- `smtp-state-machine.md`: the only allowed active SMTP protocol flow.
- `threat-model.md`: abuse, SSRF, privacy, reputation, and operational risks.
- `privacy.md`: data minimization, redaction, retention, and deletion.
- `test-strategy.md`: deterministic fixtures and acceptance metrics.
- `operations.md`: sender identity, deployment gates, kill switches, and runbooks.
- `data-sources.md`: dataset license and update requirements.
- `readiness-checklist.md`: per-deployment gates before any active probing.
- `runbooks/`: operator incident procedures.
- `beta-report-template.md`: template for recording a limited beta.
- `releasing.md`: package build and release procedure.
- `release-report.md`: record of the 0.1.0 release preparation (Japanese).
- `usage-ja.md`: CLI usage guide (Japanese).
- `adr/`: durable architecture decisions.

## Informative references

- RFC 5321: SMTP
- RFC 5322: Internet Message Format
- RFC 3463: Enhanced Mail System Status Codes
- RFC 7505: Null MX
- RFC 6531: SMTPUTF8
- RFC 7208: SPF
- RFC 2308: Negative DNS caching

The implementation must not assume that a remote provider follows one fixed
behavior merely because of its brand or MX hostname.
