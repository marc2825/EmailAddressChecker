# Documentation index

## Normative documents

The following files define behavior. In conflicts, the order below wins:

1. `docs/requirements.md`
2. `docs/status-model.md`
3. `docs/threat-model.md`
4. `docs/smtp-state-machine.md`
5. accepted ADRs
6. Phase prompt
7. implementation comments

`CLAUDE.md` imports `AGENTS.md`; together they define the implementation workflow and invariants.

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
- `claude-code-setup.md`: Claude Code memory, skills, hooks, and Phase workflow.
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
