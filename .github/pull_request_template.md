## Summary

<!-- What does this change do, and why? Link the issue if there is one. -->

-

## Scope

- Explicit non-goals:

## Safety invariants

Tick each one this change preserves. If a change touches an invariant, explain
the impact below; weakening one needs a security review and an ADR
(see `CONTRIBUTING.md`).

- [ ] No SMTP `DATA`, `AUTH`, `VRFY`, or `EXPN`, and no message content
- [ ] At most one recipient touch per verification operation; no recipient-stage replay
- [ ] TLS requirement for active SMTP is not weakened
- [ ] Destination safety (private/reserved ranges, peer validation, blocks, allowlist) is not weakened
- [ ] Rate limits and quotas are not weakened
- [ ] No complete email address in normal logs
- [ ] Ambiguous evidence still resolves to `unknown` or `temporary_unknown`
- [ ] Tests stay offline: no public DNS, no third-party MX hosts

Safety impact (if any):

## Validation

```text
make check
# paste the outcome
```

## Documentation

- [ ] Relevant document in `docs/` updated
- [ ] ADR added or superseded if a durable decision changed
- [ ] `CHANGELOG.md` updated for user-visible changes
