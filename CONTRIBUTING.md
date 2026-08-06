# Contributing

1. Work on one Phase or one narrowly scoped defect at a time.
2. Read the applicable `CLAUDE.md` and its imported `AGENTS.md`.
3. Add or update tests with the change.
4. Run `make check`.
5. Update documentation and `IMPLEMENTATION_STATUS.md` only when acceptance
   criteria pass.
6. Do not introduce real third-party SMTP integration tests into CI.
7. Do not add a dataset without source, license, version, and update policy.
8. Use an ADR for dependency, protocol, storage, or public-contract decisions.
