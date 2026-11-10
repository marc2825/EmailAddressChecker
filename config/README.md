# Configuration files

| File | Read by code? | Purpose |
|---|---|---|
| `budgets.toml` | **Yes** — `emailcheck … --config config/budgets.toml` | CLI budget settings: batch limits, rate limits, quotas. A complete working example. |
| `local-passive.toml` | No | Reference only: the intended shape of the passive profile. |
| `lab-active.toml.example` | No | Reference only: a lab profile with a destination allowlist. |
| `service-active.toml.example` | No | Reference only: an authenticated service profile. |

The three reference files describe deployment profiles from the design
(`docs/architecture.md`, `docs/operations.md`). No loader reads them today, and
passing one to `--config` is refused because the budget schema is closed.

None of these files authorizes active probing. Authorization is an explicit
operator decision; see `docs/readiness-checklist.md`.

Never commit real configuration, credentials, or a filled-in readiness record.
