# Configuration files

| File | Read by code? | Purpose |
|---|---|---|
| `budgets.toml` | Yes, through `emailcheck … --config config/budgets.toml` | A complete, working example of the CLI budget settings: batch limits, rate limits, and quotas. |
| `local-passive.toml` | No | Reference: the intended shape of the passive profile. |
| `lab-active.toml.example` | No | Reference: a lab profile with a destination allowlist. |
| `service-active.toml.example` | No | Reference: an authenticated service profile. |

The three reference files describe the deployment profiles in `docs/architecture.md` and `docs/operations.md`. No code loads them, and `--config` refuses them because the budget schema accepts no other keys.

None of these files authorizes active probing. That takes an explicit operator decision; see `docs/readiness-checklist.md`.

Never commit real configuration, credentials, or a filled-in readiness record.
