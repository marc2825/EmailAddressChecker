# ADR 0022: Local Active Mode in the CLI

- Status: Accepted
- Date: 2026-11-26
- Supersedes: the sentence in `docs/requirements.md` section 12 that allowed a direct active mode only for the lab profile.

## Context

The restricted SMTP pipeline (ADR 0003, 0008, 0009, 0019) was complete and tested, but nothing a user could run reached it. Active checks needed either a lab deployment with a destination allowlist or a service with authentication, an isolated worker, and persistent stores. Neither can be built from an installed package on a personal computer, so the project's original aim, more evidence about one recipient without sending mail, was out of reach for its users.

The owner decided that the local CLI may run SMTP checks without a dedicated server, account, or API key. This does not remove the safety rules, and it does not change what checking other people's addresses requires: the user must own the address or be allowed to check it.

## Options

| | A. A mode on `check` | B. A separate command | C. A local profile | D. A separate package |
| --- | --- | --- | --- | --- |
| Cost | Small | Small, plus a second UX | Small | Large: split build, release, and tests |
| User experience | One command, one more option | Two commands for one task | Not visible to users | Two installs |
| Reuse | All of `check`'s output | Duplicates `check` | All of the pipeline | Same code, moved |
| Safety | Same pipeline | Same pipeline | The profile refuses unsafe settings | Not safer: the SMTP code already ships as library code |
| Compatibility | Additive | Additive | Additive | Breaks imports |

## Decision

Combine A and C.

- `emailcheck check ADDRESS --mode active --config FILE` is the only way in. Passive stays the default. Active Mode takes exactly one address; `batch` accepts only `passive`, and nothing connects `expand` to a check.
- The CLI builds a `local-active` deployment through `composition.py`. It is local-passive plus the existing SMTP service: no jobs, no executor, no store, no retention daemon, and no service component. The profile refuses a store and refuses to exist without probing.
- The user's configuration file has an `[smtp]` section: `ehlo_hostname`, `envelope_sender`, and `acknowledged`. The sender identity goes through `load_sender_identity`, which refuses the null sender and an EHLO name unrelated to the sender's domain. Until `acknowledged = true`, the CLI prints what a probe reveals and requires, and stops before any DNS or SMTP use.
- Every existing protection applies unchanged: the six-command vocabulary with no DATA, BDAT, VRFY, EXPN, or AUTH; at most one `RCPT TO` per check (ADR 0019) and the attempt cap; the destination policy and peer check; required TLS with certificate and host-name verification; rate-limit permission before a socket; per-stage timeouts and the 30-second total deadline; and the aggregation rules, so an acceptance is at most `likely_deliverable` at medium confidence.
- The output says whether the SMTP step ran (`smtp_executed`, also true when pacing stopped it before a connection), shows the SMTP step in the evidence ladder, separates "not run" from "tried and failed", and gives a hint for a blocked port, a TLS failure, or a policy refusal.

## What is and is not enforced

Enforced in code and tests: no message content; at most one `RCPT TO` per check; no private, loopback, or metadata destination; TLS required; one address per command; no SMTP without the acknowledgement; no SMTP from `batch`, `expand`, or the legacy single-address form.

Not enforced, and documented as such: quotas and pacing live in one process, so running the command repeatedly, or changing the source, bypasses them; the tool cannot verify that the user owns the EHLO domain or may check the address. Service-active and lab-active keep their own requirements; this profile is not a service and claims no service-level abuse resistance.

## Consequences

- Users can get recipient-stage evidence locally. Many networks block outbound port 25, and many servers refuse home or cloud addresses, so `temporary_unknown` and `unknown` remain common; `docs/evaluation.md` shows what the rules do on scripted servers.
- An accept-all server makes an absent mailbox look accepted. The local CLI does not detect accept-all servers; acceptance stays "not proof".
- `docs/requirements.md` sections 12 and 15, the threat model, and the privacy guide describe the new profile.
