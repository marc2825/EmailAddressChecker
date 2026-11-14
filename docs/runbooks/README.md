# Runbooks

Seven procedures, one file each, for
the seven situations a limited beta can actually get into.

Every one is written to be followed at 03:00 by somebody who did not write the
code. So each has the same five sections, in the same order:

1. **When this fires** — the signal that sends you here.
2. **Do this now** — the smallest action that stops the harm, first.
3. **Then diagnose** — what to look at, once nothing is getting worse.
4. **Do not** — the tempting actions that are forbidden, and why.
5. **Record and escalate** — what to write down, and who to tell.

## The seven

| Runbook | `docs/operations.md` section 4 items it carries |
| --- | --- |
| [stop-active-checks.md](stop-active-checks.md) | disable active probing; rotate a compromised API key |
| [sender-identity-incident.md](sender-identity-incident.md) | disable sender identity |
| [abuse-complaint.md](abuse-complaint.md) | respond to abuse complaint |
| [false-invalid-investigation.md](false-invalid-investigation.md) | investigate false invalid; roll back ruleset |
| [privacy-deletion.md](privacy-deletion.md) | delete user data |
| [destination-ssrf-alert.md](destination-ssrf-alert.md) | investigate destination SSRF alert |
| [queue-store-outage.md](queue-store-outage.md) | restore queue/store |

## The rule that outranks every runbook

**Do not bypass a safety control to make an incident go away.** Every control
these procedures touch was put there by an ADR or the threat model, and an
incident is the moment it is most tempting and least safe to remove one. In
particular, no procedure in this directory may ever tell you to:

- send SMTP `DATA`, `VRFY`, or `EXPN`, or transmit any message content —
  `CONTRIBUTING.md` forbids all four unconditionally, and no outage makes them
  diagnostic;
- retry with additional recipients, or issue a second `RCPT TO` in a session —
  one verification is at most one `RCPT TO`, and more recipients is what
  address harvesting looks like from the receiving end;
- disable TLS, downgrade `TLSPolicy.REQUIRED`, or ignore a certificate error to
  get a result;
- disable or raise a rate limit to clear a backlog — pacing is what keeps this
  project distinguishable from a harvester, and a backlog is not an emergency;
- change the egress IP, the PTR, the EHLO name, or the envelope sender to get
  around a remote block — that is identity rotation, and this project does not
  do it at any severity.

If a runbook seems to require one of these, it is the runbook that is wrong.
Stop, escalate to the incident owner, and leave the control in place.

## Turning things off is always allowed

The inverse is never restricted. Any operator may throw the global kill switch,
suspend a key, block a domain, or stop the worker without approval, at any time.
`docs/operations.md` section 2's switches exist to be used, and every one of
them fails toward *less* outbound activity. Nothing in this project needs
permission to become quieter.

## Before the beta

Two of these are also deployment gates in `docs/operations.md` section 1 —
`global kill switch tested` and `retention deletion tested`. Testing them means
performing [stop-active-checks.md](stop-active-checks.md) and
[privacy-deletion.md](privacy-deletion.md) on the deployment, once, before the
beta starts, and recording who did it and when. A procedure nobody has run is a
document, not a control.
