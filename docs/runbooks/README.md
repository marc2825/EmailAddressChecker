# Runbooks

Seven procedures, one per situation a limited beta can get into. Each is written to be followed at 03:00 by someone who did not write the code, and each has the same five sections in the same order:

1. When this fires: the signal that sends you here.
2. Do this now: the smallest action that stops the harm.
3. Then diagnose: what to examine once nothing is getting worse.
4. Do not: tempting actions that are forbidden, and why.
5. Record and escalate: what to write down and whom to tell.

## The seven

| Runbook | `docs/operations.md` section 4 topics |
| --- | --- |
| [stop-active-checks.md](stop-active-checks.md) | disable active probing; rotate a compromised API key |
| [sender-identity-incident.md](sender-identity-incident.md) | disable sender identity |
| [abuse-complaint.md](abuse-complaint.md) | respond to abuse complaint |
| [false-invalid-investigation.md](false-invalid-investigation.md) | investigate false invalid; roll back ruleset |
| [privacy-deletion.md](privacy-deletion.md) | delete user data |
| [destination-ssrf-alert.md](destination-ssrf-alert.md) | investigate destination SSRF alert |
| [queue-store-outage.md](queue-store-outage.md) | restore queue/store |

## The rule that outranks every runbook

Do not bypass a safety control to make an incident go away. An incident is when removing a control is most tempting and least safe. No procedure here may ever tell you to:

- send SMTP `DATA`, `VRFY`, or `EXPN`, or any message content (`CONTRIBUTING.md` forbids them unconditionally, and no outage makes them diagnostic);
- retry with additional recipients or issue a second `RCPT TO` in a session (one verification is at most one `RCPT TO`, and more recipients is what harvesting looks like to the receiver);
- disable TLS, downgrade `TLSPolicy.REQUIRED`, or ignore a certificate error to get a result;
- disable or raise a rate limit to clear a backlog (pacing keeps this project distinguishable from a harvester, and a backlog is not an emergency);
- change the egress IP, PTR, EHLO name, or envelope sender to get around a remote block (that is identity rotation, which this project never does).

If a runbook seems to require one of these, the runbook is wrong. Stop, escalate to the incident owner, and leave the control in place.

## Turning things off is always allowed

Any operator may throw the global kill switch, suspend a key, block a domain, or stop the worker at any time without approval. The switches in `docs/operations.md` section 2 all reduce outbound activity, and nothing needs permission to become quieter.

## Before the beta

Two deployment gates in `docs/operations.md` section 1, `global kill switch tested` and `retention deletion tested`, are met by performing [stop-active-checks.md](stop-active-checks.md) and [privacy-deletion.md](privacy-deletion.md) once on the deployment before the beta starts, and recording who did it and when.
