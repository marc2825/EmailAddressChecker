# Runbook: stop active checks

Covers `docs/operations.md` section 4's *disable active probing* and *rotate a
compromised API key*.

This is the runbook every other runbook falls back to. If you are unsure which
procedure applies, perform this one first: stopping outbound SMTP is never the
wrong first move, and it is always reversible.

## 1. When this fires

- A receiving operator has asked you to stop.
- The egress IP appears on a blocklist.
- Timeouts, tarpits, or policy blocks rise sharply (`docs/operations.md`
  section 3's first two alerts).
- An API key or account is behaving in a way nobody can account for.
- You are about to test the `global kill switch tested` deployment gate.
- Anything at all is on fire and you want it to stop.

## 2. Do this now

**The global switch, at the widest scope you can justify.** Through the
administrative interface, `AdminControl.set_active_probing(False)`.

Two things happen, and both matter:

- new active submissions are refused at admission;
- **the worker stops too.** `docs/operations.md` section 2 is explicit that a
  switch stopping only new work would leave the queue connecting to remote hosts
  after an operator said stop. Verify this: watch that in-flight connections
  drain and no new ones open.

Passive checks keep answering, by design. `docs/architecture.md` section 5
requires the passive API to survive when active components are unavailable, and
an operator switching probing off is that condition arrived at deliberately.
**Do not stop the whole service to stop probing** — a full outage is a larger
incident than the one you have.

If the problem is narrower than "everything", the narrower switch is better,
because it costs less and is easier to reason about afterwards:

| Scope | Call |
| --- | --- |
| One caller's key | `AdminControl.suspend_key(key_id)` |
| One caller's account | `AdminControl.suspend_account(account_id)` |
| One recipient domain | `AdminControl.block_domain(domain)` |
| One exchanger | `AdminControl.block_exchanger(mx_host)` |
| One sender identity | `AdminControl.disable_sender(identity)` — see [sender-identity-incident.md](sender-identity-incident.md) |

Blocking a domain refuses verifications for it. Blocking a single exchanger
*skips* that host and continues with the remaining candidates: the two
granularities are separate rows in `docs/operations.md` section 2 and they mean
different things. If you need a domain to stop entirely, block the domain.

Every one of these writes an audit event. That is deliberate — you will need it
in section 5.

## 3. Then diagnose

Once outbound activity has stopped:

- read the audit trail (`AdminControl.audit_events()`) and confirm your switch
  is the most recent change, and that nobody else changed something at the same
  time;
- check `kill_switch_state` and `admin_refusal` in the metrics to confirm the
  refusals you expect are the refusals happening;
- work out which of the other six runbooks the underlying cause belongs to, and
  go there.

### If an API key is compromised

1. `AdminControl.suspend_key(key_id)` first. Suspension is immediate and is
   checked before the work is admitted, not after.
2. Issue a replacement key through the ordinary provisioning path and give it to
   the owner over a channel you already trust.
3. Do not restore the old key. `AdminControl.restore_key` exists for a
   suspension made in error, not for a key that leaked.
4. Read the audit trail and the per-key metrics for what the key did while it
   was out of your control. Note that this project never logs a complete
   address, so you will see counts, principals, and reason codes — not the
   addresses that were submitted. That is the privacy property working, and it
   is not something to switch off to improve the investigation.

## 4. Do not

- **Do not bypass the switch** to "finish the jobs already queued". The queue
  stopping is the switch working.
- Do not disable rate limiting, TLS, or the destination policy to get the
  service healthy again. None of them is why you are here.
- Do not change the egress IP, PTR, EHLO name, or envelope sender to escape a
  block. That is identity rotation and this project does not do it.
- Do not add recipients to a session or issue a second `RCPT TO` while
  diagnosing. One verification is at most one `RCPT TO`.
- Do not edit configuration files on the host as a substitute for the switch:
  the switch is audited and a file edit is not.

## 5. Record and escalate

Tell the incident owner named under the `incident_owner_assigned` deployment
gate. Write in the incident log:

- what you switched off, at what scope, and at what time (UTC);
- the audit event identifiers;
- what you observed that sent you here;
- which runbook you moved on to.

## 6. Restoring

Restore only when the cause is understood and closed, and only through the same
administrative interface: `set_active_probing(True)`, `restore_key`,
`restore_account`, `unblock_domain`, `unblock_exchanger`, `enable_sender`. Each
restoration is audited exactly like the suspension.

Restore the **narrowest** thing first and watch it before widening. If you
cannot say what changed since you switched it off, it is too early to restore.
