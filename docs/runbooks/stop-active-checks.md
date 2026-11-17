# Runbook: stop active checks

Covers *disable active probing* and *rotate a compromised API key* from `docs/operations.md` section 4.

Every other runbook falls back to this one. If you are unsure which procedure applies, do this first: stopping outbound SMTP is never the wrong first move, and it can always be undone.

## 1. When this fires

- A receiving operator has asked you to stop.
- The egress IP is on a blocklist.
- Timeouts, tarpitting, or policy blocks rise sharply (the first two alerts in `docs/operations.md` section 3).
- An API key or account is doing something nobody can explain.
- You are testing the `global kill switch tested` deployment gate.
- Anything is on fire and you want it to stop.

## 2. Do this now

Throw the global switch through the administrative interface: `AdminControl.set_active_probing(False)`.

- New active submissions are refused at admission.
- The worker stops too. Check that in-flight connections drain and no new ones open.

Passive checks keep working by design (`docs/architecture.md` section 5). Do not stop the whole service to stop probing; a full outage is a bigger incident than the one you have.

If the problem is narrower, use a narrower switch. It costs less and is easier to reason about afterwards:

| Scope | Call |
| --- | --- |
| One caller's key | `AdminControl.suspend_key(key_id)` |
| One caller's account | `AdminControl.suspend_account(account_id)` |
| One recipient domain | `AdminControl.block_domain(domain)` |
| One exchanger | `AdminControl.block_exchanger(mx_host)` |
| One sender identity | `AdminControl.disable_sender(identity)`; see [sender-identity-incident.md](sender-identity-incident.md) |

Blocking a domain refuses every verification for it. Blocking one exchanger skips that host and continues with the other candidates. To stop a domain entirely, block the domain.

Each call writes an audit event, which you need in section 5.

## 3. Then diagnose

Once outbound activity has stopped:

- Read the audit trail (`AdminControl.audit_events()`) and confirm your switch is the latest change and that nobody else changed something at the same time.
- Check `kill_switch_state` and `admin_refusal` in the metrics to confirm the expected refusals are happening.
- Decide which of the other six runbooks the underlying cause belongs to, and continue there.

### If an API key is compromised

1. Suspend it first with `AdminControl.suspend_key(key_id)`. Suspension takes effect immediately and is checked before work is admitted.
2. Issue a replacement through the ordinary provisioning path and give it to the owner over a channel you already trust.
3. Do not restore the old key. `AdminControl.restore_key` is for a suspension made by mistake, not for a leaked key.
4. Read the audit trail and per-key metrics for what the key did while out of your control. You will see counts, principals, and reason codes, not the submitted addresses, because complete addresses are never logged. Do not switch that off to help the investigation.

## 4. Do not

- Do not bypass the switch to "finish the jobs already queued". The queue stopping is the switch working.
- Do not disable rate limiting, TLS, or the destination policy to make the service healthy again; none of them is why you are here.
- Do not change the egress IP, PTR, EHLO name, or envelope sender to escape a block. That is identity rotation.
- Do not add recipients to a session or issue a second `RCPT TO` while diagnosing.
- Do not edit configuration files on the host instead of using the switch: the switch is audited and a file edit is not.

## 5. Record and escalate

Tell the incident owner named under the `incident_owner_assigned` deployment gate. In the incident log, write:

- what you switched off, at what scope, and when (UTC);
- the audit event identifiers;
- what you saw that sent you here;
- which runbook you moved on to.

## 6. Restoring

Restore only when the cause is understood and closed, and only through the administrative interface: `set_active_probing(True)`, `restore_key`, `restore_account`, `unblock_domain`, `unblock_exchanger`, `enable_sender`. Each restoration is audited like the suspension.

Restore the narrowest thing first and watch it before widening. If you cannot say what has changed since you switched it off, it is too early to restore.
