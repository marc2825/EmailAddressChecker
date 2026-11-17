# Runbook: abuse complaint

Covers *respond to abuse complaint* from `docs/operations.md` section 4.

A complaint means someone at a receiving site wrote to you instead of quietly blocking you. Treat it as the useful signal it is.

## 1. When this fires

- Mail about this deployment's traffic arrives at the abuse or postmaster mailbox.
- A receiving operator contacts you directly or through the hosting provider.
- The `remote abuse complaint` alert in `docs/operations.md` section 3 fires.
- A caller reports that their customers are complaining about checks they submitted.

## 2. Do this now

Stop the traffic the complaint is about before you reply.

- The complaint names one recipient domain: `AdminControl.block_domain(domain)`.
- It names one exchanger: `AdminControl.block_exchanger(mx_host)`.
- It names your IP or sender: go to [sender-identity-incident.md](sender-identity-incident.md) first.
- You cannot tell what it names, or it names more than you can list in a couple of minutes: throw the global switch ([stop-active-checks.md](stop-active-checks.md)) and narrow afterwards.

Stop first and understand second. Each switch can be reversed in seconds, and a complainant who sees the traffic stop while you investigate is a very different correspondent from one who sees it continue.

Acknowledge the complaint the same working day, even if the answer is "we have stopped and are investigating". That is why the `abuse_postmaster_monitored` gate exists.

## 3. Then diagnose

1. Match the complaint to the traffic. Use the audit trail, the `ABUSE_INDICATOR` metrics, and per-account counters to find whose submissions reached that destination, and at what rate.
2. Check the pacing actually applied, not the pacing you intended. Destination limits in `QuotaSettings` count verification budget units, and one active submission spends more than one (`docs/operations.md` section 2), so a limit that looked conservative may not have been.
3. Look for the harvesting pattern. A high ratio of unknown-recipient outcomes from one caller against one domain is list validation (`docs/threat-model.md`), and the receiving operator sees it too. If a caller is doing that, the caller is the problem, not the pacing.
4. Decide what you can tell the complainant. Complete addresses are never logged, so you can describe volumes, times, destination domains, and reason codes, but you cannot produce the list of addresses probed. Say so plainly.

## 4. Do not

- Do not disable rate limits, the destination policy, or any other control to clear the backlog that builds while you are stopped. A backlog is not an emergency; a complaint is.
- Do not bypass a block for a caller waiting on results for the blocked domain. If the caller escalates, escalate to the incident owner instead of lifting the block.
- Do not change the egress IP, PTR, EHLO name, or envelope sender in response to a complaint; rotating away from a complainant is evasion.
- Do not resume probing the complaining domain "at a lower rate" without its agreement. The objection may be to the practice, not the volume.
- Do not retry the affected verifications with more recipients per session or a second `RCPT TO` to reduce connections. One verification is at most one `RCPT TO`; fewer connections come from doing less work.
- Do not send message content, a delivery status probe, or `VRFY`/`EXPN` to the complainant's infrastructure while investigating.
- Do not offer the complainant a suppression list of the addresses involved. Building one would mean keeping exactly the data `docs/privacy.md` says not to keep.

## 5. Record and escalate

Escalate to the incident owner, and record in the incident log:

- the complaint verbatim, its source, and when it arrived;
- what you blocked, at what scope, and when (UTC);
- the caller accounts involved and what their traffic looked like;
- every reply you sent, with its time;
- the outcome the complainant accepted, if any.

If a caller was using the service to enumerate addresses, that is a terms violation and a suspension decision, not an engineering one. `AdminControl.suspend_account(account_id)` stops it now; the incident owner decides what follows.

## 6. Restoring

Unblock only after the complainant confirms they are satisfied, or after the incident owner records an explicit decision to resume without that confirmation. Note which of the two it was; a resumption nobody agreed to is what the second complaint will be about.
