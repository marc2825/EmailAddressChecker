# Runbook: abuse complaint

Covers `docs/operations.md` section 4's *respond to abuse complaint*.

A complaint means a person at a receiving site spent their time writing to you
instead of silently blocking you. Treat it as the useful signal it is.

## 1. When this fires

- Mail arrives at the abuse or postmaster mailbox about this deployment's
  traffic.
- A receiving operator contacts you directly, or through the hosting provider.
- `docs/operations.md` section 3's `remote abuse complaint` alert fires.
- A caller reports that *their* customers are complaining about checks they
  submitted.

## 2. Do this now

**Stop the traffic the complaint is about, before you reply.**

- If the complaint names one recipient domain: `AdminControl.block_domain(domain)`.
- If it names one exchanger: `AdminControl.block_exchanger(mx_host)`.
- If it names your IP or sender: go to
  [sender-identity-incident.md](sender-identity-incident.md) first.
- If you cannot tell what it names, or it names more than you can enumerate in a
  couple of minutes: throw the global switch
  ([stop-active-checks.md](stop-active-checks.md)) and narrow afterwards.

Stopping first and understanding second is the correct order here. Every one of
these switches is reversible within seconds, and a complainant who watches the
traffic stop while you investigate is a very different correspondent from one
who watches it continue.

Acknowledge receipt to the complainant within the same working day, even if the
answer is "we have stopped and are investigating". The
`abuse_postmaster_monitored` gate exists so that this acknowledgement is
possible.

## 3. Then diagnose

1. **Match the complaint to the traffic.** Use the audit trail, the
   `ABUSE_INDICATOR` metrics, and per-account counters to find which caller's
   submissions reached that destination and at what rate.
2. **Check the pacing that was actually applied**, not the pacing you intended:
   the destination limits in `QuotaSettings` are counted in verification budget
   units, and `docs/operations.md` section 2's sizing note explains why one
   active submission spends more than one. A limit that looked conservative may
   not have been.
3. **Look for the harvesting shape.** A high ratio of unknown-recipient outcomes
   from one caller against one domain is what `docs/threat-model.md` describes as
   list validation, and it is what a receiving operator sees too. If a caller is
   doing that, the caller is the problem, not the pacing.
4. **Establish what you can and cannot tell the complainant.** This project does
   not log complete addresses, so you can describe volumes, times, destination
   domains, and reason codes, and you cannot produce the list of addresses
   probed. Say so plainly.

## 4. Do not

- **Do not disable rate limits, the destination policy, or any other control to
  clear the backlog** that builds up while you are stopped. A backlog is not an
  emergency; a complaint is.
- **Do not bypass a block to satisfy a caller** who is waiting on results for
  the blocked domain. If a caller escalates, escalate to the incident owner
  rather than lifting the block.
- Do not change the egress IP, PTR, EHLO name, or envelope sender in response to
  a complaint. Rotating away from a complainant is evasion.
- Do not resume probing the complaining domain "at a lower rate" without their
  agreement. Their objection may be to the practice, not the volume.
- Do not retry the affected verifications with more recipients per session, or a
  second `RCPT TO`, to reduce connection count. One verification is at most one
  `RCPT TO`; the connection count is reduced by doing less work, not by packing
  more into each session.
- Do not send any message content, delivery status probe, or `VRFY`/`EXPN` to
  the complainant's infrastructure while investigating.
- Do not offer the complainant a suppression list of the addresses involved.
  Building one would mean retaining exactly the data `docs/privacy.md` says not
  to retain.

## 5. Record and escalate

Escalate to the incident owner. In the incident log record:

- the complaint verbatim, its source, and the time it arrived;
- what you blocked, at what scope, and when (UTC);
- the caller accounts implicated and what their traffic looked like;
- every reply you sent, with its timestamp;
- the outcome the complainant accepted, if any.

If the complaint indicates a caller was using this service to enumerate
addresses, that is a terms violation and a suspension decision, not an
engineering one: `AdminControl.suspend_account(account_id)` stops it now, and
the incident owner decides what happens next.

## 6. Restoring

Unblock only after the complainant has confirmed they are satisfied, or the
incident owner has made an explicit, recorded decision to resume without that
confirmation. Note in the log which of the two it was — a resumption nobody
agreed to is the thing a second complaint will be about.
