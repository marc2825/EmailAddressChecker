# Runbook: sender identity incident

Covers `docs/operations.md` section 4's *disable sender identity*.

The sender identity is the egress IP, its PTR, the EHLO name, the envelope
sender, and the SPF record authorizing them — the five deployment gates in
`docs/operations.md` section 1 that describe *who this deployment is* to a
receiving site. This runbook is for when that identity is in trouble.

## 1. When this fires

- The egress IP appears on a blocklist (`docs/operations.md` section 3's
  `sender IP blocklist appearance` alert).
- A receiving operator names your IP, PTR, or envelope sender in a complaint.
- The PTR, forward DNS, or SPF record changed without a change request — someone
  else's change, or someone else entirely.
- Bounces or replies to the envelope sender mailbox indicate it is being treated
  as a sending source rather than a probe origin.
- The hosting provider contacts you about the traffic.

## 2. Do this now

**Disable the identity: `AdminControl.disable_sender(sender_identity)`.**

This stops active checks that would present that identity. It is narrower than
the global switch, and it is the right first action when the problem is *this
deployment's reputation* rather than the traffic volume. If more than one
identity is configured, or you cannot tell which is affected, use the global
switch from [stop-active-checks.md](stop-active-checks.md) instead and narrow
afterwards.

Passive checks continue. A blocklisted IP has no bearing on passive
classification, and taking the passive API down would be a self-inflicted
outage.

## 3. Then diagnose

Establish, in this order:

1. **Is the identity still what you configured?** Compare the live PTR, the
   forward DNS for the EHLO name, and the SPF record against the values recorded
   in [../readiness-checklist.md](../readiness-checklist.md). A drift here is
   the most common cause and the easiest to fix.
2. **Whose traffic was it?** Read the audit trail and the per-account metrics.
   The abuse indicators from `application/abuse.py` — `ABUSE_INDICATOR` in the
   metrics — will show whether one caller was responsible.
3. **What did the receiving side see?** A listing usually names a reason. Rate,
   unknown-recipient ratio, and connection count are the ones this project can
   affect, and all three are governed by controls that are already configured;
   check what they are set to before changing anything.
4. **Was the identity's mailbox monitored?** The `sender_mailbox_monitored` and
   `abuse_postmaster_monitored` gates exist so that a receiving operator can
   reach you before listing you. If the answer is no, that is a finding in its
   own right.

## 4. Do not

- **Do not rotate the IP, the PTR, the EHLO name, or the envelope sender to get
  around a block.** This is the single most tempting action in this document and
  it is forbidden without exception: `CONTRIBUTING.md` prohibits rotating IPs or
  identities to bypass remote limits, and doing it converts a reputation problem
  into evasion. If the identity is blocked, it stays blocked until the receiving
  operator lifts it or you retire the deployment openly.
- Do not request delisting while the cause is unfixed. You will be listed again
  and the second listing is harder to lift.
- Do not disable TLS, and do not lower `TLSPolicy.REQUIRED`, in the belief that
  a cleaner handshake profile will help. Transport security is not a
  reputation lever.
- Do not raise rate limits to "prove" the traffic is normal, and do not lower
  the unknown-recipient ratio by probing more addresses you expect to succeed.
  Shaping a metric is not fixing a cause.
- Do not send a test message from the deployment to check the identity works.
  That would be `DATA`, which this project must never implement. Use an ordinary
  mail client from a different host if you need to send something.
- Do not bypass the disabled-sender check to run "just one" verification.

## 5. Record and escalate

Escalate to the incident owner immediately — this is the class of incident that
ends a beta, and it involves parties outside your organization. Record:

- the identity affected and the exact time it was disabled (UTC);
- the listing or complaint, verbatim, with its source;
- the configuration values you compared, and whether they had drifted;
- the caller accounts implicated, if any;
- any contact with the receiving operator or the hosting provider, including who
  said what.

Notify the hosting provider if the listing implicates their address space. They
will find out anyway, and hearing it from you is the difference between a
conversation and a termination.

## 6. Restoring

Re-enable with `AdminControl.enable_sender(identity)` only when all of:

- the cause is identified and corrected;
- the listing is lifted, or the receiving operator has confirmed in writing that
  it is;
- the identity's five gates have been re-verified by a human and the checklist
  updated with the new date;
- the incident owner has agreed.

Restart at a lower rate than before and watch the policy-block and timeout
metrics for a full day before returning to the previous configuration.
