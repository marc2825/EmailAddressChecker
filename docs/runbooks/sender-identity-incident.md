# Runbook: sender identity incident

Covers *disable sender identity* from `docs/operations.md` section 4.

The sender identity is the egress IP, its PTR, the EHLO name, the envelope sender, and the SPF record that authorizes them: the identity gates in `docs/operations.md` section 1 that tell a receiving site who this deployment is. Use this runbook when that identity is in trouble.

## 1. When this fires

- The egress IP is on a blocklist (the `sender IP blocklist appearance` alert in `docs/operations.md` section 3).
- A receiving operator names your IP, PTR, or envelope sender in a complaint.
- The PTR, forward DNS, or SPF record changed without a change request.
- Bounces or replies to the envelope sender show it is being treated as a sending source rather than a probe origin.
- The hosting provider contacts you about the traffic.

## 2. Do this now

Disable the identity: `AdminControl.disable_sender(sender_identity)`.

This stops active checks that would present that identity. It is narrower than the global switch and is the right first step when the problem is this deployment's reputation rather than traffic volume. If several identities are configured, or you cannot tell which one is affected, use the global switch in [stop-active-checks.md](stop-active-checks.md) and narrow afterwards.

Passive checks continue; a blocklisted IP does not affect them, and taking the passive API down would be a self-inflicted outage.

## 3. Then diagnose

In this order:

1. Is the identity still what you configured? Compare the live PTR, the forward DNS of the EHLO name, and the SPF record with the values in [../readiness-checklist.md](../readiness-checklist.md). Drift here is the most common cause and the easiest fix.
2. Whose traffic was it? Read the audit trail and per-account metrics; the abuse indicators (`ABUSE_INDICATOR`) show whether one caller was responsible.
3. What did the receiving side see? A listing usually gives a reason. Rate, unknown-recipient ratio, and connection count are the ones this project can affect, and all three are governed by configured controls; check their settings before changing anything.
4. Were the mailboxes monitored? The `sender_mailbox_monitored` and `abuse_postmaster_monitored` gates exist so a receiving operator can reach you before listing you. If they were not monitored, that is a finding in itself.

## 4. Do not

- Do not rotate the IP, PTR, EHLO name, or envelope sender to get around a block. This is the most tempting action here and it is forbidden without exception (`CONTRIBUTING.md`): it turns a reputation problem into evasion. A blocked identity stays blocked until the receiving operator lifts the block or you retire the deployment openly.
- Do not request delisting while the cause is unfixed; a second listing is harder to lift.
- Do not disable TLS or lower `TLSPolicy.REQUIRED` hoping a different handshake will help. Transport security is not a reputation lever.
- Do not raise rate limits to "prove" the traffic is normal, and do not improve the unknown-recipient ratio by probing addresses you expect to succeed. Shaping a metric fixes nothing.
- Do not send a test message from the deployment. That would be `DATA`, which this project never implements. If you must send something, use an ordinary mail client on another host.
- Do not bypass the disabled-sender check to run "just one" verification.

## 5. Record and escalate

Escalate to the incident owner immediately: this kind of incident can end a beta and involves people outside your organization. Record:

- the identity affected and when it was disabled (UTC);
- the listing or complaint, verbatim, with its source;
- the configuration values you compared, and whether they had drifted;
- the caller accounts involved, if any;
- every contact with the receiving operator or the hosting provider, including who said what.

Tell the hosting provider if the listing involves their address space. They will find out anyway, and hearing it from you first changes the conversation.

## 6. Restoring

Re-enable with `AdminControl.enable_sender(identity)` only when:

- the cause is identified and corrected;
- the listing is lifted, or the receiving operator has confirmed in writing that it will be;
- a human has re-verified the identity gates and updated their dates in the checklist;
- the incident owner agrees.

Restart at a lower rate than before and watch the policy-block and timeout metrics for a full day before returning to the previous configuration.
