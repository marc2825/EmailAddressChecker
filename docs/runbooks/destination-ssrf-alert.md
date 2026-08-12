# Runbook: destination SSRF alert

Covers `docs/operations.md` section 4's *investigate destination SSRF alert* and
section 3's `unsafe destination resolution attempt` alert.

This alert means DNS pointed a verification at an address the destination policy
refused: a private range, loopback, link-local, a cloud metadata endpoint, or
one of the other classes in `DestinationDenyReason`. The refusal already
happened — `security/destination.py` denied it before any socket existed. What
you are investigating is *why the answer contained that address*.

## 1. When this fires

- The `unsafe destination resolution attempt` alert, or a `DestinationDecision`
  with a deny reason appearing in the metrics.
- A `METADATA`, `LOOPBACK`, `PRIVATE`, `UNIQUE_LOCAL`, or `TRANSLATED` denial in
  particular. These are the ones worth waking somebody for: the first is a
  credential-theft target and the rest are internal-service reachability.
- Repeated denials for one recipient domain, or for one caller's submissions.

## 2. Do this now

**Nothing, to the destination policy.** It worked. The connection did not
happen, and the correct first action is to leave every barrier exactly where it
is.

Do this instead:

1. **Block the recipient domain** whose MX resolved to the refused address:
   `AdminControl.block_domain(domain)`. This is not because the policy needs
   help — it is because a domain that resolves to internal space is one you
   should stop spending verifications on until you know why.
2. **If more than one domain is involved, or the same caller is behind several**,
   suspend the account: `AdminControl.suspend_account(account_id)`. A caller
   steering the worker at internal addresses is `docs/threat-model.md`'s SSRF
   threat with a name attached to it.
3. **If the denials are spread across unrelated domains**, suspect the resolver
   rather than the callers, and go to section 3 before blocking anything else.

## 3. Then diagnose

1. **Which reason?** `DestinationDenyReason` has one member per class of range
   precisely so you can tell a private network from a metadata endpoint without
   reading free text. `METADATA` is a targeted attack until proven otherwise;
   `PRIVATE` on a single domain is more often a misconfigured MX; `MALFORMED` is
   usually a broken zone.
2. **Whose DNS answered?** Re-resolve the domain from a resolver outside this
   deployment. If the external answer is a public address and the deployment's
   resolver returned an internal one, your resolver is the problem — a
   split-horizon view, a rewriting resolver, or a compromised one. That is a
   larger incident than the alert.
3. **Was every hop validated?** The controls validate all A/AAAA answers and
   CNAME hops, approve only an address the candidate actually resolved to, and
   re-check the peer address *and port* at connect. Confirm from the audit and
   metrics that the denial happened at the expected barrier. If the denial
   appeared at a *later* barrier than you expect — at `ConfirmedPeer` rather
   than at `approve_destination` — that ordering is itself a finding, because it
   means an earlier check let something through.
4. **Check the network-level barrier.** The `private_egress_blocked` deployment
   gate requires the firewall or security group to prevent the worker reaching
   internal ranges. The in-process policy is the first barrier, not the only
   one. Confirm the second is actually in place; an incident is a good moment to
   discover it never was.

## 4. Do not

- **Do not add an exception to the destination policy.** Not for a customer, not
  for a test domain, not temporarily. The ranges are listed explicitly rather
  than derived from `ipaddress.is_private` or `is_global` (ADR 0006) because the
  library predicates allow carrier-grade NAT, IPv6 multicast, and a NAT64
  address reaching loopback. Every entry in that list is there because leaving
  it out was a way to reach something internal.
- **Do not bypass `approve_destination`, `ApprovedDestination`, or
  `ConfirmedPeer`** to reproduce the connection "safely". These are types rather
  than steps specifically so that no code path — including a diagnostic one —
  can skip them.
- Do not connect to the refused address by hand from the worker host to see
  what is there. If you need to know what is running on an internal address, ask
  the team that owns it, from a host that is supposed to reach it.
- Do not disable the network-level egress block while investigating the
  in-process one, or the reverse. Two barriers are only two barriers when both
  are up.
- Do not raise rate limits or retry the verification. The answer will not change
  and the attempt is the thing being alerted on.
- Do not send `VRFY`, `EXPN`, `DATA`, or any message content to anything, at any
  point in this procedure.

## 5. Record and escalate

Escalate to the incident owner. `METADATA` denials, or any denial you cannot
explain by misconfiguration, should also go to whoever owns the deployment's
network — a caller probing your internal space is their incident too.

Record:

- the deny reason, the recipient domain, and the refused address;
- the caller account, if the denials cluster on one;
- the external resolution of the domain, for comparison;
- whether the network-level egress block is confirmed in place;
- what you blocked and when (UTC).

## 6. Restoring

Unblock the domain only when its MX resolves to a public address from both your
resolver and an external one, and you can say why it did not before. Restore a
suspended account only after the incident owner has decided that the caller's
submissions were a mistake rather than an attempt.
