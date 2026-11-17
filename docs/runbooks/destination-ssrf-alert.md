# Runbook: destination SSRF alert

Covers *investigate destination SSRF alert* from `docs/operations.md` section 4 and the `unsafe destination resolution attempt` alert from section 3.

The alert means DNS pointed a verification at an address the destination policy refused: a private range, loopback, link-local, a cloud metadata endpoint, or another class in `DestinationDenyReason`. The refusal has already happened; `security/destination.py` denied it before any socket existed. You are investigating why the DNS answer contained that address.

## 1. When this fires

- The `unsafe destination resolution attempt` alert, or a `DestinationDecision` with a deny reason in the metrics.
- In particular, a `METADATA`, `LOOPBACK`, `PRIVATE`, `UNIQUE_LOCAL`, or `TRANSLATED` denial. These justify waking someone: the first is a credential-theft target, and the others mean internal services are reachable.
- Repeated denials for one recipient domain or for one caller's submissions.

## 2. Do this now

Leave the destination policy alone. It worked, and every barrier stays where it is.

1. Block the recipient domain whose MX resolved to the refused address: `AdminControl.block_domain(domain)`. The policy does not need help; a domain that resolves to internal space should simply get no more verifications until you know why.
2. If several domains are involved, or one caller is behind several, suspend the account: `AdminControl.suspend_account(account_id)`. A caller steering the worker at internal addresses is the SSRF threat in `docs/threat-model.md`.
3. If the denials are spread over unrelated domains, suspect the resolver rather than callers, and go to section 3 before blocking anything else.

## 3. Then diagnose

1. Which reason? `DestinationDenyReason` has one member per class of range so you can tell them apart without reading free text. Treat `METADATA` as a targeted attack until proven otherwise. `PRIVATE` on a single domain is more often a misconfigured MX, and `MALFORMED` is usually a broken zone.
2. Whose DNS answered? Resolve the domain from a resolver outside this deployment. If the outside answer is public and the deployment's resolver returned an internal address, the resolver is the problem (split-horizon, rewriting, or compromised), which is a larger incident than the alert.
3. Did the denial happen at the expected barrier? Every A/AAAA answer and CNAME hop is validated, only an address the candidate actually resolved to is approved, and the peer address and port are checked at connect. If the denial appeared later than expected (at `ConfirmedPeer` instead of `approve_destination`), an earlier check let something through, and that is a finding.
4. Is the network-level barrier in place? The `private-network egress blocked` gate requires the firewall or security group to stop the worker reaching internal ranges. The in-process policy is the first barrier, not the only one; confirm the second actually exists.

## 4. Do not

- Do not add an exception to the destination policy, for a customer, a test domain, or temporarily. The ranges are listed explicitly instead of using `ipaddress.is_private` or `is_global` (ADR 0006), because those predicates allow carrier-grade NAT, IPv6 multicast, and a NAT64 address that reaches loopback. Every entry is there because leaving it out reached something internal.
- Do not bypass `approve_destination`, `ApprovedDestination`, or `ConfirmedPeer` to reproduce the connection "safely". They are types precisely so that no code path, diagnostic or not, can skip them.
- Do not connect to the refused address by hand from the worker host. If you need to know what runs there, ask the team that owns it, from a host meant to reach it.
- Do not disable the network egress block while investigating the in-process policy, or the reverse. Two barriers only count when both are up.
- Do not raise rate limits or retry the verification. The answer will not change, and the attempt is what triggered the alert.
- Do not send `VRFY`, `EXPN`, `DATA`, or any message content to anything during this procedure.

## 5. Record and escalate

Escalate to the incident owner. Send `METADATA` denials, and any denial you cannot explain by misconfiguration, to the owner of the deployment's network as well; a caller probing your internal space is their incident too.

Record:

- the deny reason, the recipient domain, and the refused address;
- the caller account, if the denials cluster on one;
- the external resolution of the domain, for comparison;
- whether the network egress block is confirmed in place;
- what you blocked, and when (UTC).

## 6. Restoring

Unblock the domain only when its MX resolves to a public address from both your resolver and an external one, and you can explain why it did not before. Restore a suspended account only after the incident owner decides the caller's submissions were a mistake, not an attempt.
