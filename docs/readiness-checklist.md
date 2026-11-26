# Operational readiness checklist

One row for each deployment gate in `docs/operations.md` section 1, in the same order, with space to record who verified it and when. These gates are for a service deployment; local Active Mode on a user's own machine is covered by ADR 0022 instead.

A beta starts only from a signed copy of this checklist, after a human has verified every gate. Phase 8 is ready for manual gate, not production approved. Until this document is filled in and the incident owner agrees, `external_probing_authorized` stays `False` and the harness probes nothing.

## What the software can and cannot tell you

`emailcheck --check-deployment` prints all thirteen gates and reports what this
process knows about each. Read what it actually claims:

| It says | It means |
| --- | --- |
| `requires_human_verification` | Nothing in this process can observe this gate. Ten of thirteen are like this. |
| `configured_in_process` | This deployment holds the configuration the gate depends on. It does not mean the gate is satisfied. |
| `not_configured_in_process` | The configuration is absent. This is conclusive, and it is bad. |

There is deliberately no `passed`. Every gate is either an external fact (a PTR record, an open port 25, an SPF record) or a human commitment ("the abuse mailbox is monitored"), and a process cannot observe either about itself. The command is therefore advisory and always exits with 0; a non-zero code would invite scripting a deployment against it.

The command resolves no name, opens no socket, and reads no environment.

## Fill this in

Do not record any secret here: no API key, no password, no key material, no private DNS zone contents. Record who checked, when, and where the evidence is. Checklists are circulated and copied, so treat this one as public within your organization.

Make a copy for each deployment and fill in its name and profile at the top.

- Deployment: ______________________
- Profile: ______________________
- Egress IP: ______________________
- Incident owner: ______________________
- Deputy: ______________________
- Completed on (UTC): ______________________

## The thirteen gates

### 1. static public IP

Why: docs/requirements.md section 9 requires a static IP for active checks: reputation attaches to an address, and a changing one cannot carry PTR, SPF, or a complaint history.

Verify: Confirm with the hosting provider that the egress address is static and reserved to this deployment. Record the address in the checklist.

| | |
| --- | --- |
| Verified by | |
| Date (UTC) | |
| Evidence | |
| In-process evidence | None. This process cannot observe it. |

### 2. outbound port 25 confirmed

Why: Port 25 is the only port this project connects to, and many providers block it silently. Discovering that during a beta makes every result a connection timeout.

Verify: From the deployment host, confirm outbound 25 reaches an exchanger you own. This project does not test it: a probe from here would be an external connection the beta has not yet been authorized to make.

| | |
| --- | --- |
| Verified by | |
| Date (UTC) | |
| Evidence | |
| In-process evidence | None. This process cannot observe it. |

### 3. PTR configured

Why: docs/requirements.md section 9 requires a PTR aligned with the EHLO host. Receiving sites treat a missing or generic PTR as a harvesting signal.

Verify: Look up the PTR for the egress IP from a host outside this deployment and confirm it names the EHLO FQDN.

| | |
| --- | --- |
| Verified by | |
| Date (UTC) | |
| Evidence | |
| In-process evidence | None. This process cannot observe it. |

### 4. EHLO forward DNS aligned

Why: Section 9 requires forward DNS that resolves the EHLO host back to the egress IP. A PTR alone is half of the pair and proves nothing on its own.

Verify: Resolve the EHLO FQDN from outside this deployment and confirm it answers with the egress IP.

| | |
| --- | --- |
| Verified by | |
| Date (UTC) | |
| Evidence | |
| In-process evidence | None. This process cannot observe it. |

### 5. SPF configured

Why: Section 9 requires SPF authorizing the egress IP for the envelope sender's domain. Without it the MAIL FROM this project presents is unauthenticated.

Verify: Retrieve the SPF record for the configured envelope sender's domain and confirm it authorizes the egress IP.

| | |
| --- | --- |
| Verified by | |
| Date (UTC) | |
| Evidence | |
| In-process evidence | None. This process cannot observe it. |

### 6. sender mailbox monitored

Why: Section 9 requires a managed envelope sender. A bounce or a reply that nobody reads is a complaint this project never learns about.

Verify: Confirm a named person or rota reads the envelope sender's mailbox, and record who.

| | |
| --- | --- |
| Verified by | |
| Date (UTC) | |
| Evidence | |
| In-process evidence | None. This process cannot observe it. |

### 7. abuse and postmaster mailboxes monitored

Why: Section 9 requires monitored abuse and postmaster channels. docs/threat-model.md's sender-reputation controls name the abuse mailbox as the route a receiving operator uses to reach you before blocklisting.

Verify: Send a test message to each from outside and confirm a monitored human receives it. Record the rota.

| | |
| --- | --- |
| Verified by | |
| Date (UTC) | |
| Evidence | |
| In-process evidence | None. This process cannot observe it. |

### 8. hosting terms reviewed

Why: Section 9 requires a provider and host policy that permits the use. Many hosting agreements forbid exactly this traffic pattern.

Verify: Read the acceptable-use policy and record who reviewed it and when. If it is ambiguous, get written confirmation before the beta.

| | |
| --- | --- |
| Verified by | |
| Date (UTC) | |
| Evidence | |
| In-process evidence | None. This process cannot observe it. |

### 9. global kill switch tested

Why: docs/operations.md section 2 makes the global switch the first control. A switch nobody has thrown is one nobody knows works, and it is needed at exactly the moment there is no time to find out.

Verify: Throw the switch on the deployment, confirm a queued job stops and a new active submission is refused, then restore it. docs/runbooks/stop-active-checks.md.

| | |
| --- | --- |
| Verified by | |
| Date (UTC) | |
| Evidence | |
| In-process evidence | `emailcheck --check-deployment` reports configuration for this gate. Configuration is not verification. |

### 10. rate limits tested

Why: Destination pacing is what keeps this project from resembling the harvesting docs/threat-model.md describes. Untested limits are a configuration nobody has exercised.

Verify: Exercise the configured limits against an exchanger you own and confirm pacing and refusals behave as configured.

| | |
| --- | --- |
| Verified by | |
| Date (UTC) | |
| Evidence | |
| In-process evidence | `emailcheck --check-deployment` reports configuration for this gate. Configuration is not verification. |

### 11. private-network egress blocked

Why: docs/architecture.md section 5 requires worker egress limited to DNS and allowed SMTP destinations. The destination policy refuses private ranges, and a network-level block is the second barrier behind it.

Verify: Confirm at the firewall or security group that the worker cannot reach internal ranges. The in-process policy is not a substitute.

| | |
| --- | --- |
| Verified by | |
| Date (UTC) | |
| Evidence | |
| In-process evidence | None. This process cannot observe it. |

### 12. retention deletion tested

Why: docs/privacy.md section 7 requires deletion to be implemented and tested. A retention policy that has never deleted anything is a claim rather than a control.

Verify: Run a retention sweep against the deployment store and confirm expired records are gone and the run is audited. docs/runbooks/privacy-deletion.md.

| | |
| --- | --- |
| Verified by | |
| Date (UTC) | |
| Evidence | |
| In-process evidence | `emailcheck --check-deployment` reports configuration for this gate. Configuration is not verification. |

### 13. incident owner assigned

Why: SECURITY.md requires an incident log and owner. Every runbook escalates to somebody, and an unnamed somebody is nobody.

Verify: Name the person and the deputy, and record where the incident log lives.

| | |
| --- | --- |
| Verified by | |
| Date (UTC) | |
| Evidence | |
| In-process evidence | None. This process cannot observe it. |

## Sign-off

All thirteen gates above are verified, with evidence recorded.

- Verified by: ______________________  Date (UTC): ____________
- Incident owner agrees the beta may start: ______________________  Date (UTC): ____________

Only after both lines are signed may an operator set `BetaAuthorization.external_probing_authorized = True` for a corpus of owned or explicitly authorized targets. That flag is the only record of the decision, and nothing in this project infers it: not this checklist, not the validation command, not a clean metrics dashboard.

## Re-verification

Verification is not one-off. Verify again:

- every gate, before a beta resumes after a pause of more than a month;
- the five identity gates (static IP, port 25, PTR, forward DNS, SPF), after any change to the host, its address, or its DNS, and after any incident handled with [runbooks/sender-identity-incident.md](runbooks/sender-identity-incident.md);
- `global kill switch tested` and `retention deletion tested`, after any change to the administrative interface or the retention configuration;
- `incident owner assigned`, whenever the owner or the deputy changes.

A gate verified before the last change to what it describes is not verified.

## Related

- [operations.md](operations.md), sections 1 and 2: the gates and the switches.
- [runbooks/](runbooks/): the seven procedures; two of them are how the kill switch and retention gates are tested.
- [privacy.md](privacy.md), section 7: what deletion must do.
- [threat-model.md](threat-model.md): why the egress and destination gates exist.
