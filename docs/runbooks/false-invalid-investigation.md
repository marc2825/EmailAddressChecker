# Runbook: false invalid investigation

Covers *investigate false invalid* and *roll back ruleset* from `docs/operations.md` section 4.

A false `invalid` is the most damaging error this project can make. A false `unknown` costs a caller some certainty; a false `invalid` gets a real person's address deleted from a list. `docs/status-model.md` section 4.1 gates `invalid` behind three conditions for this reason, so a false `invalid` means a gate leaked.

## 1. When this fires

- A caller reports that an address answered `invalid` but demonstrably receives mail.
- A beta target with controlled truth `owned_mailbox`, `owned_alias`, or `owned_forwarding` produced `invalid` (the harness reports it as `contradicts`).
- The `verdict_status` metric shows an unexplained jump in the `invalid` share, especially one starting at a deployment.
- An `invalid` appears whose reason codes you cannot map to one of the five reasons in `docs/status-model.md` section 2.

## 2. Do this now

Do not switch anything off yet. This is the one runbook that does not start with a kill switch: a false `invalid` is a correctness fault, not outbound harm, and stopping the service removes the traffic you need to diagnose it.

1. Preserve the evidence: the job identifier, the time, and the exact published result. Raw evidence is kept only for a bounded window (`docs/privacy.md`); if your investigation will take longer, the retention sweep will remove it first.
2. Record the versions: run `emailcheck --report-versions --json` and keep the output. The ruleset and dataset versions make this observation comparable with others and are the first thing you need if it is a regression.
3. Reproduce passively with `emailcheck ADDRESS --verbose`. If the passive check alone produces `invalid`, the fault is in syntax or DNS handling, no SMTP session is involved, and you can reproduce it offline.

If false `invalid` results appear at volume (many addresses, one pattern), stop active checks ([stop-active-checks.md](stop-active-checks.md)) while you investigate; every second it continues writes wrong results into callers' systems.

## 3. Then diagnose

Work through the layers; each has a different fix.

1. Syntax: was the reason `invalid_syntax`? Compare the address with the grammar in `docs/requirements.md`. A form the grammar does not support must give an `unsupported_*` reason and `unknown`, never `invalid`; if it gave `invalid`, file a classification defect.
2. DNS: was it `domain_nxdomain`, `null_mx`, or `no_mail_route`? Resolve the domain again from a different resolver. A filtering or captive resolver that answers NXDOMAIN for real domains produces false `invalid` results for as long as it is configured, and is the most common real cause. Check the deployment's resolver before suspecting the code.
3. SMTP: was it a `550`-class recipient rejection? Confirm the reason is target-specific and not temporary. A bare `550` is not mailbox-not-found; sender, connection, reputation, and policy failures are never target invalidity, and neither is a TLS failure. If a policy rejection became `invalid`, the mapping is at fault.
4. Aggregation: if each layer's evidence looks right but the verdict does not follow from it, the fault is in tier resolution. Capture the evidence set and reproduce it in a unit test; the fix must be pinned by that test before it ships.

### Rolling back the ruleset

If the false `invalid` began at a deployment that changed the aggregation ruleset version:

1. Confirm the correlation with `emailcheck --report-versions` output from before and after.
2. Redeploy the previous ruleset version through the ordinary release path.
3. Re-run the controlled beta corpus or the offline fixtures and confirm the contradiction is gone.
4. Keep the reproducing case as a test, so the faulty change cannot return unnoticed.

A rollback does not correct results already returned. If wrong `invalid` results were served, tell the affected callers; they may have acted on them.

## 4. Do not

- Do not weaken the `invalid` gate to make the symptom go away. The three conditions in `docs/status-model.md` section 4.1 constrain the fix; making `invalid` easier to reach turns one false invalid into a class of them.
- Do not "fix" a false `invalid` by turning it into `likely_deliverable`. If the evidence does not support a decisive answer, `unknown` or `temporary_unknown` is correct; `CONTRIBUTING.md` forbids the optimistic verdict as firmly as the pessimistic one.
- Do not probe the address repeatedly for a "second opinion". Repeated probing of one address is what rate limits exist to prevent, and the second answer is no truer than the first.
- Do not add recipients to a session, issue a second `RCPT TO`, or send `VRFY`, `EXPN`, or `DATA` to find out whether the mailbox exists. This project cannot establish that, by design.
- Do not disable TLS or lower `TLSPolicy.REQUIRED` to see "what the server would have said". A TLS failure maps to `smtp_tls_failure`, never to invalidity, so there is nothing to learn.
- Do not add the address to a per-address override list. None exists, because it would make one caller's complaint disappear without fixing anyone else's.

## 5. Record and escalate

Record in the incident log:

- the address, redacted the way the logs redact it; never write a complete address into the incident log;
- the job identifier, the published result, and the reason codes;
- the ruleset and dataset versions from `--report-versions`;
- which layer was at fault, and the test that now pins it;
- whether any caller received a wrong `invalid`, and whether they were told.

Escalate to the incident owner if wrong results reached callers, or if the cause is in aggregation rather than configuration: a tier-resolution defect affects every result, not one caller.
