# Runbook: false invalid investigation

Covers `docs/operations.md` section 4's *investigate false invalid* and *roll
back ruleset*.

A false `invalid` is this project's most damaging possible error. A false
`unknown` costs a caller a little certainty; a false `invalid` gets a real
person's address deleted from somebody's list. `docs/status-model.md` section
4.1 gates `invalid` behind three conditions for exactly this reason, and a
report that one got through is a report that a gate leaked.

## 1. When this fires

- A caller reports that an address answered `invalid` and demonstrably receives
  mail.
- A beta target with controlled truth `owned_mailbox`, `owned_alias`, or
  `owned_forwarding` produced `invalid` — the harness reports this as
  `contradicts`.
- The `verdict_status` metric shows an unexplained step change in the `invalid`
  share, especially one that starts at a deployment.
- Any `invalid` appears whose supporting reason codes you cannot immediately
  map to one of `docs/status-model.md` section 2's five permitted reasons.

## 2. Do this now

**Do not switch anything off yet.** This is the one runbook that does not open
with a kill switch: a false `invalid` is a correctness fault, not an outbound
harm, and stopping the service destroys the traffic you need to diagnose it.

Do this instead, in this order:

1. **Preserve the evidence.** Note the job identifier, the time, and the exact
   published result. Raw evidence is retained for a bounded window under
   `docs/privacy.md`; if that window is short relative to your investigation,
   the retention sweep will remove it before you finish.
2. **Record the versions.** Run `emailcheck --report-versions --json` and keep
   the output. The aggregation ruleset and dataset versions are what makes this
   observation comparable with any other, and they are the first thing you will
   want if this turns out to be a regression.
3. **Reproduce passively.** Run the same address through the local passive check
   (`emailcheck ADDRESS --verbose`). If passive alone produces `invalid`, the
   fault is in syntax or DNS handling and no SMTP session is involved — which
   makes it reproducible offline, and much easier.

If the false `invalid` is being produced *at volume* — many addresses, one
pattern — then stop active checks
([stop-active-checks.md](stop-active-checks.md)) while you investigate. A
systematic false `invalid` is being written into callers' systems every second
it continues.

## 3. Then diagnose

Work down the layers, because each has a different answer:

1. **Syntax.** Was the reason `invalid_syntax`? Compare the address against
   `docs/requirements.md`'s supported grammar. An address the grammar does not
   *support* must produce an `unsupported_*` reason and `unknown`, never
   `invalid`. If a merely unsupported form produced `invalid`, that is a
   classification defect — file it as one.
2. **DNS.** Was it `domain_nxdomain`, `null_mx`, or `no_mail_route`? Re-resolve
   the domain from a different resolver. A resolver that answers NXDOMAIN for a
   domain that exists — a filtering or captive resolver — will manufacture false
   `invalid` results for as long as it is configured, and this is the single
   most common cause of a real false `invalid` in practice. Check what resolver
   the deployment uses before suspecting the code.
3. **SMTP.** Was it a `550`-class recipient rejection? Confirm the reason code
   is target-specific and non-temporary. `docs/status-model.md` is explicit that
   a bare `550` is not mailbox-not-found, that sender, connection, reputation,
   and policy failures are outside target invalidity, and that a TLS failure is
   never invalidity. If a policy rejection was mapped to `invalid`, the mapping
   is the fault.
4. **Aggregation.** If every layer's evidence looks correct but the verdict does
   not follow from it, the fault is in the tier resolution. Capture the evidence
   set and reproduce it in a unit test — this is the level at which a fix must
   be pinned by a test before it ships.

### Rolling back the ruleset

If the false `invalid` began at a deployment and the aggregation ruleset version
changed at that deployment, roll the ruleset back:

1. Confirm the correlation with `emailcheck --report-versions` output from
   before and after.
2. Redeploy the previous ruleset version, through the ordinary release path.
3. Re-run the controlled beta corpus, or the offline fixtures, and confirm the
   contradiction disappears.
4. Keep the reproducing case. A ruleset rollback with no test to stop the
   reissue is a rollback you will perform twice.

Results already returned to callers are not corrected by a rollback. If wrong
`invalid` results were served, say so to the callers affected — they may have
acted on them.

## 4. Do not

- **Do not weaken the `invalid` gate to make the symptom go away.** The three
  conditions in `docs/status-model.md` section 4.1 are the fix's constraint, not
  its subject. Anything that makes `invalid` easier to reach turns one false
  invalid into a class of them.
- **Do not "fix" a false `invalid` by making it `likely_deliverable`.** If the
  evidence does not support a decisive answer, `unknown` and
  `temporary_unknown` are the correct answers, and an optimistic verdict is
  forbidden by `CONTRIBUTING.md` in the same sentence as the pessimistic one.
- Do not probe the address repeatedly to "get a second opinion". Repeated
  probing of one address is what the rate limits exist to prevent, and the
  second answer is not more true than the first.
- Do not add recipients to a session, issue a second `RCPT TO`, or send `VRFY`,
  `EXPN`, or `DATA` to establish whether the mailbox exists. This project cannot
  establish that, by design; a runbook is not the place to start.
- Do not disable TLS or lower `TLSPolicy.REQUIRED` to see "what the server would
  have said". A TLS failure is already mapped to `smtp_tls_failure` and never to
  invalidity, so there is nothing to learn.
- Do not add the address to a per-address override list. There is no such list,
  and the reason there is none is that it would be a way to make one caller's
  complaint disappear without fixing anybody else's.

## 5. Record and escalate

Record in the incident log:

- the address, **redacted as the logs redact it** — do not write a complete
  address into the incident log to make the investigation easier;
- the job identifier, the published result, and the supporting reason codes;
- the ruleset and dataset versions from `--report-versions`;
- which layer was at fault, and the test that now pins it;
- whether any caller received a wrong `invalid`, and whether they were told.

Escalate to the incident owner if wrong results were served to callers, or if
the cause is in aggregation rather than in configuration. A defect in the tier
resolution affects every result and is not a single-caller matter.
