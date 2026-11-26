# Passive Mode and Active Mode: evaluation

This compares the two modes on controlled, scripted mail servers. It shows what extra evidence Active Mode can obtain and where it still cannot tell. It is **not** an accuracy figure for real mail systems: the scenarios are answers a server can give, chosen to cover the rules, not a sample of real addresses.

## Method

`scripts/evaluate_modes.py` runs `emailcheck check ADDRESS --json`, once without and once with `--mode active`, through the real production pipeline: composition, abuse controls, DNS route, destination policy, pacing, the SMTP dialogue, reply parsing, evidence, and aggregation. Two parts are replaced: the DNS resolver answers from a script, and the SMTP transport is the scripted peer in `tests/fake_smtp_server.py`. Every socket call is refused while it runs.

```bash
python scripts/evaluate_modes.py            # the tables below
python scripts/evaluate_modes.py --timing   # also time and memory per check
```

`tests/test_evaluation.py` runs the script and fails when the tables below differ from its output.

"Truth" is what is true in the scenario: `exists`, `absent`, or `undecidable` when nobody outside the server could know.

## Results (2026-11-26)

| Scenario | Truth | Passive | Active | SMTP ran |
| --- | --- | --- | --- | --- |
| server accepts the recipient (250) | exists | `unknown` low (mx_available) | `likely_deliverable` medium (rcpt_accepted) | yes |
| server says no such user (550 5.1.1) | absent | `unknown` low (mx_available) | `invalid` medium (rcpt_rejected_address) | yes |
| accept-all server, mailbox absent (250) | absent | `unknown` low (mx_available) | `likely_deliverable` medium (rcpt_accepted) | yes |
| greylisting (451 4.7.1) | exists | `unknown` low (mx_available) | `temporary_unknown` medium (smtp_temporary_failure) | yes |
| policy refusal (550 5.7.1) | undecidable | `unknown` low (mx_available) | `unknown` low (rcpt_rejected_policy) | yes |
| bare 550, no enhanced code | undecidable | `unknown` low (mx_available) | `unknown` low (smtp_ambiguous_permanent_failure) | yes |
| server declines to verify (252) | undecidable | `unknown` low (mx_available) | `unknown` low (rcpt_unverifiable) | yes |
| malformed reply | undecidable | `unknown` low (mx_available) | `unknown` low (smtp_protocol_error) | yes |
| no STARTTLS offered | undecidable | `unknown` low (mx_available) | `unknown` low (smtp_tls_failure) | yes |
| invalid certificate | undecidable | `unknown` low (mx_available) | `unknown` low (smtp_tls_failure) | yes |
| port 25 blocked (connect timeout) | undecidable | `unknown` low (mx_available) | `temporary_unknown` low (smtp_connection_timeout) | yes |
| connection refused | undecidable | `unknown` low (mx_available) | `temporary_unknown` low (smtp_connection_refused) | yes |
| domain does not exist | absent | `invalid` high (domain_nxdomain) | `invalid` high (domain_nxdomain) | no |
| MX points to a private address | undecidable | `unknown` low (unsafe_destination) | `unknown` low (unsafe_destination) | no |

| Count over 14 scenarios | Passive | Active |
| --- | --- | --- |
| `invalid` while the mailbox exists or is undecidable | 0 | 0 |
| `likely_deliverable` while the mailbox is absent | 0 | 1 |
| `likely_deliverable` while the mailbox exists | 0 | 1 |
| `invalid` while the mailbox is absent | 1 | 2 |
| `unknown` | 13 | 7 |
| `temporary_unknown` | 0 | 3 |

## Reading the results

- Active Mode turned 6 of the 13 passive `unknown` answers into a decision or into `temporary_unknown`. The two decisions it can add are `likely_deliverable` (a recipient accepted, medium confidence) and `invalid` (an explicit 5.1.1, medium confidence).
- Neither mode reported `invalid` for a mailbox that exists or cannot be known. Policy refusals, a bare 550, 252, TLS failures, and connection failures stay `unknown` or `temporary_unknown`.
- **An accept-all server defeats the check.** It accepts every recipient, so an absent mailbox looks the same as an existing one (the first row) and Active Mode reports `likely_deliverable`. The existing-mailbox case on such a server is the first row again and is not listed twice. This is why an acceptance is shown as "not proof" and never gets high confidence. This build does not detect accept-all servers in the local CLI.
- A blocked port 25 or a refused connection is `temporary_unknown`, a fact about the network path rather than the address. On many home and cloud networks every check ends this way.
- Time and memory in the scripted setting (a few milliseconds and well under 1 MiB per check) say nothing about real servers. A real check is bounded by the 30-second total deadline and the per-stage SMTP timeouts.
