# Project status

## Implementation

The Phase 0–10 implementation roadmap is complete. The security remediation
work that followed it is complete, and the final system audit is closed. The
offline test suite and the lint, type, and SMTP-invariant checks are green; run
`make check` to see the current state rather than trusting a number written
here.

## What publication does not mean

Publishing this source says nothing about any particular deployment. In
particular it does **not** mean:

- that a representative TLS measurement has been performed for your population
  of destinations;
- that an authorized limited beta has run;
- that any deployment is approved for production use.

Those are per-deployment evidence, not properties of the code.

## Deployment readiness

Readiness is evaluated **per deployment**, by a human, against
[docs/readiness-checklist.md](docs/readiness-checklist.md). That checklist ships
as a blank template with thirteen gates — static IP, outbound port 25, PTR,
forward DNS, SPF, monitored sender and abuse mailboxes, hosting terms, a tested
kill switch, tested rate limits, blocked private-network egress, tested
retention deletion, and a named incident owner. Ten of them describe facts about
a host, a DNS zone, or an organization that no software can observe about
itself.

`emailcheck --check-deployment` prints the gates and reports what the process
knows. It is advisory: it resolves no name, opens no socket, and its exit code
is always zero, precisely so it cannot be scripted into a pass.

## External probing

External probing is **not authorized by default**. Authorization is an explicit
operator decision, recorded in one place in configuration, and nothing in this
project infers it — not a passing test suite, not a completed checklist, and not
a clean dashboard.

## See also

- [docs/readiness-checklist.md](docs/readiness-checklist.md) — the gates.
- [docs/operations.md](docs/operations.md) — operator controls and runbooks.
- [SECURITY.md](SECURITY.md) — reporting and responsible use.

## 0.1.0 distribution preparation

Offline expansion and a separate local passive batch CLI are implemented.
The Active BatchService remains gated and absent from public CLI/API surfaces.
TOML budgets, bounded DNS reuse, MX pacing and temporary-response backoff are
included. Packaging uses `email-address-checker`, retaining `emailcheck` imports
and commands. See [release instructions](docs/releasing.md) and the local
[release report](docs/release-report.md) for validation evidence and remaining work.
No PyPI/TestPyPI upload, push, GitHub Release or Active operation approval has
been performed by this implementation work.
