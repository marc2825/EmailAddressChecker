# Roadmap

Planned work after 0.1.0, roughly in priority order. Nothing here is a release commitment, and nothing listed changes the safety rules in [CONTRIBUTING.md](CONTRIBUTING.md). The current state is in [STATUS.md](STATUS.md).

## Repository and release

Owner actions before 0.1.0 ([release procedure](docs/releasing.md)):

- Create the `testpypi` and `pypi` Environments, protect `v*` tags, register the Trusted Publishers, and set `PUBLISH_ENABLED`.
- Publish to TestPyPI from the tag, check the install, then publish to PyPI by the confirmed manual run.
- Tidy the required checks on `main`: list `check (3.12)` once, bound to GitHub Actions, and add the `distribution` jobs. Private vulnerability reporting is already enabled.

After 0.1.0:

- Make the Docker build reproducible (pinned base image and dependency versions).
- Decide whether to split the service components out of the CLI distribution, which would shrink the package and its attack surface. Today they ship as library-only code ([component reachability](docs/architecture.md#component-reachability)).

## CLI and interfaces

- The subcommands are the main interface; the aliases kept for 0.1.x are listed in the [compatibility policy](docs/usage-ja.md#互換性の方針). Open display and output ideas are in issue #5.
- A Python API for DNS checks is not part of 0.1.0. If there is demand, design a small passive-only API (sync and async, explicit timeouts and cleanup, the same result schema), tested against the installed package.

## Service components

No public service ships in 0.1.0, and configuration alone never makes a library-only component reachable from the CLI ([component reachability](docs/architecture.md#component-reachability)). Each step is a separate, reviewed change, in this order:

1. An HTTP binding for `apps/api.py`, passive endpoint first. It adds the web framework as a production dependency with its own ADR and must meet all seven [stop conditions on the ASGI binding](docs/architecture.md#stop-conditions-on-the-asgi-binding).
2. Active jobs behind that binding, only for a deployment that has completed the [readiness checklist](docs/readiness-checklist.md), with persistent job and account-state stores and the operator approvals in [operations](docs/operations.md).
3. Active batch upload, after step 2, for operator-approved accounts, with the request body bounded while it is read.

The accept-all experiment and the beta harness stay operator tooling and are not planned as public endpoints.

Running more than one worker or replica also needs shared, atomic destination pacing, quotas, queue ownership, kill switches, and crash fencing ([future scale](docs/architecture.md#7-future-scale)).

## Evidence and data

- Populate the disposable, free-mail, and provider datasets once a redistributable source with verified provenance is chosen, and decide on free-mail overrides first ([dataset policy](docs/data-sources.md)).
- Read the authoritative negative TTL (SOA MINIMUM) instead of the fixed 60-second default ([ADR 0006](docs/adr/0006-dnspython-resolver-and-destination-policy.md)).
- Under an authorized beta, measure the STARTTLS `not_offered` rate, per-attempt TLS outcomes, and connections per job. This needs instrumentation on the production path ([beta report template](docs/beta-report-template.md)).
- Give the remote `--remote` client a total deadline and prompt cancellation; today it relies on per-socket timeouts in a blocking thread ([security audit](docs/security-audit.md)).
- Add calibrated confidence scores only after a labelled, representative evaluation ([requirements](docs/requirements.md), section 17).
- Publish a reproducible evaluation on synthetic data, public specifications, and controlled DNS fixtures: wrong rejections and acceptances, behaviour on DNS failures, the `unknown` rate, batch speed, and memory. It measures the passive checks only, never mailbox existence.
- Compare with other tools (for example email-validator) only from their current documentation and code, and claim no feature that has not been checked.

## Not planned

- Sending message content, `VRFY` or `EXPN`, provider account enumeration, or rotating IPs or identities.
- Complete SMTPUTF8 support; such local parts stay `unknown`.
