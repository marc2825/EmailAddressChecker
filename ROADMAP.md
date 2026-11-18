# Roadmap

Planned work after 0.1.0, roughly in priority order. Nothing here is a release commitment, and nothing listed changes the safety rules in [CONTRIBUTING.md](CONTRIBUTING.md). The current state is in [STATUS.md](STATUS.md).

## Repository and release

Owner actions:

- Protect `main`: require the CI checks and a review before merging. The current ruleset only forbids deletion and force pushes.
- Enable private vulnerability reporting.
- Configure the PyPI and TestPyPI environments and trusted publishers, then publish 0.1.0 ([release procedure](docs/releasing.md)).

CI and packaging:

- Enforce a minimum test coverage in CI.
- Make the Docker build reproducible (pinned base image and dependency versions).

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

## Not planned

- Sending message content, `VRFY` or `EXPN`, provider account enumeration, or rotating IPs or identities.
- Complete SMTPUTF8 support; such local parts stay `unknown`.
