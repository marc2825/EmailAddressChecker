"""`emailcheck ADDRESS` — the local passive check, and the remote active one.

`docs/requirements.md` section 12 defines both. The default runs passive checks
locally, and it is not merely configured not to probe — the stack it builds has
`active_probing` false, so `build_verification_stack` returns a service with
**no SMTP component in it at all**. A flag can be flipped; an absent object
cannot.

`--remote URL` submits an active job to another instance and, with `--wait`,
polls it. There is no unrestricted local active flag and no direct-active mode:
section 12 allows one only for the lab profile behind an explicit destination
allowlist, which is a deployment concern rather than a command-line one.

**The remote key comes from a file, not from a flag and not from the
environment.** A secret in `--remote-key` is a secret in `ps` output and in the
shell history; a secret in an environment variable is one that whoever can set a
variable in this process's environment controls, which is the shape the Phase 4
trust inspection already refuses elsewhere in this tree.

**The output carries no evidence detail.** Every format is built from the same
`PublicResult` the API returns, so there is one allowlist rather than two, and
`--json` cannot print something the API would not. `--verbose` adds the
supporting reason codes — published vocabulary — and nothing else.

**Nothing is printed as a result before a job finishes.** A pending job prints
its state. Inventing a status for work that has not happened is the
re-derivation Phase 5 stop condition 1 forbids, and this would be the most
misleading possible place to do it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import secrets
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from emailcheck import __version__
from emailcheck.adapters.http.urllib_client import UrllibRemoteCheckClient
from emailcheck.adapters.system.clock import SystemSleeper
from emailcheck.application.aggregate import aggregate_evidence
from emailcheck.application.public_job import PublicJob
from emailcheck.application.public_result import PublicResult, public_result
from emailcheck.application.readiness import report_versions, validate_deployment
from emailcheck.application.verification import SubmittedInputTooLong, VerificationRefused
from emailcheck.classification.repository import load_shipped_datasets
from emailcheck.composition import Deployment, build_verification_stack
from emailcheck.domain.job import TERMINAL_STATES, JobState
from emailcheck.ports.clock import Sleeper
from emailcheck.ports.remote_check import RemoteCheckClient, RemoteCheckError
from emailcheck.security.remote_url import RemoteUrlError, normalize_base_url

#: The account the local CLI runs as.
#:
#: A real principal rather than an anonymous one, because per-account isolation
#: is keyed by identity and a `None` account would have to be special-cased
#: everywhere downstream. It is local to this process, is not an API key, and
#: grants nothing: the local-passive profile opens no sockets.
LOCAL_ACCOUNT: Final = "local-cli"

#: The most a key file may hold. Generous for any API key and small enough that
#: pointing `--remote-key-file` at the wrong file costs a bounded read rather
#: than the file's size in memory.
MAX_REMOTE_KEY_BYTES: Final = 4096

#: How long `--wait` may poll for, and how often. Both bounded, because a
#: polling loop with no ceiling is a loop that hangs a terminal forever.
DEFAULT_WAIT_SECONDS: Final = 120.0
DEFAULT_POLL_INTERVAL_SECONDS: Final = 2.0

#: The states a job stops changing in, as published values.
_FINISHED: Final[frozenset[str]] = frozenset(state.value for state in TERMINAL_STATES)

EXIT_OK: Final = 0
EXIT_INVALID_INPUT: Final = 2
EXIT_REFUSED: Final = 3
EXIT_INCOMPLETE: Final = 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="emailcheck",
        description=(
            "Estimate whether one address is currently deliverable, without "
            "transmitting any message content. A local check performs no SMTP."
        ),
        epilog="Commands: check ADDRESS..., batch FILE, expand PATTERN, config show.",
    )
    parser.add_argument("address", nargs="?", help="the address to check; omitted prints this help")
    parser.add_argument("--version", action="store_true", help="print the package version")
    parser.add_argument(
        "--check-deployment",
        action="store_true",
        help=(
            "report every deployment gate in docs/operations.md section 1. "
            "Advisory and reporting only: it contacts nothing and passes no gate"
        ),
    )
    parser.add_argument(
        "--report-versions",
        action="store_true",
        help="print the aggregation ruleset, dataset versions, and HMAC canonicalization",
    )
    parser.add_argument("--json", action="store_true", help="print the public result as JSON")
    parser.add_argument("--config", type=Path, help="TOML budgets for a local check")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="include the supporting reason codes (published vocabulary only)",
    )
    parser.add_argument(
        "--remote",
        metavar="URL",
        help="remote validator HTTPS URL (HTTP only for 127.0.0.1 or [::1])",
    )
    parser.add_argument(
        "--remote-key-file",
        metavar="PATH",
        help="file holding the API key for --remote; never passed on the command line",
    )
    parser.add_argument(
        "--wait",
        action="store_true",
        help="with --remote, poll until the job finishes or the wait bound expires",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    actual = list(sys.argv[1:] if argv is None else argv)
    if actual and actual[0] in {"check", "batch", "expand", "config"}:
        from emailcheck.apps.commands import run

        return run(actual)
    parser = build_parser()
    arguments = parser.parse_args(argv)
    if arguments.version:
        print(__version__)
        return EXIT_OK
    if arguments.check_deployment:
        return _print_deployment_report(arguments)
    if arguments.report_versions:
        return _print_version_report(arguments)
    if arguments.address is None:
        parser.print_help()
        return EXIT_OK
    if arguments.remote is not None:
        if arguments.config is not None:
            print(
                "emailcheck: --config is local; remote budgets belong to the server",
                file=sys.stderr,
            )
            return EXIT_INVALID_INPUT
        prepared = _prepare_remote(arguments)
        if isinstance(prepared, int):
            return prepared
        base_url, key = prepared
        return asyncio.run(_run_remote(arguments, base_url=base_url, key=key))
    if arguments.wait or arguments.remote_key_file:
        print("emailcheck: --wait and --remote-key-file need --remote", file=sys.stderr)
        return EXIT_INVALID_INPUT
    return asyncio.run(_run_local(arguments))


# --- readiness reporting, from `docs/beta-report-template.md` ------------------


def _print_deployment_report(arguments: argparse.Namespace) -> int:
    """Work item 1: the deployment validation command.

    **Reporting only.** It resolves no name, opens no socket, and reads no
    environment: every one of `docs/operations.md` section 1's gates is either an
    external fact or a human commitment, so checking one from here would be an
    outbound operation this project has not been authorized to make.

    It also **authorizes nothing**. A clean report is not permission to start a
    beta — `docs/beta-report-template.md`'s exit criteria give that to a human, and
    `BetaAuthorization.external_probing_authorized` is where the decision lives.
    The exit code is `EXIT_OK` whatever the gates say, because a non-zero code
    would turn an advisory report into a pass/fail somebody could script against.
    """
    report = validate_deployment(_local_deployment())
    if arguments.json:
        print(json.dumps(report.as_json_object(), indent=2, sort_keys=True))
        return EXIT_OK

    print(f"deployment gates for profile {report.profile!r}\n")
    for gate in report.gates:
        print(f"  [{gate.status.value}] {gate.title}")
        if arguments.verbose:
            print(f"      why:    {gate.why}")
            print(f"      action: {gate.operator_action}")
    print(
        f"\n{len(report.requires_human_verification)} of {len(report.gates)} gates "
        "can only be verified outside this process."
    )
    print(report.disclaimer)
    return EXIT_OK


def _print_version_report(arguments: argparse.Namespace) -> int:
    """Work item 6: ruleset and dataset version reporting.

    Read from **this deployment's own datasets** — the same `PassiveDatasets`
    the local passive check classifies against — so the versions reported are
    the versions any result was produced under. Constructing a fresh default
    here reported the empty snapshot rather than the shipped one, which an
    independent review measured as `role = empty` beside a shipped role list at
    `2026-08-07.1`.

    A dataset that is declared unavailable *and* observed empty reports a stable
    category rather than an empty string: an operator reading `version=""`
    cannot tell "unavailable on purpose" from "the loader failed". A populated
    one reports its own version whatever the declaration says.
    """
    report = report_versions(
        package_version=__version__,
        aggregation_ruleset=aggregate_evidence(()).ruleset,
        datasets=_local_deployment().passive_datasets,
    )
    if arguments.json:
        print(json.dumps(report.as_json_object(), indent=2, sort_keys=True))
        return EXIT_OK

    print(f"package             {report.package_version}")
    print(f"aggregation ruleset {report.aggregation_ruleset}")
    print(f"hmac canonical form {report.canonical_input_version}")
    print("datasets:")
    for name, version in sorted(report.dataset_versions.items()):
        print(f"  {name:<22} {version}")
    if report.unavailable_datasets:
        print(
            "\nDeclared unavailable for the limited beta: "
            + ", ".join(report.unavailable_datasets)
            + ".\nAbsence is not a negative answer."
            + "\nSee src/emailcheck/data/passive/README.md and ADR 0007."
        )
    return EXIT_OK


# --- the local passive check ------------------------------------------------


async def _run_local(arguments: argparse.Namespace) -> int:
    from emailcheck.settings import load_settings

    try:
        deployment = load_settings(arguments.config).apply(_local_deployment())
    except ValueError:
        print("emailcheck: invalid configuration", file=sys.stderr)
        return EXIT_INVALID_INPUT
    stack = build_verification_stack(deployment)
    principal = stack.authenticator.authenticate(_LOCAL_KEY)
    if principal is None:  # pragma: no cover - the key is built beside the account
        print("emailcheck: the local profile is misconfigured", file=sys.stderr)
        return EXIT_REFUSED

    try:
        outcome = await stack.verification.verify(
            arguments.address, principal=principal, active=False
        )
    except SubmittedInputTooLong:
        print("emailcheck: the address is too long to check", file=sys.stderr)
        return EXIT_INVALID_INPUT
    except VerificationRefused as refusal:
        print(f"emailcheck: {refusal.scope} refused this check", file=sys.stderr)
        return EXIT_REFUSED

    result = public_result(outcome.verdict)
    if arguments.json:
        print(json.dumps(result.as_json_object(), indent=2, sort_keys=True))
    else:
        print(_render(result, verbose=arguments.verbose))
    return EXIT_OK


#: A per-process credential for the local profile. Generated rather than fixed,
#: so nothing about a running CLI is guessable from the source, and never
#: printed.
_LOCAL_KEY: Final = secrets.token_urlsafe(32)


def _local_deployment() -> Deployment:
    """The local-passive profile, as `docs/requirements.md` section 15 defines it.

    No active probes, no store, and a correlation key that lives for one
    process — nothing is persisted, so nothing needs a key that outlives the
    command.
    """
    return Deployment(
        api_keys={LOCAL_ACCOUNT: _LOCAL_KEY},
        correlation_key=secrets.token_bytes(32),
        active_probing=False,
        # The shipped snapshot, not the empty default. `--report-versions`
        # describes the datasets this deployment classifies against, and the
        # local passive check applies the role list it ships with.
        passive_datasets=load_shipped_datasets(),
    )


# --- the remote active check ------------------------------------------------


def _prepare_remote(arguments: argparse.Namespace) -> tuple[str, str] | int:
    """Validate the endpoint and load the key, before any event loop starts.

    Synchronous on purpose: reading a file blocks, and a blocking read inside a
    coroutine is the shape this project moves to a worker thread everywhere
    else. There is nothing to overlap it with here, so it happens first.

    Returns an exit code instead of the pair when the configuration is unusable.
    The key's contents never reach a message.
    """
    try:
        base_url = normalize_base_url(arguments.remote)
    except RemoteUrlError as refusal:
        print(f"emailcheck: {refusal}", file=sys.stderr)
        return EXIT_INVALID_INPUT

    if not arguments.remote_key_file:
        print("emailcheck: --remote needs --remote-key-file", file=sys.stderr)
        return EXIT_INVALID_INPUT
    try:
        key = read_key_file(Path(arguments.remote_key_file))
    except RemoteKeyError as refusal:
        print(f"emailcheck: {refusal}", file=sys.stderr)
        return EXIT_INVALID_INPUT
    return base_url, key


class RemoteKeyError(ValueError):
    """The key file is not one this CLI will read a credential out of.

    Every message it carries is a fixed category. The path is not repeated and
    the contents never are: a message that echoed either would put the operator's
    secret, or the location of it, into a terminal and a shell history.
    """


def read_key_file(path: Path) -> str:
    """One API key from a file, read under a hard bound.

    `Path.read_text()` has no ceiling, so `--remote-key-file /dev/zero` or a
    mistyped path to a large file is the file's size in memory. This reads one
    byte more than the maximum and refuses when that byte exists, so the bound
    is enforced rather than checked afterwards.

    **Exactly one conventional line ending is removed**, and nothing else. A
    bare `.strip()` would silently rewrite a credential whose first or last
    character is a space or a tab — `adapters/auth/api_keys.py` hashes what it is
    given, so a quietly altered key is a key that never authenticates and a
    failure nobody can see. Interior whitespace is left alone for the same
    reason.
    """
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_REMOTE_KEY_BYTES + 1)
    except OSError:
        # Covers a missing file, a directory, and a permission refusal. Which
        # one it was is not repeated back.
        raise RemoteKeyError("the remote key file could not be read") from None
    if len(raw) > MAX_REMOTE_KEY_BYTES:
        raise RemoteKeyError(f"the remote key file is larger than {MAX_REMOTE_KEY_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise RemoteKeyError("the remote key file is not valid UTF-8 text") from None

    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]

    if not text:
        raise RemoteKeyError("the remote key file is empty")
    if not text.isprintable():
        # A control character in a credential is a copy-paste artefact or a
        # smuggled newline. Refused rather than stripped, so what the operator
        # put in the file is what this client sends.
        raise RemoteKeyError("the remote key file carries a control character")
    if not text.isascii():
        raise RemoteKeyError("the remote key file must contain a printable ASCII key")
    return text


async def _run_remote(arguments: argparse.Namespace, *, base_url: str, key: str) -> int:
    """Submit one job to a remote validator, and optionally wait for it."""
    client = UrllibRemoteCheckClient(base_url=base_url, api_key=key)
    return await run_remote_check(
        client,
        SystemSleeper(),
        address=arguments.address,
        wait=bool(arguments.wait),
        as_json=bool(arguments.json),
        verbose=bool(arguments.verbose),
    )


async def run_remote_check(
    client: RemoteCheckClient,
    sleeper: Sleeper,
    *,
    address: str,
    wait: bool,
    as_json: bool,
    verbose: bool,
    wait_seconds: float = DEFAULT_WAIT_SECONDS,
    interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
) -> int:
    """Submit, optionally poll, and print. The whole remote policy, in one place.

    Takes the client and the sleeper rather than building them, so every branch
    below is testable against a fake and no test of this policy needs a socket
    or a wall clock.
    """
    try:
        job = await client.submit(address)
        if wait and job.state not in _FINISHED:
            job = await poll_until_finished(
                client,
                sleeper,
                job_id=job.id,
                wait_seconds=wait_seconds,
                interval_seconds=interval_seconds,
            )
    except RemoteCheckError as failure:
        print(f"emailcheck: {failure}", file=sys.stderr)
        return EXIT_REFUSED
    except ValueError:
        # `application/public_job.py` refused the remote's answer: it carried a
        # status, level, reason, or flag this build does not publish.
        print("emailcheck: the remote validator answered with unknown vocabulary", file=sys.stderr)
        return EXIT_REFUSED
    except asyncio.CancelledError:
        # Interrupted mid-poll. The job keeps running remotely, and saying so is
        # more useful than implying it stopped.
        print("emailcheck: stopped waiting; the remote job continues", file=sys.stderr)
        raise

    if as_json:
        print(json.dumps(job.as_json_object(), indent=2, sort_keys=True))
    else:
        print(_render_job(job, verbose=verbose))
    return EXIT_OK if job.state == JobState.COMPLETED.value else EXIT_INCOMPLETE


async def poll_until_finished(
    client: RemoteCheckClient,
    sleeper: Sleeper,
    *,
    job_id: str,
    wait_seconds: float,
    interval_seconds: float,
) -> PublicJob:
    """Poll one job until it finishes or the bound expires.

    Bounded twice over: a fixed interval, and a number of attempts derived from
    the wait budget. There is no `while True` here, so a remote that never
    finishes ends the loop rather than the terminal session, and the job is
    returned in whatever state it actually reached.
    """
    attempts = max(1, int(wait_seconds / interval_seconds))
    job = await client.fetch(job_id)
    for _ in range(attempts):
        if job.state in _FINISHED:
            return job
        await sleeper.sleep(interval_seconds)
        job = await client.fetch(job_id)
    return job


# --- rendering --------------------------------------------------------------


def _render(result: PublicResult, *, verbose: bool) -> str:
    """The human format. Published vocabulary, and a caveat that is not optional.

    The caveat is printed on every result rather than only on a positive one:
    `docs/requirements.md` section 1 says this system does not prove mailbox
    existence, and a line that appears only sometimes is a line people learn to
    read as a hedge on the doubtful cases.
    """
    lines = [
        f"status     : {result.status}",
        f"confidence : {result.confidence}",
        f"reason     : {result.primary_reason or '-'}",
    ]
    if result.risk_flags:
        lines.append(f"risk       : {', '.join(result.risk_flags)}")
    if verbose and result.reasons:
        lines.append(f"reasons    : {', '.join(result.reasons)}")
        for name, check in result.checks.items():
            lines.append(f"  {name:<22}: {check.result}")
    lines.append("")
    lines.append("This is an estimate. It does not prove that a mailbox exists or is in use.")
    lines.append(_message_data_line(result))
    return "\n".join(lines)


def _message_data_line(result: PublicResult) -> str:
    """The safety statement, printed only when the result actually makes it.

    **It used to be an unconditional string literal**, so this build printed
    "No message content was sent." over a result whose `no_message_data_sent`
    was `False` — a promise about somebody else's mail server that the result
    itself contradicted. Reachable through `--remote`, where the result comes
    from another instance rather than from this process's own dialogue, and the
    final system audit found it.

    The line is still unconditional in the sense that matters: something is
    always printed, so the affirmative statement is never merely missing and
    left to be assumed. The negative case says what is true instead. Neither
    branch names the remote host, the reply, or the address.
    """
    if result.no_message_data_sent:
        return "No message content was sent."
    return "WARNING: this result does not assert that no message content was sent."


def _render_job(job: PublicJob, *, verbose: bool) -> str:
    """A job, and its result only when there is one.

    A job that has not finished prints its state and stops. There is no line
    here that could be read as an answer about the address before one exists.
    """
    lines = [f"job        : {job.id}", f"state      : {job.state}"]
    if job.failure is not None:
        lines.append(f"failure    : {job.failure}")
    if job.result is None:
        lines.append("")
        lines.append("No result yet. This job has not produced a verdict.")
        return "\n".join(lines)
    lines.append("")
    lines.append(_render(job.result, verbose=verbose))
    return "\n".join(lines)
