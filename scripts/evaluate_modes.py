"""Compare Passive Mode and Active Mode on scripted, controlled scenarios.

Runs `emailcheck check ADDRESS [--mode active]` in process, through the real
production pipeline, with two replacements: the DNS resolver answers from a
script, and the SMTP transport is the scripted peer from
`tests/fake_smtp_server.py`. Every socket call is refused for the duration, so
nothing leaves the machine.

    python scripts/evaluate_modes.py            # the table in docs/evaluation.md
    python scripts/evaluate_modes.py --timing   # plus time and memory per check

The scenarios are what a mail server can answer, not a sample of real mail
systems. The counts say how the rules behave on these answers; they are not an
accuracy measurement for any real population of addresses.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import io
import json
import socket
import sys
import tempfile
import time
import tracemalloc
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from unittest import mock

ROOT: Final = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.fake_smtp_server import (  # noqa: E402
    RCPT_ACCEPTED,
    RCPT_BARE_PERMANENT,
    RCPT_GREYLISTED,
    RCPT_MALFORMED,
    RCPT_NO_SUCH_USER,
    RCPT_POLICY,
    RCPT_UNVERIFIABLE,
    Response,
    ScriptedSMTPTransport,
    plain_session_peer,
    tls_failure,
    tls_session_peer,
)

from emailcheck.apps import commands  # noqa: E402
from emailcheck.domain.dns import (  # noqa: E402
    AddressLookup,
    DNSFailure,
    MXLookup,
    MXRecord,
    apply_ttl_policy,
)
from emailcheck.domain.smtp_destination import PeerEndpoint  # noqa: E402
from emailcheck.domain.smtp_transport import TransportFailure  # noqa: E402

PUBLIC: Final = "93.184.216.34"
CONFIG: Final = """\
[smtp]
ehlo_hostname = "probe.example.test"
envelope_sender = "verify@probe.example.test"
acknowledged = true
"""
RESOLVER: Final = "emailcheck.adapters.dns.dnspython_resolver.DNSPythonResolver"


@dataclass(frozen=True)
class Scenario:
    """One controlled situation and what is actually true in it."""

    name: str
    #: `exists`, `absent`, or `undecidable` (the truth cannot be known from
    #: the outside either, such as a server that refuses to say).
    truth: str
    mx: str | None = "mx.recipient.test.example"
    mx_failure: DNSFailure | None = None
    address: str = PUBLIC
    rcpt: Response = RCPT_ACCEPTED
    tls: bool = True
    tls_error: TransportFailure | None = None
    connect_failure: TransportFailure | None = None


SCENARIOS: Final = (
    Scenario("server accepts the recipient (250)", "exists"),
    Scenario("server says no such user (550 5.1.1)", "absent", rcpt=RCPT_NO_SUCH_USER),
    Scenario("accept-all server, mailbox exists (250)", "exists"),
    Scenario("accept-all server, mailbox absent (250)", "absent"),
    Scenario("greylisting (451 4.7.1)", "exists", rcpt=RCPT_GREYLISTED),
    Scenario("policy refusal (550 5.7.1)", "undecidable", rcpt=RCPT_POLICY),
    Scenario("bare 550, no enhanced code", "undecidable", rcpt=RCPT_BARE_PERMANENT),
    Scenario("server declines to verify (252)", "undecidable", rcpt=RCPT_UNVERIFIABLE),
    Scenario("malformed reply", "undecidable", rcpt=RCPT_MALFORMED),
    Scenario("no STARTTLS offered", "undecidable", tls=False),
    Scenario(
        "invalid certificate",
        "undecidable",
        tls_error=TransportFailure.TLS_CERTIFICATE_INVALID,
    ),
    Scenario(
        "port 25 blocked (connect timeout)",
        "undecidable",
        connect_failure=TransportFailure.CONNECT_TIMEOUT,
    ),
    Scenario(
        "connection refused",
        "undecidable",
        connect_failure=TransportFailure.CONNECTION_REFUSED,
    ),
    Scenario("domain does not exist", "absent", mx=None, mx_failure=DNSFailure.NXDOMAIN),
    Scenario("MX points to a private address", "undecidable", address="10.0.0.7"),
)


@dataclass(frozen=True)
class Observation:
    status: str
    confidence: str
    reason: str
    smtp: bool
    seconds: float
    peak_bytes: int


@contextlib.contextmanager
def _offline() -> Iterator[None]:
    """Refuse every socket, so a mistake here fails instead of reaching out."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise RuntimeError("the evaluation must not use the network")

    with (
        mock.patch.object(socket, "getaddrinfo", refuse),
        mock.patch.object(socket, "create_connection", refuse),
        mock.patch.object(socket.socket, "connect", refuse),
        mock.patch.object(socket.socket, "sendto", refuse),
    ):
        yield


def _resolver(scenario: Scenario) -> dict[str, Callable[..., object]]:
    positive = apply_ttl_policy(3600, positive=True)
    negative = apply_ttl_policy(60, positive=False)

    async def query_mx(self: object, domain: object) -> MXLookup:
        await asyncio.sleep(0)
        if scenario.mx is None:
            return MXLookup(failure=scenario.mx_failure, ttl=negative)
        return MXLookup(records=(MXRecord(preference=10, exchange=scenario.mx),), ttl=positive)

    async def query_a(self: object, host: object) -> AddressLookup:
        return AddressLookup(addresses=(scenario.address,), ttl=positive)

    async def query_aaaa(self: object, host: object) -> AddressLookup:
        return AddressLookup(failure=DNSFailure.NO_RECORDS, ttl=negative)

    return {"query_mx": query_mx, "query_a": query_a, "query_aaaa": query_aaaa}


def _transport(scenario: Scenario) -> Callable[[], ScriptedSMTPTransport]:
    endpoint = PeerEndpoint(address=PUBLIC, port=25)
    if scenario.tls:
        outcome = None if scenario.tls_error is None else tls_failure(scenario.tls_error)
        template = tls_session_peer(endpoint, rcpt=scenario.rcpt, tls_outcome=outcome)
    else:
        template = plain_session_peer(endpoint, rcpt=scenario.rcpt)
    return lambda: ScriptedSMTPTransport(
        template=template, connect_failure=scenario.connect_failure
    )


def observe(scenario: Scenario, *, active: bool, config: Path) -> Observation:
    argv = ["check", "probe.target@recipient.test.example", "--json", "--config", str(config)]
    if active:
        argv += ["--mode", "active"]
    out = io.StringIO()
    with (
        _offline(),
        mock.patch.multiple(RESOLVER, **_resolver(scenario)),
        mock.patch("emailcheck.composition.AsyncioSMTPTransport", _transport(scenario)),
        contextlib.redirect_stdout(out),
        contextlib.redirect_stderr(io.StringIO()),
    ):
        tracemalloc.start()
        started = time.perf_counter()
        code = commands.run(argv, looks={"LANG": "C.UTF-8"})
        seconds = time.perf_counter() - started
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
    if code not in (0, 3):
        raise RuntimeError(f"{scenario.name}: exit code {code}")
    (row,) = json.loads(out.getvalue())
    return Observation(
        status=str(row.get("status", row.get("state"))),
        confidence=str(row.get("confidence", "-")),
        reason=str(row.get("primary_reason") or row.get("error") or "-"),
        smtp=row.get("smtp_executed") is True,
        seconds=seconds,
        peak_bytes=peak,
    )


def evaluate() -> list[tuple[Scenario, Observation, Observation]]:
    with tempfile.TemporaryDirectory() as directory:
        config = Path(directory) / "emailcheck.toml"
        config.write_text(CONFIG, encoding="utf-8")
        return [
            (
                scenario,
                observe(scenario, active=False, config=config),
                observe(scenario, active=True, config=config),
            )
            for scenario in SCENARIOS
        ]


def _cell(observation: Observation) -> str:
    return f"`{observation.status}` {observation.confidence} ({observation.reason})"


def table(results: list[tuple[Scenario, Observation, Observation]]) -> str:
    lines = [
        "| Scenario | Truth | Passive | Active | SMTP ran |",
        "| --- | --- | --- | --- | --- |",
    ]
    for scenario, passive, active in results:
        lines.append(
            f"| {scenario.name} | {scenario.truth} | {_cell(passive)} | {_cell(active)} | "
            f"{'yes' if active.smtp else 'no'} |"
        )
    return "\n".join(lines)


def summary(results: list[tuple[Scenario, Observation, Observation]]) -> str:
    def count(index: int, rule: Callable[[Scenario, Observation], bool]) -> int:
        return sum(1 for item in results if rule(item[0], item[index]))  # type: ignore[arg-type]

    rows = [
        (
            "`invalid` while the mailbox exists or is undecidable",
            lambda s, o: o.status == "invalid" and s.truth != "absent",
        ),
        (
            "`likely_deliverable` while the mailbox is absent",
            lambda s, o: o.status == "likely_deliverable" and s.truth == "absent",
        ),
        (
            "`likely_deliverable` while the mailbox exists",
            lambda s, o: o.status == "likely_deliverable" and s.truth == "exists",
        ),
        (
            "`invalid` while the mailbox is absent",
            lambda s, o: o.status == "invalid" and s.truth == "absent",
        ),
        ("`unknown`", lambda s, o: o.status == "unknown"),
        ("`temporary_unknown`", lambda s, o: o.status == "temporary_unknown"),
    ]
    lines = [
        f"| Count over {len(results)} scenarios | Passive | Active |",
        "| --- | --- | --- |",
    ]
    for label, rule in rows:
        lines.append(f"| {label} | {count(1, rule)} | {count(2, rule)} |")
    return "\n".join(lines)


def timing(results: list[tuple[Scenario, Observation, Observation]]) -> str:
    passive = [item[1] for item in results]
    active = [item[2] for item in results]

    def describe(observations: list[Observation]) -> str:
        slowest = max(observation.seconds for observation in observations)
        peak = max(observation.peak_bytes for observation in observations)
        return f"slowest {slowest * 1000:.1f} ms, peak traced memory {peak / 1024:.0f} KiB"

    return f"Passive: {describe(passive)}\nActive: {describe(active)}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--timing", action="store_true", help="also print time and memory")
    arguments = parser.parse_args()
    results = evaluate()
    print(table(results))
    print()
    print(summary(results))
    if arguments.timing:
        print()
        print(timing(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
