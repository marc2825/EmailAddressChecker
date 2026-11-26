"""Active Mode in the local CLI: `emailcheck check ADDRESS --mode active` (ADR 0022).

Every test runs the production pipeline — composition, the guard, the route,
the destination policy, pacing, the SMTP dialogue with its TLS requirement,
reply parsing, evidence, and aggregation — with two replacements: the dnspython
resolver answers from a script, and the socket transport is the scripted peer
from `tests/fake_smtp_server.py`. Certificate verification, per-socket
timeouts, and socket release are therefore not exercised here; the adapter
tests in `tests/unit/adapters/` and `tests/integration/` cover them. The
suite-wide network guard still refuses every real socket.

What a review should check:

- Passive stays the default and builds no transport at all.
- Nothing touches DNS or SMTP until the user configured `[smtp]` and set
  `acknowledged = true`; the notice is printed instead.
- The dialogue is EHLO, STARTTLS, EHLO, MAIL FROM, one RCPT TO, then RSET or
  QUIT. No DATA, BDAT, VRFY, or EXPN is ever written.
- An accepted recipient is `likely_deliverable` at medium confidence and is
  shown as "not proof"; a policy refusal, a bare 550, a 252, a TLS failure, and
  a connection failure are never `invalid`.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

import pytest
from tests.fake_smtp_server import (
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

from emailcheck.apps import cli, commands
from emailcheck.domain.dns import AddressLookup, DNSFailure, MXLookup, MXRecord, apply_ttl_policy
from emailcheck.domain.smtp_contract import SMTPCommand
from emailcheck.domain.smtp_destination import PeerEndpoint
from emailcheck.domain.smtp_transport import TransportFailure
from emailcheck.settings import load_settings

DOMAIN: Final = "recipient.test.example"
ADDRESS: Final = f"probe.target@{DOMAIN}"
EXCHANGER: Final = "mx.recipient.test.example"
PUBLIC: Final = "93.184.216.34"
JAPANESE: Final = {"LANG": "ja_JP.UTF-8"}
CONFIG: Final = """\
[smtp]
ehlo_hostname = "probe.example.test"
envelope_sender = "verify@probe.example.test"
acknowledged = true
"""


@dataclass
class Network:
    """What the scripted DNS and SMTP saw."""

    #: The A record the exchanger resolves to; a test may point it elsewhere.
    address: str = PUBLIC
    dns_queries: list[str] = field(default_factory=list)
    transports: list[ScriptedSMTPTransport] = field(default_factory=list)

    @property
    def transport(self) -> ScriptedSMTPTransport:
        assert len(self.transports) == 1
        return self.transports[0]

    @property
    def peer_commands(self) -> list[SMTPCommand]:
        (connection,) = self.transport.connections
        return list(connection.transcript)


@pytest.fixture
def network(monkeypatch: pytest.MonkeyPatch) -> Network:
    seen = Network()
    positive = apply_ttl_policy(3600, positive=True)
    negative = apply_ttl_policy(60, positive=False)

    async def query_mx(self: object, domain: object) -> MXLookup:
        seen.dns_queries.append(f"MX {domain}")
        await asyncio.sleep(0)
        return MXLookup(records=(MXRecord(preference=10, exchange=EXCHANGER),), ttl=positive)

    async def query_a(self: object, host: object) -> AddressLookup:
        seen.dns_queries.append(f"A {host}")
        return AddressLookup(addresses=(seen.address,), ttl=positive)

    async def query_aaaa(self: object, host: object) -> AddressLookup:
        seen.dns_queries.append(f"AAAA {host}")
        return AddressLookup(failure=DNSFailure.NO_RECORDS, ttl=negative)

    resolver = "emailcheck.adapters.dns.dnspython_resolver.DNSPythonResolver"
    monkeypatch.setattr(f"{resolver}.query_mx", query_mx)
    monkeypatch.setattr(f"{resolver}.query_a", query_a)
    monkeypatch.setattr(f"{resolver}.query_aaaa", query_aaaa)
    return seen


def serve(
    monkeypatch: pytest.MonkeyPatch,
    network: Network,
    *,
    rcpt: Response = RCPT_ACCEPTED,
    tls: bool = True,
    tls_error: TransportFailure | None = None,
    connect_failure: TransportFailure | None = None,
) -> None:
    """Replace the socket transport with a scripted server, and nothing else."""
    endpoint = PeerEndpoint(address=PUBLIC, port=25)
    if tls:
        outcome = None if tls_error is None else tls_failure(tls_error)
        template = tls_session_peer(endpoint, rcpt=rcpt, tls_outcome=outcome)
    else:
        template = plain_session_peer(endpoint, rcpt=rcpt)

    def build() -> ScriptedSMTPTransport:
        transport = ScriptedSMTPTransport(template=template, connect_failure=connect_failure)
        network.transports.append(transport)
        return transport

    monkeypatch.setattr("emailcheck.composition.AsyncioSMTPTransport", build)


@pytest.fixture
def config(tmp_path: Path) -> Path:
    path = tmp_path / "emailcheck.toml"
    path.write_text(CONFIG, encoding="utf-8")
    return path


def active(config: Path, *extra: str, address: str = ADDRESS) -> list[str]:
    return ["check", address, "--mode", "active", "--config", str(config), *extra]


def run_json(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, object]]:
    code = commands.run([*argv, "--json"])
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 1
    return code, rows[0]


# --- the default and the gates before any network use ---------------------------


def test_passive_is_the_default_and_builds_no_transport(
    monkeypatch: pytest.MonkeyPatch,
    network: Network,
    config: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    serve(monkeypatch, network)
    code, row = run_json(["check", ADDRESS, "--config", str(config)], capsys)
    assert code == 0
    assert network.transports == []
    assert row["smtp_executed"] is False
    assert "smtp" not in row["checks"]  # type: ignore[operator]


def test_active_mode_needs_an_smtp_section(
    monkeypatch: pytest.MonkeyPatch, network: Network, capsys: pytest.CaptureFixture[str]
) -> None:
    serve(monkeypatch, network)
    assert commands.run(["check", ADDRESS, "--mode", "active"]) == 2
    err = capsys.readouterr().err
    assert "needs an [smtp] section" in err
    assert "emailcheck config example" in err
    assert network.dns_queries == []
    assert network.transports == []


def test_without_the_acknowledgement_the_notice_is_shown_and_nothing_connects(
    monkeypatch: pytest.MonkeyPatch,
    network: Network,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    serve(monkeypatch, network)
    path = tmp_path / "emailcheck.toml"
    path.write_text(CONFIG.replace("acknowledged = true", "acknowledged = false"), "utf-8")
    assert commands.run(active(path)) == 2
    err = capsys.readouterr().err
    for promise in (
        "It never sends a message",
        "The receiving server learns the address you check, your IP address",
        "Check only addresses you own or are allowed to check",
        "An accepted recipient is not proof that a mailbox exists",
        "block outbound port 25",
        f"add acknowledged = true to the [smtp] section of {path}",
    ):
        assert promise in err, promise
    assert network.dns_queries == []
    assert network.transports == []


def test_the_notice_in_japanese(
    monkeypatch: pytest.MonkeyPatch,
    network: Network,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "emailcheck.toml"
    path.write_text(CONFIG.replace("acknowledged = true", ""), "utf-8")
    assert commands.run(active(path), looks=JAPANESE) == 2
    err = capsys.readouterr().err
    assert "メールは送りません" in err
    assert "自分が管理するか、検査の許可を得たアドレスだけ" in err


def test_active_mode_checks_one_address_and_never_a_file(
    monkeypatch: pytest.MonkeyPatch,
    network: Network,
    config: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    serve(monkeypatch, network)
    argv = ["check", ADDRESS, f"second@{DOMAIN}", "--mode", "active", "--config", str(config)]
    assert commands.run(argv) == 2
    assert "one address at a time" in capsys.readouterr().err
    source = tmp_path / "in.txt"
    source.write_text(f"{ADDRESS}\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        commands.run(["batch", str(source), "--mode", "active", "--config", str(config)])
    assert network.transports == []


def test_an_unaligned_sender_is_refused_as_configuration(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "emailcheck.toml"
    path.write_text(CONFIG.replace("verify@probe.example.test", "me@elsewhere.example"), "utf-8")
    assert commands.run(active(path)) == 2
    assert "must be the same name or one a subdomain" in capsys.readouterr().err


def test_the_configuration_example_parses_and_is_not_acknowledged(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for looks in ({}, JAPANESE):
        assert commands.run(["config", "example"], looks=looks) == 0
        path = tmp_path / "example.toml"
        path.write_text(capsys.readouterr().out, encoding="utf-8")
        settings = load_settings(path)
        assert settings.smtp is not None
        assert settings.smtp.acknowledged is False


# --- the dialogue ------------------------------------------------------------------


def test_an_accepted_recipient_is_likely_deliverable_and_no_message_is_sent(
    monkeypatch: pytest.MonkeyPatch,
    network: Network,
    config: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    serve(monkeypatch, network)
    code, row = run_json(active(config), capsys)
    assert code == 0
    assert row["status"] == "likely_deliverable"
    assert row["confidence"] == "medium"
    assert row["checks"]["smtp"] == {"result": "rcpt_accepted"}  # type: ignore[index]
    assert row["smtp_executed"] is True
    assert row["no_message_data_sent"] is True

    assert network.peer_commands[:5] == [
        SMTPCommand.EHLO,
        SMTPCommand.STARTTLS,
        SMTPCommand.EHLO,
        SMTPCommand.MAIL_FROM,
        SMTPCommand.RCPT_TO,
    ]
    assert network.transport.connections[0].recipient_commands == 1
    wire = network.transport.connections[0].wire_text().upper()
    for forbidden in ("DATA", "BDAT", "VRFY", "EXPN", "AUTH"):
        assert forbidden not in wire, forbidden
    assert network.transport.all_closed


def test_the_ladder_shows_the_smtp_step_and_says_it_is_not_proof(
    monkeypatch: pytest.MonkeyPatch,
    network: Network,
    config: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    serve(monkeypatch, network)
    assert commands.run([*active(config), "--output-format", "text"]) == 0
    captured = capsys.readouterr()
    out = captured.out
    assert out.startswith("p***@recipient.test.example\n")
    assert "likely_deliverable  Likely deliverable (confidence medium)" in out
    assert "recipient accepted (not proof)" in out
    assert "rcpt_accepted" in out
    assert "does not prove that a mailbox exists" in out
    assert "No message content was sent." in out
    assert "Active Mode: connecting over SMTP to the mail server for recipient.test.example" in (
        captured.err
    )
    assert ADDRESS not in out + captured.err


def test_the_ladder_in_japanese(
    monkeypatch: pytest.MonkeyPatch,
    network: Network,
    config: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    serve(monkeypatch, network)
    assert commands.run([*active(config), "--output-format", "text"], looks=JAPANESE) == 0
    captured = capsys.readouterr()
    assert "受信者を受け付けた（実在の証明ではない）" in captured.out
    assert "メールボックスの実在や利用を証明するものではありません" in captured.out
    assert "メール本文は送信しません" in captured.err


@pytest.mark.parametrize(
    ("rcpt", "status", "reason"),
    [
        (RCPT_NO_SUCH_USER, "invalid", "rcpt_rejected_address"),
        (RCPT_GREYLISTED, "temporary_unknown", "smtp_temporary_failure"),
        (RCPT_POLICY, "unknown", "rcpt_rejected_policy"),
        (RCPT_BARE_PERMANENT, "unknown", "smtp_ambiguous_permanent_failure"),
        (RCPT_UNVERIFIABLE, "unknown", "rcpt_unverifiable"),
        (RCPT_MALFORMED, "unknown", "smtp_protocol_error"),
    ],
    ids=["5.1.1", "greylisted", "policy", "bare-550", "252", "malformed"],
)
def test_each_recipient_answer_keeps_its_conservative_meaning(
    monkeypatch: pytest.MonkeyPatch,
    network: Network,
    config: Path,
    capsys: pytest.CaptureFixture[str],
    rcpt: Response,
    status: str,
    reason: str,
) -> None:
    serve(monkeypatch, network, rcpt=rcpt)
    code, row = run_json(active(config), capsys)
    assert code == 0
    assert row["status"] == status
    assert row["primary_reason"] == reason
    assert network.transport.connections[0].recipient_commands == 1
    assert network.transport.all_closed


def test_a_server_without_starttls_is_not_probed_in_plaintext(
    monkeypatch: pytest.MonkeyPatch,
    network: Network,
    config: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    serve(monkeypatch, network, tls=False)
    code, row = run_json(active(config), capsys)
    assert code == 0
    assert row["status"] == "unknown"
    assert row["primary_reason"] == "smtp_tls_failure"
    assert SMTPCommand.MAIL_FROM not in network.peer_commands
    assert SMTPCommand.RCPT_TO not in network.peer_commands


@pytest.mark.parametrize(
    "failure",
    [
        TransportFailure.TLS_CERTIFICATE_INVALID,
        TransportFailure.TLS_HOSTNAME_MISMATCH,
        TransportFailure.TLS_HANDSHAKE_FAILED,
    ],
)
def test_a_tls_failure_stops_before_the_recipient_and_is_unknown(
    monkeypatch: pytest.MonkeyPatch,
    network: Network,
    config: Path,
    capsys: pytest.CaptureFixture[str],
    failure: TransportFailure,
) -> None:
    serve(monkeypatch, network, tls_error=failure)
    code, row = run_json(active(config), capsys)
    assert code == 0
    assert row["status"] == "unknown"
    assert row["primary_reason"] == "smtp_tls_failure"
    assert SMTPCommand.RCPT_TO not in network.peer_commands
    assert network.transport.all_closed


@pytest.mark.parametrize(
    "failure", [TransportFailure.CONNECT_TIMEOUT, TransportFailure.CONNECTION_REFUSED]
)
def test_a_connection_failure_is_not_a_judgement_and_explains_port_25(
    monkeypatch: pytest.MonkeyPatch,
    network: Network,
    config: Path,
    capsys: pytest.CaptureFixture[str],
    failure: TransportFailure,
) -> None:
    serve(monkeypatch, network, connect_failure=failure)
    assert commands.run([*active(config), "--output-format", "text"]) == 0
    out = capsys.readouterr().out
    assert "temporary_unknown" in out
    assert "invalid" not in out.split("\n")[1]
    assert "port 25" in out
    assert "The address was not judged." in out


def test_a_private_destination_is_never_contacted(
    monkeypatch: pytest.MonkeyPatch,
    network: Network,
    config: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """DNS rebinding to a private address: the destination policy refuses it."""
    serve(monkeypatch, network)
    network.address = "10.0.0.7"
    code, row = run_json(active(config), capsys)
    assert code == 0
    assert row["status"] == "unknown"
    assert row["primary_reason"] == "unsafe_destination"
    assert row["smtp_executed"] is False
    assert all(transport.connect_calls == [] for transport in network.transports)


def test_a_syntax_error_reaches_neither_dns_nor_smtp(
    monkeypatch: pytest.MonkeyPatch,
    network: Network,
    config: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    serve(monkeypatch, network)
    code, row = run_json(active(config, address="not an address"), capsys)
    assert code == 0
    assert row["status"] == "invalid"
    assert network.dns_queries == []
    assert all(transport.connect_calls == [] for transport in network.transports)


def test_ctrl_c_during_the_check_exits_130(
    monkeypatch: pytest.MonkeyPatch, network: Network, config: Path
) -> None:
    class Interrupted:
        async def connect(self, destination: object) -> object:
            raise KeyboardInterrupt

    monkeypatch.setattr("emailcheck.composition.AsyncioSMTPTransport", Interrupted)
    assert commands.run(active(config)) == 130


def test_no_log_line_carries_the_address(
    monkeypatch: pytest.MonkeyPatch,
    network: Network,
    config: Path,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    serve(monkeypatch, network, rcpt=RCPT_NO_SUCH_USER)
    with caplog.at_level(logging.DEBUG):
        run_json(active(config), capsys)
    assert ADDRESS not in caplog.text
    assert "probe.target" not in caplog.text


# --- what did not change -----------------------------------------------------------


def test_the_legacy_single_address_form_still_has_no_active_flag() -> None:
    options = {action.dest for action in cli.build_parser()._actions}
    assert "mode" not in options


def test_only_check_accepts_active() -> None:
    root = commands.parser()
    modes: dict[str, tuple[str, ...]] = {}
    for action in root._actions:
        for name, sub in (getattr(action, "choices", None) or {}).items():
            for option in getattr(sub, "_actions", ()):
                if option.dest == "mode":
                    modes[name] = tuple(option.choices)
    assert modes == {"check": ("passive", "active"), "batch": ("passive",)}


# --- privacy of the output (security review B1) ------------------------------------


def test_json_and_files_omit_the_address_unless_asked(
    monkeypatch: pytest.MonkeyPatch,
    network: Network,
    config: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    serve(monkeypatch, network)
    _, row = run_json(active(config), capsys)
    assert "email" not in row

    for name in ("out.json", "out.csv"):
        output = tmp_path / name
        assert commands.run([*active(config), "--output", str(output)]) == 0
        assert "probe.target" not in output.read_text(encoding="utf-8")
    capsys.readouterr()

    _, row = run_json([*active(config), "--include-address"], capsys)
    assert row["email"] == ADDRESS
