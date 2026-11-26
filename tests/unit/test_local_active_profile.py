"""The `local-active` profile refuses what it is not (ADR 0022, security review S1).

The CLI's one-address rule and acknowledgement live in `apps/commands.py`;
these are the limits the profile itself keeps, whatever calls it: it probes,
it keeps no store, it runs one check at a time, and it builds no executor, job
service, or retention daemon. Nothing here opens a socket.
"""

from __future__ import annotations

import secrets
from dataclasses import replace
from pathlib import Path
from typing import Final

import pytest

from emailcheck.application.admission import AdmissionSettings
from emailcheck.application.local_batch import InputRow, passive_rows
from emailcheck.composition import (
    LOCAL_ACTIVE_ADMISSION,
    Deployment,
    DeploymentProfile,
    build_verification_stack,
)
from emailcheck.settings import load_settings

KEY: Final = "k" * 40
SENDER: Final = {
    "ehlo_hostname": "probe.example.test",
    "envelope_sender": "verify@probe.example.test",
}


def local_active(**overrides: object) -> Deployment:
    values: dict[str, object] = {
        "api_keys": {"local-cli": KEY},
        "correlation_key": secrets.token_bytes(32),
        "profile": DeploymentProfile.LOCAL_ACTIVE,
        "active_probing": True,
        "sender_identity": SENDER,
        "admission": LOCAL_ACTIVE_ADMISSION,
    }
    values.update(overrides)
    return Deployment(**values)  # type: ignore[arg-type]


def test_the_profile_builds_an_smtp_service_and_nothing_of_a_service() -> None:
    stack = build_verification_stack(local_active())
    assert stack.verification.smtp is not None
    assert stack.executor is None
    assert stack.jobs is None
    assert stack.retention_scheduler is None
    assert stack.store is None
    assert stack.job_store is None


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"active_probing": False}, "exists to probe"),
        ({"sender_identity": None}, "sender identity"),
        ({"admission": AdmissionSettings()}, "one check at a time"),
        ({"lab_destination_allowlist": frozenset({"mx.example.test"})}, "lab-active setting"),
    ],
    ids=["not-probing", "no-sender", "concurrent", "allowlist"],
)
def test_the_profile_refuses_settings_it_cannot_honour(
    overrides: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        local_active(**overrides)


@pytest.mark.parametrize("field", ["store_path", "job_store_path", "account_state_path"])
def test_the_profile_keeps_no_store(tmp_path: Path, field: str) -> None:
    extra: dict[str, object] = {field: tmp_path / "x.db"}
    if field != "account_state_path":
        extra["account_state_path"] = tmp_path / "state.db"
    with pytest.raises(ValueError, match="keeps no store"):
        local_active(**extra)


def test_the_passive_profile_still_refuses_to_probe() -> None:
    with pytest.raises(ValueError, match="does not probe"):
        replace(local_active(), profile=DeploymentProfile.LOCAL_PASSIVE)


@pytest.mark.asyncio
async def test_passive_rows_never_ask_for_an_active_check() -> None:
    """A file can never reach SMTP: `passive_rows` passes `active=False`."""
    asked: list[bool] = []

    class Service:
        async def verify(self, submitted: str, *, principal: object, active: bool) -> object:
            asked.append(active)
            raise RuntimeError("stop here")

    rows = [InputRow(1, "a@example.test"), InputRow(2, "b@example.test")]
    async for _ in passive_rows(rows, service=Service(), principal=object()):  # type: ignore[arg-type]
        pass
    assert asked == [False, False]


# --- the [smtp] section (security review S2) ---------------------------------------


GOOD: Final = (
    '[smtp]\nehlo_hostname = "probe.example.test"\nenvelope_sender = "verify@probe.example.test"\n'
)


@pytest.mark.parametrize(
    "text",
    [
        GOOD + 'acknowledged = "true"\n',
        GOOD + "acknowledged = 1\n",
        GOOD + 'sender_ip = "192.0.2.1"\n',
        '[[smtp]]\nehlo_hostname = "probe.example.test"\n',
        '[smtp]\nehlo_hostname = "probe.example.test"\n',
        GOOD.replace("verify@probe.example.test", ""),
        GOOD.replace('"probe.example.test"', "7"),
    ],
    ids=["string-true", "integer", "unknown-key", "array", "no-sender", "null-sender", "number"],
)
def test_a_malformed_smtp_section_is_refused(tmp_path: Path, text: str) -> None:
    path = tmp_path / "emailcheck.toml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError):
        load_settings(path)


def test_acknowledged_must_be_the_boolean_true(tmp_path: Path) -> None:
    path = tmp_path / "emailcheck.toml"
    path.write_text(GOOD + "acknowledged = true\n", encoding="utf-8")
    smtp = load_settings(path).smtp
    assert smtp is not None
    assert smtp.acknowledged is True
    path.write_text(GOOD, encoding="utf-8")
    smtp = load_settings(path).smtp
    assert smtp is not None
    assert smtp.acknowledged is False
