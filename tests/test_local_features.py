"""Offline release regressions: generation, passive streaming and closed settings."""

from __future__ import annotations

import asyncio
import csv
import io
import json
import string
from dataclasses import replace
from pathlib import Path

import pytest

from emailcheck.application.expansion import ExpansionError, plan_expansion
from emailcheck.application.local_batch import InputRow, passive_rows
from emailcheck.apps import cli
from emailcheck.apps.local_io import csv_cell, output_file, read_rows
from emailcheck.composition import build_verification_stack
from emailcheck.domain.batch import BatchLimits
from emailcheck.domain.dns import DNSFailure, MXLookup, apply_ttl_policy
from emailcheck.settings import load_settings


def test_676_deterministic_candidates() -> None:
    plan = plan_expansion("m**rc@gmail.com", candidates=string.ascii_lowercase)
    assert plan.count == 676
    values = list(plan)
    assert values[:3] == ["maarc@gmail.com", "mabrc@gmail.com", "macrc@gmail.com"]
    assert values[-1] == "mzzrc@gmail.com"
    assert list(plan) == values


def test_position_strings_duplicates_and_empty_substitution() -> None:
    assert list(plan_expansion("m**rc@example.com", positions=[["a", "b"], ["0", "1"]])) == [
        "ma0rc@example.com",
        "ma1rc@example.com",
        "mb0rc@example.com",
        "mb1rc@example.com",
    ]
    assert list(
        plan_expansion("m*rc@example.com", candidates=["", "a", "ab", "abc", "xyz", "a"])
    ) == [
        "mrc@example.com",
        "marc@example.com",
        "mabrc@example.com",
        "mabcrc@example.com",
        "mxyzrc@example.com",
    ]
    plan = plan_expansion("m**@example.com", positions=[["a", "ab"], ["bc", "c"]])
    assert plan.count == 4
    assert len(list(plan)) == 3


def test_literal_escape_and_unicode_domain() -> None:
    assert list(plan_expansion(r"m\*rc@example.com")) == ["m*rc@example.com"]
    assert list(plan_expansion("a@例え.jp")) == ["a@例え.jp"]
    assert list(plan_expansion("a@example.com")) == ["a@example.com"]


@pytest.mark.parametrize(
    "pattern,candidates",
    [
        ("m*@example.com", []),
        ("m*@example.com", ["日"]),
        ("m*@example.com", ["\n"]),
        ("bad", ["a"]),
        ("a@*.com", ["a"]),
        ("a*..b@example.com", ["x"]),
        ("a*@example.com", ["@"]),
        ("a*@example.com", ["x" * 65]),
        (r"a\q@example.com", ["a"]),
        ("x" * 255, ["a"]),
    ],
)
def test_expansion_refuses_invalid_and_unsupported(pattern: str, candidates: list[str]) -> None:
    with pytest.raises(ExpansionError):
        list(plan_expansion(pattern, candidates=candidates))


def test_huge_product_refused_without_enumeration(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object) -> None:
        pytest.fail("Cartesian product must not be constructed")

    monkeypatch.setattr("emailcheck.application.expansion.itertools.product", forbidden)
    with pytest.raises(ExpansionError, match="exceeds limit"):
        plan_expansion("*" * 60 + "@example.com")
    with pytest.raises(ExpansionError):
        plan_expansion("**@example.com", max_candidates=675)


def test_laziness_later_invalid_value() -> None:
    iterator = iter(plan_expansion("a*@example.com", candidates=["b", " "]))
    assert next(iterator) == "ab@example.com"
    with pytest.raises(ExpansionError):
        next(iterator)


@pytest.mark.parametrize(
    "text",
    [
        "[rate_limit]\nglobal_concurrency=65",
        "[rate_limit]\ndomain_refill_seconds=nan",
        "[quota]\ndaily_total=0",
        "[quota]\nper_target=true",
        "[batch]\nmax_rows=50001",
        "[batch]\nmax_input_bytes=9000000",
        "[active]\nenabled=true",
        "[rate_limit]\ntls=false",
        '[quota]\ndaily_total="none"',
    ],
)
def test_invalid_config(tmp_path: Path, text: str) -> None:
    path = tmp_path / "config.toml"
    path.write_text(text)
    with pytest.raises(ValueError):
        load_settings(path)


def test_settings_apply_and_process_scope(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text("[rate_limit]\nglobal_concurrency=2\n[passive_quota]\nper_target=1")
    config = load_settings(path)
    deployment = config.apply(cli._local_deployment())
    stack = build_verification_stack(deployment)
    assert stack.limiter.settings.global_concurrency == 2
    assert stack.verification.smtp is None
    assert stack.verification.passive_guard is not stack.guard
    assert stack.verification.passive_guard.settings.per_target == 1
    with pytest.raises(ValueError, match="one worker"):
        replace(deployment, worker_processes=2)


@pytest.fixture
def fake_dns(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls = []

    async def mx(self: object, domain: object) -> MXLookup:
        calls.append(str(domain))
        await asyncio.sleep(0)
        return MXLookup(failure=DNSFailure.NXDOMAIN, ttl=apply_ttl_policy(60, positive=False))

    monkeypatch.setattr("emailcheck.adapters.dns.dnspython_resolver.DNSPythonResolver.query_mx", mx)
    return calls


def test_generation_to_batch_and_privacy(
    tmp_path: Path, fake_dns: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "candidates.csv"
    output = tmp_path / "results.json"
    assert cli.main(["expand", "m**rc@gmail.com", "--chars", "ab", "--output", str(source)]) == 0
    assert cli.main(["batch", str(source), "--output", str(output), "--progress"]) == 0
    results = json.loads(output.read_text())
    assert [r["row"] for r in results] == [1, 2, 3, 4]
    assert all(r["smtp_executed"] is False for r in results)
    assert all("email" not in r for r in results)
    assert len(fake_dns) == 1
    assert sum(r["dns_cache_used"] for r in results) == 3
    assert "gmail.com" not in output.read_text()
    assert "completed=4" in capsys.readouterr().err


def test_bad_rows_and_duplicate_policy(tmp_path: Path, fake_dns: list[str]) -> None:
    source = tmp_path / "input.csv"
    source.write_text(
        "email,tag\na@example.com,x\nbroken\nbad,x\na@EXAMPLE.com,x\nb@example.com,x\n"
    )
    output = tmp_path / "out.json"
    assert cli.main(["batch", str(source), "--duplicates", "skip", "--output", str(output)]) == 3
    rows = json.loads(output.read_text())
    assert [r["row"] for r in rows] == [1, 2, 3, 4, 5]
    assert rows[1]["error"] == "malformed_row"
    assert rows[2]["status"] == "invalid"
    assert rows[3]["state"] == "duplicate"
    assert rows[3]["duplicate_of"] == 1
    assert "status" not in rows[3]
    assert rows[4]["state"] == "completed"


def test_txt_resume_and_csv_injection(tmp_path: Path, fake_dns: list[str]) -> None:
    source = tmp_path / "input.txt"
    source.write_text("a@example.com\n=cmd@example.com\na@example.com\n")
    output = tmp_path / "out.csv"
    assert (
        cli.main(
            [
                "batch",
                str(source),
                "--start-row",
                "2",
                "--duplicates",
                "skip",
                "--include-address",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    rows = list(csv.DictReader(io.StringIO(output.read_text())))
    assert rows[0]["row"] == "2"
    assert rows[0]["email"] == "'=cmd@example.com"
    assert rows[1]["state"] == "duplicate"
    assert csv_cell("  =cmd") == "'  =cmd"


def test_bounds_and_atomic_output(tmp_path: Path) -> None:
    source = tmp_path / "input.txt"
    source.write_text("x\nx\nx\n")
    with pytest.raises(ValueError, match="row limit"):
        list(read_rows(source, "txt", BatchLimits(max_rows=2)))
    with pytest.raises(ValueError, match="file size"):
        list(read_rows(source, "txt", BatchLimits(max_input_bytes=2)))
    output = tmp_path / "out.csv"
    output.write_text("original")
    with pytest.raises(KeyboardInterrupt), output_file(output) as handle:
        handle.write("partial")
        raise KeyboardInterrupt
    assert output.read_text() == "original"
    assert not list(tmp_path.glob(".emailcheck-*"))
    assert (
        cli.main(
            [
                "expand",
                "a*@example.com",
                "--candidate",
                "b",
                "--candidate",
                " ",
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert output.read_text() == "original"


@pytest.mark.asyncio
async def test_shared_quota_refusal_without_status(fake_dns: list[str]) -> None:
    settings = replace(
        load_settings(), passive_quota=replace(load_settings().passive_quota, per_target=1)
    )
    stack = build_verification_stack(settings.apply(cli._local_deployment()))
    principal = stack.authenticator.authenticate(cli._LOCAL_KEY)
    await stack.verification.verify("a@example.com", principal=principal, active=False)
    results = [
        r
        async for r in passive_rows(
            [InputRow(1, "a@example.com"), InputRow(2, "b@example.com")],
            service=stack.verification,
            principal=principal,
        )
    ]
    assert results[0]["state"] == "refused"
    assert "status" not in results[0]
    assert results[1]["state"] == "completed"


@pytest.mark.asyncio
async def test_cancellation_cleans_bounded_workers(monkeypatch: pytest.MonkeyPatch) -> None:
    started = 0
    finished = 0

    class Service:
        async def verify(self, *args: object, **kwargs: object) -> object:
            nonlocal started, finished
            started += 1
            try:
                await asyncio.Event().wait()
            finally:
                finished += 1

    stack = build_verification_stack(cli._local_deployment())
    principal = stack.authenticator.authenticate(cli._LOCAL_KEY)
    consumed = 0

    def rows():
        nonlocal consumed
        for i in range(10000):
            consumed += 1
            yield InputRow(i + 1, "x@example.com")

    async def run():
        async for _ in passive_rows(
            rows(), service=Service(), principal=principal, limits=BatchLimits(max_in_flight=4)
        ):
            pass

    task = asyncio.create_task(run())
    for _ in range(20):
        await asyncio.sleep(0)
        if started == 4:
            break
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert started == finished == consumed == 4


def test_no_active_surface(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["batch", "whatever", "--mode", "active"])
    with pytest.raises(SystemExit):
        cli.main(["expand", "a*@gmail.com", "--remote", "https://example.com"])


@pytest.mark.asyncio
async def test_passive_budget_observes_current_account_suspension(fake_dns: list[str]) -> None:
    from emailcheck.application.verification import VerificationRefused

    stack = build_verification_stack(load_settings().apply(cli._local_deployment()))
    principal = stack.authenticator.authenticate(cli._LOCAL_KEY)
    assert principal is not None
    assert stack.admin is not None
    stack.admin.suspend_account(principal.account_id)
    with pytest.raises(VerificationRefused):
        await stack.verification.verify("a@example.com", principal=principal, active=False)
    assert fake_dns == []


@pytest.mark.asyncio
async def test_dns_cache_remaining_ttl_expiry_and_capacity() -> None:
    from datetime import timedelta

    from emailcheck.adapters.dns.cached_resolver import CachedDNSResolver
    from emailcheck.domain.dns import HostName
    from phase6_fixtures import FakeClock

    class Resolver:
        calls = 0

        async def query_mx(self, domain):
            self.calls += 1
            return MXLookup(failure=DNSFailure.NXDOMAIN, ttl=apply_ttl_policy(60, positive=False))

    clock = FakeClock()
    source = Resolver()
    resolver = CachedDNSResolver(source, clock, max_entries=2)
    host = HostName("example.com")
    await resolver.query_mx(host)
    clock.current += timedelta(seconds=17)
    hit = await resolver.query_mx(host)
    assert hit.ttl.applied_seconds == 43
    assert source.calls == 1
    clock.current += timedelta(seconds=43)
    await resolver.query_mx(host)
    assert source.calls == 2
    for i in range(10):
        await resolver.query_mx(HostName(f"d{i}.example"))
    assert len(resolver._mx) == 2


def test_slot_files_empty_tokens_and_config_cli(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_text("a\nab\n", encoding="utf-8")
    second.write_text("0\n\n", encoding="utf-8")
    assert (
        cli.main(
            ["expand", "m**rc@example.com", "--slot-file", str(first), "--slot-file", str(second)]
        )
        == 0
    )
    assert capsys.readouterr().out.splitlines() == [
        "email",
        "ma0rc@example.com",
        "marc@example.com",
        "mab0rc@example.com",
        "mabrc@example.com",
    ]
    assert cli.main(["config", "show", "--config", "config/budgets.toml"]) == 0
    assert json.loads(capsys.readouterr().out)["passive_quota"]["per_api_key"] == 10000
