"""The human CLI views, their two languages, and the errors a person reads.

`apps/render.py`, `apps/messages.py`, and `apps/vocabulary.py`. Machine output
is covered where it already was; this file pins what changed for people: the
evidence ladder, the row view, the summaries, the explanations, the language
switch, colour rules, address redaction, and errors that say how to fix them.

Every check goes through a fake resolver, so nothing here reaches DNS.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
from pathlib import Path

import pytest

from emailcheck.application.public_result import PublicCheck, PublicResult
from emailcheck.apps import cli, commands
from emailcheck.apps.messages import detect_language
from emailcheck.apps.render import Style, display_target, ladder, printable
from emailcheck.apps.vocabulary import (
    CONFIDENCE,
    REASONS,
    RISK_FLAGS,
    ROW_ERRORS,
    STATES,
    STATUSES,
)
from emailcheck.domain.dns import DNSFailure, MXLookup, apply_ttl_policy
from emailcheck.domain.reasons import ReasonCode
from emailcheck.domain.verdict import ConfidenceLevel, RiskFlag, Status

JAPANESE = {"LANG": "ja_JP.UTF-8"}


@pytest.fixture
def nxdomain(monkeypatch: pytest.MonkeyPatch) -> None:
    async def mx(self: object, domain: object) -> MXLookup:
        await asyncio.sleep(0)
        return MXLookup(failure=DNSFailure.NXDOMAIN, ttl=apply_ttl_policy(60, positive=False))

    monkeypatch.setattr("emailcheck.adapters.dns.dnspython_resolver.DNSPythonResolver.query_mx", mx)


def route_result(*, flags: tuple[str, ...] = ()) -> PublicResult:
    return PublicResult(
        status="unknown",
        confidence="low",
        primary_reason="mx_available",
        reasons=("mx_available", *flags),
        risk_flags=flags,
        checks={"dns": PublicCheck("mx_available")},
        no_message_data_sent=True,
        ruleset="aggregation-test",
    )


# --- the vocabulary -------------------------------------------------------------


def test_every_published_value_has_an_explanation_in_both_languages() -> None:
    """A value added to an enum without words here fails this test."""
    assert set(STATUSES) == {member.value for member in Status}
    assert set(CONFIDENCE) == {member.value for member in ConfidenceLevel}
    assert set(REASONS) == {member.value for member in ReasonCode}
    assert set(RISK_FLAGS) == {member.value for member in RiskFlag}
    assert set(STATES) == {"completed", "duplicate", "rejected", "refused", "failed"}
    assert set(ROW_ERRORS) == {
        "malformed_row",
        "input_too_long",
        "verification_refused",
        "processing_failed",
    }
    for table in (STATUSES, CONFIDENCE, REASONS, RISK_FLAGS, STATES, ROW_ERRORS):
        for term in table.values():
            assert term.en_label and term.ja_label and term.en_meaning and term.ja_meaning


@pytest.mark.parametrize(
    "code", ["mx_available", "implicit_mx_available", "rcpt_accepted", "rcpt_forwarded"]
)
def test_positive_sounding_reasons_say_what_they_do_not_prove(code: str) -> None:
    term = REASONS[code]
    assert "not proof" in term.en_meaning or "says nothing" in term.en_meaning
    assert "証明ではありません" in term.ja_meaning or "実在は示しません" in term.ja_meaning


def test_the_positive_status_disclaims_mailbox_existence() -> None:
    term = STATUSES["likely_deliverable"]
    assert "does not prove that the mailbox exists" in term.en_meaning
    assert "証明するものではありません" in term.ja_meaning


def test_risk_flags_are_described_as_separate_from_the_verdict() -> None:
    for term in RISK_FLAGS.values():
        assert "not part of the deliverability verdict" in term.en_meaning
        assert "配送の判定とは別" in term.ja_meaning


# --- language and style -----------------------------------------------------------


@pytest.mark.parametrize(
    ("environ", "expected"),
    [
        ({}, "en"),
        ({"LANG": "ja_JP.UTF-8"}, "ja"),
        ({"LANG": "C.UTF-8"}, "en"),
        ({"LANG": "ja_JP.UTF-8", "LC_ALL": "C"}, "en"),
        ({"LANG": "C", "LC_MESSAGES": "ja_JP"}, "ja"),
        ({"LANG": "en_US.UTF-8", "LC_ALL": "ja_JP.UTF-8"}, "ja"),
    ],
)
def test_the_language_follows_the_posix_locale_order(
    environ: dict[str, str], expected: str
) -> None:
    assert detect_language(environ) == expected


class _Terminal(io.StringIO):
    def __init__(self, encoding: str = "utf-8") -> None:
        super().__init__()
        self._encoding = encoding

    @property
    def encoding(self) -> str:  # type: ignore[override]
        return self._encoding

    def isatty(self) -> bool:
        return True


def test_colour_only_on_a_terminal_and_never_with_no_color_or_a_dumb_terminal() -> None:
    assert Style.for_stream(_Terminal(), {}).color is True
    assert Style.for_stream(_Terminal(), {"NO_COLOR": "1"}).color is False
    assert Style.for_stream(_Terminal(), {"TERM": "dumb"}).color is False
    assert Style.for_stream(io.StringIO(), {}).color is False


def test_marks_fall_back_to_ascii_when_the_encoding_lacks_them() -> None:
    style = Style.for_stream(_Terminal("ascii"), {})
    assert style.unicode is False
    rendered = ladder(route_result(), lang="en", style=style)
    rendered.encode("ascii")


def test_every_coloured_status_is_also_a_word() -> None:
    rendered = ladder(route_result(), lang="en", style=Style(color=True))
    assert "\x1b[" in rendered
    assert "unknown" in rendered
    assert "Cannot tell" in rendered


# --- addresses on screen ----------------------------------------------------------


def test_a_parsed_address_is_shown_redacted_and_a_rejected_one_not_at_all() -> None:
    assert display_target("alice@example.test", include_address=False) == "a***@example.test"
    assert display_target("secret.person@@example.test", include_address=False) is None
    assert display_target("alice@example.test", include_address=True) == "alice@example.test"


def test_a_full_address_cannot_control_the_terminal() -> None:
    hostile = "\x1b[2J‮alice@example.test\x00"
    shown = display_target(hostile, include_address=True)
    assert shown is not None
    assert "\x1b" not in shown
    assert "‮" not in shown
    assert "\x00" not in shown
    assert printable("\x1b") == "\\x1b"


# --- the ladder -------------------------------------------------------------------


def test_the_ladder_explains_an_unknown_route_and_keeps_risk_apart() -> None:
    rendered = ladder(route_result(flags=("role_account",)), lang="en", style=Style())
    lines = rendered.splitlines()
    assert lines[0] == "unknown  Cannot tell (confidence low)"
    assert "says nothing about whether this recipient exists" in lines[1]
    assert any("Syntax" in line and "valid form" in line for line in lines)
    assert any("mail route found (MX)" in line and "mx_available" in line for line in lines)
    assert any("does not connect to SMTP" in line for line in lines)
    assert any(line.strip().startswith("Note  role_account") for line in lines)
    assert "does not prove that a mailbox exists" in rendered
    assert "No message content was sent." in rendered


def test_the_ladder_in_japanese() -> None:
    rendered = ladder(route_result(), lang="ja", style=Style())
    assert rendered.startswith("unknown  判定できません（信頼度 低）")
    assert "検査しません（SMTPに接続しないため）" in rendered
    assert "メールボックスの実在や利用を証明するものではありません" in rendered


def test_a_syntax_failure_stops_the_ladder() -> None:
    result = PublicResult(
        status="invalid",
        confidence="high",
        primary_reason="invalid_syntax",
        reasons=("invalid_syntax",),
        risk_flags=(),
        checks={"syntax": PublicCheck("invalid_syntax")},
        no_message_data_sent=True,
        ruleset="aggregation-test",
    )
    rendered = ladder(result, lang="en", style=Style())
    assert rendered.count("not reached") == 2


# --- check and batch through the command ------------------------------------------


def test_one_address_in_text_shows_the_ladder_without_the_address(
    nxdomain: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert commands.run(["check", "alice@example.test", "--output-format", "text"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("a***@example.test\ninvalid  Invalid (confidence high)")
    assert "domain does not exist" in out
    assert "alice" not in out


def test_include_address_shows_it_in_full(
    nxdomain: None, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = ["check", "alice@example.test", "--output-format", "text", "--include-address"]
    assert commands.run(argv) == 0
    assert capsys.readouterr().out.startswith("alice@example.test\n")


def test_a_terminal_gets_text_and_a_pipe_gets_json(
    nxdomain: None, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert commands.run(["check", "alice@example.test"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["status"] == "invalid"

    monkeypatch.setattr(commands, "_is_terminal", lambda stream: True)
    assert commands.run(["check", "alice@example.test"]) == 0
    assert "Invalid (confidence high)" in capsys.readouterr().out


def test_many_rows_print_one_line_each_and_a_summary(
    nxdomain: None, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = ["check", "alice@example.test", "bad address", "--output-format", "text"]
    assert commands.run(argv) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split() == ["row", "status", "confidence", "reason", "address"]
    assert lines[1].split() == ["1", "invalid", "high", "domain_nxdomain", "a***@example.test"]
    assert lines[2].split() == ["2", "invalid", "high", "invalid_syntax", "-"]
    assert "  2 rows: invalid 2" in lines
    assert "  No message content was sent." in lines


def test_the_row_view_in_japanese_names_rows_without_a_status(
    nxdomain: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "input.csv"
    source.write_text("email,tag\na@example.test,x\nbroken\na@example.test,y\n", encoding="utf-8")
    argv = ["batch", str(source), "--duplicates", "skip", "--output-format", "text"]
    assert commands.run(argv, looks=JAPANESE) == 3
    out = capsys.readouterr().out
    assert "列の数が合いません" in out
    assert "重複（1行目と同じ）" in out
    assert "3件: invalid 1 / 重複 1 / 検査できず 1" in out
    assert "終了コードは3です" in out


def test_a_saved_batch_prints_a_summary_only_when_someone_is_watching(
    nxdomain: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "input.txt"
    source.write_text("a@example.test\n", encoding="utf-8")
    output = tmp_path / "out.json"
    assert commands.run(["batch", str(source), "--output", str(output)]) == 0
    assert capsys.readouterr().err == ""

    assert commands.run(["batch", str(source), "--output", str(output), "--progress"]) == 0
    err = capsys.readouterr().err
    assert f"Checked 1 rows → {output}" in err
    assert "invalid 1" in err


def test_progress_counts_against_the_total(
    nxdomain: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "input.txt"
    source.write_text("".join(f"user{i}@example.test\n" for i in range(100)), encoding="utf-8")
    output = tmp_path / "out.json"
    assert commands.run(["batch", str(source), "--output", str(output), "--progress"]) == 0
    assert "checked 100 of 100" in capsys.readouterr().err


def test_text_output_is_for_the_screen_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = ["check", "a@example.test", "--output-format", "text", "--output", str(tmp_path / "x")]
    assert commands.run(argv) == 2
    assert "--output-format text is for the screen" in capsys.readouterr().err


def test_csv_booleans_use_json_spelling(nxdomain: None, tmp_path: Path) -> None:
    output = tmp_path / "out.csv"
    assert commands.run(["check", "a@example.test", "--output", str(output)]) == 0
    row = next(csv.DictReader(io.StringIO(output.read_text(encoding="utf-8"))))
    assert row["smtp_executed"] == "false"
    assert row["dns_cache_used"] == "false"


# --- errors -------------------------------------------------------------------------


def test_a_missing_input_file_is_named_with_a_way_forward(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    missing = tmp_path / "missing.csv"
    assert commands.run(["batch", str(missing)]) == 2
    err = capsys.readouterr().err.splitlines()
    assert err == [
        f"emailcheck batch: Input file not found: {missing}",
        "Help: emailcheck batch --help",
    ]


def test_a_csv_without_an_email_column_says_how_to_fix_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "input.csv"
    source.write_text("name\nx\n", encoding="utf-8")
    assert commands.run(["batch", str(source)], looks=JAPANESE) == 2
    err = capsys.readouterr().err
    assert "email 列がちょうど1つ必要です" in err
    assert "--format txt" in err


def test_a_configuration_error_names_the_setting(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "budgets.toml"
    config.write_text("[batch]\nmax_rows = 999999\n", encoding="utf-8")
    assert commands.run(["config", "show", "--config", str(config)], looks=JAPANESE) == 2
    assert "max_rows は50000以下にしてください" in capsys.readouterr().err


def test_a_missing_output_folder_is_reported_before_any_work(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    output = tmp_path / "nowhere" / "out.json"
    assert commands.run(["check", "a@example.test", "--output", str(output)]) == 2
    assert f"The output folder does not exist: {output.parent}" in capsys.readouterr().err


def test_an_argument_error_is_one_line_and_a_hint(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stopped:
        commands.run(["check"], looks=JAPANESE)
    assert stopped.value.code == 2
    err = capsys.readouterr().err
    assert err.splitlines() == [
        "emailcheck check: 必要な引数がありません: ADDRESS",
        "詳しくは: emailcheck check --help",
    ]


def test_a_command_typo_is_not_checked_as_an_address(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["chek", "a@example.test"]) == 2
    err = capsys.readouterr().err
    assert "'chek' is not a command." in err
    assert "Did you mean: check" in err
    assert capsys.readouterr().out == ""


def test_a_word_far_from_any_command_is_still_checked_as_an_address(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["frobnicate"]) == 0
    assert "invalid" in capsys.readouterr().out


# --- explain, help, and the reports --------------------------------------------------


def test_explain_lists_every_value(capsys: pytest.CaptureFixture[str]) -> None:
    assert commands.run(["explain"]) == 0
    out = capsys.readouterr().out
    for member in (*Status, *ConfidenceLevel, *ReasonCode, *RiskFlag):
        assert member.value in out


def test_explain_one_code_in_japanese(capsys: pytest.CaptureFixture[str]) -> None:
    assert commands.run(["explain", "null_mx"], looks=JAPANESE) == 0
    out = capsys.readouterr().out
    assert out.startswith("null_mx  受信しない宣言（null MX）\n理由コード\n")
    assert "証拠の層: dns" in out


def test_explain_shows_both_meanings_of_a_shared_name(capsys: pytest.CaptureFixture[str]) -> None:
    assert commands.run(["explain", "role_account"]) == 0
    out = capsys.readouterr().out
    assert "Reason code" in out
    assert "Risk flag" in out


def test_explain_says_an_absent_dataset_flag_is_not_a_negative_answer(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert commands.run(["explain", "free_mail"]) == 0
    assert "a missing flag is not a negative answer" in capsys.readouterr().out


def test_explain_suggests_the_nearest_code(capsys: pytest.CaptureFixture[str]) -> None:
    assert commands.run(["explain", "nul_mx"]) == 2
    err = capsys.readouterr().err
    assert "'nul_mx' is not a status" in err
    assert "Did you mean: null_mx" in err


def test_the_overview_lists_every_command_with_an_example(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["--help"]) == 0
    out = capsys.readouterr().out
    for command in commands.COMMANDS:
        assert f"\n  {command}" in out
    assert "emailcheck check alice@example.com" in out
    assert "never proof that a mailbox exists" in out


def test_the_overview_in_japanese(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LANG", "ja_JP.UTF-8")
    assert cli.main([]) == 0
    assert "メールを送らずに" in capsys.readouterr().out


def test_every_option_has_help_text() -> None:
    for lang in ("en", "ja"):
        root = commands.parser(lang)  # type: ignore[arg-type]
        for action in root._actions:
            for name, sub in getattr(action, "choices", {}).items() or ():
                if not hasattr(sub, "_actions"):
                    continue
                for option in sub._actions:
                    assert option.help, (lang, name, option.dest)


@pytest.mark.parametrize("command", ["versions", "deployment"])
def test_the_report_subcommands_match_the_old_flags(
    command: str, capsys: pytest.CaptureFixture[str]
) -> None:
    flag = {"versions": "--report-versions", "deployment": "--check-deployment"}[command]
    assert commands.run([command, "--json"]) == 0
    new = json.loads(capsys.readouterr().out)
    assert cli.main([flag, "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == new


@pytest.mark.parametrize(
    "argv",
    [
        ["batch", "\x1b[2Jmissing.csv"],
        ["explain", "\x1b[31mnull_mx"],
        ["check", "a@example.test", "--\x1b[31m"],
    ],
    ids=["path", "code", "argument"],
)
def test_no_error_echoes_a_control_character(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    try:
        code = commands.run(argv)
    except SystemExit as stopped:
        code = stopped.code
    assert code == 2
    err = capsys.readouterr().err
    assert "\x1b" not in err
    assert "\\x1b" in err


def test_a_remote_result_cannot_put_control_characters_on_screen() -> None:
    """Security review: `checks[*].result` and `ruleset` are not validated at the
    remote boundary, so the ladder escapes them and does not explain them."""
    hostile = "\x1b]0;PWNED\x07\x1b[2Jmailbox_confirmed"
    result = PublicResult(
        status="unknown",
        confidence="low",
        primary_reason=None,
        reasons=(),
        risk_flags=(),
        checks={"smtp": PublicCheck(hostile)},
        no_message_data_sent=True,
        ruleset="\x1b[31mruleset",
    )
    rendered = ladder(result, lang="en", style=Style(), local=False, verbose=True)
    assert "\x1b" not in rendered
    assert "\x07" not in rendered
    assert "unrecognised result" in rendered


def test_a_saved_path_is_escaped_in_the_summary(
    nxdomain: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "input.txt"
    source.write_text("a@example.test\n", encoding="utf-8")
    folder = tmp_path / "out\x1bdir"
    folder.mkdir()
    output = folder / "out.json"
    assert commands.run(["batch", str(source), "--output", str(output), "--progress"]) == 0
    err = capsys.readouterr().err
    assert "\x1b" not in err
    assert "out\\x1bdir" in err


def test_no_subcommand_has_an_option_that_could_make_this_process_probe() -> None:
    """The legacy parser is checked in `test_cli.py`; this covers the subcommands."""
    forbidden = ("active", "smtp", "probe", "insecure", "tls", "sender", "lab", "allowlist")
    root = commands.parser()
    for action in root._actions:
        for sub in (getattr(action, "choices", None) or {}).values():
            for option in getattr(sub, "_actions", ()):
                for name in forbidden:
                    assert name not in option.dest, (option.dest, name)
