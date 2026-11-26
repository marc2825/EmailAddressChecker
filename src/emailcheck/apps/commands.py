"""Local-only check, batch, expansion, explanation, and reporting commands.

**Who reads the output decides its form.** In a terminal, `check` and `batch`
print the human views from `apps/render.py`; into a pipe or a file they print
the same JSON or CSV as before, so scripts see no difference. `--output-format`
chooses explicitly.

The words come from `apps/messages.py` in the reader's language. Published
values (statuses, reason codes, option names) are never translated.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import string
import sys
from collections.abc import AsyncGenerator, Iterator, Mapping, Sequence
from contextlib import aclosing
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final, NoReturn, TextIO

from emailcheck.application.aggregate import aggregate_evidence
from emailcheck.application.expansion import MAX_POOL_BYTES, ExpansionError, plan_expansion
from emailcheck.application.local_batch import InputRow, check_row, passive_rows
from emailcheck.application.public_result import public_result_from_json_object
from emailcheck.application.readiness import report_versions
from emailcheck.application.verification import AddressVerificationService
from emailcheck.apps.local_io import InputRefused, ResultWriter, csv_cell, output_file, read_rows
from emailcheck.apps.messages import (
    CliError,
    Lang,
    argparse_error,
    detect_language,
    number,
    presentation_environment,
    printable,
    suggest,
    text,
)
from emailcheck.apps.render import (
    RowLayout,
    SmtpStep,
    Style,
    Tally,
    batch_summary,
    display_target,
    ladder,
    row_line,
    row_problem,
    rows_footer,
)
from emailcheck.apps.vocabulary import DATASET_OF, TABLES, every_code, lookup
from emailcheck.composition import (
    LOCAL_ACTIVE_ADMISSION,
    DeploymentProfile,
    build_verification_stack,
)
from emailcheck.domain.address import AddressAccepted, RawAddressInput, parse_address
from emailcheck.domain.principal import Principal
from emailcheck.settings import Settings, load_settings

#: Every subcommand. `apps/cli.py` routes an argument list to `run` when its
#: first word is one of these.
COMMANDS: Final = ("check", "batch", "expand", "explain", "config", "versions", "deployment")


# --- the parser ---------------------------------------------------------------


class _Formatter(argparse.RawDescriptionHelpFormatter):
    usage_prefix: str = "usage: "

    def add_usage(
        self,
        usage: str | None,
        actions: object,
        groups: object,
        prefix: str | None = None,
    ) -> None:
        super().add_usage(
            usage,
            actions,  # type: ignore[arg-type]
            groups,  # type: ignore[arg-type]
            self.usage_prefix if prefix is None else prefix,
        )


class _JapaneseFormatter(_Formatter):
    usage_prefix = "使い方: "


class CliParser(argparse.ArgumentParser):
    """An argument parser that speaks the reader's language and stays short.

    argparse's own errors print the whole usage block above one line of
    English. This prints the one line, translated when the pattern is known,
    and where to find help.
    """

    def __init__(self, *args: object, lang: Lang = "en", **kwargs: object) -> None:
        kwargs.setdefault("formatter_class", _JapaneseFormatter if lang == "ja" else _Formatter)
        kwargs["add_help"] = False
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.lang: Lang = lang

    def error(self, message: str) -> NoReturn:
        self.exit(
            2,
            f"{self.prog}: {printable(argparse_error(message, self.lang))}\n"
            f"{text('error.help', self.lang, prog=self.prog)}\n",
        )


@dataclass(frozen=True, slots=True)
class _Words:
    """Option help in one language: `say(english, japanese)`."""

    lang: Lang

    def __call__(self, english: str, japanese: str) -> str:
        return japanese if self.lang == "ja" else english


def _groups(
    parser: argparse.ArgumentParser, say: _Words
) -> tuple[argparse._ArgumentGroup, argparse._ArgumentGroup]:
    arguments = parser.add_argument_group(say("arguments", "引数"))
    options = parser.add_argument_group(say("options", "オプション"))
    options.add_argument(
        "-h", "--help", action="help", help=say("show this help", "このヘルプを表示する")
    )
    return arguments, options


def _examples(say: _Words, *lines: str) -> str:
    return say("examples:", "例:") + "\n" + "\n".join(f"  {line}" for line in lines)


def parser(lang: Lang = "en") -> argparse.ArgumentParser:
    say = _Words(lang)
    root = CliParser(prog="emailcheck", lang=lang)
    commands = root.add_subparsers(dest="command", required=True, parser_class=CliParser)

    check = commands.add_parser(
        "check",
        lang=lang,
        description=say(
            "Check addresses by syntax and DNS. With --mode active, also check one "
            "address over SMTP without sending mail.",
            "アドレスを構文とDNSで検査します。"
            "--mode active では、1件だけメールを送らずにSMTPでも確かめます。",
        ),
        epilog=_examples(
            say,
            "emailcheck check alice@example.com",
            "emailcheck check a@example.com b@example.org --output results.csv",
            "emailcheck check alice@example.org --mode active --config emailcheck.toml",
        ),
    )
    check_arguments, check_options = _groups(check, say)
    check_arguments.add_argument(
        "addresses",
        nargs="+",
        metavar="ADDRESS",
        help=say("one or more addresses", "検査するアドレス（複数可）"),
    )

    batch = commands.add_parser(
        "batch",
        lang=lang,
        description=say(
            "Check every address in a UTF-8 CSV or TXT file. Nothing connects to SMTP.",
            "UTF-8のCSV / TXTファイルのアドレスをまとめて検査します。SMTPには接続しません。",
        ),
        epilog=_examples(
            say,
            "emailcheck batch addresses.csv --output results.csv",
            "emailcheck batch addresses.txt --duplicates skip --progress --output results.json",
        ),
    )
    batch_arguments, batch_options = _groups(batch, say)
    batch_arguments.add_argument(
        "input",
        type=Path,
        metavar="FILE",
        help=say(
            "a CSV with one 'email' column, or a TXT with one address per line",
            "email 列が1つあるCSV、または1行に1アドレスのTXT",
        ),
    )
    batch_options.add_argument(
        "--format",
        choices=("csv", "txt"),
        help=say(
            "input format (default: by extension, .txt means TXT)",
            "入力形式（既定: 拡張子で判断し、.txt ならTXT）",
        ),
    )
    # Batch is passive only. The option is accepted for symmetry and refuses
    # every other value, so a file can never be checked over SMTP.
    batch_options.add_argument(
        "--mode", choices=("passive",), default="passive", help=argparse.SUPPRESS
    )
    # ADR 0022: the only way into SMTP from the CLI. One address, and only with
    # an [smtp] section the user configured and acknowledged.
    check_options.add_argument(
        "--mode",
        choices=("passive", "active"),
        default="passive",
        help=say(
            "passive (default): syntax and DNS only. active: also one SMTP check of a "
            "single address, without sending mail; needs [smtp] in --config "
            "(see: emailcheck config example)",
            "passive（既定）: 構文とDNSだけ。active: 1件だけ、メールを送らずにSMTPでも確かめる。"
            "--config に [smtp] が必要（例: emailcheck config example）",
        ),
    )
    batch_options.add_argument(
        "--start-row",
        type=int,
        default=1,
        metavar="N",
        help=say("start checking at row N (default: 1)", "N行目から検査する（既定: 1）"),
    )

    for options in (check_options, batch_options):
        options.add_argument(
            "--output",
            type=Path,
            metavar="PATH",
            help=say(
                "save results to a file (.csv for CSV, otherwise JSON)",
                "結果をファイルに保存する（.csv ならCSV、それ以外はJSON）",
            ),
        )
        options.add_argument(
            "--output-format",
            choices=("text", "json", "csv"),
            help=say(
                "text, json, or csv (default: text on a terminal, json in a pipe or file)",
                "text / json / csv（既定: 画面なら text、パイプやファイルなら json）",
            ),
        )
        options.add_argument(
            "--json",
            action="store_true",
            help=say("same as --output-format json", "--output-format json と同じ"),
        )
        options.add_argument(
            "--include-address",
            action="store_true",
            help=say(
                "show and save the full address (default: a redacted form on screen, "
                "nothing in files)",
                "アドレス全体を表示・保存する（既定: 画面は伏せ字、ファイルには含めない）",
            ),
        )
        options.add_argument(
            "--duplicates",
            choices=("keep", "skip"),
            default="keep",
            help=say(
                "check repeated addresses (keep) or point them to the first row (skip)",
                "重複したアドレスを検査する（keep）か、最初の行を参照してスキップする（skip）",
            ),
        )

    expand = commands.add_parser(
        "expand",
        lang=lang,
        description=say(
            "Generate candidate addresses offline from a pattern with *. Nothing is checked.",
            "* を含むパターンから候補のアドレスを作ります。検査や通信はしません。",
        ),
        epilog=_examples(
            say,
            "emailcheck expand 'a**ce@example.com' --chars abc --output candidates.csv",
            "emailcheck expand 'a**ce@example.com' --charset lower --dry-run",
        ),
    )
    expand_arguments, expand_options = _groups(expand, say)
    expand_arguments.add_argument(
        "pattern",
        metavar="PATTERN",
        help=say(
            "an address whose local part marks each position with *",
            "置き換える位置を * で示したアドレス（例: a*ce@example.com）",
        ),
    )
    shared = expand_options.add_mutually_exclusive_group()
    shared.add_argument(
        "--chars",
        metavar="TEXT",
        help=say("use each character of TEXT", "TEXT の各文字を候補にする"),
    )
    shared.add_argument(
        "--charset",
        choices=("lower", "upper", "digits", "alnum"),
        help=say("a preset (default: lower)", "プリセット（既定: lower）"),
    )
    shared.add_argument(
        "--candidate",
        action="append",
        metavar="TEXT",
        help=say("use TEXT as a candidate; repeatable", "TEXT を候補にする（繰り返し可）"),
    )
    shared.add_argument(
        "--candidates-file",
        type=Path,
        metavar="FILE",
        help=say("use each line of FILE", "FILE の各行を候補にする"),
    )
    positions = expand_options.add_mutually_exclusive_group()
    positions.add_argument(
        "--slot",
        action="append",
        metavar="JSON",
        help=say(
            "candidates for one *, as a JSON string array; once per *",
            "* ごとの候補をJSONの文字列配列で指定する（* の数だけ繰り返す）",
        ),
    )
    positions.add_argument(
        "--slot-file",
        action="append",
        type=Path,
        metavar="FILE",
        help=say(
            "candidates for one *, one per line; once per *",
            "* ごとの候補ファイル（* の数だけ繰り返す）",
        ),
    )
    expand_options.add_argument(
        "--max-candidates", type=int, metavar="N", help=say("the most to generate", "生成数の上限")
    )
    expand_options.add_argument(
        "--dry-run",
        action="store_true",
        help=say("only count; write nothing", "生成せず、候補数の上限だけを表示する"),
    )
    expand_options.add_argument(
        "--output-format",
        choices=("csv", "txt"),
        default="csv",
        help=say(
            "csv (with an 'email' header) or txt (default: csv)",
            "csv（email ヘッダー付き）か txt（既定: csv）",
        ),
    )
    expand_options.add_argument(
        "--output",
        type=Path,
        metavar="PATH",
        help=say("write to a file instead of the screen", "画面ではなくファイルに書き出す"),
    )

    for options in (check_options, batch_options, expand_options):
        options.add_argument(
            "--progress",
            action="store_true",
            help=say(
                "show progress and a summary on stderr", "進捗と要約を標準エラー出力に表示する"
            ),
        )

    explain = commands.add_parser(
        "explain",
        lang=lang,
        description=say(
            "Explain a status, confidence level, reason code, risk flag, or row state.",
            "判定・信頼度・理由コード・注意フラグ・行の処理状態の意味を表示します。",
        ),
        epilog=_examples(say, "emailcheck explain", "emailcheck explain mx_available"),
    )
    explain_arguments, _ = _groups(explain, say)
    explain_arguments.add_argument(
        "code",
        nargs="?",
        metavar="CODE",
        help=say("the value to explain; omit to list every value", "説明する値（省略すると一覧）"),
    )

    config = commands.add_parser(
        "config",
        lang=lang,
        description=say(
            "Show the limits and settings in effect, as JSON.",
            "読み込んだ上限と設定をJSONで表示します。",
        ),
        epilog=_examples(say, "emailcheck config show --config config/budgets.toml"),
    )
    config_arguments, config_options = _groups(config, say)
    config_arguments.add_argument(
        "action",
        choices=("show", "example"),
        help=say(
            "show: the settings in effect; example: a commented configuration file",
            "show: 読み込んだ設定を表示する。example: 説明付きの設定ファイルの例を表示する",
        ),
    )

    versions = commands.add_parser(
        "versions",
        lang=lang,
        description=say(
            "Show the package, ruleset, and dataset versions.",
            "パッケージ・判定ルール・データセットのバージョンを表示します。",
        ),
    )
    _, versions_options = _groups(versions, say)
    deployment = commands.add_parser(
        "deployment",
        lang=lang,
        description=say(
            "List the readiness items for active checks. Advisory: it contacts nothing "
            "and passes nothing.",
            "Active運用の準備項目を表示します。参考情報で、通信も合否の判定もしません。",
        ),
    )
    _, deployment_options = _groups(deployment, say)
    deployment_options.add_argument(
        "--verbose", action="store_true", help=say("add why and what to do", "理由と対応も表示する")
    )
    for options in (versions_options, deployment_options):
        options.add_argument(
            "--json", action="store_true", help=say("print JSON", "JSONで表示する")
        )

    for options in (check_options, batch_options, expand_options, config_options):
        options.add_argument(
            "--config",
            type=Path,
            metavar="PATH",
            help=say(
                "a TOML configuration: limits, and [smtp] for Active Mode "
                "(see: emailcheck config example)",
                "TOMLの設定ファイル。上限と、Active Mode 用の [smtp]"
                "（例: emailcheck config example）",
            ),
        )
    return root


# --- running a command ----------------------------------------------------------


def run(argv: Sequence[str], *, looks: Mapping[str, str] | None = None) -> int:
    """`looks` replaces the presentation variables, for tests."""
    env = presentation_environment() if looks is None else looks
    lang = detect_language(env)
    args = parser(lang).parse_args(argv)
    prog = f"emailcheck {args.command}"
    try:
        if args.command == "explain":
            return explain(args, lang)
        if args.command in ("versions", "deployment"):
            return _report(args)
        settings = _settings(args.config)
        if args.command == "config":
            if args.action == "example":
                print(text("config.example", lang), end="")
                return 0
            print(json.dumps(settings.as_json_object(), indent=2, sort_keys=True))
            return 0
        _check_output_folder(args.output)
        if args.command == "expand":
            return expand(args, settings, lang)
        result_format = _result_format(args, sys.stdout)
        rows = len(args.addresses) if args.command == "check" else 0
        last_row = rows
        if args.command == "batch":
            # Read and validate the whole input before the event loop starts.
            # Inside `asyncio.run` a blocking read held off Ctrl-C (issue #3).
            rows, last_row = _validate_batch_input(args, settings)
        elif rows > settings.batch.max_rows:
            raise CliError("error.too_many", limit=number(settings.batch.max_rows))
        active = args.command == "check" and args.mode == "active"
        if active:
            _check_active(args, settings, lang)
        job = _Job(
            lang=lang,
            format=result_format,
            rows=rows,
            last_row=last_row,
            looks=env,
            active=active,
        )
        return asyncio.run(check(args, settings, job))
    except KeyboardInterrupt:
        print(f"{prog}: {text('error.cancelled', lang)}", file=sys.stderr)
        return 130
    except CliError as refusal:
        return _refuse(prog, refusal, lang)
    except InputRefused as refusal:
        return _refuse(prog, CliError.with_values(refusal.key, refusal.values), lang)
    except OSError as failure:
        reason = failure.strerror or type(failure).__name__
        return _refuse(prog, CliError("error.io", detail=reason), lang)
    except ValueError:
        return _refuse(prog, CliError("error.generic"), lang)


def _check_active(args: argparse.Namespace, settings: Settings, lang: Lang) -> None:
    """Refuse Active Mode before anything touches the network (ADR 0022).

    One address; an `[smtp]` section; and `acknowledged = true`, which the user
    sets after reading the notice printed here. Then one line on stderr names
    the server about to be contacted.
    """
    if len(args.addresses) != 1:
        raise CliError("error.active_one")
    if settings.smtp is None:
        raise CliError("error.active_config")
    if not settings.smtp.acknowledged:
        print(text("active.notice", lang) + "\n", file=sys.stderr)
        raise CliError("error.active_ack", path=args.config)
    parsed = parse_address(RawAddressInput(args.addresses[0]))
    if isinstance(parsed, AddressAccepted):
        print(
            text("active.running", lang, domain=parsed.address.domain.ascii_form), file=sys.stderr
        )


def _refuse(prog: str, refusal: CliError, lang: Lang) -> int:
    print(f"{prog}: {refusal.render(lang)}", file=sys.stderr)
    if refusal.suggestion:  # always one of this project's own command or code names
        print(text("error.did_you_mean", lang, suggestion=refusal.suggestion), file=sys.stderr)
    print(text("error.help", lang, prog=prog), file=sys.stderr)
    return 2


def _settings(path: Path | None) -> Settings:
    try:
        return load_settings(path)
    except ValueError as refusal:
        # Only this project's own messages reach here: `load_settings` replaces
        # parser and file errors with fixed text, and the limits raise
        # `BatchError` with fixed text.
        raise CliError("error.config", detail=str(refusal), translate=True) from None


def _check_output_folder(path: Path | None) -> None:
    if path is not None and not path.parent.is_dir():
        raise CliError("error.output_dir", path=path.parent)


def _is_terminal(stream: TextIO) -> bool:
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False


def _result_format(args: argparse.Namespace, stdout: TextIO) -> str:
    if args.json:
        return "json"
    if args.output_format == "text" and args.output:
        raise CliError("error.text_to_file")
    if args.output_format:
        return str(args.output_format)
    if args.output:
        return "csv" if args.output.suffix.lower() == ".csv" else "json"
    return "text" if _is_terminal(stdout) else "json"


def _report(args: argparse.Namespace) -> int:
    from emailcheck.apps.cli import _print_deployment_report, _print_version_report

    if args.command == "versions":
        return _print_version_report(argparse.Namespace(json=args.json, verbose=False))
    return _print_deployment_report(argparse.Namespace(json=args.json, verbose=args.verbose))


# --- explain --------------------------------------------------------------------


def explain(args: argparse.Namespace, lang: Lang) -> int:
    if args.code is None:
        print(_explain_all(lang))
        return 0
    terms = lookup(args.code)
    if not terms:
        raise CliError(
            "error.unknown_code",
            code=args.code,
            suggestion=suggest(args.code, every_code()),
        )
    unavailable = set(_unavailable_datasets())
    blocks = []
    for term in terms:
        lines = [
            f"{term.code}  {term.label(lang)}",
            text(f"kind.{term.kind}", lang),
            "",
            term.meaning(lang),
        ]
        if term.layer:
            lines.append(text("explain.layer", lang, layer=term.layer))
        dataset = DATASET_OF.get(term.code)
        if dataset in unavailable:
            lines.append(text("explain.dataset_missing", lang, dataset=dataset))
        blocks.append("\n".join(lines))
    print("\n\n".join(blocks))
    return 0


def _explain_all(lang: Lang) -> str:
    cells = max(len(code) for code in every_code()) + 2
    sections = []
    for table in TABLES:
        kind = next(iter(table.values())).kind
        lines = [text(f"kind.{kind}", lang)]
        lines.extend(f"  {code.ljust(cells)}{term.label(lang)}" for code, term in table.items())
        sections.append("\n".join(lines))
    sections.append(text("explain.more", lang))
    return "\n\n".join(sections)


def _unavailable_datasets() -> tuple[str, ...]:
    from emailcheck import __version__
    from emailcheck.classification.repository import load_shipped_datasets

    return report_versions(
        package_version=__version__,
        aggregation_ruleset=aggregate_evidence(()).ruleset,
        datasets=load_shipped_datasets(),
    ).unavailable_datasets


# --- expand ---------------------------------------------------------------------


def _pool_file(path: Path) -> list[str]:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_POOL_BYTES + 1)
    except FileNotFoundError:
        raise CliError("error.input_missing", path=path) from None
    if len(raw) > MAX_POOL_BYTES:
        raise CliError("error.pool_file")
    try:
        return raw.decode("utf-8-sig").splitlines()
    except UnicodeError:
        raise CliError("error.encoding") from None


def _slots(values: list[str]) -> list[list[str]]:
    pools: list[list[str]] = []
    for value in values:
        try:
            pool = json.loads(value)
        except ValueError:
            raise CliError("error.slot_json") from None
        if not isinstance(pool, list) or any(not isinstance(item, str) for item in pool):
            raise CliError("error.slot_json")
        pools.append(pool)
    return pools


def expand(args: argparse.Namespace, settings: Settings, lang: Lang) -> int:
    candidates = list(string.ascii_lowercase)
    if args.chars is not None:
        candidates = list(args.chars)
    elif args.charset:
        candidates = list(
            {
                "lower": string.ascii_lowercase,
                "upper": string.ascii_uppercase,
                "digits": string.digits,
                "alnum": string.ascii_letters + string.digits,
            }[args.charset]
        )
    elif args.candidate is not None:
        candidates = args.candidate
    elif args.candidates_file:
        candidates = _pool_file(args.candidates_file)
    positions = None
    if args.slot or args.slot_file:
        if any((args.chars is not None, args.charset, args.candidate, args.candidates_file)):
            raise CliError("error.pool_mix")
        positions = (
            [_pool_file(path) for path in args.slot_file] if args.slot_file else _slots(args.slot)
        )
    maximum = args.max_candidates if args.max_candidates is not None else settings.batch.max_rows
    if maximum > settings.batch.max_rows:
        raise CliError("error.candidate_limit", limit=number(settings.batch.max_rows))
    try:
        plan = plan_expansion(
            args.pattern, candidates=candidates, positions=positions, max_candidates=maximum
        )
        if args.dry_run:
            if _is_terminal(sys.stdout):
                print(text("expand.dry_run", lang, count=number(plan.count), limit=number(maximum)))
            else:
                print(
                    json.dumps(
                        {"candidate_count_upper_bound": plan.count, "max_candidates": maximum}
                    )
                )
            return 0
        # Every candidate is checked before anything is written, so a later
        # invalid or formula-like candidate leaves stdout empty, not half
        # written (issue #3). The plan is bounded and can be iterated twice.
        for address in plan:
            if args.output_format == "csv" and csv_cell(address) != address:
                raise CliError("error.formula")
    except ExpansionError as refusal:
        raise CliError("error.expand", detail=str(refusal), translate=True) from None

    progress = _Progress(sys.stderr, enabled=args.progress)
    count = 0
    with output_file(args.output) as handle:
        writer = csv.writer(handle, lineterminator="\n")
        if args.output_format == "csv":
            writer.writerow(["email"])
        for count, address in enumerate(plan, 1):
            if args.output_format == "csv":
                writer.writerow([address])
            else:
                handle.write(address + "\n")
            if count % 100 == 0:
                progress.show(
                    text("progress.expand", lang, done=number(count), total=number(plan.count))
                )
    progress.done()
    if args.output and (args.progress or _is_terminal(sys.stderr)):
        print(
            text("expand.saved", lang, count=number(count), path=printable(str(args.output))),
            file=sys.stderr,
        )
    return 0


# --- check and batch ------------------------------------------------------------


def _batch_format(args: argparse.Namespace) -> str:
    return str(args.format or ("txt" if args.input.suffix.lower() == ".txt" else "csv"))


def _validate_batch_input(args: argparse.Namespace, settings: Settings) -> tuple[int, int]:
    """Check the batch arguments and read the whole input once, synchronously.

    The input is read twice (here, then while checking), so it must be a
    regular file: a pipe or FIFO would be empty on the second read, and opening
    one can block.

    Returns how many rows will be checked and the last row number, which the
    progress line and the row view use.
    """
    if args.start_row < 1:
        raise CliError("error.start_row")
    if not args.input.exists():
        raise CliError("error.input_missing", path=args.input)
    if not args.input.is_file():
        raise CliError("error.input_not_file", path=args.input)
    if args.output and args.input.resolve() == args.output.resolve():
        raise CliError("error.same_file")
    rows = 0
    last = 0
    for row in read_rows(args.input, _batch_format(args), settings.batch):
        last = row.number
        rows += row.number >= args.start_row
    return rows, last


@dataclass(frozen=True, slots=True)
class _Job:
    lang: Lang
    format: str
    rows: int
    last_row: int
    looks: Mapping[str, str]
    active: bool = False


class _Progress:
    """One updating line on a terminal, one line per update elsewhere."""

    def __init__(self, stream: TextIO, *, enabled: bool) -> None:
        self.stream = stream
        self.enabled = enabled
        self.live = enabled and _is_terminal(stream)
        self.shown = False

    def show(self, line: str) -> None:
        if not self.enabled:
            return
        if self.live:
            self.stream.write("\r\x1b[2K" + line)
            self.stream.flush()
        else:
            print(line, file=self.stream)
        self.shown = True

    def done(self) -> None:
        if self.live and self.shown:
            self.stream.write("\n")
            self.stream.flush()


async def check(args: argparse.Namespace, settings: Settings, job: _Job) -> int:
    from emailcheck import __version__
    from emailcheck.apps.cli import _LOCAL_KEY, _local_deployment

    if args.command == "batch":
        rows = read_rows(args.input, _batch_format(args), settings.batch)
    else:
        rows = (InputRow(i, value) for i, value in enumerate(args.addresses, 1))
    deployment = settings.apply(_local_deployment())
    if job.active:
        # Checked by `_check_active` before the event loop started.
        assert settings.smtp is not None
        deployment = replace(
            deployment,
            profile=DeploymentProfile.LOCAL_ACTIVE,
            active_probing=True,
            admission=LOCAL_ACTIVE_ADMISSION,
            sender_identity=settings.smtp.sender_identity(),
        )
    versions = report_versions(
        package_version=__version__,
        aggregation_ruleset=aggregate_evidence(()).ruleset,
        datasets=deployment.passive_datasets,
    ).dataset_versions
    stack = build_verification_stack(deployment)
    principal = stack.authenticator.authenticate(_LOCAL_KEY)
    assert principal is not None
    lang = job.lang
    as_text = job.format == "text"
    screen = Style.for_stream(sys.stdout, job.looks)
    progress = _Progress(sys.stderr, enabled=args.progress)
    tally = Tally()
    single = as_text and args.command == "check" and len(args.addresses) == 1
    layout = RowLayout(last_row=job.last_row, lang=lang)

    def report(count: int) -> None:
        if count % 100 == 0:
            done, total = number(count), number(job.rows)
            progress.show(text("progress.check", lang, done=done, total=total))

    try:
        with output_file(None if as_text else args.output) as handle:
            writer = None if as_text else ResultWriter(handle, job.format, args.include_address)
            if as_text and not single:
                print(layout.header_line(screen))
            stream = (
                _active_rows(
                    rows,
                    stack.verification,
                    principal,
                    # As for passive rows: the full address reaches a record
                    # only for the screen (which redacts it) or on request.
                    include=args.include_address or as_text,
                )
                if job.active
                else passive_rows(
                    rows,
                    service=stack.verification,
                    principal=principal,
                    limits=settings.batch,
                    duplicates=args.duplicates,
                    start_row=getattr(args, "start_row", 1),
                    # The text views need the input to show its redacted form; it
                    # is printed in full only with --include-address.
                    include_address=args.include_address or as_text,
                    progress=report,
                )
            )
            async with aclosing(stream):
                async for result in stream:
                    tally.add(result)
                    if writer is not None:
                        result["dataset_versions"] = dict(versions)
                        writer.write(result)
                    elif single:
                        print(_single(result, args, lang, screen, active=job.active))
                    else:
                        target = display_target(
                            str(result.get("email", "")), include_address=args.include_address
                        )
                        print(row_line(result, layout=layout, style=screen, target=target))
            if writer is not None:
                writer.finish()
    finally:
        rows.close()
        await stack.aclose()
    progress.done()
    if as_text and not single:
        print("\n".join(rows_footer(tally, lang=lang, style=screen)))
    elif not as_text and (args.progress or _is_terminal(sys.stderr)):
        saved = str(args.output) if args.output else None
        notes = Style.for_stream(sys.stderr, job.looks)
        print(
            "\n".join(batch_summary(tally, lang=lang, style=notes, saved_to=saved)), file=sys.stderr
        )
    return 3 if tally.not_checked else 0


async def _active_rows(
    rows: Iterator[InputRow],
    service: AddressVerificationService,
    principal: Principal,
    *,
    include: bool,
) -> AsyncGenerator[dict[str, object]]:
    """The single Active Mode row. `_check_active` has refused anything else."""
    for row in rows:
        yield await check_row(
            row, service=service, principal=principal, include_address=include, active=True
        )


def _single(
    result: Mapping[str, object],
    args: argparse.Namespace,
    lang: Lang,
    style: Style,
    *,
    active: bool = False,
) -> str:
    """The ladder for one address, or why there is no result."""
    target = display_target(str(result.get("email", "")), include_address=args.include_address)
    if result.get("state") != "completed":
        return text("row_not_checked", lang, why=row_problem(result, lang))
    published = public_result_from_json_object(
        {key: value for key, value in result.items() if key not in {"email", "row", "state"}}
    )
    smtp: SmtpStep = "off"
    if active:
        smtp = "attempted" if result.get("smtp_executed") is True else "skipped"
    return ladder(published, lang=lang, style=style, target=target, smtp=smtp)
