"""The CLI's own words, in English and Japanese.

The language comes from the POSIX locale variables, in their usual order:
`LC_ALL`, then `LC_MESSAGES`, then `LANG`. A value starting with `ja` selects
Japanese; anything else, or nothing, selects English. `LANG=C` therefore
always gives English, which is what scripts and the test suite use.

Published values (statuses, reason codes, flags, option names) are never
translated: they are API vocabulary and the same in both languages.

Errors follow one shape: what went wrong, then how to fix it, with no stack
trace and no text from a network library.
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Iterable, Mapping
from typing import Final, Literal

Lang = Literal["en", "ja"]

_LOCALE_VARIABLES: Final = ("LC_ALL", "LC_MESSAGES", "LANG")

#: The only environment variables this project reads, and only to choose how
#: the CLI looks: its language, and whether it uses colour.
#:
#: `docs/adr/0009-smtp-dialogue-and-tls.md` keeps every other module from
#: reading the environment, because a value there is configuration chosen by
#: whoever can set a variable in the process. These five cannot configure
#: anything: each value is only compared (`ja...`, set or not, `dumb`), never
#: printed, and passed only to the code that picks the language and colour.
#: None reaches trust, a network operation, a limit, or a verdict.
#: `tests/unit/adapters/test_tls_context.py` pins that this function is the one
#: place that reads the environment, its exact body, its callers, and this list.
PRESENTATION_VARIABLES: Final = ("LC_ALL", "LC_MESSAGES", "LANG", "NO_COLOR", "TERM")


def presentation_environment() -> dict[str, str]:
    """The presentation variables, read once per command."""
    import os

    return {name: os.environ.get(name, "") for name in PRESENTATION_VARIABLES}


def detect_language(environ: Mapping[str, str]) -> Lang:
    for name in _LOCALE_VARIABLES:
        value = environ.get(name, "")
        if value:
            return "ja" if value.lower().startswith("ja") else "en"
    return "en"


#: key -> (English, Japanese). Values use `str.format` fields.
_TEXT: Final[dict[str, tuple[str, str]]] = {
    # --- evidence ladder ---------------------------------------------------
    "layer.syntax": ("Syntax", "構文"),
    "layer.dns": ("DNS / MX", "DNS・MX"),
    "layer.mailbox": ("Mailbox", "メールボックス"),
    "step.syntax_ok": ("valid form", "形式は正しい"),
    "step.not_reached": ("not reached", "ここまで進んでいません"),
    "step.no_result": ("no result", "結果なし"),
    "step.unrecognised": ("unrecognised result", "このビルドが知らない結果"),
    "step.no_smtp": (
        "not checked (Passive Mode; --mode active checks over SMTP)",
        "検査しません（Passive Mode。SMTPで確かめるには --mode active）",
    ),
    "step.smtp_no_result": (
        "SMTP step ran, but no answer was obtained",
        "SMTPの手順に進みましたが、結果を得られませんでした",
    ),
    "step.smtp_skipped": (
        "SMTP not run: there is nowhere to connect",
        "SMTPは実施していません（接続先がありません）",
    ),
    "hint.label": ("Hint", "ヒント"),
    "refusal.deadline": ("the time limit was reached", "時間の上限に達しました"),
    "refusal.limit": ("a rate limit or quota was reached", "件数の上限かレート制限に達しました"),
    "refusal.capacity": ("too many checks were running", "同時に実行できる数を超えました"),
    # --- Active Mode -----------------------------------------------------------
    "active.running": (
        "Active Mode: connecting over SMTP to the mail server for {domain}. No message "
        "is sent. Check only addresses you own or are allowed to check.",
        "Active Mode: {domain} のメールサーバーにSMTPで接続します。メール本文は送信しません。"
        "検査してよいのは、自分が管理するか許可を得たアドレスだけです。",
    ),
    "active.notice": (
        """Active Mode connects to the mail server of the address's domain and names
the address in one RCPT TO command. It never sends a message: no DATA, no
BDAT, no VRFY, no EXPN, and it ends the session with QUIT.

- The receiving server learns the address you check, your IP address, and the
  EHLO name and sender you configured, and may log and share them.
- Check only addresses you own or are allowed to check. Probing other
  people's addresses can get your IP address or domain blocklisted, and may
  break the law or the terms of your network.
- Use an EHLO name and sender on a domain you manage. Using someone else's
  domain misrepresents you.
- An accepted recipient is not proof that a mailbox exists or is used; many
  servers accept every address and bounce later.
- Many ISPs and cloud providers block outbound port 25, and this tool requires
  TLS with a valid certificate, so a check may not be able to finish.
- The limits in this tool apply to one process only and do not make probing
  safe for other people's addresses.""",
        """Active Mode は、アドレスのドメインのメールサーバーに接続し、RCPT TO コマンド
で1回だけアドレスを伝えます。メールは送りません（DATA、BDAT、VRFY、EXPN は使わず、
QUIT で終了します）。

- 接続先のサーバーには、検査したアドレス、あなたのIPアドレス、設定したEHLO名と
  送信者が伝わり、記録・共有されることがあります。
- 検査してよいのは、自分が管理するか、検査の許可を得たアドレスだけです。他人の
  アドレスを調べると、IPアドレスやドメインがブロックリストに載ったり、法律や
  ネットワークの規約に反したりすることがあります。
- EHLO名と送信者には、自分が管理するドメインを使ってください。他人のドメインを
  使うと、あなたの身元を偽ることになります。
- 受信者が受け付けられても、メールボックスの実在や利用の証明にはなりません。
  すべてのアドレスを受け付けて後から返送するサーバーも多くあります。
- 多くのISPやクラウドはポート25への接続を遮断しています。またこのツールは証明書を
  検証できるTLSを必須にしているので、検査を完了できないことがあります。
- このツールの制限は1つのプロセスの中だけで働きます。他人のアドレスを調べてよい
  理由にはなりません。""",
    ),
    "config.example": (
        """# emailcheck configuration. Use it with: emailcheck ... --config FILE
#
# [smtp] enables Active Mode: emailcheck check ADDRESS --mode active
# Use host and sender names on a domain you manage. The EHLO name and the
# sender's domain must be the same name or one a subdomain of the other.
[smtp]
ehlo_hostname = "mail.example.org"
envelope_sender = "verify@example.org"
# Set to true only after reading the notice emailcheck prints without it.
acknowledged = false

# Optional limits; the values below are the defaults. See config/budgets.toml.
# [batch]
# max_rows = 10000
""",
        """# emailcheck の設定ファイル。使い方: emailcheck ... --config FILE
#
# [smtp] で Active Mode を使えます: emailcheck check ADDRESS --mode active
# ホスト名と送信者には、自分が管理するドメインを使ってください。EHLO名と送信者の
# ドメインは、同じ名前か、一方が他方のサブドメインである必要があります。
[smtp]
ehlo_hostname = "mail.example.org"
envelope_sender = "verify@example.org"
# true にするのは、これがないときに表示される注意を読んでからにしてください。
acknowledged = false

# 上限の設定（任意）。値は既定値です。config/budgets.toml を参照。
# [batch]
# max_rows = 10000
""",
    ),
    "error.active_one": (
        "Active Mode checks one address at a time.",
        "Active Mode で検査できるのは1件だけです。",
    ),
    "error.active_config": (
        "Active Mode needs an [smtp] section in a --config file. "
        "Print an example with: emailcheck config example",
        "Active Mode には、--config で指定するファイルに [smtp] セクションが必要です。"
        "例は emailcheck config example で表示できます。",
    ),
    "error.active_ack": (
        "Read the notice above, then add acknowledged = true to the [smtp] section of {path}.",
        "上の注意を読んだうえで、{path} の [smtp] セクションに "
        "acknowledged = true を加えてください。",
    ),
    "confidence": ("confidence {level}", "信頼度 {level}"),
    "headline": ("{code}  {label} ({confidence})", "{code}  {label}（{confidence}）"),
    "risk.line": ("{note}  {code}  {label} ({separate})", "{note}  {code}  {label}（{separate}）"),
    "rows.header": ("row|status|confidence|reason|address", "行|判定|信頼度|理由|アドレス"),
    "risk.note": ("Note", "注意"),
    "risk.separate": ("separate from the verdict", "配送の判定とは別"),
    "more_reasons": ("Other reasons", "その他の理由"),
    "ruleset": ("Ruleset", "判定ルール"),
    "footer.estimate": (
        "This is an estimate. It does not prove that a mailbox exists or is in use.",
        "推定です。メールボックスの実在や利用を証明するものではありません。",
    ),
    "footer.no_message": ("No message content was sent.", "メッセージの内容は送信していません。"),
    "footer.warning": (
        "WARNING: this result does not assert that no message content was sent.",
        "警告: この結果は、メッセージの内容を送信していないことを示していません。",
    ),
    "unparsed": ("(not a parseable address)", "（アドレスとして解析できません）"),
    "not_checked": ("not checked", "検査できず"),
    "duplicate_of": ("duplicate of row {row}", "重複（{row}行目と同じ）"),
    "row_not_checked": ("This row was not checked: {why}.", "この行は検査していません: {why}。"),
    # --- summaries and progress ----------------------------------------------
    "summary.rows": ("{count} rows", "{count}件"),
    "summary.saved": ("Checked {count} rows → {path}", "{count}行を検査しました → {path}"),
    "summary.checked": ("Checked {count} rows.", "{count}行を検査しました。"),
    "summary.duplicate": ("duplicate", "重複"),
    "summary.exit3": (
        "Some rows could not be checked, so the exit code is 3.",
        "検査できなかった行があるため、終了コードは3です。",
    ),
    "summary.explain": (
        "Meaning of a code: emailcheck explain <code>",
        "コードの意味: emailcheck explain <コード>",
    ),
    "progress.check": ("checked {done} of {total}", "{done} / {total} 行を検査しました"),
    "progress.expand": ("generated {done} (at most {total})", "{done}件を生成（最大{total}件）"),
    "expand.saved": (
        "Wrote {count} candidates → {path}",
        "{count}件の候補を書き出しました → {path}",
    ),
    "expand.dry_run": (
        "At most {count} candidates (limit {limit}). Nothing was written.",
        "候補は最大{count}件です（上限{limit}件）。ファイルは作っていません。",
    ),
    # --- remote jobs ---------------------------------------------------------
    "job.id": ("Job", "ジョブ"),
    "job.state": ("State", "状態"),
    "job.failure": ("Failure", "失敗の種類"),
    "job.no_result": (
        "No result yet. This job has not produced a verdict.",
        "まだ結果はありません。このジョブは判定を出していません。",
    ),
    # --- explain ------------------------------------------------------------
    "kind.status": ("Status", "判定"),
    "kind.confidence": ("Confidence", "信頼度"),
    "kind.reason": ("Reason code", "理由コード"),
    "kind.risk_flag": ("Risk flag", "注意フラグ"),
    "kind.state": ("Row state", "行の処理状態"),
    "kind.row_error": ("Row error", "行のエラー"),
    "explain.layer": ("evidence layer: {layer}", "証拠の層: {layer}"),
    "explain.dataset_missing": (
        "This build ships no {dataset} dataset, so a missing flag is not a negative answer.",
        "このビルドには {dataset} の分類データが含まれていないので、"
        "フラグが付かなくても「該当しない」という意味にはなりません。",
    ),
    "explain.more": ("Details: emailcheck explain <code>", "詳細: emailcheck explain <コード>"),
    # --- errors --------------------------------------------------------------
    "error.help": ("Help: {prog} --help", "詳しくは: {prog} --help"),
    "error.did_you_mean": ("Did you mean: {suggestion}", "もしかして: {suggestion}"),
    "error.unknown_command": (
        "'{word}' is not a command.",
        "「{word}」はコマンドではありません。",
    ),
    "error.unknown_code": (
        "'{code}' is not a status, confidence level, reason code, risk flag, or row state.",
        "「{code}」は、判定・信頼度・理由コード・注意フラグ・処理状態のどれでもありません。",
    ),
    "error.input_missing": ("Input file not found: {path}", "入力ファイルが見つかりません: {path}"),
    "error.input_not_file": (
        "The input must be a regular file, not a pipe or a directory: {path}",
        "入力は通常のファイルにしてください（パイプやディレクトリは使えません）: {path}",
    ),
    "error.same_file": (
        "The input and the output must be different files.",
        "入力と出力に同じファイルは使えません。",
    ),
    "error.start_row": ("--start-row must be 1 or more.", "--start-row は1以上にしてください。"),
    "error.too_many": (
        "Too many addresses (the limit is {limit}). Put them in a file and use batch.",
        "アドレスが多すぎます（上限{limit}件）。ファイルにまとめて batch を使ってください。",
    ),
    "error.row_limit": (
        "The input has more than {limit} rows. Split the file, or raise [batch] max_rows "
        "with --config (at most 50,000).",
        "入力が{limit}行を超えています。ファイルを分けるか、--config で "
        "[batch] max_rows を上げてください（最大50,000）。",
    ),
    "error.size_limit": (
        "The input is larger than {limit} bytes. Split the file, or raise [batch] "
        "max_input_bytes with --config (at most 8 MiB).",
        "入力が{limit}バイトを超えています。ファイルを分けるか、--config で "
        "[batch] max_input_bytes を上げてください（最大8 MiB）。",
    ),
    "error.encoding": (
        "The input is not well-formed UTF-8 text or CSV. Check the encoding and the CSV quotes.",
        "入力をUTF-8のテキストまたはCSVとして読めません。文字コードとCSVの引用符を確認してください。",
    ),
    "error.nul": (
        "The input contains a NUL character. Remove it and try again.",
        "入力にNUL文字が含まれています。取り除いてから実行してください。",
    ),
    "error.header_repeat": (
        "The CSV header repeats a column name. Each column name must be unique.",
        "CSVのヘッダーに同じ列名があります。列名は重複しないようにしてください。",
    ),
    "error.header_email": (
        "The CSV header needs exactly one 'email' column. For one address per line, use a "
        ".txt file or --format txt.",
        "CSVのヘッダーには email 列がちょうど1つ必要です。"
        "1行1アドレスのファイルなら、拡張子を .txt にするか --format txt を付けてください。",
    ),
    "error.config": (
        "The configuration file cannot be used: {detail}. See config/budgets.toml for an example.",
        "設定ファイルを使えません: {detail}。例は config/budgets.toml にあります。",
    ),
    "error.output_dir": (
        "The output folder does not exist: {path}",
        "出力先のフォルダがありません: {path}",
    ),
    "error.io": (
        "Reading or writing a file failed: {detail}",
        "ファイルの読み書きに失敗しました: {detail}",
    ),
    "error.text_to_file": (
        "--output-format text is for the screen. With --output, use json or csv.",
        "--output-format text は画面表示用です。--output には json か csv を使ってください。",
    ),
    "error.expand": (
        "The pattern or candidates cannot be used: {detail}",
        "パターンか候補を使えません: {detail}",
    ),
    "error.formula": (
        "A candidate would be read as a spreadsheet formula. Use --output-format txt.",
        "表計算ソフトが数式と解釈する候補があります。--output-format txt を使ってください。",
    ),
    "error.pool_mix": (
        "Use either shared candidates (--chars, --charset, --candidate, --candidates-file) "
        "or per-star candidates (--slot, --slot-file), not both.",
        "共通の候補（--chars, --charset, --candidate, --candidates-file）と、"
        "* ごとの候補（--slot, --slot-file）は同時に使えません。",
    ),
    "error.slot_json": (
        '--slot takes a JSON array of strings, such as \'["a","b"]\'.',
        '--slot にはJSONの文字列配列を指定してください（例: \'["a","b"]\'）。',
    ),
    "error.candidate_limit": (
        "--max-candidates must not exceed the batch row limit ({limit}).",
        "--max-candidates はバッチの行数の上限（{limit}）以下にしてください。",
    ),
    "error.pool_file": (
        "The candidate file is larger than 1 MiB.",
        "候補ファイルが1 MiBを超えています。",
    ),
    "error.too_long": ("The address is too long to check.", "アドレスが長すぎて検査できません。"),
    "error.refused": (
        "This check was not run: a {scope} limit was reached.",
        "上限（{scope}）に達したため、検査しませんでした。",
    ),
    "error.invalid_config": ("The configuration is not valid.", "設定が正しくありません。"),
    "error.generic": (
        "The input, configuration, or output was refused.",
        "入力・設定・出力のいずれかを受け付けられませんでした。",
    ),
    "error.cancelled": (
        "Cancelled. An existing output file was left unchanged.",
        "中断しました。既存の出力ファイルは変更していません。",
    ),
}


def printable(value: str) -> str:
    """`value` with every character a terminal could act on escaped.

    Used for anything the user supplied that is printed back: an address with
    `--include-address`, a path, an unknown code or argument. A crafted value
    cannot move the cursor, change colours, or reorder text with a bidi
    control.
    """
    out = []
    for char in value:
        if char.isprintable():
            out.append(char)
        elif ord(char) < 0x100:
            out.append(f"\\x{ord(char):02x}")
        elif ord(char) < 0x10000:
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(f"\\U{ord(char):08x}")
    return "".join(out)


def text(key: str, lang: Lang, **values: object) -> str:
    english, japanese = _TEXT[key]
    template = japanese if lang == "ja" else english
    return template.format(**values) if values else template


def number(value: int) -> str:
    """Digits grouped by thousands, the same in both languages."""
    return f"{value:,}"


class CliError(Exception):
    """A refusal with a fixed, translatable message and nothing else.

    Carries a catalogue key and the values to put in it, never exception text
    from a library, so what the user reads is always something this project
    wrote. `translate` marks a `detail` value that is one of this project's own
    refusal messages, which `detail()` can put into Japanese.
    """

    def __init__(
        self,
        key: str,
        *,
        suggestion: str | None = None,
        translate: bool = False,
        **values: object,
    ) -> None:
        super().__init__(key)
        self.key = key
        self.suggestion = suggestion
        self.translate = translate
        self.values = values

    @classmethod
    def with_values(cls, key: str, values: Mapping[str, object]) -> CliError:
        refusal = cls(key)
        refusal.values = dict(values)
        return refusal

    def render(self, lang: Lang) -> str:
        values = {name: printable(str(value)) for name, value in self.values.items()}
        if self.translate and "detail" in values:
            values["detail"] = detail(values["detail"], lang)
        return text(self.key, lang, **values)


def suggest(word: str, choices: Iterable[str]) -> str | None:
    matches = difflib.get_close_matches(word, list(choices), n=1, cutoff=0.75)
    return matches[0] if matches else None


# --- this project's own refusal messages, translated --------------------------

#: Exact English messages raised inside this project, with their Japanese form.
#: Only this project's own words are listed; anything else is shown as it is.
_KNOWN_DETAILS: Final[dict[str, str]] = {
    "configuration exceeds 65536 bytes": "設定ファイルが65,536バイトを超えています",
    "configuration must be a readable UTF-8 TOML file": "UTF-8のTOMLファイルとして読めません",
    "unknown configuration section": "知らないセクションがあります",
    "unknown or malformed configuration setting": (
        "知らない項目か、値の形式が正しくない項目があります"
    ),
    "too many substitution entries": "候補が多すぎます",
    "a substitution exceeds 64 characters or contains controls": (
        "64文字を超える候補か、制御文字を含む候補があります"
    ),
    "substitutions cannot contain @ or backslash": "候補に @ や \\ は使えません",
    "substitutions exceed the byte limit": "候補の合計サイズが上限を超えています",
    "a substitution pool cannot be empty": "候補が空です",
    "pattern must be one address of at most 254 characters": (
        "パターンは254文字以内の1つのアドレスにしてください"
    ),
    "domain wildcards and escapes are not supported": "ドメインには * や \\ を使えません",
    "only star and backslash may be escaped": "\\ でエスケープできるのは * と \\ だけです",
    "unfinished pattern escape": "パターンが \\ で終わっています",
    "an expanded address has invalid or unsupported syntax": (
        "生成したアドレスに、構文が正しくないか未対応のものがあります"
    ),
    "provide exactly one pool per wildcard": "* の数と同じ数だけ --slot を指定してください",
    "pattern produces invalid or unsupported address syntax": (
        "このパターンからは、正しい構文のアドレスを作れません"
    ),
}

_PATTERNS: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    (re.compile(r"^max_candidates must be 1\.\.(\d+)$"), "--max-candidates は1〜{0}にしてください"),
    (
        re.compile(r"^candidate count (\d+) exceeds limit (\d+)$"),
        "候補数{0}件が上限{1}件を超えています",
    ),
    (re.compile(r"^(\w+) above (\d+) is not a bound$"), "{0} は{1}以下にしてください"),
    (re.compile(r"^(\w+) must be positive$"), "{0} は1以上にしてください"),
    (re.compile(r"^(\w+) must be a whole number, not a boolean$"), "{0} は整数にしてください"),
)


def detail(message: str, lang: Lang) -> str:
    """One of this project's own refusal messages, in the reader's language."""
    if lang == "en":
        return message
    if message in _KNOWN_DETAILS:
        return _KNOWN_DETAILS[message]
    for pattern, template in _PATTERNS:
        match = pattern.match(message)
        if match:
            return template.format(*match.groups())
    return message


# --- argparse's own errors ------------------------------------------------------

_ARGPARSE: Final[tuple[tuple[re.Pattern[str], tuple[str, str]], ...]] = (
    (
        re.compile(r"^the following arguments are required: (.+)$"),
        ("Missing argument: {0}", "必要な引数がありません: {0}"),
    ),
    (
        re.compile(r"^unrecognized arguments: (.+)$"),
        ("Unknown option or extra argument: {0}", "知らないオプションか、余分な引数です: {0}"),
    ),
    (
        re.compile(r"^argument (\S+): invalid choice: (.+?) \(choose from (.+)\)$"),
        (
            "{0} does not accept {1}. Choose from: {2}",
            "{0} に {1} は指定できません。指定できる値: {2}",
        ),
    ),
    (
        re.compile(r"^argument (\S+): expected one argument$"),
        ("{0} needs a value.", "{0} には値が1つ必要です。"),
    ),
    (
        re.compile(r"^argument (\S+): invalid \w+ value: (.+)$"),
        ("{0} does not accept {1}.", "{0} に {1} は指定できません。"),
    ),
    (
        re.compile(r"^argument (\S+): not allowed with argument (\S+)$"),
        ("{0} cannot be used with {1}.", "{0} と {1} は同時に使えません。"),
    ),
)


def argparse_error(message: str, lang: Lang) -> str:
    for pattern, (english, japanese) in _ARGPARSE:
        match = pattern.match(message)
        if match:
            return (japanese if lang == "ja" else english).format(*match.groups())
    return message


def top_help(lang: Lang, version: str) -> str:
    """`emailcheck --help`: the commands first, then examples, then the limits."""
    if lang == "ja":
        return f"""\
emailcheck {version} — メールを送らずに、アドレスへ届く見込みを推定します

使い方
  emailcheck <コマンド> [オプション]

コマンド
  check ADDRESS...    アドレスを検査する
  batch FILE          CSV / TXT のアドレスをまとめて検査する
  expand PATTERN      * を含むパターンから候補を作る（オフライン）
  explain [CODE]      判定・理由コード・注意フラグの意味を表示する
  config show         読み込んだ上限と設定を表示する
  versions            判定ルールとデータセットのバージョンを表示する
  deployment          Active運用の準備項目を表示する（参考情報）

例
  emailcheck check alice@example.com
  emailcheck batch addresses.csv --output results.csv
  emailcheck explain mx_available

1件だけの形式
  emailcheck ADDRESS [--json] [--verbose]
  emailcheck ADDRESS --remote URL --remote-key-file PATH [--wait]
      許可を得たリモートの検査サービスに送ります（docs/usage-ja.md）

構文とDNSだけを調べ、SMTPには接続しません。結果は推定で、
メールボックスの実在を証明するものではありません。

各コマンドの詳細: emailcheck <コマンド> --help
"""
    return f"""\
emailcheck {version} — estimate whether an address can receive mail, without sending any

Usage
  emailcheck <command> [options]

Commands
  check ADDRESS...    check addresses
  batch FILE          check the addresses in a CSV or TXT file
  expand PATTERN      generate candidates from a pattern with * (offline)
  explain [CODE]      explain a status, reason code, or risk flag
  config show         show the limits and settings in effect
  versions            show the ruleset and dataset versions
  deployment          list the readiness items for active checks (advisory)

Examples
  emailcheck check alice@example.com
  emailcheck batch addresses.csv --output results.csv
  emailcheck explain mx_available

Single-address form
  emailcheck ADDRESS [--json] [--verbose]
  emailcheck ADDRESS --remote URL --remote-key-file PATH [--wait]
      sends the address to an authorized remote service (see the README)

Only syntax and DNS are checked; nothing connects to SMTP. A result is an
estimate and never proof that a mailbox exists.

Help for a command: emailcheck <command> --help
"""
