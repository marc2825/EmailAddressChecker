# email-address-checker

A command-line tool that estimates conservatively, without sending any email, whether an address can receive mail.

[Source](https://github.com/marc2825/EmailAddressChecker/tree/v1.0.0) | [README (Japanese)](https://github.com/marc2825/EmailAddressChecker/blob/v1.0.0/README.md) | [README (English)](https://github.com/marc2825/EmailAddressChecker/blob/v1.0.0/README.en.md) | 日本語の説明は末尾にあります。

- **No email, ever.** The default Passive Mode checks syntax and DNS/MX and never connects to a mail server. The opt-in Active Mode asks the recipient's server about one address over SMTP (EHLO, STARTTLS, MAIL FROM, one RCPT TO, QUIT) and never sends a message. Neither can show that a mailbox exists or that a message will be delivered.
- **Local.** No dedicated server, account, or API key; everything runs on your computer.
- **Built for lists.** CSV/TXT input, results in input order, duplicate handling, bounded work, JSON or CSV output, and atomic file writes.
- **Explains itself.** Each result names its evidence: syntax, DNS/MX, and what was not checked. `emailcheck explain <code>` describes every status and reason code.
- **Conservative.** When the evidence is not decisive, the answer is `unknown`, which is not the same as invalid.
- **Private by default.** Output files omit addresses unless you ask; the screen shows them redacted; CSV cells are escaped against spreadsheet formulas.
- **Japanese and English** messages, chosen from your locale.

If you only need to validate syntax inside a Python program, a syntax-validation library such as [email-validator](https://pypi.org/project/email-validator/) is a better fit. This tool is for checking and cleaning lists of addresses from the command line.

## Install

Requires Python 3.12 or later. CI installs and runs the package on Linux, Windows, and macOS; the full test suite runs on Linux.

```bash
pipx install email-address-checker
# or: uv tool install email-address-checker
# or: python -m pip install email-address-checker
```

The command and the import name are both `emailcheck`.

## Use

```bash
emailcheck check alice@example.com bob@example.org
emailcheck batch addresses.csv --output results.csv
emailcheck explain mx_available
```

On a terminal you get a readable view; in a pipe or a file you get JSON (or CSV). Statuses are `invalid`, `unknown`, `temporary_unknown`, and `likely_deliverable`. Passive Mode never gives `likely_deliverable`, because a mail route says nothing about one recipient. `confidence` is a category, not a probability.

Active Mode, for one address you own or are allowed to check:

```bash
emailcheck config example > emailcheck.toml   # set an EHLO name and sender on your domain
emailcheck check alice@example.org --mode active --config emailcheck.toml
```

It prints a notice and stops until you set `acknowledged = true`. The receiving server learns the address, your IP address, and your EHLO name and sender. Many networks block outbound port 25, TLS with a valid certificate is required, and a server that accepts every address makes an absent mailbox look accepted, so many checks end as `unknown` or `temporary_unknown`.

The domains you check are sent to your DNS resolver. Addresses typed on the command line can stay in your shell history; use a file for sensitive lists. Use candidate generation (`emailcheck expand`) only for addresses you own or are allowed to work with, never to guess or enumerate other people's addresses.

From Python, only the syntax parser and the published vocabulary are supported (`emailcheck.parse_address`, `Status`, `ReasonCode`, `RiskFlag`, and the other names in `emailcheck.__all__`). Other modules are internal and may change.

More: [CLI reference (Japanese)](https://github.com/marc2825/EmailAddressChecker/blob/v1.0.0/docs/usage-ja.md) | [Status model](https://github.com/marc2825/EmailAddressChecker/blob/v1.0.0/docs/status-model.md) | [Privacy](https://github.com/marc2825/EmailAddressChecker/blob/v1.0.0/docs/privacy.md) | [Security policy](https://github.com/marc2825/EmailAddressChecker/blob/v1.0.0/SECURITY.md) | [Changelog](https://github.com/marc2825/EmailAddressChecker/blob/v1.0.0/CHANGELOG.md)

Licence: Apache-2.0.

## 日本語

メールを送らずに、メールアドレスへ届く見込みを保守的に判定するコマンドラインツールです。既定の Passive Mode は構文とDNS / MXだけを調べ、SMTPには接続しません。Active Mode（`--mode active`、1件ずつ）は宛先のサーバーにSMTPで受信者を確かめますが、メールは送りません。どちらもメールボックスの実在やメールの到達は証明しません。判定できないときは `unknown` になり、これは「無効」という意味ではありません。

CSV / TXTの一括検査、入力順のままのJSON / CSV出力、重複の処理、判定根拠の表示（`emailcheck explain`）、日本語と英語の表示に対応しています。

```bash
pipx install email-address-checker
emailcheck check alice@example.com
```

詳しくは[日本語のREADME](https://github.com/marc2825/EmailAddressChecker/blob/v1.0.0/README.md)と[CLIリファレンス](https://github.com/marc2825/EmailAddressChecker/blob/v1.0.0/docs/usage-ja.md)を参照してください。
