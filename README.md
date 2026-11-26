# EmailAddressChecker

[日本語](README.md) | [English](README.en.md)

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/teaser-dark.svg">
    <img src="docs/assets/teaser-light.svg" width="100%" alt="EmailAddressCheckerのロゴ">
  </picture>
</p>

EmailAddressCheckerは、**メールを送らずに**、メールアドレスへ届く見込みを保守的に判定するPython製のCLIです。

- 既定の **Passive Mode** は、構文とドメインのDNS / MXレコードだけを調べ、SMTPサーバーには接続しません。
- **Active Mode**（`--mode active`、1件ずつ）は、宛先のメールサーバーにSMTPで接続して受信者を受け付けるかを確かめます。メールは送りません。
- どちらのモードも、メールボックスの実在やメールが届くことは証明しません。判定できないときは `unknown` になり、これは「無効」という意味ではありません。
- 自分のPCだけで動きます。専用のサーバー、アカウント、APIキーは要りません。

## どんなときに使うか

メールアドレスの一覧を、コマンドラインで点検・整理するためのツールです。

- CSV・TXTの一括検査。入力の順のまま、重複の処理、件数とサイズの上限、途中で失敗しても壊れないファイル出力
- JSON・CSVの機械向け出力と、安定した理由コード
- 判定の根拠の表示。構文・DNS・メールボックスのどこまで確認したかを示し、`emailcheck explain` で各コードを説明
- 必要なときだけ、1件をSMTPで追加確認（Active Mode）
- 日本語と英語の表示
- プライバシーへの配慮。ファイルには既定でアドレスを含めず、画面では伏せ字にし、CSVは表計算ソフトの数式として解釈されないようにする

Pythonプログラムの中で構文だけを検査したい場合は、[email-validator](https://pypi.org/project/email-validator/) などの構文検査ライブラリのほうが適しています。

### 既存ツールとの違い

SMTPで受信者を確かめるツールは、ほかにもあります。このツールの違いは、次の組み合わせです。

- 外部のAPIやアカウントを使わず、手元だけで動く
- SMTPは既定で無効で、1件ずつ明示的に指定したときだけ使う。ファイルや候補生成からSMTPにつながる経路はない
- 証明書を検証できるTLSを必須とし、暗号化なしの通信に切り替えない
- 判定の根拠を段階ごとに示し、保守的な判定と段階的な信頼度を使い、確率のスコアは出さない
- 受動検査の一括処理、機械向けの出力、プライバシーに配慮した既定値、日英の表示
- 再現できる評価と、公開された安全性のテスト

逆に、すべてのアドレスを受け付けるサーバー（catch-all）は検出できません。また、TLSの条件が厳しいため、検査を完了できるサーバーは他のツールより少なくなります。詳しい比較と、SMTP検査そのものの限界は[比較](docs/comparison.md)にまとめています（2026-11-26時点）。

## 主な機能

- SMTPに接続せず、構文とDNS / MXレコードを確認する受動検査
- CSV・TXTファイルの一括検査と、入力順を維持したJSON・CSV出力
- `*` を指定した文字で置き換えて候補アドレスを作成する、オフラインの候補生成（ワイルドカード）
- 1件ずつ明示的に指定する、メールを送らないSMTP検査（Active Mode）
- 別途許可を得たリモート検査サービスに送る形式（`--remote`、運用者向け）

## インストール

Python 3.12以降が必要です。

~~~bash
git clone https://github.com/marc2825/EmailAddressChecker.git
cd EmailAddressChecker
python -m pip install .
~~~

PyPIへの公開（1.0.0、準備中）のあとは、次のどれでもインストールできます。

~~~bash
pipx install email-address-checker
uv tool install email-address-checker
python -m pip install email-address-checker
~~~

CIでは、Linux・Windows・macOSでインストールと動作を確認し、全テストはLinuxで実行しています。

## 使い方

コマンド名とPythonのimport名はどちらも `emailcheck` です。

~~~bash
# 1件または複数件を検査（SMTPには接続しない）
emailcheck check alice@example.com bob@example.org

# email列を持つCSVを検査
emailcheck batch addresses.csv --output results.csv

# 1行1アドレスのTXTを検査
emailcheck batch addresses.txt --format txt --output results.json

# 重複をスキップし、進捗を表示
emailcheck batch addresses.csv --duplicates skip --progress --output results.json

# 候補アドレスをオフラインで生成
emailcheck expand 'a**ce@example.com' --chars abc --output candidates.csv

# 生成される候補数の上限のみを確認
emailcheck expand 'a**ce@example.com' --charset lower --dry-run

# 判定や理由コードの意味を確認
emailcheck explain mx_available
~~~

画面に1件を表示すると、どの段階で何が分かったかを示します。

~~~text
$ emailcheck check alice@example.com
a***@example.com
invalid  無効です（信頼度 高）
このドメインは、メールを受け取らないとDNSで宣言しています（RFC 7505）。

  ✓ 構文            形式は正しい
  ✗ DNS・MX         受信しない宣言（null MX）  null_mx
  – メールボックス  ここまで進んでいません

推定です。メールボックスの実在や利用を証明するものではありません。
メッセージの内容は送信していません。
~~~

2件以上は1行に1件ずつ並べ、最後に件数をまとめます。表示は `LC_ALL`、`LC_MESSAGES`、`LANG` の言語設定に合わせて日本語か英語になり（`LANG=C` なら英語）、`NO_COLOR` を設定すると色を使いません。従来の単一アドレス指定（`emailcheck alice@example.com --json`）も引き続き使用できます。

### 入出力と制限

- CSVはUTF-8（BOM付きも可）で、`email` 列が1つ必要です。TXTは1行に1アドレスです。
- 画面には読みやすい形で表示し、パイプやファイルには入力の順にJSONで出力します。`--output-format csv` を付けるか、出力ファイル名を `.csv` にするとCSVになります。
- 画面ではアドレスを伏せ字（`a***@example.com`）で表示し、ファイルには含めません。全体を表示・保存するのは `--include-address` を付けたときだけです。
- 一括処理は既定で10,000行までですが、受動検査のクォータは既定でキーごとに1時間1,000件です。大きなファイルでは一部の行が拒否されることがあるので、[config/budgets.toml](config/budgets.toml) で調整してください。
- 制限はプロセスごとにかかり、複数のプロセスの間では共有しません。

~~~bash
emailcheck batch addresses.csv --config config/budgets.toml --output results.csv
~~~

入力と出力のファイルには個人情報が含まれ得るので、取り扱いに注意してください。機密性の高いアドレスは、シェル履歴に残るコマンド引数ではなくファイルで渡してください。詳しくは[利用ガイド](docs/usage-ja.md)と[設定ファイルの説明](config/README.md)を参照してください。

## Passive Mode と Active Mode

| | Passive Mode（既定） | Active Mode |
| --- | --- | --- |
| 指定 | なし | `emailcheck check ADDRESS --mode active --config FILE` |
| 調べるもの | 構文、DNS / MX | 構文、DNS / MX、宛先サーバーの `RCPT TO` への応答 |
| 対象 | 1件から一括（CSV / TXT）まで | 1件だけ |
| 宛先サーバーへの接続 | しない | する（メールは送らない） |
| 出せる判定 | `invalid`、`unknown`、`temporary_unknown` | 加えて `likely_deliverable`、受信者不存在の明示による `invalid` |

Active Mode の準備（初回だけ）:

~~~bash
emailcheck config example > emailcheck.toml
# emailcheck.toml を編集: 自分が管理するドメインのEHLO名と送信者を書く
emailcheck check alice@example.org --mode active --config emailcheck.toml
# 表示される注意を読み、acknowledged = true に書き換えてから、もう一度実行する
~~~

Active Mode について知っておくべきこと:

- 検査してよいのは、自分が管理するか、検査の許可を得たアドレスだけです。
- 接続先のサーバーには、検査したアドレス、あなたのIPアドレス、設定したEHLO名と送信者が伝わり、記録されることがあります。
- 送るコマンドは EHLO、STARTTLS、MAIL FROM、RCPT TO（1回）、RSET、QUIT だけです。DATA、BDAT、VRFY、EXPN は実装していません。
- 証明書を検証できるTLSが必須です。暗号化できないサーバーは検査しません。
- 多くのISPやクラウドはポート25への接続を遮断しており、そのときは `temporary_unknown` になります。家庭やクラウドのIPアドレスからの接続を拒否するサーバーも多くあります。
- 受信者が受け付けられても実在の証明ではありません。すべてのアドレスを受け付けるサーバーでは、存在しないアドレスも `likely_deliverable` になります（[評価](docs/evaluation.md)）。
- 件数や間隔の制限は1つのプロセスの中だけで働き、繰り返し実行すれば回避できます。他人のアドレスを調べてよい理由にはなりません。

## 判定結果の見方

| ステータス | 意味 |
| --- | --- |
| `likely_deliverable` | 配送できることを示す根拠がある。実在は保証しない。 |
| `invalid` | 構文や配送経路に明らかな不備があるか、配送できないことを示す権威ある根拠がある。 |
| `temporary_unknown` | 一時的な問題で判定できない。 |
| `unknown` | 根拠が足りないか曖昧、または非対応の形式で判定できない。 |

Passive Mode では `likely_deliverable` にはなりません。DNS/MXが正常でも、特定のメールボックスがあるとは限らないためです。Active Mode で受信者が受け付けられたときだけ、信頼度「中」で `likely_deliverable` になります。`confidence` は段階で表した信頼度で、確率ではありません。`refused` や `failed` などの処理状態は、判定とは別に出力します。各コードの意味は `emailcheck explain <コード>` で確認できます。詳しくは[ステータス仕様](docs/status-model.md)を参照してください。

## Pythonから使う場合

1.xで互換性を保つPythonの機能は、構文の解析（`emailcheck.parse_address`）と、判定・理由コード・注意フラグなどの語彙（`emailcheck.__all__` に含まれる名前）だけです。DNSを含む検査をPythonから呼ぶAPIはありません。その場合はCLIを呼び出し、JSONの出力を読んでください。これ以外のモジュールは内部実装で、予告なく変わることがあります。

## プライバシーと利用上の注意

- 検査するドメインは、使っているDNSリゾルバーに問い合わせとして送られます。
- コマンドの引数に書いたアドレスは、シェルの履歴に残ることがあります。機密性の高い一覧はファイルで渡してください。
- 候補生成（`emailcheck expand`）は、自分が管理するか、扱う許可を得たアドレスの整理にだけ使ってください。他人のメールアドレスの推測や列挙には使わないでください。

## 機能の範囲と安全性

- SMTPによる検査は初期状態で無効です。Active Mode は1件ずつ明示的に指定し、設定ファイルで注意事項への同意を記録したときだけ動きます。対象は自分が所有するか許可を得たものに限ります（[ADR 0022](docs/adr/0022-local-active-mode.md)、[セキュリティポリシー](SECURITY.md)）。
- メール本文を送る機能や、SMTPで一括検査する機能、候補生成とSMTP検査をつなぐ機能はありません。
- SMTP検査では、証明書とホスト名を検証するTLSが必須です。`--remote` もHTTPSが必須で、開発用のHTTPは `127.0.0.1` と `[::1]` だけを許可します（[ADR 0021](docs/adr/0021-required-encryption-at-network-boundaries.md)）。
- 使い捨てメール、フリーメール、プロバイダーの分類データは未収録です。フラグが付かなくても安全とは限りません。ロールアドレス（役割アドレス）の分類は使えます（[データセットの状態](src/emailcheck/data/passive/README.md)）。
- APIキー認証、HTTPリクエストの処理、ジョブの保存、SMTPの一括検査などのサービス向け部品は、ライブラリとしてだけ提供しています。HTTPサーバーは同梱しておらず、Active Mode もこれらを使いません（[コンポーネントの到達範囲](docs/architecture.md#component-reachability)、[今後の計画](ROADMAP.md)）。

## 開発

~~~bash
python -m pip install -e '.[dev,release]'
python -m pytest
~~~

設計、テスト、公開の手順は[ドキュメント一覧](docs/INDEX.md)を、コントリビューションの方法は[CONTRIBUTING.md](CONTRIBUTING.md)を参照してください。

ライセンスは [Apache 2.0](LICENSE) です。