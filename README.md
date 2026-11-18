# EmailAddressChecker

[日本語](README.md) | [English](README.en.md)

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/teaser-dark.svg">
    <img src="docs/assets/teaser-light.svg" width="100%" alt="EmailAddressCheckerのロゴ">
  </picture>
</p>

EmailAddressCheckerは、**実際にメールを送信することなく、メールアドレスの存在を推定する**サービスです。

具体的には、メールアドレスの構文とドメインのDNS / MXレコードから配送見込みを推定するような、Python製のCLI・ライブラリです。メールボックスの実在や、メールが実際に届くことまでは保証しません。

※ ローカルでの検査ではSMTPサーバーに接続しません。SMTPによる検査は、別途設定して許可を得た運用環境向けの機能です。

## 主な機能

- SMTPに接続せず、構文とDNS / MXレコードを確認する受動検査
- CSV・TXTファイルの一括検査と、入力順を維持したJSON・CSV出力
- `*` を指定した文字で置き換えて候補アドレスを作成する、オフラインの候補生成（ワイルドカード）
- 明示的に設定・許可されたリモート検査サービスを使用する、限定的なSMTP検査

## インストール

Python 3.12以降が必要です。

~~~bash
git clone https://github.com/marc2825/EmailAddressChecker.git
cd EmailAddressChecker
python -m pip install .
~~~

※ 準備が整い次第、 PyPI に公開する予定です。

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
~~~

従来の単一アドレス指定（`emailcheck alice@example.com --json`）も引き続き使用できます。

### 入出力と制限

- CSVはUTF-8（BOM付きも可）で、`email` 列が1つ必要です。TXTは1行に1アドレスです。
- 結果は入力の順に、既定ではJSONで出力します。`--output-format csv` を付けるか、出力ファイル名を `.csv` にするとCSVになります。
- 元のメールアドレスは、`--include-address` を付けたときだけ結果に含めます。
- 一括処理は既定で10,000行までですが、受動検査のクォータは既定でキーごとに1時間1,000件です。大きなファイルでは一部の行が拒否されることがあるので、[config/budgets.toml](config/budgets.toml) で調整してください。
- 制限はプロセスごとにかかり、複数のプロセスの間では共有しません。

~~~bash
emailcheck batch addresses.csv --config config/budgets.toml --output results.csv
~~~

入力と出力のファイルには個人情報が含まれ得るので、取り扱いに注意してください。機密性の高いアドレスは、シェル履歴に残るコマンド引数ではなくファイルで渡してください。詳しくは[利用ガイド](docs/usage-ja.md)と[設定ファイルの説明](config/README.md)を参照してください。

## 判定結果の見方

| ステータス | 意味 |
| --- | --- |
| `likely_deliverable` | 配送できることを示す根拠がある。実在は保証しない。 |
| `invalid` | 構文や配送経路に明らかな不備があるか、配送できないことを示す権威ある根拠がある。 |
| `temporary_unknown` | 一時的な問題で判定できない。 |
| `unknown` | 根拠が足りないか曖昧、または非対応の形式で判定できない。 |

ローカルの検査（構文とDNSのみ）では `likely_deliverable` にはなりません。DNS/MXが正常でも、特定のメールボックスがあるとは限らないためです。`confidence` は段階で表した信頼度で、確率ではありません。`refused` や `failed` などの処理状態は、判定とは別に出力します。詳しくは[ステータス仕様](docs/status-model.md)を参照してください。

## 機能の範囲と安全性

- SMTPによる検査は初期状態で無効です。使うには、認証、宛先の制限、レート制限、運用者の明示的な許可を備えた別の環境が必要で、対象は自分が所有するか許可を得たものに限ります（[セキュリティポリシー](SECURITY.md)、[運用前チェックリスト](docs/readiness-checklist.md)）。
- メール本文を送る機能や、無制限にSMTPで一括検査する機能はありません。
- SMTP検査では、証明書とホスト名を検証するTLSが必須です。`--remote` もHTTPSが必須で、開発用のHTTPは `127.0.0.1` と `[::1]` だけを許可します（[ADR 0021](docs/adr/0021-required-encryption-at-network-boundaries.md)）。
- 使い捨てメール、フリーメール、プロバイダーの分類データは未収録です。フラグが付かなくても安全とは限りません。ロールアドレス（役割アドレス）の分類は使えます（[データセットの状態](src/emailcheck/data/passive/README.md)）。
- APIキー認証、HTTPリクエストの処理、ジョブの保存、SMTPの一括検査などのサービス向け部品は、ライブラリとしてだけ提供しています。HTTPサーバーは同梱しておらず、`emailcheck` コマンドからは使いません（[コンポーネントの到達範囲](docs/architecture.md#component-reachability)、[今後の計画](ROADMAP.md)）。

## 開発

~~~bash
python -m pip install -e '.[dev,release]'
python -m pytest
~~~

設計、テスト、公開の手順は[ドキュメント一覧](docs/INDEX.md)を、コントリビューションの方法は[CONTRIBUTING.md](CONTRIBUTING.md)を参照してください。

ライセンスは [Apache 2.0](LICENSE) です。