# EmailAddressChecker

[English](README.md) | [日本語](README.ja.md)

EmailAddressCheckerは、メールを送らずに、メールアドレスの構文とドメインのDNS/MXレコードを調べて配送できる見込みを推定するPython製のCLI・ライブラリです。メールボックスが実在することや、メールが実際に届くことは保証しません。

ローカルの検査ではSMTPサーバーに接続しません。SMTPによる検査は、別に設定して許可を得た運用環境向けの機能です。

## 主な機能

- SMTPに接続せず、構文とDNS/MXレコードを確認する受動検査
- CSV・TXTファイルの一括検査と、入力順でのJSON・CSV出力
- `*` を指定した文字で置き換えて候補アドレスを作る、オフラインの候補生成
- 明示的に設定・許可したリモート検査サービスを使う、限定的なSMTP検査

## インストール

Python 3.12以降が必要です。v0.1.0はまだPyPIに公開していないため、リポジトリからインストールします。

```bash
git clone https://github.com/marc2825/EmailAddressChecker.git
cd EmailAddressChecker
python -m pip install .
```

コマンド名とPythonのimport名はどちらも `emailcheck` です。

## 使い方

```bash
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

# 生成する候補数の上限だけを確認
emailcheck expand 'a**ce@example.com' --charset lower --dry-run
```

従来の単一アドレスの指定（`emailcheck alice@example.com --json`）も使えます。

### 入出力と制限

CSVはUTF-8で、`email` 列が必要です。表計算ソフトが先頭に付けるBOMはあっても構いません。TXTには1行に1アドレスを書きます。結果は入力の順に出力し、形式は既定でJSONです。`--output-format csv` を指定するか、出力ファイル名を `.csv` にするとCSVになります。

結果に元のメールアドレスを含めるのは、`--include-address` を指定したときだけです。入力・出力ファイルには個人情報が含まれ得るので、取り扱いに注意してください。機密性の高いアドレスは、シェル履歴に残り得る引数ではなくファイルで渡すことを勧めます。

一括処理の既定の上限は10,000行ですが、受動検査の既定のクォータはキーごとに1時間あたり1,000件です。そのため、設定を変えずに大きなファイルを処理すると、一部の行が拒否される場合があります。上限は [config/budgets.toml](config/budgets.toml) で調整できます。

```bash
emailcheck batch addresses.csv --config config/budgets.toml --output results.csv
```

制限はプロセスごとにかかり、複数のプロセスの間では共有しません。詳しくは[利用ガイド](docs/usage-ja.md)と[設定ファイルの説明](config/README.md)を参照してください。

## 判定結果の見方

| ステータス | 意味 |
| --- | --- |
| `likely_deliverable` | 配送できることを示す証拠がある。ただし実在は保証しない。 |
| `invalid` | 構文や配送経路に明らかな不備があるか、権威ある否定的な証拠がある。 |
| `temporary_unknown` | 一時的な問題で判断できない。 |
| `unknown` | 情報不足、曖昧な証拠、非対応のアドレス形式などで判断できない。 |

`confidence` は段階で表した信頼度で、確率ではありません。DNS/MXが正常でも、そのドメインに特定のメールボックスがあるとは限りません。`refused` や `failed` などの処理状態は、配送の判定とは別に出力します。判定の根拠と理由コードは[ステータス仕様](docs/status-model.md)にあります。

## 機能の範囲と安全性

SMTPによる検査は初期状態では無効です。使うには、認証、宛先の制限、レート制限、運用者による明示的な許可を備えた別の環境が必要です。メール本文を送る機能や、無制限にSMTPで一括検査する機能はありません。SMTP検査は、自分が所有するか明示的に許可を得た対象だけに使ってください。[セキュリティポリシー](SECURITY.md)と[運用前チェックリスト](docs/readiness-checklist.md)も参照してください。

`--remote` にはHTTPSが必要です。開発用のHTTPは `127.0.0.1` と `[::1]` のIPリテラルだけを許可し、`localhost`、リダイレクト、環境変数のプロキシは使いません。SMTP検査は、ライブラリから使う場合も証明書とホスト名を検証するTLSが必須です。従来の `OPPORTUNISTIC` は削除しました。移行方法は[ADR 0021](docs/adr/0021-required-encryption-at-network-boundaries.md)を参照してください。

使い捨てメール、フリーメール、プロバイダーの分類データは、現時点では収録していません。フラグが付かないことを、安全だという証拠と受け取らないでください。役割アドレスの分類は使えます。詳しくは[データセットの状態](src/emailcheck/data/passive/README.md)を参照してください。

リポジトリには、APIキー認証、HTTPリクエストの処理、ジョブと判定結果の保存、SMTPの一括検査などのサービス向けの部品も含まれていますが、ライブラリとしてだけ提供しています。HTTPサーバーは同梱しておらず、インストールした `emailcheck` コマンドからは使いません。接続の前提条件と今後の計画は[コンポーネントの到達範囲](docs/architecture.md#component-reachability)にあります。

## 開発

```bash
python -m pip install -e '.[dev,release]'
python -m pytest
```

設計、テスト、公開の手順は[ドキュメント一覧](docs/INDEX.md)から、コントリビューションの方法は[CONTRIBUTING.md](CONTRIBUTING.md)を参照してください。

ライセンスは [Apache 2.0](LICENSE) です。
