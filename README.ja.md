# EmailAddressChecker

[English](README.md) | [日本語](README.ja.md)

EmailAddressCheckerは、メールアドレスの構文やDNS/MXレコードを調べ、配送可能性を推定するPython製のCLI・ライブラリです。**メールボックスの実在や、実際にメールが届くことを保証するものではありません。**

通常のローカル検査ではSMTPサーバーに接続しません。SMTPによる検査は、別途設定・許可された運用環境向けの機能です。

## 主な機能

- **受動検査：** SMTP接続を行わず、構文とDNS/MXレコードを確認
- **一括処理：** CSV・TXTを読み込み、結果をJSON・CSVで出力
- **オフライン候補生成：** `*` を指定した文字列で置換し、候補アドレスを生成
- **限定的なSMTP検査：** 明示的に設定・許可されたリモート検査サービスに接続

## インストール

**Python 3.12以降** が必要です。v0.1.0はまだPyPIに公開されていないため、リポジトリからインストールします。

```bash
git clone https://github.com/marc2825/EmailAddressChecker.git
cd EmailAddressChecker
python -m pip install .
```

コマンド名とPythonのimport名は、どちらも `emailcheck` です。

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

# 生成候補数の上限だけを確認
emailcheck expand 'a**ce@example.com' --charset lower --dry-run
```

従来の単一アドレス指定も利用できます：`emailcheck alice@example.com --json`。

### 入出力と制限

CSVはUTF-8形式で `email` 列が必要です。TXTは1行につき1アドレスを記述します。結果は入力順で出力され、既定の形式はJSONです。`--output-format csv` または `.csv` の出力ファイル名を指定するとCSVになります。

結果に元のメールアドレスを含める場合だけ `--include-address` を指定してください。入力・出力ファイルには個人情報が含まれ得るため、取り扱いに注意が必要です。機密性の高いアドレスは、シェル履歴に残り得る直接指定よりファイル入力を推奨します。

一括処理の既定上限は **10,000行** ですが、受動検査の既定クォータは **キーごとに1時間あたり1,000件** です。大きな一括処理では、設定を変更しないと一部の行が拒否される場合があります。[config/budgets.toml](config/budgets.toml) で調整できます。

```bash
emailcheck batch addresses.csv --config config/budgets.toml --output results.csv
```

制限はプロセスごとに適用され、複数プロセス間で共有されません。詳細は[利用ガイド](docs/usage-ja.md)と[設定ファイルの説明](config/README.md)を参照してください。

## 判定結果の見方

| ステータス | 意味 |
| --- | --- |
| `likely_deliverable` | 配送できる可能性を示す証拠がある。ただし実在は保証しない。 |
| `invalid` | 構文や配送経路の明確な不備、または権威ある否定的な証拠がある。 |
| `temporary_unknown` | 一時的な問題により判断できない。 |
| `unknown` | 情報不足・曖昧な証拠・非対応のアドレス形式などにより判断できない。 |

`confidence` は段階的な信頼度であり、確率ではありません。DNS/MXが正常でも、そのドメインに特定のメールボックスが存在するとは限りません。また、`refused` や `failed` などの処理状態は、配送可否の判定とは別です。

判定根拠や理由コードの詳細は[ステータス仕様](docs/status-model.md)を参照してください。

## 機能の範囲と安全性

受動検査ではDNSを参照しますが、SMTP接続は行いません。候補生成は完全にオフラインです。SMTP検査は初期状態では無効で、認証、宛先制限、レート制限、運用者による明示的な許可などを備えた別環境が必要です。メール本文を送信する機能や、無制限のSMTP一括検査機能はありません。

使い捨てメール・フリーメール・プロバイダー分類のデータは現時点で未収録です。フラグが付かないことを、安全性の証拠と解釈しないでください。役割アドレスの分類は利用できます。詳細は[データセットの状態](src/emailcheck/data/passive/README.md)を参照してください。

SMTP検査は、自身が所有するか、明示的な許可を得た対象に限定してください。[セキュリティポリシー](SECURITY.md)と[運用前チェックリスト](docs/readiness-checklist.md)も参照してください。

## 開発・ドキュメント

```bash
python -m pip install -e '.[dev,release]'
python -m pytest
```

設計、テスト、公開手順は[ドキュメント一覧](docs/INDEX.md)、コントリビューションについては[CONTRIBUTING.md](CONTRIBUTING.md)を参照してください。

ライセンスは [Apache 2.0](LICENSE) です。
