# CLIリファレンス（日本語）

本書は `emailcheck` のローカルCLIについて、入出力形式、オプション、制限をまとめたものです。概要とインストール手順は [日本語README](../README.ja.md) を参照してください。

**ローカル検査はDNSを参照しますがSMTPには接続しません。** メールボックスの実在や到達を保証するものではありません。

## 検査

```bash
# 1件・複数件の受動検査
emailcheck check alice@example.com bob@example.org --output results.json

# 旧形式の単一アドレス検査
emailcheck alice@example.com --json

# CSV / TXTの一括検査
emailcheck batch addresses.csv --output results.csv
emailcheck batch addresses.txt --format txt --output results.json

# 重複スキップ・進捗表示
emailcheck batch addresses.csv --duplicates skip --progress --output results.json
```

`check` と `batch` は受動検査専用です。`--mode` で指定できるのは `passive` のみです。

### 入力形式

| 形式 | 仕様 |
| --- | --- |
| CSV | UTF-8（BOM可）。`email` 列が必須。列名の前後の空白と大文字・小文字は区別しない。ほかの列は検査に使用しない。 |
| TXT | UTF-8。1行につき1アドレス。空行も空の入力として検査する。 |

アドレスの前後の空白は自動削除しません。コメント行の構文もありません。CSVの列数が一致しない行は `rejected` として記録し、処理を継続します。一方、CSVの構文・文字コードの破損や、ファイル全体の上限超過はコマンドを中止します。一括処理では検査の前に入力ファイル全体を確認します。

`batch` の入力形式は拡張子 `.txt` ならTXT、それ以外はCSVとして判定します。`--format csv|txt` で明示できます。

### 主なオプション

| オプション | 動作 |
| --- | --- |
| `--output PATH` | 結果をファイルに保存。指定しない場合は標準出力。 |
| `--output-format json\|csv` | 出力形式を指定。既定はJSON。出力ファイル名が `.csv` ならCSVになる。 |
| `--json` | JSON出力を明示指定。 |
| `--include-address` | 結果に元のメールアドレスを含める（既定では含まない）。 |
| `--duplicates keep\|skip` | 重複行を検査するか、初回出現行への参照とともにスキップするか。既定は `keep`。 |
| `--progress` | 件数のみの進捗を標準エラー出力へ表示。 |
| `--start-row N` | `batch` 専用。N行目以降を新たに受動検査する。 |
| `--config PATH` | 検査・処理予算を記述したTOMLを読み込む。 |

`--duplicates skip` の重複行には `duplicate_of` が付き、初回出現行の判定結果はコピーされません。`--start-row N` は初回出現行の識別情報と元の行番号を維持しますが、前回のDNS結果や出力を復元・結合する機能ではありません。

### 出力と終了コード

`check` と `batch` は入力順に結果を出力します。JSONは配列、CSVは1行1結果で、配列・オブジェクト列はJSON文字列として格納されます。`status` は配送に関する判定、`state` はその行の処理状態です。

- **判定 (`status`)**：`likely_deliverable`、`invalid`、`temporary_unknown`、`unknown`。
- **処理状態 (`state`)**：`completed`、`duplicate`、`rejected`、`refused`、`failed`。`refused` と `failed` など、検査できなかった行に配送判定は付与しません。
- **信頼度 (`confidence`)**：`high` / `medium` / `low` のカテゴリであり、確率ではありません。

詳しくは [判定モデル](status-model.md) を参照してください。

| 終了コード | `check` / `batch` での意味 |
| --- | --- |
| `0` | 全行の処理が完了。`invalid` の判定が含まれていても成功。 |
| `2` | 入力・設定・出力のエラー。 |
| `3` | いずれかの行が `rejected`、`refused` または `failed`。 |
| `130` | Ctrl-Cによる中断。 |

`--output` 指定時は正常完了した場合だけ出力ファイルを置き換えます。中断やエラーでは既存ファイルを保持します。標準出力は中断時に不完全なデータになることがあります。強制終了後に `.emailcheck-*` という一時ファイルが残った場合は、内容を確認してから削除してください。

## オフライン候補生成

```bash
# 2か所の * をa, b, cでそれぞれ置換
emailcheck expand 'a**ce@example.com' --chars abc --output candidates.csv

# 生成数の上限だけを確認（ファイルは生成しない）
emailcheck expand 'a**ce@example.com' --charset lower --dry-run

# * ごとに異なる候補集合を使用
emailcheck expand 'a**ce@example.com' --slot '["a","b"]' --slot '["0","1"]'

# 文字列単位の候補とTXT出力
emailcheck expand 'a*ce@example.com' --candidate b --candidate xyz --output-format txt --output candidates.txt
```

`*` はローカルパート内の置換位置を表し、各位置に候補を1つずつ適用します。出力は直積の順序です。

| オプション | 動作 |
| --- | --- |
| `--charset lower\|upper\|digits\|alnum` | 英小文字・大文字・数字・英数字のプリセット。 |
| `--chars TEXT` | 文字列を1文字ずつ候補として使用。 |
| `--candidate TEXT` | 繰り返し指定した文字列を候補として使用。 |
| `--candidates-file FILE` | UTF-8ファイルの各行を共通候補として使用。 |
| `--slot JSON` | `*` ごとにJSON文字列配列を指定。位置数だけ繰り返す。 |
| `--slot-file FILE` | 位置ごとの候補ファイルを指定。 |
| `--max-candidates N` | 候補の直積数に対する上限を指定（既定上限以下のみ）。 |
| `--dry-run` | 候補数の上限だけを表示。 |
| `--output-format csv\|txt` | 候補の出力形式。既定はCSVで、`email` ヘッダーを付ける。 |

共通候補（`--chars` など）と位置別候補（`--slot` など）は併用できません。候補ファイルの空行は空文字列を表し、空ファイルは拒否されます。パターン中の `\*` は置換しない `*` です。ドメイン側の `*` は使用できません。

同じ候補や同一の生成結果は重複排除します。`--dry-run` の個数は**ユニークな生成件数の上限**であり、生成後の実件数とは異なる場合があります。候補の構文は生成時に検査されます。UnicodeドメインはIDNAで扱いますが、SMTPUTF8が必要なローカルパートの候補生成は非対応です。

出力CSVで表計算ソフトの数式と解釈され得る候補は拒否されます。そのような文字列を扱う場合はTXT形式を使用してください。候補生成からActive SMTP検査を自動実行する機能はありません。

## 上限と設定

| 項目 | 既定 | 設定可能な上限 |
| --- | ---: | ---: |
| 一括入力行数 | 10,000行 | 50,000行 |
| 一括入力サイズ | 4 MiB | 8 MiB |
| 同時処理行数 | 8 | 64 |
| 候補の直積数 | 10,000 | バッチ行数設定以下、最大50,000 |

候補パターンは最大254文字、置換トークンは1件64文字、候補集合は最大10,000入力・1 MiBです。入力の上限と別に、受動検査には既定で**APIキーごとに1時間1,000件**のクォータがあり、大きなバッチでは一部の行が `refused` になる場合があります。

```bash
emailcheck config show --config config/budgets.toml
emailcheck batch addresses.csv --config config/budgets.toml --output results.csv
```

CLI設定で読み込めるセクションは `[batch]`、`[rate_limit]`、`[quota]`、`[passive_quota]` です。実際の設定例は [budgets.toml](../config/budgets.toml) を参照してください。TLS、認証情報、宛先許可などは、この設定ファイルでは変更できません。`config/local-passive.toml` などのデプロイ例はCLI用の設定ファイルではありません。

制限はプロセスごとに管理され、複数プロセスや複数レプリカにまたがる共有制御ではありません。設定の区別は [config/README.md](../config/README.md) を参照してください。

## その他のコマンド

```bash
emailcheck --version
emailcheck --report-versions
emailcheck --check-deployment
```

`--report-versions` はパッケージ、判定ルール、データセットのバージョンを表示します。使い捨てメール・フリーメール・プロバイダーの分類データは現時点で未収録であり、フラグが付かないことは「該当しない」という意味ではありません。`--check-deployment` はActive環境の準備状況を表示する参考情報で、外部接続も運用承認も行わず、終了コードは常に0です。

従来形式の `emailcheck ADDRESS --remote URL --remote-key-file PATH [--wait]` は、別途構築・許可されたActive検査サービス向けです。リモート接続はHTTPS必須です。開発用HTTPは厳密な `127.0.0.1` / `[::1]` のみ許可し、`localhost`、リダイレクト、環境プロキシは使用しません。対象の所有・許可、認証、レート制限、TLS、運用準備が必要です。通常の `check` / `batch` にActive検査への切り替え機能はありません。詳しくは [運用ガイド](operations.md) と [セキュリティポリシー](../SECURITY.md) を参照してください。
