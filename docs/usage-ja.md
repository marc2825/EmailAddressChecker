# CLIリファレンス（日本語）

ローカルで使う `emailcheck` コマンドの入出力形式、オプション、制限をまとめます。概要とインストールの手順は[README](../README.md)を参照してください。

ローカルの検査はDNSを参照しますが、SMTPには接続しません。メールボックスの実在やメールの到達は保証しません。

## 検査

```bash
# 1件・複数件の受動検査
emailcheck check alice@example.com bob@example.org --output results.json

# 旧形式の単一アドレス検査
emailcheck alice@example.com --json

# CSV / TXTの一括検査
emailcheck batch addresses.csv --output results.csv
emailcheck batch addresses.txt --format txt --output results.json

# 重複のスキップと進捗の表示
emailcheck batch addresses.csv --duplicates skip --progress --output results.json
```

`check` と `batch` は受動検査だけを行います。`--mode` に指定できるのは `passive` だけです。

### 入力形式

| 形式 | 仕様 |
| --- | --- |
| CSV | UTF-8（BOM可）。`email` 列がちょうど1つ必要で、同じ列名の重複は不可。列名の前後の空白と大文字・小文字は区別しない。ほかの列は検査に使わない。 |
| TXT | UTF-8（BOM可）。1行に1アドレス。空行も空の入力として検査する。 |

BOMとして扱うのはファイル先頭の1つだけです。ほかの位置にあるU+FEFFはアドレスの一部として検査し、構文エラーになります。アドレスの前後にあるASCIIの空白（スペース、タブ、改行など）は、構文検査の前に取り除きます。ノーブレークスペースなど、それ以外の空白は取り除かずに検査し、構文エラーになります。コメント行の書き方はありません。

一括処理では、検査を始める前に入力ファイル全体を確認するため、入力は通常のファイルである必要があります（パイプやFIFOは不可）。CSVの空行は読み飛ばし、列の数が合わない行は `rejected` として記録して処理を続けます。`email` 列が空の行は、空の入力として検査します。CSVの構文や文字コードが壊れているとき、NULを含むとき、またはファイル全体が上限を超えるときは、コマンドを中止します。

`batch` は拡張子が `.txt` のファイルをTXT、それ以外をCSVとして読みます。`--format csv|txt` で明示することもできます。

`user@localhost` のような単一ラベルのドメインや、`user@192.0.2.1` のように角括弧のない数字だけのドメインは、構文上はDNS名として受け付けます。判定はDNSと宛先ポリシーで決まります。数字だけのトップレベルラベルは存在しないのでNXDOMAINになります。DNSがループバックやプライベートアドレスを返したときは、そのアドレスを接続先として拒否します。IPアドレスリテラルとして読み替えたり、そのIPに直接接続したりはしません。角括弧付きの `user@[192.0.2.1]` は未対応の形式として `unknown` になります。

### 主なオプション

| オプション | 動作 |
| --- | --- |
| `--output PATH` | 結果をファイルに保存する。指定しなければ標準出力に出す。 |
| `--output-format json\|csv` | 出力形式。既定はJSON。出力ファイル名が `.csv` ならCSVになる。 |
| `--json` | JSONで出力する。 |
| `--include-address` | 結果に元のメールアドレスを含める（既定では含めない）。 |
| `--duplicates keep\|skip` | 重複した行を検査するか、最初に出た行への参照を付けてスキップするか。既定は `keep`。 |
| `--progress` | 件数だけの進捗を標準エラー出力に表示する。 |
| `--start-row N` | `batch` 専用。N行目から新しく受動検査する。 |
| `--config PATH` | 検査と処理の予算を書いたTOMLを読み込む。 |

`--duplicates skip` でスキップした行には `duplicate_of` が付き、最初に出た行の判定はコピーしません。`--start-row N` は最初に出た行の識別情報と元の行番号を保ちますが、前回のDNS結果や出力を復元したり、つなげたりはしません。

### 出力と終了コード

`check` と `batch` は入力の順に結果を出力します。JSONは配列、CSVは1行1結果で、配列やオブジェクトの列はJSON文字列として入ります。

- `status`（判定）: `likely_deliverable`、`invalid`、`temporary_unknown`、`unknown` のいずれか。配送についての判定です。
- `state`（処理状態）: `completed`、`duplicate`、`rejected`、`refused`、`failed` のいずれか。`refused` や `failed` のように検査できなかった行には、配送の判定を付けません。
- `confidence`（信頼度）: `high`、`medium`、`low` の段階で、確率ではありません。

詳しくは[判定モデル](status-model.md)を参照してください。

| 終了コード | `check` / `batch` での意味 |
| --- | --- |
| `0` | 全行の処理が完了した。`invalid` の判定が含まれていても成功。 |
| `2` | 入力、設定、出力のエラー。 |
| `3` | いずれかの行が `rejected`、`refused`、`failed` のどれか。 |
| `130` | Ctrl-Cで中断した。 |

`--output` を指定したときは、正常に完了した場合だけ出力ファイルを置き換え、中断やエラーのときは既存のファイルを残します。標準出力は、中断すると途中までのデータになることがあります。強制終了のあとに `.emailcheck-*` という一時ファイルが残っていたら、内容を確認してから削除してください。

## オフライン候補生成

```bash
# 2か所の * をa, b, cでそれぞれ置き換える
emailcheck expand 'a**ce@example.com' --chars abc --output candidates.csv

# 生成数の上限だけを確認する（ファイルは作らない）
emailcheck expand 'a**ce@example.com' --charset lower --dry-run

# * ごとに別の候補を使う
emailcheck expand 'a**ce@example.com' --slot '["a","b"]' --slot '["0","1"]'

# 文字列の候補を使い、TXTで出力する
emailcheck expand 'a*ce@example.com' --candidate b --candidate xyz --output-format txt --output candidates.txt
```

`*` はローカルパートの中の置き換える位置で、各位置に候補を1つずつ当てはめます。出力は直積の順です。

| オプション | 動作 |
| --- | --- |
| `--charset lower\|upper\|digits\|alnum` | 英小文字、英大文字、数字、英数字のプリセット。 |
| `--chars TEXT` | 文字列の各文字を候補にする。 |
| `--candidate TEXT` | 指定した文字列を候補にする。繰り返し指定できる。 |
| `--candidates-file FILE` | UTF-8ファイルの各行を、すべての位置で共通の候補にする。 |
| `--slot JSON` | `*` ごとの候補をJSONの文字列配列で指定する。位置の数だけ繰り返す。 |
| `--slot-file FILE` | 位置ごとの候補ファイルを指定する。 |
| `--max-candidates N` | 候補の直積数の上限を指定する（既定の上限以下に限る）。 |
| `--dry-run` | 候補数の上限だけを表示する。 |
| `--output-format csv\|txt` | 候補の出力形式。既定はCSVで、`email` ヘッダーを付ける。 |

共通の候補（`--chars` など）と位置ごとの候補（`--slot` など）は同時に使えません。候補ファイルの空行は空文字列として扱い、空のファイルは拒否します。パターン中の `\*` は置き換えない `*` です。ドメイン側には `*` を使えません。

同じ候補や同じ生成結果は1つにまとめます。そのため `--dry-run` が示すのはユニークな生成件数の上限で、実際に生成される件数とは違う場合があります。候補の構文は生成するときに検査します。UnicodeドメインはIDNAで扱いますが、SMTPUTF8が必要なローカルパートの候補は生成できません。

出力したCSVを表計算ソフトが数式と解釈し得る候補は拒否します。生成する前にすべての候補を検査するので、エラーのときは標準出力にも何も出力しません。そうした文字列を扱うときはTXT形式を使ってください。候補生成からSMTP検査を自動で実行する機能はありません。

## 上限と設定

| 項目 | 既定 | 設定できる上限 |
| --- | ---: | ---: |
| 一括入力の行数 | 10,000行 | 50,000行 |
| 一括入力のサイズ | 4 MiB | 8 MiB |
| 同時に処理する行数 | 8 | 64 |
| 候補の直積数 | 10,000 | バッチ行数の設定以下、最大50,000 |

候補のパターンは最大254文字、置き換えるトークンは1件64文字まで、候補の集合は最大10,000件・1 MiBです。入力の上限とは別に、受動検査には既定でAPIキーごとに1時間1,000件のクォータがあるため、大きなバッチでは一部の行が `refused` になる場合があります。

```bash
emailcheck config show --config config/budgets.toml
emailcheck batch addresses.csv --config config/budgets.toml --output results.csv
```

CLIの設定ファイルで読み込めるセクションは `[batch]`、`[rate_limit]`、`[quota]`、`[passive_quota]` です。設定の例は [budgets.toml](../config/budgets.toml) にあります。TLS、認証情報、宛先の許可などは、この設定ファイルでは変えられません。`config/local-passive.toml` などのデプロイ例は、CLIの設定ファイルではありません。

制限はプロセスごとに管理し、複数のプロセスやレプリカの間では共有しません。設定ファイルの区別は [config/README.md](../config/README.md) を参照してください。

## その他のコマンド

```bash
emailcheck --version
emailcheck --report-versions
emailcheck --check-deployment
```

`--report-versions` は、パッケージ、判定ルール、データセットのバージョンを表示します。使い捨てメール、フリーメール、プロバイダーの分類データは現時点では収録していないので、フラグが付かなくても「該当しない」という意味にはなりません。`--check-deployment` はActive環境の準備状況を参考として表示します。外部への接続も運用の承認もせず、終了コードは常に0です。

従来形式の `emailcheck ADDRESS --remote URL --remote-key-file PATH [--wait]` は、別に構築して許可を得たActive検査サービスに接続するためのものです。リモート接続にはHTTPSが必要です。開発用のHTTPは `127.0.0.1` と `[::1]` だけを許可し、`localhost`、リダイレクト、環境変数のプロキシは使いません。使うには、対象の所有または許可、認証、レート制限、TLS、運用の準備が必要です。通常の `check` と `batch` には、Active検査に切り替える機能はありません。詳しくは[運用ガイド](operations.md)と[セキュリティポリシー](../SECURITY.md)を参照してください。
