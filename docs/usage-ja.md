# 日本語利用ガイド

メール配送可能性を保守的に推定します。メールボックスの実在を証明しません。
ローカルチェックはDNSを使いますがSMTPには接続しません。候補生成は完全オフラインです。
配布名は `email-address-checker`、import名とコマンド名は `emailcheck` です。
0.1.0は公開準備中で、PyPIへのアップロードは実施していません。

```bash
emailcheck check a@example.com b@example.org --output results.json
emailcheck batch input.csv --output results.csv --progress
emailcheck batch addresses.txt --format txt --duplicates skip
emailcheck expand 'm**rc@example.com' --chars abc --dry-run
emailcheck expand 'm**rc@example.com' --slot '["a","b"]' --slot '["0","1"]'
emailcheck expand 'm*rc@example.com' --candidate a --candidate ab --output candidates.csv
emailcheck batch candidates.csv --mode passive --output results.csv
emailcheck config show --config config/budgets.toml
```

CSVは `email` ヘッダー付きUTF-8、TXTは1行1アドレスです。出力は入力順で、
既定ではアドレスを含みません。必要な場合だけ `--include-address` を指定してください。
重複は既定では各行を検査し、`--duplicates skip` では初出行番号付きでスキップします。
上限超過は拒否されます。行ごとの処理拒否は配送判定と分離して記録します。

各 `*` は独立した置換です。`--chars` は1文字ずつ、`--candidate` は文字列単位、
`--slot` は位置ごとのJSON配列です。`--candidates-file` と `--slot-file` は
UTF-8の行単位候補を読みます。空行は空文字列、空ファイルはエラーです。
パターンの `\*` は文字としての `*` です。ドメイン側のワイルドカードは不可です。
UnicodeドメインはIDNA、Unicodeローカルパートは既存仕様どおり非対応です。

候補数は既定10,000、ハード上限50,000です。直積を生成する前に数を確認し、
遅延生成します。重複トークンは先着順で除き、結合結果の衝突も抑制します。
dry-runはユニーク出力数の上限で、全候補の構文検証は生成時に行います。

Ctrl-Cで中断できます。`--output` は成功時にだけ既存ファイルを置き換えます。
標準出力は途中で切れる場合があります。強制終了後に残る `.emailcheck-*` は
確認後に削除してください。`--start-row N` は指定行からの新しい受動チェックであり、
チェックポイント復元・出力マージではありません。

TOMLの `[batch]`、`[rate_limit]`、`[quota]`、`[passive_quota]` を設定できます。
実例は [budgets.toml](../config/budgets.toml) です。Activeとpassiveの予算は分離し、
単発と一括は同じ検証サービスを使います。制限は単一プロセス内です。
複数CLI起動や複数レプリカをまとめた予算保証はありません。

Active SMTPは所有または明示的に許可された宛先について、既存の認証・許可リスト・
監査・TLS・緊急停止・デプロイ準備ゲートを満たした場合に限ります。
ワイルドカードからSMTP列挙を実行する機能はありません。

詳細な上限・出力例・Python API・配布手順は [README](../README.md) と
[公開手順](releasing.md) を参照してください。
