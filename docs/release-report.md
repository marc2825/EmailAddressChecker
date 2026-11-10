# 0.1.0 実装・公開準備レポート

作業日: 2026-10-22（利用者のAsia/Tokyo基準）。
対象: marc2825/EmailAddressChecker。開始時のmainは `eea2981`、origin/mainと同じ。
他のローカルブランチ・タグ・未コミット変更はありませんでした。
リモート追跡情報もorigin/mainのみでした。GitHub側の最新heads/tagsを読み取る
`git ls-remote` は認証不足で失敗したため、未取得のリモート参照の有無は未検証です。

## 到達点

| 区分 | 状態 |
|---|---|
| 機能実装 | 完了。オフライン候補生成、受動一括CLI、設定、出力、DNS/MX制御 |
| ローカル検証 | LinuxでPython 3.12 / 3.13 / 3.14の全4,343件が各々成功 |
| PyPI公開用コード・配布物の準備 | 完了。ビルド、メタデータ、隔離インストール、承認付きworkflowを整備 |
| 外部の公開設定 | 未実施。Environment、Trusted Publisher、公開スイッチ設定が必要 |
| 実際のPyPI / TestPyPI公開 | 未実施 |
| Active SMTP運用承認 | なし。外部SMTP接続も未実施 |

Windowsでの実行とGitHub Actions上の確認は未実施です。Linux/Windows ×
Python 3.12/3.13/3.14の配布インストールCI、およびLinuxの全テストCIを追加しました。
Windowsを含むCIと公開設定の確認前に、公開作業そのものの準備完了とは判断しません。

## 1. 実装と主要ファイル

- `application/expansion.py`: 遅延生成、直積数の事前計算、上限、独立した各位置の
  候補、任意長トークン、重複除去、構文検査。ネットワーク依存なし。
- `application/local_batch.py`, `apps/commands.py`, `apps/local_io.py`:
  複数指定、CSV/TXT、順序維持、JSON/CSV、重複方針、行エラー継続、進捗、
  Ctrl-C、原子的ファイル置換、行番号での新規再実行。既定ではアドレス非出力。
- `settings.py`, `config/budgets.toml`: 閉じたTOMLスキーマ、型・有限値・上限検査、
  `config show`、passive/active予算分離。TLS/認証/宛先設定は変更不可。
- `adapters/dns/cached_resolver.py`, `adapters/memory/dns_cache.py`:
  上限付きDNS再利用、同時要求の集約、残りTTLを返す処理、利用有無の行別記録。
- `adapters/system/rate_limit.py`, `application/smtp_probe.py`:
  MXを共有するドメイン・アカウント間の制限、60秒の一時応答後待機。
  消費済みトークンを追い出しで回復させない処理、キャンセル時の解放。
- `composition.py`, `application/verification.py`: 共通サービスへの接続と
  passive予算の分離、最新の管理者停止状態の参照、単一ワーカープロセス設定。
- `adapters/storage/sqlite_batch_store.py`: SQLiteビルド差に左右されない
  `secure_delete` 指定。WAL・バックアップの完全消去を保証する変更ではありません。
- `tests/fixtures/tls/ca.crt`: Python 3.13以降の厳格X.509検証向けCA keyUsage。
  テスト用の既存公開鍵素材を利用。実装のTLS検証は緩和していません。
- `pyproject.toml`, `__init__.py`, `Dockerfile`, `scripts/check_artifacts.py`,
  `scripts/smoke_distribution.py`, `.github/workflows/{ci,release}.yml`:
  配布・インストール・スキャン・公開準備。
- README、CHANGELOG、STATUS、ADR 0020、日本語利用ガイド、公開手順を更新。

## 2. 既存実装の再利用

AddressVerificationService、BatchLimits、メールアドレスパーサーと正規化/HMAC識別、
AdmissionControl、AbuseGuard、RateLimitSettings、QuotaSettings、分類器、
PublicResultの公開フィールド制限、DNSのTTL/宛先ポリシーを再利用しました。
既存Active BatchServiceは承認済みJobServiceを前提とするため直接CLIには接続せず、
小さな受動専用オーケストレーターを追加しました。Activeの認可、再開、アカウント隔離、
永続化、保持期限、削除フェンスの既存テストを維持しています。

旧仕様の「CLIにbatchという単語がない」「MXの制限がない」という検査は、
新仕様に対応する「Active BatchServiceを公開しない」「共有MXも制限する」検査に更新。
安全上の保証を消すためのテスト削除は行っていません。

## 3. 候補生成と実行例

```bash
emailcheck expand 'm**rc@example.com' --charset lower --dry-run
# candidate_count_upper_bound = 676
emailcheck expand 'm**rc@example.com' --slot '["a","b"]' --slot '["0","1"]'
emailcheck expand 'm*rc@example.com' --candidate a --candidate ab --candidate abc
emailcheck expand 'm*rc@example.com' --candidates-file tokens.txt --output candidates.csv
emailcheck batch candidates.csv --mode passive --output results.csv
```

左から位置を割り当て、右端が最速で変わる決定的順序です。既定上限10,000、
BatchLimitsと共通のハード上限50,000。上限超過は直積を実体化する前に拒否します。
パターン254文字、トークン64文字、各候補集合10,000入力・1MiB。
ファイルはUTF-8の行単位、空行は空文字列、空ファイルは拒否。
`\*` はリテラルの星。ドメインへのワイルドカードは非対応です。
UnicodeドメインはIDNA、Unicodeローカルパートは既存のSMTPUTF8非対応を維持。
重複トークンは先着順に除去し、結合衝突も抑制します。dry-run値はユニーク数の上限で、
全候補の構文は生成時に検証します。候補からActive SMTP列挙する経路はありません。

## 4. 一括処理・設定

```bash
emailcheck check a@example.com b@example.org --output results.json
emailcheck batch input.csv --output results.csv --progress --duplicates skip
emailcheck batch addresses.txt --format txt --start-row 101 --output resumed.json
emailcheck config show --config config/budgets.toml
emailcheck batch input.csv --config config/budgets.toml --output results.csv
```

CSVはemailヘッダー、TXTは1行1アドレス。順序は維持します。重複は既定keep、
skipでは初出行を参照する行を残します。`--start-row` は元の行番号を維持した新しい
受動チェックであり、チェックポイント復旧・出力追記ではありません。
出力にアドレスを含める場合だけ `--include-address` を指定します。
生成CSVは数式様アドレスを拒否し、結果CSVは数式注入を無害化します。

設定セクションはbatch/rate_limit/quota/passive_quotaのみです。既存の既定予算を
維持するため、10,000行でも既定の1,000件/時のAPIキー予算で拒否行が生じ得ます。
例示TOMLはpassive側だけ10,000件に設定します。SMTPの宛先予算は受動チェックでは
消費しません。全体の上限は単一プロセス内であり、複数起動・複数レプリカの共有保証は
ありません。Redis等による原子的共有予算は今回実装していません。

## 5. 配布・検証結果

配布名 `email-address-checker`、バージョン `0.1.0`、import/CLIは `emailcheck`。
Hatchlingが__init__.pyのバージョンを読む単一ソースです。Apache-2.0/SPDX、
Python要件、URL、作者、extras、ライセンスファイル、package dataを整備しました。
2026-10-22のPyPI JSON APIで本名称・marc2825付き候補・旧名は全て404でした。
これは登録の保証ではないため、公開前に再確認が必要です。

- `python -m build`: sdistおよびそのsdistからのwheel生成成功。
- `python -m twine check dist/*`: 両成果物成功。
- wheel/sdist各々をチェックアウト外の新規仮想環境にインストール成功。
- 最終wheelをuv toolとpipxでも一時領域にインストールし、CLIの0.1.0起動を確認。
- 通常依存と `phase6,service` extrasの両構成で `pip check`、CLI/module起動、
  importlib.metadataとのバージョン一致、データセット読込、受動構文チェック、
  オフライン展開のスモークテスト成功。
- 配布物には5種類のデータTOMLが含まれ、wheelにTLS鍵・テスト・例示TOMLは入りません。
  sdistには再現可能なテスト用の公開TLSフィクスチャが含まれます。
- pytest: 各Python版 **4,343成功、0失敗**。3版合計13,029成功。
  元の4,305件に38件の追加ケースを含みます。
- Ruff check/format、mypy（133ソースファイル）、SMTPスキャナー
  （24ファイル・14コマンド）成功。
- Gitleaks: 開始時全23コミットと配布物を検査。既知の公開テスト鍵、固定の
  idempotencyサンプル、変数参照の誤検知に限定した除外後、未処理検出0。
- pip-audit: ランタイムのみ、および開発/追加依存込みの環境とも既知問題0。
  発見したpytest 8.4.2の既知問題はpytest>=9.0.3への更新で解消。

## 6. セキュリティと残作業

外部DNS/SMTPを禁止する既存テストガードを使用しました。実接続する統合テストは
ループバックのみです。本文非送信、禁止コマンド、RCPT総接触1回、TLS、
内部/予約IP拒否、peer照合、アカウント隔離、削除/保持、未知判定の保守性を検証。
今回、外部メールサービスへのSMTP検証、push、PR、Release作成、公開設定変更、
PyPI/TestPyPIアップロードは実行していません。

残作業・未提供事項:

- Windows実機/CI実行、GitHub Actions自体の実行、実PyPIからのインストール。
- GitHub pypi/testpypi Environmentsにrequired reviewers等を設定し、各インデックスの
  Trusted Publisherを登録。公開前にのみPUBLISH_ENABLEDを設定。詳しくは公開手順。
- Gitタグの作成/push、公開承認、公開後チェックは利用者の別途操作。
- 共有ストアによる複数プロセス制御、Activeバッチ公開API、ローカルの永続チェックポイント、
  生成からチェックまでの単一CLIコマンドは未提供。生成イテレーターとpassive_rowsは合成可能。
- disposable/free-mail/providerデータセットはライセンス確認済みデータ未選定で空。
  roleリストは同梱済み。空であることを「該当なし」と表示しません。
- Git履歴には削除済みの開発用資料が存在します。秘密情報のパターンスキャンだけで
  非公開文章の不存在は証明できないため、公開前の人間による履歴確認を残します。
- Active運用は既存の所有/許諾、デプロイ準備、認証、宛先、監査、予算の承認が別途必須。

## 7. Git状態

作業ブランチは `release/0.1.0-preparation`。開始時の変更はゼロでした。
実装コミットは `9fa17c4`（Add bounded passive CLI and prepare 0.1.0 distribution）。
今回の実装のみをローカルコミットにまとめ、pushせずに保持しています。
最終コミットIDとworking tree状態は作業完了メッセージで報告します。
