# 0.1.0 実装・公開準備レポート

2026-10-22（Asia/Tokyo）時点の記録です。現在の状態は[STATUS.md](../STATUS.md)とCIで確認してください。この時点のmainは `eea2981` で、作業はブランチ `release/0.1.0-preparation` のコミット `9fa17c4` にまとめました。

## 到達点

| 区分 | 当時の状態 |
|---|---|
| 機能実装 | 完了。オフラインの候補生成、受動検査の一括CLI、設定、出力、MXをまたぐ送信先の制御 |
| ローカル検証 | Linux上のPython 3.12/3.13/3.14で、各4,343件のテストがすべて成功 |
| PyPI公開用の準備 | 完了。ビルド、メタデータ、隔離した環境へのインストール、承認付きのworkflow |
| 外部の公開設定 | 未実施。Environment、Trusted Publisher、公開スイッチの設定が必要 |
| PyPI / TestPyPIへの公開 | 未実施 |
| Active SMTPの運用承認 | なし。外部へのSMTP接続もしていない |

WindowsとGitHub Actions上での確認は、この時点では未実施でした。のちのCIで確認しています（[security-audit.md](security-audit.md)）。

## 主な実装

- 候補生成（`application/expansion.py`）：遅延生成、直積数の事前計算と上限、位置ごとの候補、重複除去、構文検査。ネットワークは使わない。
- 受動検査の一括処理（`application/local_batch.py`、`apps/commands.py`、`apps/local_io.py`）：CSV/TXT、入力順の維持、JSON/CSV出力、重複の方針、行単位のエラー継続、進捗、Ctrl-C、ファイルの原子的な置き換え、行番号を指定した新規の再実行。既定ではアドレスを出力しない。
- 設定（`settings.py`、`config/budgets.toml`）：閉じたTOMLスキーマ、型・有限値・上限の検査、`config show`。TLS、認証、宛先の設定は変更できない。
- DNSの再利用（`adapters/dns/cached_resolver.py`）：上限付きのキャッシュ、同時要求の集約、残りTTLの返却。
- 送信先の制限（`adapters/system/rate_limit.py`、`application/smtp_probe.py`）：MXを共有するドメインやアカウントの間での制限、一時応答の後の待機、消費済みのトークンを退避で回復させないこと、キャンセル時の解放。
- 配布（`pyproject.toml`、`scripts/check_artifacts.py`、`scripts/smoke_distribution.py`、`.github/workflows/`）。

Active一括処理（`BatchService`）は承認済みのジョブを前提とするためCLIには接続せず、受動検査専用の小さなオーケストレーターを追加しました。

## 検証結果

- `python -m build` と `python -m twine check dist/*`：成功。
- wheelとsdistを、それぞれリポジトリ外の新しい仮想環境にインストールして成功。uv toolとpipxでもCLIの起動を確認。
- インストールした環境で、`pip check`、CLIとモジュールの起動、バージョンの一致、データセットの読み込み、受動の構文検査、オフライン生成を確認。
- 配布物にはデータのTOML 5種類が入り、wheelにはTLS鍵、テスト、例示のTOMLが入らないことを確認。
- Ruff、mypy（133ファイル）、SMTPスキャナー（24ファイル、禁止コマンド14）：成功。
- Gitleaks：全23コミットと配布物で、公開テスト鍵などの既知の除外を除き検出0件。
- pip-audit：既知の問題0件（pytestは9.0.3以上に更新）。

外部のメールサービスへのSMTP検証、push、PR、Releaseの作成、公開設定の変更、PyPI/TestPyPIへのアップロードは行っていません。

## 当時の残作業

- WindowsとGitHub Actionsでの実行、PyPIからのインストール。
- GitHub EnvironmentsとTrusted Publisherの設定、タグの作成と公開の承認（[公開手順](releasing.md)）。
- 共有ストアによる複数プロセスの制御、Active一括処理の公開API、ローカルの永続チェックポイント。
- 使い捨て、フリーメール、プロバイダーのデータセットは空。役割アドレスのリストは同梱。
- 公開前に、人による履歴の確認。
