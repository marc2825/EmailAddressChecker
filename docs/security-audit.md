# 公開後セキュリティ監査・修正記録

監査日：2026-11-14〜15（Asia/Tokyo）。開始ブランチは `main`、コミットは
`8b0c364d722f3d3bd23f1b15b7159ececbce66e3`。開始時の差分はなく、GitHubの
mainと一致した。再開時に追加されていたREADME両言語の冒頭編集は保持した。
本記録はこの監査の範囲・実測・限界を示し、メールボックスの存在、配送成功、
本番運用の承認、秘密情報の完全な不存在を証明するものではない。

## A. 実施した修正

| 対象 | 修正・根拠・影響 |
| --- | --- |
| `security/remote_url.py`、`adapters/http/urllib_client.py`、`apps/cli.py` | 外部HTTPを拒否。HTTP例外は正確な127.0.0.1/::1リテラルだけ。URLのユーザー情報・制御文字・不正ポート・曖昧なauthorityを通信前に拒否。環境プロキシを明示的に無効化。ジョブIDを単一の有界パス要素に制限し、reprからキーとURLを除外。 |
| HTTP応答処理 | 全リダイレクト拒否を維持し、拒否時の応答も明示的にcloseする。実際のurllib応答処理を通す回帰テストで、別オリジン・同一オリジン・両方向のscheme変更を確認。 |
| `domain/smtp_tls.py`、`application/smtp_dialogue.py` | `OPPORTUNISTIC`を削除。既存のREQUIRED型・設定フィールドを維持し、STARTTLS未提供時は無条件で送信者・受信者コマンドより前に終了。 |
| SMTP関連テスト | 平文で受信者へ進んでいたフィクスチャを明示的な偽TLSに変更。コマンド列・一回のRCPT・キャンセル・期限の検証を維持。cleanup境界の期限テストはRCPT応答直後に偽時計を進め、TLSの読み取り回数に依存しないようにした。 |
| テスト補助コード・テスト方針 | GitHubのPython 3.13/3.14で顕在化した未close警告を調査。7ファイル39箇所の接続を、トランザクション終了後に明示的にcloseする。接続解放とcommit保持を実物のDBで確認する回帰試験を追加。厳格化で検出した子プロセステストのstdout pipeと例外時の競合接続も解放する。本体の保存アダプターは既に明示的にcloseしていた。 |
| `pyproject.toml`、ADR 0006、DNS回帰テスト | dnspython最低版を2.9.2に更新。導入済み2.8.0で検出された既知脆弱性2件を解消。 |
| `docs/architecture.md` | 文書整理で失われた七つのHTTPバインディング安全条件、ジョブ投入順序、limiterのidle/in-flight境界、primary reasonの不変条件を実装確認後に復元。 |
| `docs/`、`src/`、`tests/`の注釈 | 非公開開発文書への参照を、公開要件・状態モデル・脅威モデル・ADR等へ置換。私的文書自体は公開しない。Phase番号を保持。役割データの出所、キーの長さ検証とエントロピーの違い、過去の計測と設定上限の違いも訂正。 |
| README両言語、SECURITY、要件、SMTP仕様、変更履歴、ADR 0021 | 実装と同じTLS保証・移行方法を記載。 |

互換性上の変更：外部HTTPはHTTPSへ、開発用localhostは正確なループバックIPへ
移行する。環境プロキシに依存する構成は明示的なHTTPSエンドポイントを用意する。
ライブラリでの `TLSPolicy.OPPORTUNISTIC` は `TLSPolicy.REQUIRED` に変更する。
公開のステータス・reason code・risk flag・APIレスポンス形式は変更していない。

## B. セキュリティ監査結果

| 重要度 | 問題・確認内容 | 対応・実行経路の根拠 | 残存リスク |
| --- | --- | --- | --- |
| 高 | 外部HTTPでBearerと対象が平文送信可能 | URL検証をCLIとクライアント構築で適用。HTTP例外はDNS不要の二つのIPリテラルだけ | ローカルHTTPの受信プロセスとホストは信頼が必要 |
| 高 | ライブラリで平文SMTP継続が選択可能 | OPPORTUNISTICと分岐を削除。compositionはもともとREQUIRED、公開APIはTLS上書きフィールドを拒否していた。TLS未提供・証明書・名前・期限・ハンドシェイク失敗は非対象エラー | TLSを提供しないMXでは結論を得られない |
| 高 | dnspython既知脆弱性 | 2.9.2へ更新し最低版も固定。下記の上流情報・回帰試験を確認 | 今後の脆弱性監査は継続して必要 |
| 中 | デフォルトopenerが環境プロキシを継承 | `ProxyHandler({})`で無効化。URL異常系とreprのキー露出も修正 | HTTPSの通常のシステム信頼ストアは運用者の管理対象 |
| 中 | リダイレクト拒否応答のcloseが明示されていない | 拒否・HTTPエラー時にclose。応答処理を通す試験で確認 | OS・PythonのTLS/HTTP実装に依存 |
| 中 | CIが安全条件の文書欠落で失敗 | 文書を復元。テスト削除・基準緩和・ジョブスキップなしで、承認後のGitHub CI全10ジョブ成功 | mainへのマージ・パッケージ公開は別の承認対象 |
| 低 | テスト補助コードのSQLite接続未解放 | transaction contextを保持し、その外側でclose。CIログの警告を抑制せず、実物の接続に対する回帰試験で修正 | 本体での接続リークは確認されていない |
| 確認 | SSRF・DNSリバインディング | DNS候補検査→承認済み数値IP→接続直前再検査→実peerのIP/port照合。TLS前後にもpeerを確認。CNAMEと特殊IPv4埋込IPv6の試験を維持 | OSルーティング、egress、信頼ストアは別の運用境界 |
| 確認 | SMTP注入・受信者再送 | 六つのコマンドfactory、状態機械、recipient touch、再試行・再起動・ジョブclaimの試験を実行。DATA/VRFY/EXPN等を追加していない | 別の高水準要求を繰り返す利用者は認証・予算で抑制する必要 |
| 確認 | 認証・所有者分離・クォータ | API認証、所有者付き検索、全verifier比較、共有limiter、予算拒否、kill switch、アカウント分離の既存試験を実行 | limiter/クォータ/admin状態はプロセス内。複数workerでの全体保証はない |
| 確認 | 非同期・キャンセル・期限 | SMTP各stageの有界await、接続解放、リース解放、キャンセル伝播を既存試験で確認 | リモートHTTPのurllibはblocking threadとsocket timeout。遅い継続応答に対する接続全体の厳密な期限や、キャンセル時の即時thread停止は保証しない |
| 確認 | SQLite・削除後の復活 | パラメータ化SQL、明示的busy timeout、atomic claim、同一DBのwrite transaction内generation fence、authority binding、部分削除失敗を試験 | 複数DBの一括transactionやバックアップ・WALの物理消去は保証しない |
| 確認 | CSV数式・任意ファイル上書き | `csv_cell`が全出力セルをescape。出力は同じディレクトリのprivate一時ファイルから`os.replace`。既存ファイルは成功時だけ置換し、最終パスのsymlinkはリンク自体を置換する | 指定出力先の既存ファイルは意図どおり上書きされる。親ディレクトリとローカル利用者を信頼する |
| 確認 | 秘密情報・個人データ・配布 | 全28コミット、到達可能な644 blob版、削除済みenv/compose、fixture、公開文書、CI失敗ログ、実際のwheel/sdistを確認。Gitleaks検出なし | 合成テスト文字列と実在し得るアドレスの区別には文脈が必要。全外部CIログ・過去の第三者download・到達不能Git objectまでは網羅していない |

dnspythonの
[CVE-2026-114605](https://github.com/rthalley/dnspython/security/advisories/GHSA-45c3-73f7-pv4m)
は不正DNS wireデータの名前展開CPU負荷で、このcheckerのDNS応答経路に関わる。
[CVE-2026-128089](https://github.com/rthalley/dnspython/security/advisories/GHSA-vvf4-9x63-8xvv)
はWKS zone-text parserで、checkerはその入力経路を公開していない。
後者の小さな境界値例が2.8.0では失敗し、更新後に成功することも確認した。

TLS秘密鍵fixtureは文書化された公開テスト鍵であり、本番資格情報とは分類しない。
削除済み環境設定は開発用・置換用の値で、到達可能履歴に非公開開発文書のパスや
開発者ホームディレクトリのパスは検出されなかった。通常ログの全文アドレス・例外・
キー非露出は既存privacy corpusと新しいCLI/HTTPテストで確認した。

## C. 検証記録

環境は既存 `.venv` のPython 3.12.3。ログインPATHにbare `python` がなかったため
有効化して実行した。制限環境ではsocket作成が拒否されるため、pytestは既存の
外部接続禁止ガードを維持したままsocket利用可能な実行環境で行った。

変更前の全テストは **4,329成功・14失敗**。GitHubの
[CI run 43591040505](https://github.com/marc2825/EmailAddressChecker/actions/runs/43591040505)
もPython 3.12/3.13/3.14で同じ14件が失敗。6つの配布ジョブとsecurityジョブは成功していた。
失敗原因はarchitecture文書の安全条件欠落で、workflow自体の故障ではない。

元コミットのソースに新しいHTTP/TLS回帰試験の同期部分を適用すると、
**54失敗・8成功・7除外**となった。外部接続は行わず、許可すべき既存の正常系も含めた
対照試験である。DNS更新前にはWKS境界値回帰試験の失敗も確認した。

| コマンド | 結果 |
| --- | --- |
| `python -m pytest` | 成功、4,417件（52.96秒）。新規2ファイルの回帰試験は75件成功 |
| `python -m ruff check .` | 成功 |
| `python -m ruff format --check .` | 成功、318ファイル整形済み。`python -m ruff format .`も実施 |
| `python -m mypy src` | 成功、133 source files |
| `python scripts/check_forbidden_smtp.py` | 成功、24ファイル・禁止14コマンド |
| `python -m build` | wheel/sdistの隔離build成功 |
| `python -m twine check dist/*` | 両成果物成功 |
| `python scripts/check_artifacts.py` | 両成果物成功。展開内容も確認 |
| `python scripts/smoke_distribution.py` | wheel/sdistを別々の新規環境へinstallし、metadata・CLI/module・同梱データ・構文拒否・offline生成を確認 |
| `python -m pip_audit --skip-editable` | 更新前はdnspythonの2件を検出。更新後は既知脆弱性0件。ローカルeditable自身は指定どおり対象外 |
| `gitleaks git --log-opts=--all --redact` | 既存の全28コミットで検出0件。最終コミット後にも実行 |
| `gitleaks dir /tmp/emailcheck-artifacts --config .gitleaks.toml --redact` | 展開した両配布物で検出0件 |
| `python -m pip check` / `git diff --check` / `python -m emailcheck --version` | 成功、依存関係矛盾なし・空白エラーなし・version 0.1.0 |

GitleaksはPATHに未導入だったため、CIと同じ8.30.1を一時領域へ取得し、
CIに固定されたSHA-256を照合して実行した。新規runtime依存は追加していない。
pytest-asyncioはfixture loop scope未指定の非推奨警告を出すが、テスト失敗はない。

### 承認後のGitHub CI検証（2026-11-15）

利用者の明示的な許可後に修正ブランチをpushし、[PR #1](https://github.com/marc2825/EmailAddressChecker/pull/1)
を作成した。[CI run 43685471480](https://github.com/marc2825/EmailAddressChecker/actions/runs/43685471480)
は実装修正コミット `b27b736` で全10ジョブ成功。mainの旧失敗runを再実行した結果ではない。

| GitHubジョブ | 結果 |
| --- | --- |
| check / Python 3.12、3.13、3.14 | 各4,417件成功。Lint・整形・型検査・SMTP禁止検査も成功 |
| distribution / Linux・Windows × Python 3.12、3.13、3.14 | 全6ジョブ成功。両配布形式のbuild・metadata・内容・独立installを確認 |
| security | 成功。pip-auditは既知脆弱性0件、31コミットと展開配布物のGitleaks検出0件 |

このrunの3.13/3.14では各108件のSQLite ResourceWarningが出た。未解放を
回帰試験で再現後、テスト所有の接続を明示的にcloseするよう修正した。productionの
各SQLiteアダプターは既に `closing(connection), connection` で解放していた。
pytest設定でもResourceWarningとunraisable exceptionを失敗扱いにし、将来の
接続未解放が成功したCIの警告だけに埋もれないようにした。
この設定で子プロセス異常終了テストのstdout未closeも再現したため、Popenの
context managerと例外時にも接続を閉じる処理を使い、pipeのcloseを明示的に検証した。
追記と補助コード修正を含む最新コミットの状態は[PRのChecks](https://github.com/marc2825/EmailAddressChecker/pull/1/checks)
で確認する。ローカルの上表は初回実装検証の記録であり、接続解放回帰試験1件の追加後は
4,418件成功（27.08秒）。接続解放の回帰は修正前に失敗し、修正後に成功した。

## D. 未解決事項と公開機能の確認

通常のローカルcheck/batchはDNSのみでSMTPを構成せず、候補生成は完全オフライン。
unsupported/曖昧/TLS失敗はメールボックスinvalidへ昇格しない。使い捨て・free-mail・
providerデータは未収録で、roleデータだけを収録する。Active batch/accept-allは内部機能で、
通常の公開CLI/APIへ新たに接続していない。ローカルbatchは上限・重複方針・順序を持ち、
永続resumeはない。パッケージ配布名は `email-address-checker`、CLI/import名は `emailcheck`。
Apache-2.0と同梱roleデータの出所を確認し、第三者データを追加していない。

PyPI公開メタデータは2026-11-15の照会でHTTP 404、GitHub Releasesも空だった。
未公開という説明と整合するが、名前の将来の予約・利用可能性は保証しない。

GitHub mainのrulesetは有効だが、読めた規則は削除禁止とnon-fast-forward禁止だけで、
必須CI・レビュー要件は確認できなかった。PyPI/TestPyPI Environmentsの承認者、
Trusted Publisher、`PUBLISH_ENABLED`実値、private vulnerability reporting、
実運用ネットワークと送信者identityは別途所有者の確認が必要。
release workflowの条件付き公開・一致version tag・検証済み同一run成果物・OIDC境界は維持した。

ローカル実行はPython 3.12/Linux。修正後の3.13/3.14とWindows配布も、上記の
GitHub CIマトリクスで成功を確認した。第三者MXへのSMTPは実行していない。
古いPhaseのテスト数・計測は現在の実測として再利用していない。

## E. 公開可否

- **GitHub公開継続：可。** 修正済みソースとして公開を継続できる。
  修正ブランチのCI成功を確認した。必須チェック・レビュー保護は別途設定すること。
- **PyPI公開：条件付き可。** パッケージ検証と独立installが通り、後述の最終結果を
  確認した版が対象。全マトリクス成功と公開環境・publisher・承認者の確認前に
  アップロードを承認したという意味ではない。
- **Active SMTP本番サービス：現状では運用承認不可。** TLSのコード境界は修正したが、
  shipped executor/予算は開発用・プロセス内で、service-activeはin-process executorを拒否する。
  公開HTTP serverも同梱していない。隔離worker、transport bindingの七条件、
  必要な共有予算、送信者・egress・運用者承認の実証が必要。

## F. Git管理と次の作業

差分をレビューし、`fix/post-publication-security-audit` ブランチで関連単位の
コミットを作成した。2026-11-15に利用者がブランチpush・PR作成・CI検証を
明示的に許可し、その範囲を実施した。README冒頭の利用者編集は未コミットで保持。
mainへのマージ・tag・Release・PyPI upload・履歴書換えは行っていない。
次のPhaseはPRのレビューと公開環境の確認、許可された運用環境でのreadiness gateであり、
この監査では実装・実施しない。


## 変更ファイル一覧

<details>
<summary>監査で変更したファイル（README冒頭の利用者編集はコミット対象外）</summary>

- [CHANGELOG.md](../CHANGELOG.md)
- [CONTRIBUTING.md](../CONTRIBUTING.md)
- [README.ja.md](../README.ja.md)
- [README.md](../README.md)
- [SECURITY.md](../SECURITY.md)
- [docs/INDEX.md](../docs/INDEX.md)
- [docs/adr/0006-dnspython-resolver-and-destination-policy.md](../docs/adr/0006-dnspython-resolver-and-destination-policy.md)
- [docs/adr/0007-passive-classification-and-datasets.md](../docs/adr/0007-passive-classification-and-datasets.md)
- [docs/adr/0008-smtp-safety-gate.md](../docs/adr/0008-smtp-safety-gate.md)
- [docs/adr/0009-smtp-dialogue-and-tls.md](../docs/adr/0009-smtp-dialogue-and-tls.md)
- [docs/adr/0010-smtp-recipient-evidence-mapping.md](../docs/adr/0010-smtp-recipient-evidence-mapping.md)
- [docs/adr/0011-verification-orchestration-and-rate-limiting.md](../docs/adr/0011-verification-orchestration-and-rate-limiting.md)
- [docs/adr/0012-evidence-aggregation-and-final-status.md](../docs/adr/0012-evidence-aggregation-and-final-status.md)
- [docs/adr/0013-production-composition-and-the-public-boundary.md](../docs/adr/0013-production-composition-and-the-public-boundary.md)
- [docs/adr/0014-bounded-asynchronous-active-jobs.md](../docs/adr/0014-bounded-asynchronous-active-jobs.md)
- [docs/adr/0015-verdict-cache-and-ttl.md](../docs/adr/0015-verdict-cache-and-ttl.md)
- [docs/adr/0016-abuse-controls-privacy-and-observability.md](../docs/adr/0016-abuse-controls-privacy-and-observability.md)
- [docs/adr/0017-accept-all-control-experiment.md](../docs/adr/0017-accept-all-control-experiment.md)
- [docs/adr/0018-controlled-batch-execution.md](../docs/adr/0018-controlled-batch-execution.md)
- [docs/adr/0019-operation-recipient-budget-and-atomic-job-identity.md](../docs/adr/0019-operation-recipient-budget-and-atomic-job-identity.md)
- [docs/adr/0021-required-encryption-at-network-boundaries.md](../docs/adr/0021-required-encryption-at-network-boundaries.md)
- [docs/architecture.md](../docs/architecture.md)
- [docs/beta-report-template.md](../docs/beta-report-template.md)
- [docs/readiness-checklist.md](../docs/readiness-checklist.md)
- [docs/requirements.md](../docs/requirements.md)
- [docs/runbooks/README.md](../docs/runbooks/README.md)
- [docs/runbooks/false-invalid-investigation.md](../docs/runbooks/false-invalid-investigation.md)
- [docs/runbooks/privacy-deletion.md](../docs/runbooks/privacy-deletion.md)
- [docs/runbooks/sender-identity-incident.md](../docs/runbooks/sender-identity-incident.md)
- [docs/security-audit.md](../docs/security-audit.md)
- [docs/smtp-state-machine.md](../docs/smtp-state-machine.md)
- [docs/status-model.md](../docs/status-model.md)
- [docs/test-strategy.md](../docs/test-strategy.md)
- [docs/threat-model.md](../docs/threat-model.md)
- [docs/usage-ja.md](../docs/usage-ja.md)
- [pyproject.toml](../pyproject.toml)
- [src/emailcheck/adapters/auth/api_keys.py](../src/emailcheck/adapters/auth/api_keys.py)
- [src/emailcheck/adapters/execution/memory_executor.py](../src/emailcheck/adapters/execution/memory_executor.py)
- [src/emailcheck/adapters/http/urllib_client.py](../src/emailcheck/adapters/http/urllib_client.py)
- [src/emailcheck/adapters/observability/metrics.py](../src/emailcheck/adapters/observability/metrics.py)
- [src/emailcheck/adapters/smtp/asyncio_transport.py](../src/emailcheck/adapters/smtp/asyncio_transport.py)
- [src/emailcheck/adapters/storage/sqlite_batch_store.py](../src/emailcheck/adapters/storage/sqlite_batch_store.py)
- [src/emailcheck/adapters/storage/sqlite_job_store.py](../src/emailcheck/adapters/storage/sqlite_job_store.py)
- [src/emailcheck/adapters/storage/sqlite_store.py](../src/emailcheck/adapters/storage/sqlite_store.py)
- [src/emailcheck/application/abuse.py](../src/emailcheck/application/abuse.py)
- [src/emailcheck/application/accept_all.py](../src/emailcheck/application/accept_all.py)
- [src/emailcheck/application/admin.py](../src/emailcheck/application/admin.py)
- [src/emailcheck/application/admission.py](../src/emailcheck/application/admission.py)
- [src/emailcheck/application/aggregate.py](../src/emailcheck/application/aggregate.py)
- [src/emailcheck/application/batch.py](../src/emailcheck/application/batch.py)
- [src/emailcheck/application/batch_csv.py](../src/emailcheck/application/batch_csv.py)
- [src/emailcheck/application/beta.py](../src/emailcheck/application/beta.py)
- [src/emailcheck/application/jobs.py](../src/emailcheck/application/jobs.py)
- [src/emailcheck/application/public_job.py](../src/emailcheck/application/public_job.py)
- [src/emailcheck/application/readiness.py](../src/emailcheck/application/readiness.py)
- [src/emailcheck/application/retention.py](../src/emailcheck/application/retention.py)
- [src/emailcheck/application/smtp_dialogue.py](../src/emailcheck/application/smtp_dialogue.py)
- [src/emailcheck/application/smtp_evidence.py](../src/emailcheck/application/smtp_evidence.py)
- [src/emailcheck/application/smtp_probe.py](../src/emailcheck/application/smtp_probe.py)
- [src/emailcheck/application/smtp_verification.py](../src/emailcheck/application/smtp_verification.py)
- [src/emailcheck/application/verdict_cache.py](../src/emailcheck/application/verdict_cache.py)
- [src/emailcheck/application/verification.py](../src/emailcheck/application/verification.py)
- [src/emailcheck/apps/api.py](../src/emailcheck/apps/api.py)
- [src/emailcheck/apps/cli.py](../src/emailcheck/apps/cli.py)
- [src/emailcheck/apps/schema.py](../src/emailcheck/apps/schema.py)
- [src/emailcheck/composition.py](../src/emailcheck/composition.py)
- [src/emailcheck/data/passive/README.md](../src/emailcheck/data/passive/README.md)
- [src/emailcheck/domain/abuse.py](../src/emailcheck/domain/abuse.py)
- [src/emailcheck/domain/accept_all.py](../src/emailcheck/domain/accept_all.py)
- [src/emailcheck/domain/admin.py](../src/emailcheck/domain/admin.py)
- [src/emailcheck/domain/batch.py](../src/emailcheck/domain/batch.py)
- [src/emailcheck/domain/beta.py](../src/emailcheck/domain/beta.py)
- [src/emailcheck/domain/evidence.py](../src/emailcheck/domain/evidence.py)
- [src/emailcheck/domain/indicators.py](../src/emailcheck/domain/indicators.py)
- [src/emailcheck/domain/job.py](../src/emailcheck/domain/job.py)
- [src/emailcheck/domain/principal.py](../src/emailcheck/domain/principal.py)
- [src/emailcheck/domain/readiness.py](../src/emailcheck/domain/readiness.py)
- [src/emailcheck/domain/smtp_tls.py](../src/emailcheck/domain/smtp_tls.py)
- [src/emailcheck/domain/source.py](../src/emailcheck/domain/source.py)
- [src/emailcheck/domain/verdict.py](../src/emailcheck/domain/verdict.py)
- [src/emailcheck/ports/accept_all_cache.py](../src/emailcheck/ports/accept_all_cache.py)
- [src/emailcheck/ports/batch_store.py](../src/emailcheck/ports/batch_store.py)
- [src/emailcheck/ports/job_executor.py](../src/emailcheck/ports/job_executor.py)
- [src/emailcheck/ports/job_store.py](../src/emailcheck/ports/job_store.py)
- [src/emailcheck/ports/metrics.py](../src/emailcheck/ports/metrics.py)
- [src/emailcheck/ports/quota.py](../src/emailcheck/ports/quota.py)
- [src/emailcheck/ports/smtp_sender_identity.py](../src/emailcheck/ports/smtp_sender_identity.py)
- [src/emailcheck/security/remote_url.py](../src/emailcheck/security/remote_url.py)
- [tests/batch_fixtures.py](../tests/batch_fixtures.py)
- [tests/integration/test_load_loopback.py](../tests/integration/test_load_loopback.py)
- [tests/phase6_fixtures.py](../tests/phase6_fixtures.py)
- [tests/phase7_fixtures.py](../tests/phase7_fixtures.py)
- [tests/test_docs_phase8_contracts.py](../tests/test_docs_phase8_contracts.py)
- [tests/test_docs_smtp_contracts.py](../tests/test_docs_smtp_contracts.py)
- [tests/test_phase6_inspection.py](../tests/test_phase6_inspection.py)
- [tests/test_phase7_inspection.py](../tests/test_phase7_inspection.py)
- [tests/test_privacy_corpus.py](../tests/test_privacy_corpus.py)
- [tests/unit/adapters/test_dns_dependency_security.py](../tests/unit/adapters/test_dns_dependency_security.py)
- [tests/unit/adapters/test_memory_executor.py](../tests/unit/adapters/test_memory_executor.py)
- [tests/unit/adapters/test_phase6_adapters.py](../tests/unit/adapters/test_phase6_adapters.py)
- [tests/unit/adapters/test_tls_context.py](../tests/unit/adapters/test_tls_context.py)
- [tests/unit/application/test_abuse_budgets.py](../tests/unit/application/test_abuse_budgets.py)
- [tests/unit/application/test_accept_all_experiment.py](../tests/unit/application/test_accept_all_experiment.py)
- [tests/unit/application/test_admin_controls.py](../tests/unit/application/test_admin_controls.py)
- [tests/unit/application/test_aggregation.py](../tests/unit/application/test_aggregation.py)
- [tests/unit/application/test_batch.py](../tests/unit/application/test_batch.py)
- [tests/unit/application/test_batch_process_restart.py](../tests/unit/application/test_batch_process_restart.py)
- [tests/unit/application/test_batch_resume.py](../tests/unit/application/test_batch_resume.py)
- [tests/unit/application/test_beta_harness.py](../tests/unit/application/test_beta_harness.py)
- [tests/unit/application/test_jobs.py](../tests/unit/application/test_jobs.py)
- [tests/unit/application/test_load_scripted_server.py](../tests/unit/application/test_load_scripted_server.py)
- [tests/unit/application/test_operation_recipient_budget.py](../tests/unit/application/test_operation_recipient_budget.py)
- [tests/unit/application/test_passive_survives_active_failures.py](../tests/unit/application/test_passive_survives_active_failures.py)
- [tests/unit/application/test_retention.py](../tests/unit/application/test_retention.py)
- [tests/unit/application/test_smtp_dialogue.py](../tests/unit/application/test_smtp_dialogue.py)
- [tests/unit/application/test_smtp_probe.py](../tests/unit/application/test_smtp_probe.py)
- [tests/unit/application/test_smtp_verification.py](../tests/unit/application/test_smtp_verification.py)
- [tests/unit/application/test_smtp_verification_planning.py](../tests/unit/application/test_smtp_verification_planning.py)
- [tests/unit/apps/test_api_and_cli.py](../tests/unit/apps/test_api_and_cli.py)
- [tests/unit/apps/test_cli_readiness.py](../tests/unit/apps/test_cli_readiness.py)
- [tests/unit/apps/test_remote_and_schema.py](../tests/unit/apps/test_remote_and_schema.py)
- [tests/unit/apps/test_remote_transport_security.py](../tests/unit/apps/test_remote_transport_security.py)
- [tests/unit/domain/test_address_parsing.py](../tests/unit/domain/test_address_parsing.py)
- [tests/unit/domain/test_indicators.py](../tests/unit/domain/test_indicators.py)
- [tests/unit/domain/test_job.py](../tests/unit/domain/test_job.py)
- [tests/unit/domain/test_source_identity.py](../tests/unit/domain/test_source_identity.py)
- [tests/unit/domain/test_verdict_values.py](../tests/unit/domain/test_verdict_values.py)
- [tests/unit/test_accept_all_isolation.py](../tests/unit/test_accept_all_isolation.py)
- [tests/unit/test_batch_isolation.py](../tests/unit/test_batch_isolation.py)
- [tests/unit/test_composition.py](../tests/unit/test_composition.py)
- [tests/unit/test_failure_injection.py](../tests/unit/test_failure_injection.py)
- [tests/unit/test_metrics_cardinality.py](../tests/unit/test_metrics_cardinality.py)
- [tests/unit/test_phase7_composition.py](../tests/unit/test_phase7_composition.py)
- [tests/unit/test_readiness_reporting.py](../tests/unit/test_readiness_reporting.py)
- [tests/unit/test_remediation_d.py](../tests/unit/test_remediation_d.py)

</details>
