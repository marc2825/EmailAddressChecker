# 公開後セキュリティ監査・修正記録

監査日は2026-11-14〜15（Asia/Tokyo）です。`main` のコミット `8b0c364` から差分のない状態で始め、GitHubのmainと一致していることを確認しました。この記録は監査の範囲、実測、限界を示すもので、メールボックスの実在、配送の成功、本番運用の承認、秘密情報が一切ないことを証明するものではありません。

## A. 修正内容

| 対象 | 修正 |
| --- | --- |
| リモート検査クライアント（`security/remote_url.py`、`adapters/http/urllib_client.py`、`apps/cli.py`） | 外部へのHTTPを拒否し、HTTPは `127.0.0.1` と `::1` のIPリテラルだけを許可。URLのユーザー情報、制御文字、不正なポート、曖昧なauthorityは通信前に拒否。環境変数のプロキシを無効化し、ジョブIDを有界のパス要素1つに制限。reprからキーとURLを除外。 |
| HTTP応答の処理 | すべてのリダイレクトを拒否し、拒否した応答も明示的にcloseする。別オリジン・同一オリジン・schemeの変更を、実際のurllibの処理を通す回帰テストで確認。 |
| SMTPのTLS（`domain/smtp_tls.py`、`application/smtp_dialogue.py`） | `OPPORTUNISTIC` を削除。STARTTLSが提供されなければ、送信者・受信者コマンドの前に必ず終了する。 |
| SMTPのテスト | 平文のまま受信者へ進んでいたフィクスチャを、明示的な偽TLSに変更。コマンド列、RCPTが1回であること、キャンセル、期限の検証は維持。 |
| テストの補助コード | Python 3.13/3.14で出た未closeの警告を調べ、テストが持つSQLite接続39か所を明示的にcloseするよう修正。本体の保存アダプターはもともとcloseしていた。 |
| 依存関係（`pyproject.toml`、ADR 0006） | dnspythonの最低バージョンを2.9.2に上げ、2.8.0にあった既知の脆弱性2件を解消。 |
| 文書 | 整理の際に失われていたHTTPバインディングの七つの安全条件、ジョブ投入の順序、limiterの上限、primary reasonの不変条件を、実装を確認したうえで `docs/architecture.md` に戻した。非公開の開発文書への参照を公開文書への参照に置き換え、TLSの保証と移行方法をREADME、SECURITY、要件、SMTP仕様、変更履歴、ADR 0021に記載。 |

互換性への影響：外部HTTPはHTTPSに、開発用の `localhost` は正確なループバックIPに移行する必要があります。環境変数のプロキシに頼る構成は、明示的なHTTPSのエンドポイントを用意してください。ライブラリで `TLSPolicy.OPPORTUNISTIC` を使っていた場合は `TLSPolicy.REQUIRED` に変更します。公開のステータス、reason code、risk flag、APIレスポンスの形式は変わっていません。

## B. 監査結果

| 重要度 | 問題・確認内容 | 対応 | 残るリスク |
| --- | --- | --- | --- |
| 高 | 外部HTTPでBearerキーと対象アドレスが平文で送られ得た | URL検証をCLIとクライアントの構築時に適用。HTTPの例外はDNSに頼らない2つのIPリテラルだけ | ローカルのHTTP受信プロセスとホストは信頼する必要がある |
| 高 | ライブラリで平文のSMTPを続行する設定を選べた | `OPPORTUNISTIC` と平文の分岐を削除。compositionはもともとREQUIRED、公開APIはTLSの上書きを拒否していた | TLSを提供しないMXでは結論が出ない |
| 高 | dnspythonの既知の脆弱性 | 2.9.2に更新し、最低バージョンも固定 | 脆弱性の監査は今後も必要 |
| 中 | 既定のopenerが環境変数のプロキシを引き継いでいた | `ProxyHandler({})` で無効化。URLの異常系とreprからのキー露出も修正 | HTTPSの信頼ストアは運用者が管理する |
| 中 | リダイレクトを拒否した応答をcloseしていなかった | 拒否時とHTTPエラー時にclose | OSとPythonのTLS/HTTP実装に依存する |
| 中 | 安全条件の文書が欠けてCIが失敗していた | 文書を復元。テストの削除、基準の緩和、ジョブのスキップはしていない | — |
| 低 | テスト補助コードのSQLite接続が解放されていなかった | トランザクションの外側でclose。警告を抑えず、実際の接続に対する回帰テストで修正 | 本体での接続リークは見つかっていない |
| 確認 | SSRF・DNSリバインディング | DNS候補の検査、承認済みの数値IP、接続直前の再検査、実際のpeerのIPとポートの照合、TLS前後のpeer確認を確認 | OSのルーティング、egress、信頼ストアは運用側の境界 |
| 確認 | SMTP注入・受信者への再送 | 六つのコマンドfactory、状態機械、recipient touch、再試行・再起動・ジョブclaimの試験を実行。DATA、VRFY、EXPNなどは追加していない | 別の要求を繰り返す利用者は認証と予算で抑える |
| 確認 | 認証・所有者の分離・クォータ | 既存の試験を実行 | limiter、クォータ、admin状態はプロセス内に限られ、複数workerをまたぐ保証はない |
| 確認 | 非同期・キャンセル・期限 | SMTPの各段階の期限、接続とリースの解放、キャンセルの伝播を確認 | リモートHTTPは同期スレッドとsocket timeoutで、遅い応答に対する全体の期限やキャンセル時の即時停止は保証しない |
| 確認 | SQLite・削除後の復活 | パラメータ化SQL、busy timeout、atomic claim、同じ書き込みトランザクション内のgeneration fence、部分的な削除失敗を確認 | 複数DBをまたぐトランザクションや、バックアップとWALの物理消去は保証しない |
| 確認 | CSVの数式・ファイルの上書き | 出力の全セルをエスケープ。出力は同じディレクトリの一時ファイルから `os.replace` で置き換え、成功時だけ既存ファイルを置換 | 指定した出力先は意図どおり上書きされる |
| 確認 | 秘密情報・個人データ・配布物 | 全28コミット、到達可能な644のblob、削除済みのenvとcompose、フィクスチャ、公開文書、CIログ、実際のwheelとsdistを確認。Gitleaksの検出なし | 到達できないGitオブジェクトや第三者が過去にダウンロードしたものまでは確認していない |

dnspythonの[CVE-2026-114605](https://github.com/rthalley/dnspython/security/advisories/GHSA-45c3-73f7-pv4m)は、不正なDNSワイヤデータの名前展開でCPUを消費させるもので、このツールのDNS応答の処理に関係します。[CVE-2026-128089](https://github.com/rthalley/dnspython/security/advisories/GHSA-vvf4-9x63-8xvv)はWKSのzone-textパーサーの問題で、このツールはその入力経路を公開していません。後者の小さな境界値の例が2.8.0では失敗し、更新後は成功することを確認しました。

TLSの秘密鍵のフィクスチャは公開されたテスト用の鍵で、本番の資格情報ではありません。

## C. 検証

ローカルでは既存の `.venv`（Python 3.12.3）で、外部接続を禁止するガードを有効にしたまま実行しました。

変更前は4,329件成功・14件失敗で、GitHubの[CI run 43591040505](https://github.com/marc2825/EmailAddressChecker/actions/runs/43591040505)でも同じ14件が失敗していました。原因はarchitecture文書の安全条件の欠落です。元のソースに新しいHTTP/TLSの回帰テストを当てると54件が失敗し、修正後はすべて成功しました。

| コマンド | 結果 |
| --- | --- |
| `python -m pytest` | 4,417件成功。テスト接続の解放の回帰テストを加えたあとは4,418件 |
| `python -m ruff check .`、`python -m ruff format --check .`、`python -m mypy src` | 成功 |
| `python scripts/check_forbidden_smtp.py` | 成功（24ファイル、禁止コマンド14） |
| `python -m build`、`python -m twine check dist/*`、`python scripts/check_artifacts.py` | wheelとsdistの両方で成功 |
| `python scripts/smoke_distribution.py` | 新しい環境へのインストール、メタデータ、CLI、同梱データ、オフライン生成を確認 |
| `python -m pip_audit --skip-editable` | 更新前はdnspythonの2件、更新後は0件 |
| `gitleaks git --log-opts=--all --redact`、展開した配布物への `gitleaks dir` | 検出0件 |

[PR #1](https://github.com/marc2825/EmailAddressChecker/pull/1)のCIは全10ジョブが成功しました。Python 3.12/3.13/3.14のcheckで各4,418件が成功し、ResourceWarningとunraisableの警告は0件、Linux・Windowsの配布ジョブ6件とsecurityジョブ（既知の脆弱性0件、秘密情報の検出0件）も成功しています。ResourceWarningとunraisable exceptionはこのときからテスト失敗として扱います。

修正は `8109d24`、`35dec54`、`b27b736`、`41127cb`、`21e313f` の各コミットで行い、変更したファイルは各コミットで確認できます。

## D. 未解決事項

- ローカルの `check` と `batch` はDNSだけを使い、SMTPの部品を持ちません。候補生成は完全にオフラインです。非対応、曖昧、TLSの失敗はinvalidになりません。
- 使い捨て、フリーメール、プロバイダーのデータは未収録で、役割アドレスのデータだけを収録しています。Active一括処理とaccept-allは内部機能で、公開のCLIやAPIにはつないでいません。
- PyPIのメタデータは2026-11-15の時点でHTTP 404、GitHub Releasesも空でした。名前を今後使えるかどうかは保証されません。
- mainのrulesetで読めた規則は削除禁止とnon-fast-forward禁止だけでした。必須のCIやレビュー、PyPI/TestPyPIの承認者、Trusted Publisher、`PUBLISH_ENABLED`、private vulnerability reporting、運用ネットワーク、送信者identityは所有者が別に確認する必要があります。
- 第三者のMXへのSMTPは実行していません。

## E. 公開の判断

- GitHubでの公開の継続：可。必須チェックとレビューの保護は別に設定してください。
- PyPIへの公開：条件付きで可。上記のCIで確認した版が対象です。公開環境、publisher、承認者を確認する前のアップロードを承認するものではありません。
- Active SMTPの本番サービス：現状では運用を承認できません。同梱のexecutorと予算は開発用でプロセス内に限られ、service-activeはプロセス内のexecutorを拒否します。公開HTTPサーバーも同梱していません。隔離したworker、HTTPバインディングの七つの条件、共有の予算、送信者・egress・運用者の承認の実証が必要です。
