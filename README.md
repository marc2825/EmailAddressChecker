# emailcheck — Claude Code starter

メール本文を送信せず、メールアドレスの到達可能性を根拠付きで推定する
サービスの、Claude Code向け段階実装リポジトリです。

## 現在地

この配布物は **Phase 0 baseline** です。

- 要件、脅威モデル、状態モデルを固定
- Claude Code用`CLAUDE.md`を追加
- `AGENTS.md`を共通規約として再利用
- Phase 0〜10の実装プロンプトを同梱
- `/implement-phase`と`/review-phase`スキルを追加
- 読取専用レビューサブエージェントを追加
- 危険な直接SMTP操作を止めるフックを追加
- 初期状態では外部DNS・SMTPへ接続しない

## 最初に読む順番

1. `CLAUDE.md`
2. `AGENTS.md`
3. `docs/INDEX.md`
4. `docs/requirements.md`
5. `docs/threat-model.md`
6. `docs/status-model.md`
7. `docs/claude-code-setup.md`

## セットアップ

Python 3.12以上を使用します。

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

初期検証:

```bash
make check
```

## Claude Codeを開始

リポジトリルートで:

```bash
claude
```

最初に:

```text
/context
/status
/doctor
```

その後:

```text
/implement-phase 00
```

Phase実装後は別セッションで:

```text
/review-phase 00
```

Phase 0が通ったら、`01`、`02`の順に進めます。一度に複数Phaseを
実装させないでください。

## 重要な制約

本サービスは、メールボックスの存在、利用中、所有者、最終配送を保証しません。

主要状態:

- `likely_deliverable`
- `invalid`
- `temporary_unknown`
- `unknown`

`disposable`、`role_account`、`free_mail`、
`accept_all_suspected`は別軸の`risk_flags`です。

SMTP実装はメッセージ本文を送るコマンドや状態を持ちません。`VRFY`、
`EXPN`、プロバイダーのアカウント列挙、制限回避のIPローテーションも
実装しません。

## Claude Code用ファイル

```text
CLAUDE.md
CLAUDE.local.md.example
.claude/settings.json
.claude/hooks/pretool_guard.py
.claude/rules/
.claude/skills/implement-phase/
.claude/skills/review-phase/
.claude/agents/
```

詳細は`docs/claude-code-setup.md`を参照してください。
