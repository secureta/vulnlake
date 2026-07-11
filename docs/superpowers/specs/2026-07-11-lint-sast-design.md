# Lint / SAST 導入 設計

日付: 2026-07-11
ステータス: 承認済み

## 目的

vlake に lint と SAST を導入し、CI で自動チェックする。GitHub の CodeQL default setup は有効化済みであり、これを補完する構成とする。

## カバレッジ

| 対象 | Lint | SAST |
|------|------|------|
| Python | Ruff | Ruff S ルール + CodeQL |
| GitHub Actions | actionlint | zizmor + CodeQL (actions クエリ) |

## Python: Ruff

- `pyproject.toml` に `[tool.ruff]` 設定を追加する
- lint ルール: `E4`, `E7`, `E9`, `F`(デフォルト)に加えて
  - `I` — import 整列 (isort 相当)
  - `B` — flake8-bugbear
  - `UP` — pyupgrade(古い構文の検出)
  - `S` — flake8-bandit 相当の SAST
- `tests/` は `S101`(assert 使用)を per-file-ignores で除外する。pytest では assert が正当なため
- `ruff format` をフォーマッタとして採用する
- `ruff` は dev dependency group に追加する。バージョンはレジストリで最新安定版を確認して指定する
- 既存コードの違反は `ruff format` + `ruff check --fix` で修正し、自動修正できないものは手で直す。妥当な理由があり修正が不適切な箇所のみ、理由コメント付きで `noqa` を許可する

## GitHub Actions: actionlint + zizmor

- **actionlint** — ワークフローの lint。構文エラー、`needs`/`matrix` の参照ミス、式の型チェック、`run:` ブロックの shellcheck を検査する
- **zizmor** — ワークフローの SAST。権限過剰、テンプレートインジェクション、信頼できない checkout 等を検査する。dev dependency group に追加して `uv run zizmor` で実行する(renovate が uv.lock 経由でバージョン追従できるため)
- 既存ワークフロー(test.yml / publish.yml / backfill.yml)への指摘はこの作業内で修正する

## CI 構成

- `test.yml` に `lint` ジョブを追加し、既存の `test` ジョブと並列実行する
- `lint` ジョブのステップ:
  1. `uv run ruff check .`
  2. `uv run ruff format --check .`
  3. actionlint の実行(公式の download script でバージョンを固定して取得)
  4. `uv run zizmor .github/workflows/`
- `permissions: contents: read` を維持する

## やらないこと

- pre-commit フック
- 型チェック (mypy / pyright)
- CodeQL のワークフローファイル化(default setup のままとする)
- Semgrep / Bandit 単体の導入(Ruff S ルールで代替)

## 成功基準

- CI の `lint` ジョブが green
- 既存の 34 テストが引き続き pass
- zizmor / actionlint が既存ワークフローに対して指摘ゼロ(または妥当な理由付きで抑制)
