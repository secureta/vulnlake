---
name: lint-sast-gate
description: >-
  Use before committing or finishing changes in this repository to ensure coding
  agents run the required lint and SAST checks.
---

# lint / SAST gate

このリポジトリでコード・設定・ドキュメントを変更したら、完了報告や commit の前に
lint と SAST を必ず実行する。コメント・コミットメッセージは日本語。

## 必須コマンド

通常は mise task 経由で実行する:

```bash
mise run lint
mise run sast
```

commit 前 gate をまとめて実行する場合:

```bash
mise run pre-commit
```

この Skill は hook 生成を要求しない。人間の commit を重くしないため、
`.git/hooks/pre-commit` の生成タスクは用意しない。

## チェック内容

- `mise run lint`
  - `uv run ruff check --select E4,E7,E9,F,I,B,UP .`
  - `uv run ruff format --check .`
  - `actionlint` (引数なし。`actionlint .github/workflows/` はディレクトリ指定不可で失敗する)
- `mise run sast`
  - `uv run ruff check --select S .`
  - `uv run zizmor --no-progress .github/workflows/`

## 失敗時

1. 失敗したコマンドと出力を確認する。
2. 原因を修正する。
3. 同じコマンドを再実行し、成功を確認する。
4. 成功していない状態で「完了」「通った」と報告しない。

## 完了条件

- `mise run lint` が成功する。
- `mise run sast` が成功する。
- commit する場合は `mise run pre-commit` を実行済み。
