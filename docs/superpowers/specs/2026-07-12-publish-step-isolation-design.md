# publish.yml ステップ独立化 設計

日付: 2026-07-12

## 背景と目的

publish.yml は 7 データセット (epss / cve / ghsa / exploitdb / nuclei / cwe / kev) の
`update` を単一ジョブで直列実行している。現状は 1 ステップの失敗で後続ステップと
verify がすべてスキップされるため、例えば exploitdb の上流障害だけで nuclei / cwe /
kev のその日の更新まで止まる。

本変更は「1 データセットの失敗が他のデータセットの更新を止めない」ことを目的とする。
実行頻度 (日次 14:30 UTC) は変えない。即時性向上は目的外。

## 制約 (変えないこと)

- **カタログ書き込みの直列性**: 各 `update_*` は「カタログ取得 → 追記 → 差し替え」を
  行うため、並列実行すると後勝ちで登録が失われる。ステップは単一ジョブ内の直列実行の
  まま維持する (matrix 分割や並列化はしない)。
- **公開順序の不変条件**: pipeline 側の「Parquet 先行アップロード → カタログ最後」は
  ワークフロー変更の影響を受けない。失敗したデータセットはカタログ未更新のまま残り、
  翌日の実行で冪等に回復する — これは現状と同じ挙動。
- 実行スケジュール、Environment (`publish`)、concurrency group、permissions は不変。

## 変更内容 (.github/workflows/publish.yml のみ)

1. 各 `update` ステップに `id: <dataset>` と `continue-on-error: true` を付与する
   (7 ステップ)。失敗しても後続ステップは実行され、outcome だけが記録される。
2. `verify --max-age-days 3` は `continue-on-error` を付けない。verify 失敗は
   ジョブ失敗に直結してよく、update が失敗し続けた場合の最終防衛線として機能する。
3. 末尾に失敗集計ステップを追加する。いずれかの update ステップが失敗していたら
   失敗したデータセット名を列挙してジョブを fail させ、通知・実行履歴上は
   今まで通り赤にする:

   ```yaml
   - name: check update failures
     if: contains(steps.*.outcome, 'failure')
     env:
       STEPS: ${{ toJSON(steps) }}
     run: |
       echo "failed datasets:"
       echo "$STEPS" | jq -r 'to_entries[] | select(.value.outcome == "failure") | "  - " + .key'
       exit 1
   ```

   `${{ }}` を run 本文に直接展開せず env 経由で渡すのは、zizmor の
   テンプレートインジェクション検出 (CI で実行される) を避けるため。
4. 付随整理: 7 ステップに重複している S3 認証情報の env ブロック
   (`VLAKE_S3_ENDPOINT` / `VLAKE_S3_BUCKET` / `VLAKE_PUBLIC_URL` /
   `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_DEFAULT_REGION`) を
   ジョブレベル `env:` に引き上げる。cve ステップだけが使う `GITHUB_TOKEN`
   (Releases API のレート制限回避) はステップ側に残す。

## 検証

- `uv run zizmor .github/workflows/` と `actionlint` をローカルで実行して通す。
- マージ後の定期実行または `workflow_dispatch` で、全ステップが実行されることを確認する。
