# バックフィルの GitHub Actions 実行 設計書

Date: 2026-07-11
Status: Approved

## 目的

初期構築 (fork 直後・バケット作り直し・災害復旧) 時に、ローカル環境を用意せずに
GitHub Actions 上で EPSS 全履歴のバックフィルを実行できるようにする。
過去の変遷 (2021-04-14〜) を含む完全な lake を Actions だけで構築可能にすることがゴール。

## 前提調査の結論

- ソースの `empiricalsec/epss_scores` はサーバ側で約 2.4 GB。`--depth 1` clone なら
  ubuntu-latest runner のディスク (十数 GB 空き) に収まる。
- ファイル数は約 1900 日分。1 ファイルあたり parse → Parquet → アップロードで数秒と
  すると全体で 1.5〜3 時間程度。ジョブ上限 6 時間以内。
- `backfill_epss` は冪等: 登録済み URL はスキップし、カタログ公開は最後の 1 回のみ。
  途中で失敗してもカタログ未更新のため消費者に影響せず、再実行で回復する
  (アップロード済み Parquet は再アップロードされるが同一キーへの上書きで無害)。

## 設計

### 方式: 独立ワークフロー `backfill.yml` を新設 (採用)

`workflow_dispatch` 専用の新規ワークフロー `.github/workflows/backfill.yml` を追加する。
日次の `publish.yml` には一切手を入れない。

検討した代替案:

- **publish.yml に `mode` 入力を追加**: ファイルは 1 つに保てるが、schedule 実行と
  手動バックフィルが同じジョブ定義に混ざり条件分岐で読みにくくなる。壊してはいけない
  日次パイプライン側に変更が入るため不採用。
- **reusable workflow で共通化**: ワークフロー 2 本・env 5 変数の重複解消には過剰
  (YAGNI) のため不採用。

### backfill.yml の内容

- トリガー: `workflow_dispatch` のみ
- `environment: publish` — 既存の Secrets/Variables をそのまま再利用 (追加設定不要)
- `concurrency: { group: publish, cancel-in-progress: false }` — **publish.yml と同じ
  グループ名を共有**することで、日次 update とバックフィルが同時にカタログを
  差し替える競合を構造的に排除する (後着は待機)
- `timeout-minutes: 360` (既定上限)。冪等なので万一タイムアウトしても再実行で回復
- ステップ:
  1. `actions/checkout` (vlake 本体)
  2. `astral-sh/setup-uv` + `uv sync`
  3. `git clone --depth 1 https://github.com/empiricalsec/epss_scores` を
     `${{ runner.temp }}/epss_scores` へ
  4. `uv run vlake backfill epss --source ${{ runner.temp }}/epss_scores`
  5. `uv run vlake verify` — カタログとストレージの整合検証
     (`--max-age-days` は付けない。鮮度監視は日次 publish 側の責務)
- env ブロック (5 変数) は publish.yml と同一。重複は許容する (上記代替案の判断)

### README 追記

「Build your own lake」セクションに、fork 後は Actions タブから `backfill`
ワークフローを手動実行 (Run workflow) することでローカル環境なしに初期構築できる旨を
1 段落追記する。既存のローカル手順は代替手段として残す。

## エラーハンドリング

- 途中失敗 / タイムアウト: カタログ未公開のまま終了 → 消費者影響なし。再実行で回復。
- 日次 publish との併走: concurrency group 共有により直列化されるため考慮不要。
- ソース repo の clone 失敗: ジョブが素直に失敗するだけでよい (リトライは手動再実行)。

## テスト

- Python コードの変更はないため新規ユニットテストは不要。
- YAML は actionlint (利用可能なら) で静的検証。
- 実挙動の最終確認は本番リポジトリでの `workflow_dispatch` 実行
  (冪等なので既存 lake に対して走らせても安全)。
