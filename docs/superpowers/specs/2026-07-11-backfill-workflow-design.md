# バックフィルの GitHub Actions 実行 + 年単位コンパクション 設計書

Date: 2026-07-11
Status: Approved

## 目的

初期構築 (fork 直後・バケット作り直し・災害復旧) 時に、ローカル環境を用意せずに
GitHub Actions 上で EPSS 全履歴のバックフィルを実行できるようにする。
主用途は「1つの CVE の過去の変遷を見る」全期間クエリであるため、バックフィルが
書くレイアウトを年単位コンパクション方式に変更し、このクエリを高速化する。

## 前提調査の結論

- ソースの `empiricalsec/epss_scores` はサーバ側で約 2.4 GB。`--depth 1` clone なら
  ubuntu-latest runner のディスク (十数 GB 空き) に収まる。
- 日次 Parquet は 1 ファイル約 2.5 MB (2026 年実測)。全履歴約 1900 日で合計 3 GB 前後。
- 公開レイクには 2021 年のファイルがまだ存在しない (HTTP 404 確認済み)。
  これから走らせるバックフィルが過去年レイアウトを決める初回である。
- 日次 1900 ファイルのままだと、CVE 指定の全期間クエリは HTTPS 越しに全ファイルの
  フッタ取得が必要 (数千リクエスト)。単一巨大ファイルは読み取り最速だが、日次更新の
  たびに全体を書き直すことになり「Parquet 追記 + カタログ差し替え」のアトミック公開
  設計と根本的に相性が悪い。年単位コンパクションはその中間で、日次パイプラインを
  無変更に保ったまま全期間クエリが触るファイル数を 1900 → 約 6 + 当年分に減らす。

## 設計

### レイアウト

- 確定した過去年 (実行時点の年より前): 年 1 ファイル
  `epss/year=2021/epss-2021.parquet`。`year=` のパス構造は維持するため
  `read_parquet('https://.../epss/year=2021/*.parquet')` は従来どおり動く。
- 進行中の年: 現状どおり日次 `epss/year=2026/epss-YYYY-MM-DD.parquet`。
  日次 update パイプライン (`update_epss`) は一切変更しない。
- 年ファイル内は `ORDER BY cve, date` でソートし zstd 圧縮。CVE 指定クエリが
  行グループ統計 (zone map) で枝刈りされる。代償として「過去年の特定日の
  全スナップショット取得」は年ファイル全体の読み込みになる (この用途の主戦場は
  進行中の年 = 日次側と判断し許容)。
- 過去年の「日別 URL で直接読む」使い方は失われる (進行中の年のみ可)。README に明記。

### `backfill_epss` の実装変更 (pipeline.py)

1. ソース repo の `epss_scores-YYYY-MM-DD.csv.gz` を年ごとにグループ化する。
2. 確定年: 各日を既存の `epss.parse` → 一時ディレクトリに日次 Parquet として変換し、
   DuckDB の `COPY (SELECT * FROM read_parquet([...]) ORDER BY cve, date) TO
   'epss-YYYY.parquet' (FORMAT parquet, COMPRESSION zstd)` で 1 ファイルに集約する。
   DuckDB の外部ソートを使うためメモリに 1 年分 (最大 1 億行規模) を載せない。
   アップロード後 `lake.add_file` で登録し、一時ファイルは年ごとに削除する。
3. 進行中の年: 従来どおり `_ingest_day` で日次登録する。
4. カタログ公開は最後に 1 回 (`_publish_catalog`)。「Parquet 先行アップロード、
   カタログ差し替えは最後」の不変条件を維持する。

冪等性:

- 年ファイルの URL が登録済み → その年を skip。
- その年の日次ファイルが 1 つでも登録済みの確定年 → その年を skip して警告を出力。
  年ファイルと日次ファイルの二重登録によるデータ重複を構造的に防ぐ。
  混在状態の解消 (compact) は今回スコープ外 (将来 `vlake compact` 等で対応)。
- 進行中の年の日次は従来どおり登録済み URL を skip。

年またぎの運用: 年が明けても前年の日次ファイルはそのまま残る (クエリは正しい)。
前年を年ファイルへ圧縮する手段は上記のとおりスコープ外。

### `verify` の調整 (pipeline.py)

- パス集合の突き合わせ (storage vs catalog) は無変更で機能する。
- ファイル名由来の日付検証を混在レイアウトに対応させる:
  - max 側: 従来どおり日次キー `epss-YYYY-MM-DD.parquet` の max と
    カタログの `max(date)` を比較 (進行中の年は常に日次なので正確)。
  - min 側: 「カタログの `year(min(date))` == キー (日次 + 年ファイル) の最小年」に
    緩和する (年ファイル `epss-YYYY.parquet` は年しか分からないため)。

### GitHub Actions ワークフロー `.github/workflows/backfill.yml`

- トリガー: `workflow_dispatch` のみ。日次の `publish.yml` には手を入れない。
- `environment: publish` — 既存の Secrets/Variables をそのまま再利用 (追加設定不要)。
- `concurrency: { group: publish, cancel-in-progress: false }` — publish.yml と同じ
  グループ名を共有し、日次 update との同時カタログ差し替えを構造的に排除 (後着は待機)。
- `timeout-minutes: 360`。冪等なので万一タイムアウトしても再実行で回復。
- ステップ:
  1. `actions/checkout` (vlake 本体)
  2. `astral-sh/setup-uv` + `uv sync`
  3. `git clone --depth 1 https://github.com/empiricalsec/epss_scores` を
     `${{ runner.temp }}/epss_scores` へ
  4. `uv run vlake backfill epss --source ${{ runner.temp }}/epss_scores`
  5. `uv run vlake verify` (`--max-age-days` は付けない。鮮度監視は日次 publish 側の責務)
- env ブロック (5 変数) は publish.yml と同一。重複は許容する。
- アップロードは年ファイル約 5 件 + 当年日次約 190 件 ≒ 200 件で、1 時間以内の見込み。

検討した代替案 (不採用):

- **publish.yml に `mode` 入力を追加**: schedule 実行と手動バックフィルが同じジョブ
  定義に混ざり、壊してはいけない日次側に変更が入るため不採用。
- **reusable workflow で共通化**: env 5 変数の重複解消には過剰 (YAGNI)。
- **単一巨大 Parquet**: 読み取りは最速だが日次更新のたびに GB 級の書き直しが必要で不採用。
- **現状維持 (日次 1900 ファイル)**: コード変更不要だが、主用途の CVE 全期間クエリが
  HTTPS 越しに数千リクエストになるため不採用。
- **全年・年1ファイル + 当年は毎日同名上書き**: 読み取りは常に年数分 (〜6ファイル) で
  最も一様だが、公開済みオブジェクトの上書きは「データファイル不変 + カタログ
  差し替えのみ」というアトミック公開を壊すため不採用。具体的な不整合窓:
  (1) 年ファイル PUT とカタログ PUT の間に ATTACH した読者が旧カタログ + 新ファイル
  を掴む (毎日数秒。カタログ記録のフッタ位置・統計と不一致でクエリがエラー)、
  (2) 2つの PUT の間でジョブが死ぬと次の成功実行まで (1) の状態が継続、
  (3) 上書き瞬間を跨いで実行中のクエリが新旧バイト列を混読しデコードエラー。
  さらに日次ジョブの転送量が年末に向け往復 〜1GB/日に成長し、カタログの毎回
  再構築が必要になるためスナップショット履歴も失われる。
  「毎日壊れ得る」より「全期間クエリが当年日次の分 (最大365ファイル) だけ常に
  数秒遅い」を取る判断。なお実測では `cf-cache-status: DYNAMIC` (2026-07-11、
  Cloudflare は .parquet/.ducklake をキャッシュしていない) だったため CDN 起因の
  窓は現構成では生じないが、上書き方式を採ると .parquet へのキャッシュルール
  追加が恒久的に禁止になる点も減点とした。
- **年またぎ compact の同時実装**: 前年の日次を年ファイルへ置き換える操作は
  「新規年ファイル PUT (不変) → カタログ差し替え → 旧日次削除」の順なら窓を
  年1回・数秒・任意のタイミングに限定でき、安全に後付けできる。Storage.delete の
  新設が必要なこともあり YAGNI で今回はスコープ外とする。

### README 追記

- 「Build your own lake」に、fork 後は Actions タブから `backfill` ワークフローを
  手動実行 (Run workflow) することでローカル環境なしに初期構築できる旨を追記。
  既存のローカル手順は代替手段として残す。
- レイアウト説明を追記: 確定年は `epss-YYYY.parquet` (cve, date ソート)、
  進行中の年のみ日別ファイル。日別 URL 直接読みは進行中の年のみ。

## エラーハンドリング

- 途中失敗 / タイムアウト: カタログ未公開のまま終了 → 消費者影響なし。再実行で回復
  (アップロード済みファイルは同一キーへの上書きで無害)。
- 日次 publish との併走: concurrency group 共有により直列化されるため考慮不要。
- ソース repo の clone 失敗: ジョブが素直に失敗するだけでよい (リトライは手動再実行)。
- 日次登録済みの確定年: skip + 警告 (上記冪等性)。

## テスト

`tests/test_pipeline.py` に追加 (ローカルストレージモード、`make_epss_csv_gz` 再利用):

- 複数年ソース (確定年 2 年分 + 進行中の年数日分) で backfill →
  確定年は年ファイル 1 個ずつ、進行中の年は日次ファイル、verify ok。
- 年ファイル内が (cve, date) ソートであること。
- 再実行で added 0 (冪等)。
- 日次ファイルが登録済みの確定年は skip され、二重登録が起きないこと。
- 「進行中の年」の判定はテストから注入可能にする:
  `backfill_epss(cfg, source_dir, today=None)` とし、None なら `date.today()`。

ワークフロー YAML は actionlint (利用可能なら) で静的検証し、実挙動の最終確認は
本番リポジトリでの `workflow_dispatch` 実行 (冪等なので既存レイクに対して安全)。
