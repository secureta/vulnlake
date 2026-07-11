# バックフィルの GitHub Actions 実行 + 全年・年1ファイル方式 設計書

Date: 2026-07-11
Status: Approved

## 目的

1. 初期構築 (fork 直後・バケット作り直し・災害復旧) 時に、ローカル環境なしで
   GitHub Actions 上で EPSS 全履歴のバックフィルを実行できるようにする。
2. レイアウトを「全ての年が年1ファイル」に統一する。主用途である
   「1つの CVE の過去の変遷を見る」全期間クエリが常に年数分 (〜6個) の
   ファイルしか触らないようにし、update と backfill を
   「対象年のファイルを作り直す」という同一操作に共通化する。

## 前提調査の結論

- ソースの `empiricalsec/epss_scores` はサーバ側で約 2.4 GB。`--depth 1` clone なら
  ubuntu-latest runner のディスク (十数 GB 空き) に収まる。
- 日次 Parquet は 1 ファイル約 2.5 MB (2026 年実測)。年1ファイルは数百 MB 規模。
- 公開レイクには 2021 年のファイルがまだ存在しない (HTTP 404 確認済み)。
  現状の登録済みは 2026 年の日次数件のみで、レイアウト移行の負債はほぼない。
- `cf-cache-status: DYNAMIC` (実測): Cloudflare は `.parquet` / `.ducklake` を
  キャッシュしていない。CDN キャッシュ起因の不整合は現構成では発生しない。

## レイアウト

- 全ての年: `epss/year=YYYY/epss-YYYY.parquet` (年1ファイル、`ORDER BY cve, date`
  でソート、zstd 圧縮)。`year=` パス構造は維持するため
  `read_parquet('https://.../epss/year=2021/*.parquet')` は従来どおり動く。
- 当年ファイルは日次更新のたびに同名で上書きされる。過去年ファイルは不変。
- 日別ファイル (`epss-YYYY-MM-DD.parquet`) は廃止する。既存の日次ファイル
  (2026 年の数件) は移行時に backfill が当年ファイルへ統合するが、旧オブジェクト
  自体はストレージに残る (カタログから参照されないだけ。削除は行わない —
  Storage.delete を持たないため。気になる場合は手動削除)。
  → verify はカタログ参照集合とストレージ実集合の一致を検証するため、
  旧日次ファイルが残っていると ok=False になる。移行手順として README に
  「backfill 後に旧日次オブジェクトを手動削除する」旨を記す。

## 受容する整合性リスク (同名上書きの窓)

更新は「年ファイル PUT → カタログ PUT」の順で行う。以下の窓を許容する:

| 窓 | 発生条件 | 頻度・影響 |
|---|---|---|
| 公開の瞬間 | 2つの PUT の間に ATTACH した読者が旧カタログ + 新ファイルを掴む | 毎日数秒。フッタ位置・統計の不一致でクエリはエラー (うるさく壊れる) |
| ジョブ途中死 | 年ファイル PUT 後、カタログ PUT 前にジョブが死ぬ | 低確率。次の成功実行 (最長翌日の日次 cron) まで上記状態が継続、自動で自己修復 |
| 実行中クエリ跨ぎ | 上書きの瞬間に当年ファイルへ range リクエスト発行中 | その瞬間のクエリのみデコードエラー |

- 影響範囲は常に「当年データに触るクエリ × その瞬間」。過去年のみのクエリは無傷。
- **恒久制約**: 当年ファイルは毎日書き変わるため、`.parquet` への CDN キャッシュ
  ルールを将来追加してはならない (追加すると窓が TTL 分に拡大する)。README に明記。

## 設計

### 共通コア: `_rebuild_year` (pipeline.py)

update と backfill が共有する「対象年のファイルを作り直す」操作:

1. 入力: 対象年 / 新規分の日次データ (parse 済みの日付付き) / 既存年ファイルの有無。
2. 新規分を一時ディレクトリに日次 Parquet として書き出す。
3. 既存年ファイルがあればローカルへダウンロードし、**新規分に含まれない日付の行
   だけ**を取り込む (日付単位のアンチ結合)。これにより mirror にまだ無い日
   (例: 当日分を update が先行登録済み) のデータが失われない。
4. DuckDB の `COPY (SELECT ... ORDER BY cve, date) TO ... (FORMAT parquet,
   COMPRESSION zstd)` で単一ファイルに集約する。`SET temp_directory` により
   外部ソートでスピルさせ、1年分 (最大1億行規模) をメモリに載せない。
5. `epss/year=YYYY/epss-YYYY.parquet` へ PUT (同名上書き)。

### `update_epss` の変更

1. 従来どおり日次 CSV を fetch (未公開なら "not-published-yet")。
2. 既存の対象年ファイル (score_date の年) をダウンロードし、score_date が既に
   含まれていれば "already-registered" で終了 (冪等)。
3. `_rebuild_year` で対象年を作り直して PUT。
4. カタログを再構築して PUT (下記)。

`--date` で過去年の日付を指定した場合も同じコードパスでその年を作り直す。

日次ジョブの転送量は当年ファイルサイズに比例して成長する (年末に向けて
ダウンロード+アップロードで往復 〜1GB/日規模)。R2 は egress 無料、Actions の
実行時間は数分増にとどまるため許容する。

### `backfill_epss` の変更

シグネチャ: `backfill_epss(cfg, source_dir, today=None)` (today はテスト注入点)。

1. mirror の `epss_scores-YYYY-MM-DD.csv.gz` を年ごとにグループ化
   (beta_scores 配下は除外、従来どおり)。
2. 確定年 (today の年より前): 年ファイルがカタログ登録済みなら skip (確定年は
   不変なので再構築不要)。未登録なら `_rebuild_year` で構築して PUT。
3. 当年: 常に `_rebuild_year` で作り直す (mirror の日 ∪ 既存当年ファイルにしか
   無い日付の行)。update が先行登録した当日分はアンチ結合で保持される。
4. 最後にカタログを再構築して PUT (1回)。

戻り値: `"backfilled {N} years (skipped {M})"`。

### カタログ管理の変更: 公開のたびにゼロから再構築

上書きされた年ファイルは行数・統計・フッタ位置が変わるため、既存カタログへの
増分登録 (`ducklake_add_data_files`) では整合できない。公開時は毎回、
ストレージ一覧からカタログを新規作成して PUT する
(既存 `rebuild_catalog` と同じ方式に統一し、実装を共通化する)。

**カタログに登録するのは年ファイルパターン (`epss-YYYY.parquet`) に一致する
キーのみ**とする。移行期に残っている旧日次オブジェクトを登録すると年ファイルと
データが二重になるため、パターン外のキーはカタログから除外する (verify の
パス集合検証が不一致を報告するので、掃除漏れには気づける)。`rebuild_catalog`
コマンドも同じフィルタを適用する。

- 帰結: スナップショット履歴は蓄積されなくなる (毎回単一スナップショット)。
  frozen DuckLake としての主機能 (現在データへの ATTACH) には影響しないため許容。
- DATA_PATH は従来どおり作成時に storage.url ベースで焼き込む。
- `ducklake_add_data_files` はリモート URL の Parquet フッタを読んで統計を収集する
  (年数分 = 数リクエスト/回、軽微)。

### `verify` の調整

- パス集合の突き合わせ (storage vs catalog) は無変更で機能する。
- ファイル名由来の検証は年単位に変更: キーは `epss-YYYY.parquet` のみになるため、
  `min(date).year == 最小キー年` かつ `max(date).year == 最大キー年` を検証する。
  (日別ファイル名が消えるため日付単位の厳密比較は不可能になる。)
- `--max-age-days` の stale 判定 (カタログの max_date ベース) は無変更。

### GitHub Actions ワークフロー `.github/workflows/backfill.yml`

- トリガー: `workflow_dispatch` のみ。日次の `publish.yml` は無変更
  (実行するコマンド `vlake update epss` / `vlake verify --max-age-days 3` は同じ。
  中身の挙動だけが上記のとおり変わる)。
- `environment: publish` — 既存の Secrets/Variables をそのまま再利用。
- `concurrency: { group: publish, cancel-in-progress: false }` — publish.yml と
  同一グループ。日次 update とバックフィルが同時に当年ファイル/カタログを
  書く競合を構造的に排除する (後着は待機)。
- `timeout-minutes: 360`。冪等 (確定年 skip) なので途中死しても再実行で回復。
- ステップ: checkout → setup-uv → `uv sync` →
  `git clone --depth 1 https://github.com/empiricalsec/epss_scores "$RUNNER_TEMP/epss_scores"` →
  `uv run vlake backfill epss --source "$RUNNER_TEMP/epss_scores"` →
  `uv run vlake verify` (`--max-age-days` なし。鮮度監視は日次側の責務)。
- env ブロック (5変数) は publish.yml と同一。重複は許容する。

検討した代替案 (不採用):

- **確定年のみ年ファイル、当年は日次のまま**: 不変条件は完全維持できるが、
  当年の日次が年末に〜365個溜まり全期間クエリの効率が落ちる。年またぎの
  圧縮手段も別途必要になる。
- **日付入りファイル名 + 旧削除**: ファイル不変は保てるが、Storage.delete の新設が
  必要な上、glob 読者に重複が見える窓 or 旧カタログ読者の 404 窓が生じ、
  複雑さの割に窓が消えない。
- **単一巨大 Parquet (全年1ファイル)**: 毎日全履歴 (〜3GB) を書き直すことになり
  転送量・失敗リスクが過大。
- **publish.yml への mode 入力追加 / reusable workflow**: 初版設計時に不採用
  (日次側に触らない・YAGNI)。

### README 更新

- Schema 付近にレイアウト説明: 年1ファイル (`epss/year=YYYY/epss-YYYY.parquet`、
  cve/date ソート)、当年ファイルは日次更新で書き変わる (キャッシュ不可)、
  過去年は不変。日別 URL は存在しない。
- Parquet 直読み例を年ファイルに更新 (polars の例は
  `.../epss/year=2026/epss-2026.parquet` に)。
- 「Build your own lake」に Actions からのバックフィル手順 (Actions タブ →
  backfill → Run workflow、冪等、publish と concurrency 共有) を追記。
  旧日次レイアウトからの移行時は backfill 後に旧日次オブジェクトを手動削除する
  注意書きを添える。

## エラーハンドリング

- 途中死: 「受容する整合性リスク」の表のとおり。次の成功実行で自己修復。
- 日次 publish との併走: concurrency group 共有で直列化。
- mirror clone 失敗: ジョブが失敗するだけ (手動再実行)。
- update で対象日が既に年ファイルに存在: "already-registered" で終了 (冪等)。

## テスト

`tests/test_pipeline.py` を新レイアウト前提に書き直す
(ローカルストレージモード、`make_epss_csv_gz` 再利用):

- update 初日: 年ファイルが1個でき、verify ok。
- update 2日目: 同じ年ファイルが上書きされ行が増える。同日再実行は
  "already-registered"。
- update `--date` で過去年を指定: その年のファイルが作られる/更新される。
- backfill 複数年 (確定年2つ + 当年、today 注入): 年ファイルが年数分でき、
  (cve, date) ソートで、verify ok。再実行で確定年 skip。
- update 先行 → backfill: 当年ファイルに update 分の日付が保持される (アンチ結合)。
- verify: 年単位 min/max 検証、パス集合不一致検出 (既存テストの改修)。

ワークフロー YAML は actionlint (あれば) で静的検証。実挙動の最終確認は本番
リポジトリでの `workflow_dispatch` 実行。
