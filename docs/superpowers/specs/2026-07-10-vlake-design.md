# vlake — Security Data Frozen DuckLake 設計書

Date: 2026-07-10
Status: Approved

## 目的

セキュリティ関連データセットを、ライセンス上の再配布可否を確認した上で、S3互換オブジェクトストレージ上の **Frozen DuckLake** として公開するオープンソースプロジェクト。第1弾として EPSS (Exploit Prediction Scoring System) の全履歴 (2021-04-14〜) を収録する。

消費者は以下のいずれでも同じデータにアクセスできる:

```sql
-- DuckLake として (スナップショット履歴・カタログ付き)
ATTACH 'ducklake:https://<public-url>/vlake.ducklake' AS vlake;
SELECT * FROM vlake.epss WHERE cve = 'CVE-2021-44228' ORDER BY date;

-- 素の Parquet として (pandas / polars / DuckDB read_parquet)
SELECT * FROM read_parquet('https://<public-url>/epss/year=2026/*.parquet');
```

## 前提調査の結論

### EPSS データの再配布可否 — 可

- FIRST の EPSS FAQ (https://www.first.org/epss/faq) が根拠条文:
  > "We grant the use of EPSS scores freely to the public, subject to the following conditions. ... we ask that if you are using EPSS, that you provide appropriate attribution where possible."
- 利用は自由、帰属表示は「要請」(義務ではない)。ScanCode LicenseDB は `first-epss-usage` として認識。
- FIRST 自身が公式データページから全履歴のサードパーティ GitHub ミラー (https://github.com/empiricalsec/epss_scores) をリンクしており、再配布は事実上公認の慣行。
- 本プロジェクトは帰属表示 + 非公認ディスクレーマ ("not endorsed or certified by FIRST") を明記する。
- データ取得元:
  - 日次: `https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz` (~13:30 UTC 更新)
  - 全履歴: GitHub リポジトリ empiricalsec/epss_scores (2021-04-14〜、年別ディレクトリ)
- モデルバージョン境界: v2 = 2022-02-04、v3 = 2023-03-07、v4 = 2025-03-17。

### Frozen DuckLake

- カタログは単一の DuckDB ファイル (`vlake.ducklake`) を S3/R2 に置くだけ。消費者は HTTPS で ATTACH (読み取り専用)。
- DuckLake spec 1.0 (2026-04)、DuckDB 1.5.x の `ducklake` 拡張を使用。
- 制約1: カタログの DATA_PATH は作成後変更不可 → 最初から公開 URL を焼き込む。
- 制約2: `ducklake_add_data_files()` は冪等でない → 登録前に `ducklake_data_file` の path を照会して重複登録を防ぐ。
- 公開更新 = 新 Parquet アップロード + カタログファイル差し替え (消費者視点でアトミック)。スナップショット履歴はカタログ内に蓄積される。

## アーキテクチャ

### 構築方式: 自前 Parquet + カタログ登録

Parquet は自前で生成して人間に優しいパスで配置し、カタログには `ducklake_add_data_files()` で公開 HTTPS 絶対 URL を登録する。DuckLake 管理書き込み (OVERRIDE_DATA_PATH 方式) は、ファイル名が UUID になり素の Parquet 利用に不向きなこと、OVERRIDE_DATA_PATH の既知の不安定さ (duckdb/ducklake#580) から採用しない。

### データレイアウト

```
s3://<bucket>/
  vlake.ducklake                            # カタログ (差し替えで公開)
  epss/
    year=2021/epss-2021-04-14.parquet       # 1日1ファイル、zstd 圧縮
    ...
    year=2026/epss-2026-07-10.parquet
```

### スキーマ

```sql
CREATE TABLE epss (
  cve           VARCHAR,   -- 'CVE-2021-44228'
  epss          DOUBLE,    -- スコア [0,1]
  percentile    DOUBLE,    -- パーセンタイル [0,1]
  date          DATE,      -- スコア公表日 (ファイル単位で一定)
  model_version VARCHAR    -- CSV 先頭コメント行由来 ('v2023.03.01' 等)
);

-- ライセンス情報をデータと共に配布するメタ「ビュー」。
-- テーブルでなくビューにするのは、DuckLake テーブルへの INSERT は Parquet
-- データファイルを生むため。ビュー定義はカタログファイル内にのみ存在し、
-- 更新のたびに CREATE OR REPLACE で作り直す。
CREATE VIEW datasets AS SELECT * FROM (VALUES (...))
  AS t(name, source_url, license_name, license_text, attribution, disclaimer);
```

### 実装スタック

- Python 3.12+、uv で依存管理。依存バージョンはレジストリで最新安定版を確認して固定する (グローバル方針)。
- 主要依存: `duckdb` (+ `ducklake` 拡張)、`pyarrow`、`boto3`、`httpx`、`click` (CLI)。
- パッケージ名 `vlake`、コードのライセンスは Apache-2.0。

### 設定 (環境変数)

| 変数 | 意味 |
|---|---|
| `VLAKE_S3_ENDPOINT` | S3 互換エンドポイント URL (R2 / MinIO / AWS) |
| `VLAKE_S3_BUCKET` | バケット名 |
| `VLAKE_PUBLIC_URL` | カタログに焼き込む公開 HTTPS ベース URL |
| `AWS_ACCESS_KEY_ID` ほか | 標準 AWS 認証環境変数 |

### データセットプラグイン構造

`vlake/datasets/epss.py` が Dataset インターフェースを実装:

- `schema` — pyarrow スキーマ
- `license_info` — DATA_LICENSES.md / datasets テーブルに載せる情報 (原文引用付き)
- `fetch(date) -> pyarrow.Table | None` — 1日分の取得・正規化 (未公開なら None)
- `backfill_dates() -> list[date]` / 履歴一括取得は GitHub ミラーから

第2弾以降 (KEV 等) はモジュール追加のみで拡張。ただし新データセット追加時は必ず再配布可否のライセンス調査を先に行い、その結論を license_info と DATA_LICENSES.md に記録する。

### CLI

- `vlake backfill epss` — 全履歴を GitHub ミラーから取得し Parquet 化・アップロード・カタログ登録 (公式 CDN への大量リクエスト回避)
- `vlake update epss` — 日次更新。冪等: 登録済み日付はスキップ、当日ファイル未公開 (404) は正常終了
- `vlake rebuild-catalog` — バケット一覧からカタログをゼロから再構築 (破損時の自己修復)
- `vlake verify` — カタログ経由の行数・日付範囲が実ファイルと一致するか検証

### 日次更新フロー (`vlake update epss`)

1. `epss_scores-current.csv.gz` を取得、コメント行から model_version と score_date をパース
2. カタログを S3 からダウンロードし ATTACH、`ducklake_data_file` を照会して score_date が登録済みなら終了
3. Parquet 生成 (zstd) → `epss/year=YYYY/epss-YYYY-MM-DD.parquet` にアップロード
4. `ducklake_add_data_files()` で公開 URL を登録、`set_commit_message()` で日付を注記
5. カタログを S3 に再アップロード (アトミック公開)

### 運用 (GitHub Actions)

- `test.yml` — PR/push 時に pytest
- `publish.yml` — 日次 cron (14:30 UTC、EPSS 更新の 13:30 UTC 後) で `vlake update epss`。認証情報は Secrets。fork + Secrets 設定で誰でも自分のバケットに同じレイクを構築可能。

## エラー処理

- 当日 CSV 未公開 (404 / redirect 先が前日): 正常終了 (次回 cron で再試行)
- `ducklake_add_data_files()` の重複登録: 登録前照会で防止
- カタログ破損・不整合: `vlake rebuild-catalog` で自己修復 (バケットの Parquet 一覧が真実源)
- アップロード途中失敗: Parquet が先、カタログが後の順序なので、カタログ未更新なら消費者影響なし。次回実行が冪等に回復

## テスト

- 単体: CSV パース (コメント行のメタデータ抽出含む)、Parquet 生成、冪等性判定
- 統合: ローカルディレクトリをバケットに見立てたエンドツーエンド (backfill → update → verify → DuckDB で ATTACH して読めること)。ストレージ層を薄い抽象 (S3 / ローカル FS) にしてテスト可能にする

## ライセンス文書

- `LICENSE` — Apache-2.0 (コード)
- `DATA_LICENSES.md` — データセットごとの準拠条文を原文引用付きで記載。EPSS の帰属表示と非公認ディスクレーマを明記
- `README.md` — 消費者向けクイックスタート (ATTACH 1行 + read_parquet 例)、帰属表示

## スコープ外 (将来課題)

- 過去月 Parquet の月次コンパクション (小ファイル増加対策)
- KEV / NVD 等の追加データセット
- カタログの CORS 設定ガイド (shell.duckdb.org からの利用)
