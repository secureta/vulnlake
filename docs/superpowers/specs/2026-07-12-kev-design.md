# KEV (CISA Known Exploited Vulnerabilities) データセット追加 — 設計書

Date: 2026-07-12
Status: Approved

## 目的

vulnlake に **KEV**(提供: CISA)の悪用確認済み脆弱性カタログを追加する。
KEV は「実際に悪用が観測された CVE」の権威的リストで、EPSS(悪用予測)・
ExploitDB / nuclei(エクスプロイト・検出テンプレートの存在)と並ぶ
悪用シグナルの決定版。`cve` を結合キーとして既存データセットと同じレイク上で
「この CVE は悪用済みか」「悪用済み CVE のうちパッチ期限が近いものは」を
問い合わせ可能にする。

```sql
ATTACH 'ducklake:https://vlake.reta.work/vlake.ducklake' AS vlake;
SELECT k.cve, k.vulnerability_name, k.date_added, k.due_date, e.epss
FROM vlake.kev k LEFT JOIN vlake.epss e USING (cve)
WHERE NOT k.removed AND k.known_ransomware_campaign_use = 'Known';
```

## 前提調査の結論

- 上流: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  (単一 JSON、2026-07-10 時点で 1,637 件・約 1.5MB)。CSV 版もあるが構造化情報
  (cwes 配列) を持つ JSON を採用する。
- ライセンスは **CC0 1.0 Universal**(`https://www.cisa.gov/sites/default/files/licenses/kev/license.txt`)。
  再配布は自由。CISA ロゴ・DHS シールの使用や CISA の推奨を示唆する表現は不可、
  第三者リンク先は各サイトのポリシーに従う旨の注記あり。安全側に倒し
  `licenses/CC0-1.0-kev.txt`(CISA の注記 + CC0 全文)を同梱する。
- レコードのフィールドは 11 個 (`cveID` / `vendorProject` / `product` /
  `vulnerabilityName` / `dateAdded` / `shortDescription` / `requiredAction` /
  `dueDate` / `knownRansomwareCampaignUse` / `notes` / `cwes`)。全レコードで揃う。
  トップレベルに `title` / `catalogVersion` / `dateReleased` / `count`。
- **レコード単位の更新日時が無い**。`dateAdded` は追加日で、追記後の修正
  (dueDate 変更・ransomware 判定の更新・notes 追記等) では変わらない。
  → nuclei と同じ「カタログ latest との内容比較による差分検出」を採用する。
- KEV からレコードが削除された例が実在する (CISA が撤回したエントリ)。
  → nuclei と同じトゥームストーン (`removed=true`) で表現する。
- 過去断面の公式アーカイブは無い。→ **backfill は提供しない**(nuclei と同様、
  初回 update が全量投入)。`dateAdded` は行に保持されるため「いつ KEV 入りしたか」
  の履歴価値は初回投入だけで確保できる。

## アーキテクチャ

既存のデータセットプラグイン構造に倣い `kev.py` を追加する。方式は nuclei を踏襲:

- **update のみ**: 最新 JSON 断面を取得し、カタログ latest (cve ごと fetched_date
  最新行) と全フィールドを比較。新規・変更行と、断面から消えた cve の
  トゥームストーン行を日次 Parquet として追記する。
- 差分検出は内容ハッシュではなく **フィールド直接比較**。KEV は行が平坦で
  フィールド数が固定 (11 個) なので、latest 行の対応列と dict 比較すれば足りる
  (nuclei の digest は YAML 本文が対象だったための工夫であり KEV には不要)。
- 断面の異常縮小ガード: 断面件数がカタログ内 active 件数の半分未満なら
  RuntimeError で中断 (nuclei と同一のロジック)。
- 公開順序の不変条件は既存どおり: Parquet アップロード → カタログ登録 →
  カタログ公開が最後。

## スキーマ

テーブル `kev_history` (append-only) + ビュー `kev` (cve ごと fetched_date 最新の1行)。

```
cve                             VARCHAR   -- cveID
vendor_project                  VARCHAR
product                         VARCHAR
vulnerability_name              VARCHAR
short_description               VARCHAR
required_action                 VARCHAR
known_ransomware_campaign_use   VARCHAR   -- 'Known' / 'Unknown' (上流の文字列を保持)
notes                           VARCHAR
cwe                             VARCHAR[] -- cwes (列名は cve_history / nuclei に合わせ cwe)
date_added                      DATE
due_date                        DATE
fetched_date                    DATE      -- 取り込み実行日 (pipeline が付与)
removed                         BOOLEAN   -- 上流から消えた cve のトゥームストーン
```

- `cveID` が欠落・不正 (`CVE-\d{4}-\d+` に不一致) の行は bad としてカウントし
  読み飛ばす (上流異常の観測点)。
- `dateAdded` / `dueDate` は ISO 日付。パース不能なら None (行自体は収録)。
- 同一 cve が重複した場合は最初の1件を採用 (上流は一意を保証、保険)。

## ストレージキー

```
kev/updates/year=YYYY/kev-updates-YYYY-MM-DD.parquet
```

日付は実行日 (UTC)。JSON の `dateReleased` はカタログ全体の再署名でも変わるため
キーには使わない。同日再実行は登録済みチェックで skip (冪等)。

## 各層の変更

- **kev.py** (新規): `NAME` / `SCHEMA` / `LICENSE_INFO` / `FEED_URL` /
  `parse_record()` / `parse_catalog()` / `rows_to_table()` (cve 昇順ソート) /
  `key_for_update()` / `write_parquet()` / `download()`。
- **lake.py**: `kev_history` テーブル定義、`kev_latest_rows()` (差分検出と
  トゥームストーン生成用の全行スナップショット)、`refresh_kev_view()`。
- **pipeline.py**: `update_kev()` (update_nuclei と同型)、`_publish_catalog` の
  LICENSE_INFO / ビュー再生成に追加、`rebuild_catalog` の tables に
  `"kev/": "kev_history"`、`verify` に `_verify_history(prefix="kev/",
  ts_column="fetched_date")` を追加。
- **cli.py**: `update` の Choice に `kev` を追加。`backfill` には追加しない。
- **tests**: `conftest.py` に `make_kev_record` / `make_kev_json`、
  `test_kev.py` (パース・キー命名・Parquet)、`test_pipeline_kev.py`
  (初回全量・冪等・差分/トゥームストーン/復活・縮小ガード・verify・rebuild)。
- **CI**: `publish.yml` に `uv run vlake update kev` を追加。`backfill.yml` は対象外。
- **docs**: README (説明・クエリ例・スキーマ節)、DATA_LICENSES.md、CLAUDE.md の
  データセット列挙、`licenses/CC0-1.0-kev.txt`。

## テスト方針

既存と同じ統合スタイル (VLAKE_LOCAL_DIR + tmp_path、ネットワーク不使用)。
`kev.download` を monkeypatch し、conftest のフィクスチャが実フォーマット
(トップレベル 4 キー + vulnerabilities 配列、フィールド 11 個) を忠実に模した
JSON を生成する。

## 却下した代替案

- **日次スナップショット全量追記** (EPSS 型): 1,600 行 × 365 日/年の重複行は
  小さいとはいえ、latest ビューの意味論が「日付でのフィルタ」に変わり
  他データセットと不整合。修正検出もできる内容差分型が優る。
- **`dateAdded` ウォーターマーク型** (cve/ghsa 型): 追記後の修正・削除を
  検出できないため不採用。
- **`catalogVersion` / `dateReleased` の行への保持**: 変更を検出した断面の
  バージョンが行に残る形になるが、provenance としては fetched_date で十分。
  列を増やす価値が無いため見送り。
