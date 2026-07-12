# CWE データセット追加 — 設計書

Date: 2026-07-12
Status: Approved

## 目的

vulnlake に **CWE**(Common Weakness Enumeration、提供: MITRE)をディメンション
テーブルとして追加する。既存の CVE / GHSA / nuclei の 3 テーブルはいずれも
`cwe VARCHAR[]` 列を持つが、その ID を解決する先(名前・抽象度・親子関係・
カテゴリ/ビュー所属)がレイク内に存在しない。CWE テーブルが 1 枚あれば
「CWE-89 とその子孫に該当する CVE を EPSS スコア順に」のような分析が
レイク内で完結する。

```sql
ATTACH 'ducklake:https://vlake.reta.work/vlake.ducklake' AS vlake;
SELECT c.cve_id, w.name AS weakness
FROM vlake.cve c, UNNEST(c.cwe) AS u(cwe_id)
JOIN vlake.cwe w ON w.cwe_id = u.cwe_id
WHERE w.abstraction = 'Base';
```

## 前提調査の結論

- ソースは MITRE 公式の `https://cwe.mitre.org/data/xml/cwec_latest.xml.zip`
  (約 2 MB)。全弱点(約 1,000 件)+ カテゴリ + ビュー + 相互関係を含む正典で、
  ルート要素の `Version` / `Date` 属性でカタログバージョンが取れる。
  ビュー単位の CSV 配布は不完全なため採用しない。
- ライセンスは CWE Terms of Use。帰属表示を条件に複製・再配布を許諾。
  DATA_LICENSES.md と in-lake `datasets` ビューに帰属を追記する。
- 更新頻度は年数回(バージョン 4.x 系のリリース時のみ)。日次デルタは存在しない。
- サーバーは **ETag を返さないが `Last-Modified` を返し、`If-Modified-Since`
  に 304 で応答する**(2026-07-12 に確認)。日次実行の無駄なダウンロードは
  条件付き GET で回避できる。
- bandit(ruff で有効)が stdlib の `xml.etree` パースを B313/B314 で弾くため、
  XML パースには **defusedxml** を使う。依存追加時はレジストリで最新安定版を確認する。

## スキーマ

弱点・カテゴリ・ビューを 1 テーブルに収め、`entry_type` で区別する
(既存の「1 データセット = 1 history テーブル + 1 latest ビュー」パターンを維持)。

```
cwe_history (
    cwe_id                VARCHAR,   -- 'CWE-79' 形式。既存 3 テーブルの cwe 列とそのまま JOIN 可能
    entry_type            VARCHAR,   -- 'weakness' | 'category' | 'view'
    name                  VARCHAR,
    abstraction           VARCHAR,   -- weakness のみ: Pillar/Class/Base/Variant。他は NULL
    status                VARCHAR,   -- Stable/Draft/Incomplete/Deprecated 等
    description           VARCHAR,
    likelihood_of_exploit VARCHAR,   -- weakness のみ、NULL 可
    relations             STRUCT(nature VARCHAR, target_id VARCHAR)[],
                                     -- ChildOf/PeerOf 等 (weakness)、HasMember (category/view)。
                                     -- target_id も 'CWE-nnn' 形式
    cwe_version           VARCHAR,   -- '4.17' 等。XML ルートの Version 属性
    release_date          DATE       -- XML ルートの Date 属性
)
```

latest ビュー `cwe` は **`release_date` が最大の断面**を返す
(`cwe_version` の文字列比較は `'4.9' > '4.17'` となり順序に使えない)。
Deprecated な弱点も status 列付きでそのまま残るため、nuclei のような
トゥームストーン行は不要。

## ストレージレイアウト

```
cwe/version=<ver>/cwe-<ver>.parquet   -- バージョン断面の全件スナップショット
cwe/last-modified.txt                 -- 条件付き GET 用に保存する Last-Modified 値
```

年パーティションではなくバージョンパーティション。1 断面は全件でも数 MB。

## 更新フロー (`update_cwe`)

backfill は提供しない(nuclei と同方針)。カタログが空なら初回 update が全量投入となる。
過去バージョンのアーカイブ XML は存在するが用途がないため取り込まない (YAGNI)。

1. ストレージから `cwe/last-modified.txt` を読む(存在しなければ無条件 GET)。
2. `If-Modified-Since` 付きで zip を GET。**304 なら `not-modified` を返して即終了**
   (レイクも開かない)。`Last-Modified` ヘッダが無い等の異常時は無条件 GET に
   フォールバックする — 条件付き GET は帯域最適化にすぎず、正しさは次の
   バージョン判定が担保する。
3. XML の `Version` からストレージキーを決め、`storage.url(key)` が
   `registered_paths()` に含まれていれば `already-registered` で終了(冪等)。
4. 新バージョンなら全件を Parquet 化 → アップロード → `ducklake_add_data_files()`
   で登録 → `cwe` ビュー再生成 → カタログ公開(データ先行・カタログ最後の
   公開順序の不変条件は既存どおり)。
5. **カタログ公開が成功した後にのみ** `cwe/last-modified.txt` を更新する。
   途中失敗時は次回が無条件 GET からやり直すため回復は冪等。

## verify / rebuild-catalog

- 整合性検査(登録キーとストレージ実体の突合)は既存データセットと同様に対象へ追加。
- **`--max-age-days` の鮮度チェックからは CWE を除外する**。数ヶ月更新が
  ないのが正常なデータセットであり、日次前提の鮮度検査は誤検知にしかならない。
- rebuild-catalog は `cwe/version=*/` 配下の Parquet を他データセットと同様に
  再登録対象へ追加する。

## CLI / CI

- `cli.py`: `update` の Choice に `cwe` を追加。`backfill` には追加しない。
- `publish.yml`: 日次マトリクスに `cwe` を追加する。大半の日は 304 の
  条件付き GET 1 本(数 KB)で終わるため、日次実行のコストは無視できる。
  別スケジュールという例外運用は作らない。
- `backfill.yml`: 対象外。

## テスト

`tests/conftest.py` に実 XML 構造(`Weakness_Catalog` ルート、
`Weaknesses/Weakness`、`Categories/Category`、`Views/View`、
`Related_Weaknesses` / `Relationships/Has_Member`)を忠実に模した
`make_cwe_xml_zip(version=..., date=...)` を追加し、

- `test_cwe.py`: パース(3 種の entry_type、relations、Deprecated の保持)と
  `key_for` の命名。
- `test_pipeline_cwe.py`: 初回 update の全量投入、同バージョン再実行の
  `already-registered`、新バージョン追記後の latest ビュー切り替わり
  (release_date 順)、304 応答時の `not-modified` 早期終了、
  途中失敗後の冪等回復、verify の鮮度チェック除外。

HTTP は httpx をモックする(既存テストのネットワーク非依存方針を維持)。

## 触るファイル

`src/vlake/cwe.py`(新規)、`lake.py`(cwe_history 定義・`refresh_cwe_view`。
更新判定は registered_paths とバージョンキーで行うため `max_*` メソッドは不要)、`pipeline.py`(`update_cwe`・verify・rebuild-catalog)、
`cli.py`、`tests/conftest.py` + `test_cwe.py` + `test_pipeline_cwe.py`、
README のスキーマ節、DATA_LICENSES.md、`.github/workflows/publish.yml`、
`pyproject.toml`(defusedxml 追加)。
