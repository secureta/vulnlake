# Cloudflare WAF ChangeLog データセット追加 — 設計書

Date: 2026-07-16
Status: Approved

## 目的

vulnlake に **Cloudflare WAF ChangeLog** 由来の WAF 対応シグナルを追加する。
目的は ChangeLog の更新履歴を分析することではなく、脆弱性識別子をキーに
「この脆弱性は Cloudflare WAF ChangeLog で言及されているか」を問い合わせ可能にすること。
Cloudflare WAF ChangeLog 内に脆弱性 ID が出現した場合、Cloudflare WAF で対応されている
(または対応が告知されている)シグナルとして扱う。

```sql
ATTACH 'ducklake:https://vlake.reta.work/vlake.ducklake' AS vlake;

SELECT identifier, source_title, source_url, source_date
FROM vlake.cloudflare_waf
WHERE identifier = 'CVE-2024-3400' AND NOT removed;

SELECT cve, has_cloudflare_waf, cloudflare_waf_count
FROM vlake.cve_sources
WHERE cve = 'CVE-2024-3400';
```

CVE 以外の識別子(GHSA / GO / PYSEC / RUSTSEC 等)も、ChangeLog 本文に明確な
識別子パターンとして現れたものは `cloudflare_waf.identifier` で直接検索できるようにする。
`cve_sources` は既存どおり CVE 中心の横断ビューなので、CVE のみを集計対象にする。

## 前提調査の結論

- 取得対象は Cloudflare 公式 Docs の WAF ChangeLog。実装では **Cloudflare Docs の
  GitHub リポジトリ上の Markdown** を第一候補にする。HTML スクレイピングより構造が安定し、
  テストフィクスチャも作りやすいため。公開 Docs URL は `source_url` として保持する。
- GitHub Markdown のパスや frontmatter 形式は upstream 変更の影響を受けるため、
  取得処理とパース処理を分離する。将来 HTML 取得に切り替える場合も、パーサと
  `rows_to_table()` の契約は維持する。
- ChangeLog の履歴そのものは不要。現行 ChangeLog 断面から「識別子が存在するか」を作る
  snapshot 型データセットとして扱う。
- 公式の過去断面アーカイブは前提にしない。**backfill は提供しない**。初回
  `vlake update cloudflare_waf` が現行断面の全量投入になる。
- ライセンスは実装時に Cloudflare Docs リポジトリの `LICENSE` / `LICENSE.md` /
  `NOTICE` を確認し、`DATA_LICENSES.md` と `datasets` ビューに正確な条件・帰属・
  免責を記録する。ライセンス確認ができない場合は実装を止め、設計を更新する。

## アーキテクチャ

既存のデータセットプラグイン構造に倣い `src/vlake/cloudflare_waf.py` を追加する。
方式は `kev` / `nuclei` と同じ「update のみ + latest との内容比較 + tombstone」。

- **データセットモジュール**: Markdown 取得、ChangeLog エントリ分割、脆弱性識別子抽出、
  PyArrow Table 化、Parquet 書き出し、ストレージキー命名を担当する。
- **DuckLake**: `cloudflare_waf_history` を append-only 履歴テーブルとして追加し、
  `cloudflare_waf` view は `identifier + source_url` ごと `fetched_date` 最新の1行を返す。
- **Pipeline**: `update_cloudflare_waf()` を追加する。最新断面とカタログ latest を比較し、
  新規・変更・復活・削除(tombstone)だけを日次 Parquet として追記する。
- **CVE 横断ビュー**: `cve_sources` に `has_cloudflare_waf` と `cloudflare_waf_count` を追加する。
- **公開順序**: 既存の不変条件を維持する。Parquet データファイルを先にアップロードし、
  DuckLake カタログの差し替えは最後に行う。

## スキーマ

テーブル `cloudflare_waf_history` (append-only) + ビュー `cloudflare_waf`
(`identifier + source_url` ごと fetched_date 最新の1行)。

```sql
CREATE TABLE cloudflare_waf_history (
  identifier       VARCHAR, -- 抽出した脆弱性識別子。例: CVE-2024-3400, GHSA-xxxx-yyyy-zzzz
  identifier_type  VARCHAR, -- CVE / GHSA / GO / PYSEC / RUSTSEC / OTHER
  cve              VARCHAR, -- identifier_type = 'CVE' の場合は同じ値、それ以外は NULL
  source_title     VARCHAR, -- ChangeLog エントリ見出し
  source_url       VARCHAR, -- 公開 Docs の該当 ChangeLog URL
  source_date      DATE,    -- ChangeLog エントリ側の日付。取れない場合は NULL
  matched_text     VARCHAR, -- 識別子が含まれていた短い文脈抜粋
  fetched_date     DATE,    -- 取り込み実行日。latest ビューの順序付けキー
  removed          BOOLEAN  -- 現行断面から消えた識別子言及の tombstone
);
```

### 識別子抽出

初期実装では、誤検出が比較的少なく形式が明確な識別子を対象にする。

- `CVE-YYYY-NNNN...` → `identifier_type = 'CVE'`, `cve = identifier`
- `GHSA-xxxx-xxxx-xxxx` → `identifier_type = 'GHSA'`
- `GO-YYYY-NNNN` → `identifier_type = 'GO'`
- `PYSEC-YYYY-NNN...` → `identifier_type = 'PYSEC'`
- `RUSTSEC-YYYY-NNNN` → `identifier_type = 'RUSTSEC'`
- その他、実データで確認した明確な脆弱性 ID は `OTHER` ではなく専用 type を追加する。
  不明瞭な製品名・ルール ID・ブログ番号は収録しない。

抽出値は大文字に正規化し、同一 `identifier + source_url` の重複は1件にまとめる。
同じ識別子が複数 ChangeLog エントリに現れる場合は出典が異なるため複数行を保持し、
`cloudflare_waf_count` に反映する。

## データフロー

1. `uv run vlake update cloudflare_waf` を実行する。
2. Cloudflare Docs GitHub リポジトリ上の WAF ChangeLog Markdown を取得する。
3. Markdown をエントリ単位に分割し、見出し・日付・本文・公開 URL を抽出する。
4. 各エントリ本文から脆弱性識別子を抽出する。
5. `identifier + source_url` で重複排除し、`matched_text` には識別子周辺の短い文脈を入れる。
6. カタログ latest (`cloudflare_waf`) と比較する。
7. 新規・変更・復活・削除があれば `cloudflare_waf/updates/year=YYYY/cloudflare-waf-updates-YYYY-MM-DD.parquet`
   を作成してアップロードする。
8. `cloudflare_waf_history` にデータファイルを登録し、datasets view / latest view /
   `cve_sources` を再生成して、最後にカタログを公開する。

`fetched_date` とストレージキーの日付は実行日(UTC)を使う。同日再実行は登録済みパスで
`already-registered` とし、二重登録しない。

## 差分検出と tombstone

latest 側のキーは `identifier + source_url`。現行断面と latest の同一キーを比較し、
次の行だけを追記する。

1. **新規**: latest に無いキー。
2. **変更**: `identifier_type`, `cve`, `source_title`, `source_date`, `matched_text` のいずれかが変わったキー。
3. **復活**: latest で `removed = true` だったキーが現行断面に再出現した場合。
4. **削除**: latest で `removed = false` だが現行断面に無いキー。最新行の値を引き継ぎ、
   `removed = true`, `fetched_date = 実行日` の tombstone を追記する。

異常断面ガードとして、カタログに有効行が存在するのに現行断面の抽出件数が 0 件の場合は
RuntimeError で中断する。また、現行断面が latest の有効キー数の半分未満に急減した場合も
上流取得・パース異常とみなし中断する。初回投入で抽出件数が 0 件の場合も、対象ページや
パーサの誤りの可能性が高いため失敗させる。

## ストレージキー

```
cloudflare_waf/updates/year=YYYY/cloudflare-waf-updates-YYYY-MM-DD.parquet
```

backfill 用の年次ファイルは作らない。update の初回が現行断面の全量、2回目以降が差分になる。

## 各層の変更

- **`src/vlake/cloudflare_waf.py`**: `NAME` / `SCHEMA` / `LICENSE_INFO` /
  `CHANGELOG_SOURCE_URL` / `download()` / `parse_markdown()` / `extract_identifiers()` /
  `rows_to_table()` / `write_parquet()` / `key_for_update()` を追加する。
- **`src/vlake/lake.py`**: `cloudflare_waf_history` テーブル定義、
  `cloudflare_waf_latest_rows()`、`refresh_cloudflare_waf_view()`、
  `refresh_cve_sources_view()` の Cloudflare WAF 集計を追加する。
- **`src/vlake/pipeline.py`**: `update_cloudflare_waf()`、`_publish_catalog()` の
  license/view refresh、`rebuild_catalog()` の prefix → table mapping、`verify()` の
  history 検証を追加する。
- **`src/vlake/cli.py`**: `update` の Choice に `cloudflare_waf` を追加する。
  `backfill` には追加しない。
- **tests**: `tests/conftest.py` に Cloudflare WAF Markdown フィクスチャ生成を追加し、
  `tests/test_cloudflare_waf.py` と `tests/test_pipeline_cloudflare_waf.py` を追加する。
  既存の `datasets` 件数・`cve_sources` 列/集計テストを更新する。
- **docs / license**: `README.md`, `docs/schema.md`, `DATA_LICENSES.md`, 必要なら
  `licenses/` に Cloudflare Docs のライセンス全文または参照文を追加する。
- **CI**: `.github/workflows/publish.yml` に `uv run vlake update cloudflare_waf` を追加する。
  `.github/workflows/backfill.yml` には追加しない。

## `cve_sources` の追加列

`cloudflare_waf` の `cve IS NOT NULL AND NOT removed` のみを集計対象にする。

| Column | Type | Description |
|---|---|---|
| `has_cloudflare_waf` | BOOLEAN | Cloudflare WAF ChangeLog で CVE が言及されているか |
| `cloudflare_waf_count` | BIGINT | その CVE に対応する Cloudflare WAF ChangeLog 言及数 |

`all_cves` CTE には Cloudflare WAF の CVE も含める。これにより、CVE List や EPSS に
未収録でも Cloudflare WAF ChangeLog で言及された CVE は `cve_sources` に現れる。

## エラーハンドリング

- 上流 Markdown の取得に失敗した場合は例外で中断し、カタログは更新しない。
- パース対象ファイルが見つからない、または抽出結果が 0 件の場合は例外で中断する。
- latest 有効キー数に対して現行断面が半分未満に急減した場合は例外で中断する。
- 同日キーが既にカタログ登録済みなら `already-registered YYYY-MM-DD` を返す。
- 差分行が無い場合は `no-new-records YYYY-MM-DD` を返し、カタログ更新は行わない。
- Parquet アップロード後・カタログ公開前に失敗した場合は、次回実行で登録済みパス確認により
  冪等に回復できる既存方針に従う。

## テスト方針

既存と同じ統合スタイル(VLAKE_LOCAL_DIR + tmp_path、ネットワーク不使用)でテストする。
`cloudflare_waf.download` を monkeypatch し、Markdown 文字列は実フォーマットに近い
見出し・日付・本文・リンクを含むフィクスチャで生成する。

- `test_cloudflare_waf.py`
  - CVE / GHSA / GO / PYSEC / RUSTSEC の抽出と大文字正規化。
  - 誤検出しやすい文字列を拾わないこと。
  - Markdown エントリ分割、日付・タイトル・公開 URL 生成。
  - `identifier + source_url` 重複排除。
  - `key_for_update()` と Parquet roundtrip。
- `test_pipeline_cloudflare_waf.py`
  - 初回 update が全量投入になる。
  - 同日再実行が `already-registered` になる。
  - 別日で差分なしなら `no-new-records` になる。
  - 新規識別子追加、既存文脈変更、削除 tombstone、復活が反映される。
  - 異常縮小ガードがカタログ未更新で失敗する。
  - `cve_sources` の `has_cloudflare_waf` / `cloudflare_waf_count` が正しい。
  - `verify()` と `rebuild_catalog()` が Cloudflare WAF を扱う。

## 却下した代替案

- **ChangeLog エントリ中心スキーマ**: `entry_id` ごと1行で `identifiers` 配列を持つ方式。
  後からエントリ分析はしやすいが、主目的の「識別子で対応有無を確認する」には
  `UNNEST` が必要になり、通常クエリが複雑になるため不採用。
- **identifier だけの最小スキーマ**: 出典 URL や文脈を削る方式。実装は小さいが、
  なぜ対応ありと判断したか検証できず、ライセンス・帰属・デバッグ上も弱いため不採用。
- **HTML スクレイピング第一**: 公開ページの DOM 変更に弱い。GitHub Markdown が利用できない
  場合の fallback としては残すが、初期実装の第一候補にはしない。
- **防御文脈の自然言語判定**: 「rule added」「mitigation」等の文脈だけを採用する方式。
  取りこぼしが増え、Cloudflare の文体変更にも弱い。初期実装では ChangeLog 内の
  識別子言及を対応シグナルとして扱う。

## 実装時の注意

- コード内コメント・docstring・コミットメッセージは日本語にする。
- `vlake` は CLI / 環境変数 / パッケージ名として維持し、README タイトル等の正式名
  `vulnlake` と混同してリネームしない。
- スキーマ・latest view・`cve_sources` を変更するため、README と `docs/schema.md` は
  `readme-schema-sync` skill の対象として同期する。
- ネットワーク越しの git 操作は行わない。実装ブランチの push はユーザーが手動で行う。
