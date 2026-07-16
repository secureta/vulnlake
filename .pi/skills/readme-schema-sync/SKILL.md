---
name: readme-schema-sync
description: >-
  Use when changing vlake DuckLake schema documentation: adding/removing/changing
  tables, columns, latest views, datasets, docs/schema.md, README.md Schema summary,
  src/vlake/lake.py CREATE TABLE or refresh_*_view, or dataset storage key_for* paths.
---

# スキーマ参照ドキュメントの同期

vlake のカタログ定義 (`src/vlake/lake.py`) と `docs/schema.md` は手動同期であり、
片方だけ変えると必ずズレる。README の `## Schema` 節は概要とリンクだけを置く。
**テーブル定義・カラム・latest ビュー・ストレージキー命名のいずれかを触ったら、
このSkillの手順で `docs/schema.md` を更新すること。**

コメント・docstring・コミットメッセージは日本語 (AGENTS.md の方針)。

## いつ使うか (トリガー)

以下のどれかに当てはまったら、コミット前にこのSkillを実行する:

- `src/vlake/lake.py` の `CREATE TABLE IF NOT EXISTS ...` を追加・削除・カラム変更した
- `src/vlake/lake.py` の `refresh_*_view` / `refresh_datasets_view` を追加・変更した
  (= latest ビューの追加や、ビューが返す列の変化)
- データセットモジュール (`epss.py` / `cvelist.py` / `ghsa.py` / `exploitdb.py` /
  `nuclei.py` / `kev.py` / `cwe.py`) の `key_for` / `key_for_year` /
  `key_for_update` / `key_for_version` / `year_key_for` などストレージキー命名を変えた
- 新しいデータセットを丸ごと追加した (この場合は下の「新データセット追加時」も参照)

## どこを直すか

`docs/schema.md` は次の3パートで構成される。変更の種類に応じて該当パートを直す。

1. **概要表** (`| Query this | Backed by | One row per | Content |`)
   - 新テーブル/ビューの追加・削除、または grain (one row per) の変化で更新
2. **各テーブルのカラム表** (`### <name> — ...` 見出し + `| Column | Type | Description |`)
   - カラムの追加/削除/型変更/意味変更で更新。**このプロジェクトでは 9 個** (epss /
     cve / ghsa / exploitdb / nuclei / cwe / kev / cloudflare_waf / datasets)
3. **Storage layout 表** (`## Parquet storage layout` の `| Dataset | ... | Update files | Notes |`)
   - `key_for*` のパス命名やパーティション/ソート方針、backfill の有無を変えたら更新

README は初見ユーザー向けに保つ。新データセット追加/削除時は `## What is included` と
`## Schema` 概要表だけを更新し、詳細カラム表は置かない。

## 実行手順

### 1. 真実のソースを読む

README ではなく **コードを先に読む**。カラムの正はここ:

```bash
sed -n '/def ensure_tables/,/def registered_paths/p' src/vlake/lake.py
```

- 各 `CREATE TABLE IF NOT EXISTS {self.ALIAS}.<table> ( ... )` のカラム名・型が
  `docs/schema.md` カラム表の正。`STRUCT(...)[]` や `VARCHAR[]` もそのまま反映する。
- latest ビュー名と grain は `refresh_*_view` の
  `CREATE OR REPLACE VIEW ... QUALIFY row_number() OVER (PARTITION BY <key> ...)` を見る
  (`<key>` が「one row per」になる)。
- ストレージキーは各モジュールの `key_for*` を読む:

```bash
grep -rn "def key_for\|def year_key_for\|def key_for_year\|def key_for_update\|def key_for_version\|LAST_MODIFIED_KEY" src/vlake/
```

### 2. `docs/schema.md` を編集する

- 対応する `### <name>` セクションのカラム表を、コードのカラム順・名前・型に合わせる。
- 説明列 (Description) は人間向けの意味を書く。既存行のトーンに合わせ、
  NULL になる条件・latest ビューのキー・tombstone (`removed = true`) など
  クエリ時に効く注記を残す。
- history テーブルと latest ビューを併記する見出し規約は
  `### <view> / <table>_history — <正式名>` (例: `### cve / cve_history — CVE List V5`)。
  EPSS はビューが無いので `### epss — ...` の単独見出し。

### 3. 検証する (コードとの一致を機械照合)

Skill ディレクトリ付属の検証スクリプトで、`docs/schema.md` のカラム名・順序・型が
`src/vlake/lake.py` の `CREATE TABLE` と一致するか確認する:

```bash
uv run python .pi/skills/readme-schema-sync/scripts/check_readme_schema.py
```

Markdown 表のパイプ数が各ブロック内でそろっているか (崩れた表の検出):

```bash
awk '
/^\|/ { n=gsub(/\|/,"|"); if(inblock && n!=prev){print "PIPE MISMATCH line "NR": "$0; bad=1} prev=n; inblock=1; next }
{ inblock=0 } END{ if(!bad) print "OK: table pipes consistent" }
' README.md docs/schema.md
```

末尾空白などの混入チェック:

```bash
git diff --check -- README.md docs/schema.md .pi/skills/readme-schema-sync/SKILL.md .pi/skills/readme-schema-sync/scripts/check_readme_schema.py
```

不一致/表崩れがあれば手順 1–2 に戻る。**コードのカラム定義が正。**

## 新データセット追加時

テーブル1個の変更に加えて、AGENTS.md「新データセットを追加するときに触るファイル」の
全項目を漏れなく直す。README 関連では:

1. README の `## What is included` にデータセット名を追記
2. README と `docs/schema.md` の概要表に 1 行追加
3. `docs/schema.md` に新しい `### <view> / <ds>_history — <正式名>` セクション + カラム表を追加
4. `docs/schema.md` の Storage layout 表に 1 行追加
5. README の `## Build your own lake` のコマンド例 (`uv run vlake update <ds>` など) を追記
6. `DATA_LICENSES.md` と README のライセンス節に帰属・ライセンスを追加

README 以外 (lake.py / pipeline.py / cli.py / tests / workflows) はコード側タスク。
既存の追加例は `git log` の ghsa / exploitdb / cwe 追加コミット群と
`docs/superpowers/plans/` / `docs/superpowers/specs/` を参照。

## 完了条件

- `docs/schema.md` のカラム表がコードの `CREATE TABLE` と 1:1 (数・名前・順序・型。STRUCT はフィールド名まで一致)
- README と `docs/schema.md` の概要表・Storage layout 表・データセット一覧が実態と一致
- 上記の検証コマンドがすべて通る (`check_readme_schema.py` が OK、pipes consistent、git diff --check クリーン)
