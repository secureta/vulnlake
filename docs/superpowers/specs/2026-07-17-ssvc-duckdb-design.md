# SSVC DuckDB 提供ビュー設計

2026-07-17。vulnlake に、DuckDB 経由で SSVC を参照・計算できる公開 view を追加する。
初期対象は **cvelistV5 の CISA ADP Vulnrichment に含まれる CISA Coordinator SSVC** に限定する。
Web/API は今回のスコープ外とし、DuckLake カタログ上の view だけで提供する。

## 目的

ユーザーが CVE を起点に SSVC の記録値と decision 候補を確認できるようにする。
SSVC の入力パラメータが一部欠損している場合でも、不足パラメータの取りうる値を全展開し、
対応する decision 候補を返す。

主な利用例:

```sql
-- CVE に記録された SSVC と、不足パラメータ補完後の decision 候補を見る
SELECT *
FROM vlake.cve_ssvc_candidates
WHERE cve = 'CVE-2024-0001';

-- decision tree を直接、部分入力で絞り込む
SELECT *
FROM vlake.ssvc_decision
WHERE exploitation = 'active';
```

## スコープ

含めるもの:

- `cve.raw` / `cve_history.raw` からの SSVC 動的抽出 view
- CISA Coordinator SSVC の decision tree を全組み合わせ表として公開する view
- CVE 実データと decision tree を結合し、不足パラメータを全展開する候補 view
- README / `docs/schema.md` / `docs/llms.md` の利用例更新
- view refresh 経路とテスト

含めないもの:

- Web UI / Web API
- SSVC 抽出済み Parquet/table の物理化
- CISA Coordinator 以外の role / decision tree
- CVE パイプラインの backfill/update データファイル生成順序の変更

## 全体アーキテクチャ

初期実装は **view 中心**とする。既存の `cve_history` には CVE JSON 5.x 全文が
`raw` 列として入っているため、既存 Parquet を再生成せず DuckDB JSON 関数で SSVC を抽出する。

追加する公開 view:

| view | 目的 |
|---|---|
| `cve_ssvc_history` | `cve_history.raw` から抽出した SSVC 履歴 |
| `cve_ssvc` | 最新 `cve.raw` から抽出した SSVC |
| `ssvc_decision` | CISA Coordinator SSVC の全 decision 組み合わせ |
| `cve_ssvc_candidates` | CVE 実データを起点に、不足パラメータを全展開した decision 候補 |

`cve_ssvc_candidates` を主導線にする。SSVC が無い CVE は 0 行を返す。
SSVC があり一部パラメータが欠損している場合は、欠損している列について
`ssvc_decision` 側の全値を候補として返す。

## SSVC 抽出 view

### `cve_ssvc_history`

`cve_history` から CISA ADP Vulnrichment の CISA Coordinator SSVC を抽出する。
CVE レコード内に条件に合う SSVC が複数存在する場合は複数行を返す。
通常は 1 CVE の 1 履歴行あたり 0〜1 行を想定する。

列:

| column | type | 内容 |
|---|---|---|
| `cve` | VARCHAR | CVE ID |
| `date_updated` | TIMESTAMP | CVE レコード更新日時 |
| `ssvc_version` | VARCHAR | SSVC version |
| `ssvc_role` | VARCHAR | SSVC role。初期対象は CISA Coordinator |
| `ssvc_timestamp` | TIMESTAMP | SSVC 評価時刻 |
| `ssvc_provider` | VARCHAR | SSVC を提供した ADP/provider。例: CISA ADP Vulnrichment |
| `exploitation` | VARCHAR | SSVC `Exploitation` |
| `automatable` | VARCHAR | SSVC `Automatable` |
| `technical_impact` | VARCHAR | SSVC `Technical Impact` |
| `recorded_decision` | VARCHAR | cvelistV5 に記録された decision |
| `ssvc_raw` | VARCHAR | 抽出元 SSVC JSON 断片 |

抽出方針:

- `containers.adp[*]` を走査し、CISA ADP Vulnrichment と判定できるコンテナを対象にする。
- 対象コンテナ内の SSVC metric を走査し、role が CISA Coordinator のものを抽出する。
- `options` 配列から `Exploitation` / `Automatable` / `Technical Impact` を名前で取り出す。
- `decision` / `version` / `timestamp` / `role` は SSVC metric から取り出す。
- 元断片は `ssvc_raw` に JSON 文字列として残す。

CISA 側の JSON 形状が変わった場合に備え、正規化列で取り切れない情報は `ssvc_raw` で監査できるようにする。

### `cve_ssvc`

`cve` view から同じ抽出を行う最新状態用 view。列は `cve_ssvc_history` と同一とする。
通常利用ではこちら、履歴分析では `cve_ssvc_history` を使う。

## `ssvc_decision`

CISA Coordinator SSVC の decision tree を全組み合わせ表として公開する。
ユーザーは任意の列を `WHERE` で絞るだけで、未指定パラメータについて全候補を得られる。

列:

| column | type | 内容 |
|---|---|---|
| `ssvc_version` | VARCHAR | 対象 SSVC version |
| `ssvc_role` | VARCHAR | `CISA Coordinator` |
| `exploitation` | VARCHAR | `none` / `poc` / `active` など |
| `automatable` | VARCHAR | `yes` / `no` |
| `technical_impact` | VARCHAR | `partial` / `total` など |
| `decision` | VARCHAR | `Track` / `Track*` / `Attend` / `Act` など |
| `decision_label` | VARCHAR | 表示用ラベル。初期は `decision` と同値でよい |
| `decision_rank` | INTEGER | 並び替え用の重大度順 |

decision tree は view 内の `VALUES` または同等の固定 SQL として定義する。
値の正式な組み合わせは実装時に CISA Coordinator SSVC の公開仕様と実データを確認して固定する。

## `cve_ssvc_candidates`

`cve_ssvc` と `ssvc_decision` を結合し、CVE に記録済みの値を条件として decision 候補を返す。

結合ルール:

- CVE 側の `exploitation` が非 NULL なら `ssvc_decision.exploitation` と一致する行だけ残す。
- CVE 側の `automatable` が非 NULL なら `ssvc_decision.automatable` と一致する行だけ残す。
- CVE 側の `technical_impact` が非 NULL なら `ssvc_decision.technical_impact` と一致する行だけ残す。
- CVE 側が NULL のパラメータは、`ssvc_decision` 側の全値を候補として残す。
- SSVC が存在しない CVE は 0 行を返す。

列:

| column | 内容 |
|---|---|
| `cve` | CVE ID |
| `date_updated` | 最新 CVE レコード更新日時 |
| `ssvc_version` | SSVC version |
| `ssvc_role` | SSVC role |
| `ssvc_timestamp` | SSVC 評価時刻 |
| `ssvc_provider` | provider 情報 |
| `exploitation` | 実値または候補値 |
| `automatable` | 実値または候補値 |
| `technical_impact` | 実値または候補値 |
| `recorded_exploitation` | CVE に記録された `Exploitation` |
| `recorded_automatable` | CVE に記録された `Automatable` |
| `recorded_technical_impact` | CVE に記録された `Technical Impact` |
| `recorded_decision` | CVE に記録された decision |
| `computed_decision` | decision tree から再計算した decision |
| `decision_matches` | `recorded_decision` と `computed_decision` が一致するか。どちらか NULL なら NULL |
| `decision_rank` | 並び替え用重大度 |
| `ssvc_raw` | 抽出元 SSVC JSON 断片 |

`recorded_*` 列を残すことで、候補展開後の値と元データのどこが補完されたかを確認できる。
`recorded_decision` と `computed_decision` は両方返し、不一致はエラーにせず `decision_matches = false` とする。

## 実装位置と公開フロー

実装は `src/vlake/lake.py` に集約し、既存の view refresh パターンに合わせる。
追加メソッド案:

- `refresh_cve_ssvc_history_view()`
- `refresh_cve_ssvc_view()`
- `refresh_ssvc_decision_view()`
- `refresh_cve_ssvc_candidates_view()`

`_publish_catalog()` と `rebuild_catalog()` の view refresh 経路に組み込む。
既存 Parquet / storage key / update / backfill の公開順序は変更しない。
Parquet データファイルを先にアップロードし、カタログ差し替えを最後にする不変条件は維持する。

旧カタログに view が無い場合も、次回 `update` または `rebuild-catalog` で作られる。
将来 SSVC を物理 table 化する場合も、view 名と列名を維持して利用者互換を保つ。

## ドキュメント

スキーマ公開の変更なので、以下を同期する。

- `README.md` の dataset / schema summary と代表クエリ
- `docs/schema.md` の view 一覧と列定義
- `docs/llms.md` に代表クエリを追加する

主導線は `cve_ssvc_candidates` とし、`cve_ssvc` / `cve_ssvc_history` / `ssvc_decision` は補助として説明する。

## エラーハンドリング

SSVC 抽出は view なので、未知形式や欠損は SQL 上で NULL または 0 行として扱う。

- ADP コンテナが無い CVE: `cve_ssvc` / `cve_ssvc_candidates` では 0 行。
- CISA Coordinator SSVC が無い CVE: 0 行。
- SSVC はあるが一部 option 欠損: 欠損列は NULL。`cve_ssvc_candidates` で候補展開する。
- `recorded_decision` と `computed_decision` の不一致: エラーにせず `decision_matches = false`。
- 未知の option 値: `ssvc_decision` と結合できないため候補 0 行。将来の version/値追加として検知できる。

## テスト

中心は `tests/test_lake.py` に追加する。fixture CVE raw に CISA ADP Vulnrichment の
SSVC 断片を含め、view の抽出と候補展開を検証する。

確認項目:

1. `cve_ssvc_history` が `cve_history.raw` から SSVC を抽出する。
2. `cve_ssvc` が最新 `cve` view から SSVC を抽出する。
3. SSVC が無い CVE は 0 行を返す。
4. 欠損パラメータがある CVE は `cve_ssvc_candidates` で不足分を全候補展開する。
5. `recorded_decision` / `computed_decision` / `decision_matches` が返る。
6. `ssvc_decision` 単体で部分条件検索できる。
7. `rebuild_catalog` / publish refresh 経路で view が作られる。

## 採用しなかった案

### 抽出済み SSVC table を追加する案

高速で列指向に扱いやすいが、CVE backfill/update・verify・rebuild への変更が大きい。
初期実装では既存 `raw` を活用した view で十分な価値を出し、性能問題が出た時点で物理化する。

### 抽出 view だけ公開し、decision 候補は SQL 例に留める案

実装は最小だが、「不足パラメータの全候補を返す」という目的が利用者側 SQL に寄りすぎる。
`ssvc_decision` と `cve_ssvc_candidates` を標準 view として提供する方が使いやすい。

## 実装後の代表クエリ

```sql
-- CVE 起点の主導線
SELECT
  cve,
  exploitation,
  automatable,
  technical_impact,
  recorded_decision,
  computed_decision,
  decision_matches
FROM vlake.cve_ssvc_candidates
WHERE cve = 'CVE-2024-0001'
ORDER BY decision_rank, exploitation, automatable, technical_impact;
```

```sql
-- SSVC decision tree を直接使う
SELECT *
FROM vlake.ssvc_decision
WHERE exploitation = 'active';
```

```sql
-- SSVC の履歴変化を見る
SELECT
  cve,
  date_updated,
  ssvc_timestamp,
  exploitation,
  automatable,
  technical_impact,
  recorded_decision
FROM vlake.cve_ssvc_history
WHERE cve = 'CVE-2024-0001'
ORDER BY date_updated;
```
